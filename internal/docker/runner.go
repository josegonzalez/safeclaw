// Package docker wraps the docker CLI. Every command is run with an argument
// slice, never through a shell.
package docker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/creack/pty"
	"golang.org/x/term"

	"github.com/josegonzalez/safeclaw/internal/hostterm"
	"github.com/josegonzalez/safeclaw/internal/termtext"
)

const (
	// MaxStderr is how much of a command's stderr is kept. Only the tail is
	// kept, since that is where tools put the reason they failed.
	MaxStderr = 64 << 10
	// MaxOutput is the most stdout Output buffers before failing the
	// command with ErrOutputTooLarge.
	MaxOutput = 64 << 20
)

// ErrOutputTooLarge is returned when a command run with Output writes more
// than MaxOutput bytes to stdout.
var ErrOutputTooLarge = fmt.Errorf("output exceeds %d bytes", MaxOutput)

// Runner runs docker CLI commands.
type Runner interface {
	// Output runs docker with args, feeding stdin if non-nil, and returns stdout.
	// A non-zero exit returns an *Error carrying stderr.
	Output(ctx context.Context, stdin io.Reader, args ...string) ([]byte, error)
	// Passthrough runs docker with args attached to the current stdio,
	// with its output passed through termtext.Filter.
	Passthrough(ctx context.Context, args ...string) error
	// Stream starts docker with args and returns its stdout. Calling the
	// returned function waits for the process to exit, returning an *Error
	// carrying stderr on a non-zero exit.
	Stream(ctx context.Context, args ...string) (io.ReadCloser, func() error, error)
}

// Error is returned when a docker command exits non-zero.
type Error struct {
	Args   []string
	Stderr string
	Err    error
}

// Error returns docker's stderr, or the exit error when there is none,
// with control characters escaped: stderr often comes from inside a
// container, so it must not reach the terminal as escape sequences.
func (e *Error) Error() string {
	msg := strings.TrimSpace(e.Stderr)
	if msg == "" {
		msg = e.Err.Error()
	}
	return termtext.Escape(fmt.Sprintf("docker %s: %s", firstArg(e.Args), msg))
}

func (e *Error) Unwrap() error { return e.Err }

func firstArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

// ExecRunner runs the real docker binary.
type ExecRunner struct {
	// Binary is the docker executable. Defaults to "docker".
	Binary string
	// WaitDelay is how long Output waits for docker's stdio once docker
	// has exited or its context is done. Defaults to DefaultWaitDelay.
	WaitDelay time.Duration
}

func (r ExecRunner) bin() string {
	if r.Binary != "" {
		return r.Binary
	}
	return "docker"
}

// DefaultWaitDelay is how long Output waits for docker's stdout and stderr
// to close once docker has exited or its context is done, so a pipe a
// child of docker holds open can't keep Output from returning.
const DefaultWaitDelay = 5 * time.Second

// Output implements Runner. Docker's stdin is closed as soon as stdin
// ends, so docker sees EOF then, and Output returns once docker exits
// without waiting for the rest of stdin: os/exec would wait for its copy
// of a stdin whose Read blocks forever, even after the context killed
// docker. A stdin that fails is an error unless docker exited first.
func (r ExecRunner) Output(ctx context.Context, stdin io.Reader, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, r.bin(), args...)
	cmd.WaitDelay = r.WaitDelay
	if cmd.WaitDelay <= 0 {
		cmd.WaitDelay = DefaultWaitDelay
	}
	stdout := &limitBuffer{max: MaxOutput}
	stderr := &tailBuffer{max: MaxStderr}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	var in io.WriteCloser
	if f, ok := stdin.(*os.File); ok {
		cmd.Stdin = f
	} else if stdin != nil {
		var err error
		if in, err = cmd.StdinPipe(); err != nil {
			return nil, &Error{Args: args, Err: err}
		}
	}
	if err := cmd.Start(); err != nil {
		return nil, &Error{Args: args, Stderr: stderr.String(), Err: err}
	}
	copied := make(chan error, 1)
	if in != nil {
		go func() {
			_, err := io.Copy(in, stdin)
			// Closing ends docker's stdin, so it sees EOF.
			_ = in.Close()
			copied <- err
		}()
	}
	// Wait closes docker's stdin once docker exits, which ends a copy
	// still writing to it, but not one blocked reading stdin.
	err := cmd.Wait()
	if err == nil {
		select {
		case cerr := <-copied:
			if cerr != nil && !errors.Is(cerr, syscall.EPIPE) && !errors.Is(cerr, os.ErrClosed) {
				err = fmt.Errorf("writing stdin: %w", cerr)
			}
		default:
		}
	}
	if stdout.over {
		// The refused write closed the pipe, so docker may have died of it;
		// the real reason is the size.
		return nil, &Error{Args: args, Stderr: stderr.String(), Err: ErrOutputTooLarge}
	}
	if err != nil {
		return stdout.buf.Bytes(), &Error{Args: args, Stderr: stderr.String(), Err: err}
	}
	return stdout.buf.Bytes(), nil
}

// Passthrough implements Runner. The output of a build or pull, or of a
// sign-in running in a container, comes from the image, so it is passed
// through termtext.Filter rather than straight to the terminal. When
// stdout and stderr are both terminals, docker runs with them on a
// pseudo-terminal of its own, which keeps its progress display and the
// terminal size for `exec -it`, and with stdin left on the caller's, so
// docker reads and sets up the terminal itself as before. Otherwise its
// stdout and stderr are each filtered on the way to the caller's.
func (r ExecRunner) Passthrough(ctx context.Context, args ...string) error {
	return r.passthrough(ctx, os.Stdin, os.Stdout, os.Stderr, args)
}

func (r ExecRunner) passthrough(ctx context.Context, stdin, stdout, stderr *os.File, args []string) error {
	if term.IsTerminal(int(stdout.Fd())) && term.IsTerminal(int(stderr.Fd())) {
		winch := make(chan os.Signal, 1)
		signal.Notify(winch, syscall.SIGWINCH)
		defer signal.Stop(winch)
		code, err := hostterm.Relay(ctx, append([]string{r.bin()}, args...), hostterm.Options{
			HostStdin: stdin,
			Stdout:    stdout,
			Size:      func() (*pty.Winsize, error) { return pty.GetsizeFull(stdout) },
			Winch:     winch,
		})
		if err == nil && code != 0 {
			err = fmt.Errorf("exit status %d", code)
		}
		if err != nil {
			return &Error{Args: args, Err: err}
		}
		return nil
	}
	cmd := exec.CommandContext(ctx, r.bin(), args...)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	cmd.Stdout = termtext.NewFilter(stdout)
	cmd.Stderr = termtext.NewFilter(stderr)
	if err := cmd.Run(); err != nil {
		return &Error{Args: args, Err: err}
	}
	return nil
}

// Stream implements Runner.
func (r ExecRunner) Stream(ctx context.Context, args ...string) (io.ReadCloser, func() error, error) {
	cmd := exec.CommandContext(ctx, r.bin(), args...)
	stderr := &tailBuffer{max: MaxStderr}
	cmd.Stderr = stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	wait := func() error {
		if err := cmd.Wait(); err != nil {
			return &Error{Args: args, Stderr: stderr.String(), Err: err}
		}
		return nil
	}
	return out, wait, nil
}

// limitBuffer buffers up to max bytes, refusing the write that would go
// past it. os/exec then closes the pipe, so the command can't keep writing.
type limitBuffer struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (b *limitBuffer) Write(p []byte) (int, error) {
	if len(p) > b.max-b.buf.Len() {
		b.over = true
		return 0, ErrOutputTooLarge
	}
	return b.buf.Write(p)
}

// tailBuffer keeps the last max bytes written to it and never fails a
// write, so a command with chatty stderr still runs to completion.
type tailBuffer struct {
	buf       []byte
	max       int
	truncated bool
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if n >= b.max {
		b.buf = append(b.buf[:0], p[n-b.max:]...)
		b.truncated = true
		return n, nil
	}
	if drop := len(b.buf) + n - b.max; drop > 0 {
		b.buf = append(b.buf[:0], b.buf[drop:]...)
		b.truncated = true
	}
	b.buf = append(b.buf, p...)
	return n, nil
}

// String returns the kept tail, marked when earlier output was dropped.
func (b *tailBuffer) String() string {
	if b.truncated {
		return "[earlier output truncated] " + string(b.buf)
	}
	return string(b.buf)
}

// IsNotFound reports whether err came from docker failing to find an object.
func IsNotFound(err error) bool {
	var de *Error
	if !errors.As(err, &de) {
		return false
	}
	s := strings.ToLower(de.Stderr)
	return strings.Contains(s, "no such") || strings.Contains(s, "not found")
}

// IsNameConflict reports whether err came from docker refusing to create a
// container because another container already has its name.
func IsNameConflict(err error) bool {
	var de *Error
	if !errors.As(err, &de) {
		return false
	}
	return strings.Contains(strings.ToLower(de.Stderr), "is already in use by container")
}
