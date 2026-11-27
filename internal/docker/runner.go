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
	"strings"

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
	// Passthrough runs docker with args attached to the current stdio.
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
}

func (r ExecRunner) bin() string {
	if r.Binary != "" {
		return r.Binary
	}
	return "docker"
}

// Output implements Runner.
func (r ExecRunner) Output(ctx context.Context, stdin io.Reader, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, r.bin(), args...)
	stdout := &limitBuffer{max: MaxOutput}
	stderr := &tailBuffer{max: MaxStderr}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if stdin != nil {
		cmd.Stdin = stdin
	}
	err := cmd.Run()
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

// Passthrough implements Runner.
func (r ExecRunner) Passthrough(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, r.bin(), args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
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
