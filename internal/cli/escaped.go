package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/josegonzalez/safeclaw/internal/hangup"
	"github.com/josegonzalez/safeclaw/internal/termtext"
)

// exitCodeError makes Execute exit with code without printing an error: it
// carries the exit code of a command whose own output already said what
// went wrong.
type exitCodeError struct{ code int }

func (e exitCodeError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

// forwardedSignals are passed on to the command runChild runs. SIGHUP is
// left out when safeclaw was started with it ignored, as under nohup, so it
// stays ignored by safeclaw and the command, which inherits that.
var forwardedSignals = hangup.Signals(syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)

// runEscaped runs argv with its stdout and stderr passed through
// termtext.Writer, so control characters in them are escaped before they
// reach the caller's terminal, and returns its exit code as runChild does.
func runEscaped(argv []string, stdin io.Reader, stdout, stderr io.Writer, shareGroup bool) (int, error) {
	return runChild(argv, childOptions{stdin: stdin, stdout: stdout, stderr: stderr, escape: true, shareGroup: shareGroup})
}

// childOptions configures runChild.
type childOptions struct {
	stdin          io.Reader
	stdout, stderr io.Writer
	// escape passes stdout and stderr through termtext.Writer.
	escape bool
	// shareGroup keeps the command in safeclaw's process group.
	shareGroup bool
	// extraFiles are inherited by the command as fd 3 onwards.
	extraFiles []*os.File
	// deadline, when set, calls onDeadline once if the command is still
	// running that long after it started.
	deadline   time.Duration
	onDeadline func(*os.Process)
}

// runChild runs argv as a child and returns its exit code: 128 plus the
// signal number when it was killed by a signal, as a shell reports it.
//
// SIGINT, SIGTERM, SIGHUP and SIGQUIT sent to safeclaw are forwarded to
// the command instead of killing safeclaw (SIGHUP only when it wasn't
// ignored at start, see forwardedSignals), so its output is still escaped
// and flushed when it exits. The command runs in its own process group, so
// a Ctrl-C at the terminal reaches it once, through safeclaw. When
// shareGroup is set it stays in safeclaw's group instead, so it can read a
// terminal on stdin without being stopped; the terminal then signals it
// directly, and only SIGTERM and SIGHUP are forwarded so it doesn't get
// SIGINT or SIGQUIT twice.
func runChild(argv []string, o childOptions) (int, error) {
	stdout, stderr := o.stdout, o.stderr
	var outW, errW *termtext.Writer
	if o.escape {
		outW, errW = termtext.NewWriter(stdout), termtext.NewWriter(stderr)
		stdout, stderr = outW, errW
	}
	c := exec.Command(argv[0], argv[1:]...)
	c.Stdin = o.stdin
	c.Stdout = stdout
	c.Stderr = stderr
	c.ExtraFiles = o.extraFiles
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: !o.shareGroup}

	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, forwardedSignals...)
	defer signal.Stop(sigs)

	if err := c.Start(); err != nil {
		return 0, err
	}
	var expired <-chan time.Time
	if o.deadline > 0 {
		t := time.NewTimer(o.deadline)
		defer t.Stop()
		expired = t.C
	}
	done := make(chan struct{})
	forwarded := make(chan struct{})
	go func() {
		defer close(forwarded)
		for {
			select {
			case s := <-sigs:
				if o.shareGroup && (s == syscall.SIGINT || s == syscall.SIGQUIT) {
					continue
				}
				_ = c.Process.Signal(s)
			case <-expired:
				expired = nil
				o.onDeadline(c.Process)
			case <-done:
				return
			}
		}
	}()
	waitErr := c.Wait()
	close(done)
	<-forwarded

	var flushErr error
	if o.escape {
		flushErr = errors.Join(outW.Flush(), errW.Flush())
	}
	var exitErr *exec.ExitError
	if waitErr != nil && !errors.As(waitErr, &exitErr) {
		return 0, errors.Join(waitErr, flushErr)
	}
	return exitCode(c.ProcessState), flushErr
}

// exitCode returns a finished process's exit code, or 128 plus the signal
// number when a signal killed it.
func exitCode(ps *os.ProcessState) int {
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ps.ExitCode()
}
