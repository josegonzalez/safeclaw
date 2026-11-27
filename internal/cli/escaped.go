package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	"github.com/josegonzalez/safeclaw/internal/termtext"
)

// exitCodeError makes Execute exit with code without printing an error: it
// carries the exit code of a command whose own output already said what
// went wrong.
type exitCodeError struct{ code int }

func (e exitCodeError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

// forwardedSignals are passed on to the command runEscaped runs.
var forwardedSignals = []os.Signal{syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT}

// runEscaped runs argv with its stdout and stderr passed through
// termtext.Writer, so control characters in them are escaped before they
// reach the caller's terminal, and returns its exit code: 128 plus the
// signal number when it was killed by a signal, as a shell reports it.
//
// SIGINT, SIGTERM, SIGHUP and SIGQUIT sent to safeclaw are forwarded to
// the command instead of killing safeclaw, so its output is still escaped
// and flushed when it exits. The command runs in its own process group, so
// a Ctrl-C at the terminal reaches it once, through safeclaw. When
// shareGroup is set it stays in safeclaw's group instead, so it can read a
// terminal on stdin without being stopped; the terminal then signals it
// directly, and only SIGTERM and SIGHUP are forwarded so it doesn't get
// SIGINT or SIGQUIT twice.
func runEscaped(argv []string, stdin io.Reader, stdout, stderr io.Writer, shareGroup bool) (int, error) {
	outW := termtext.NewWriter(stdout)
	errW := termtext.NewWriter(stderr)
	c := exec.Command(argv[0], argv[1:]...)
	c.Stdin = stdin
	c.Stdout = outW
	c.Stderr = errW
	c.SysProcAttr = &syscall.SysProcAttr{Setpgid: !shareGroup}

	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, forwardedSignals...)
	defer signal.Stop(sigs)

	if err := c.Start(); err != nil {
		return 0, err
	}
	done := make(chan struct{})
	forwarded := make(chan struct{})
	go func() {
		defer close(forwarded)
		for {
			select {
			case s := <-sigs:
				if shareGroup && (s == syscall.SIGINT || s == syscall.SIGQUIT) {
					continue
				}
				_ = c.Process.Signal(s)
			case <-done:
				return
			}
		}
	}()
	waitErr := c.Wait()
	close(done)
	<-forwarded

	flushErr := errors.Join(outW.Flush(), errW.Flush())
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
