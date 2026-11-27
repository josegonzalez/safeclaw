// Package hostterm runs a command on a pseudo-terminal of its own and
// passes its output on to the host terminal through termtext.Filter, so
// output from inside a container can't act on the host terminal.
package hostterm

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"

	"github.com/josegonzalez/safeclaw/internal/hangup"
	"github.com/josegonzalez/safeclaw/internal/termtext"
)

// forwardedSignals are passed on to the command. SIGHUP is left out when
// safeclaw was started with it ignored, as under nohup.
var forwardedSignals = hangup.Signals(syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT)

// Options configures Relay.
type Options struct {
	// Stdin, when set, is copied to the pseudo-terminal, which is then
	// the command's stdin too. The copy ends only when Stdin does, so it
	// suits a command run last, such as an attach, that reads a terminal
	// in raw mode.
	Stdin io.Reader
	// HostStdin, when set instead, is the command's stdin, and the
	// pseudo-terminal is only its stdout and stderr and its controlling
	// terminal. The command, such as `docker exec -it`, then reads the
	// host terminal itself and sets its modes, and nothing is left
	// reading it once the command exits.
	HostStdin *os.File
	// Stdout is where the filtered output goes.
	Stdout io.Writer
	// Size returns the size to give the pseudo-terminal, at the start and
	// each time Winch fires.
	Size  func() (*pty.Winsize, error)
	Winch <-chan os.Signal
}

// Relay runs argv on a new pseudo-terminal, passes its output through
// termtext.Filter to o.Stdout, and resizes it from o.Size each time
// o.Winch fires, which the kernel passes on to the command as SIGWINCH.
// It pushes the host terminal's titles before the output and, once the
// output ends, undoes the modes the command left set and pops them, so
// the host terminal is left as it was found even if the command is
// killed. SIGINT, SIGTERM, SIGHUP and SIGQUIT sent to safeclaw are
// forwarded to the command (SIGHUP only when it wasn't ignored at
// start). It returns the command's exit code, or 128 plus the signal
// number when a signal killed it.
func Relay(ctx context.Context, argv []string, o Options) (int, error) {
	c := exec.CommandContext(ctx, argv[0], argv[1:]...)
	// The pseudo-terminal is fd 0 unless the command gets the host's
	// stdin, when it is fd 1.
	attrs := &syscall.SysProcAttr{Setsid: true, Setctty: true}
	if o.HostStdin != nil {
		c.Stdin = o.HostStdin
		attrs.Ctty = 1
	}
	ws, sizeErr := o.Size()
	if sizeErr != nil {
		ws = nil
	}
	ptmx, err := pty.StartWithAttrs(c, ws, attrs)
	if err != nil {
		return 0, err
	}
	sigs := make(chan os.Signal, 8)
	signal.Notify(sigs, forwardedSignals...)
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case s := <-sigs:
				_ = c.Process.Signal(s)
			case <-o.Winch:
				if ws, err := o.Size(); err == nil {
					_ = setSize(ptmx, ws)
				}
			case <-done:
				return
			}
		}
	}()
	// The signal and resize goroutine has stopped before the
	// pseudo-terminal is closed, so it never uses a closed file.
	defer func() {
		signal.Stop(sigs)
		close(done)
		wg.Wait()
		_ = ptmx.Close()
	}()
	if o.Stdin != nil && o.HostStdin == nil {
		// A write after Close fails with os.ErrClosed, which ends this
		// copy once Stdin next has input.
		go func() { _, _ = io.Copy(ptmx, o.Stdin) }()
	}

	_, _ = io.WriteString(o.Stdout, termtext.TitlePush)
	f := termtext.NewFilter(o.Stdout)
	// The copy ends once the command and anything it started have closed
	// the pseudo-terminal, which Linux reports as EIO rather than EOF.
	_, copyErr := io.Copy(f, ptmx)
	if copyErr != nil && !errors.Is(copyErr, syscall.EIO) {
		_ = c.Process.Kill()
	}
	_, _ = o.Stdout.Write(append(f.Restore(), termtext.TitlePop...))
	waitErr := c.Wait()
	var exitErr *exec.ExitError
	if waitErr != nil && !errors.As(waitErr, &exitErr) {
		return 0, waitErr
	}
	if copyErr != nil && !errors.Is(copyErr, syscall.EIO) {
		return 0, copyErr
	}
	return ExitCode(c.ProcessState), nil
}

// ExitCode returns a finished process's exit code, or 128 plus the signal
// number when a signal killed it.
func ExitCode(ps *os.ProcessState) int {
	if ws, ok := ps.Sys().(syscall.WaitStatus); ok && ws.Signaled() {
		return 128 + int(ws.Signal())
	}
	return ps.ExitCode()
}

// setSize resizes the pseudo-terminal through its raw connection rather
// than File.Fd, which isn't safe to call alongside its other uses and
// would switch it to blocking mode.
func setSize(ptmx *os.File, ws *pty.Winsize) error {
	rc, err := ptmx.SyscallConn()
	if err != nil {
		return err
	}
	var ioctlErr error
	err = rc.Control(func(fd uintptr) {
		ioctlErr = unix.IoctlSetWinsize(int(fd), unix.TIOCSWINSZ, &unix.Winsize{Row: ws.Rows, Col: ws.Cols, Xpixel: ws.X, Ypixel: ws.Y})
	})
	return errors.Join(err, ioctlErr)
}
