package cli

import (
	"errors"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"sync"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/sys/unix"
	"golang.org/x/term"

	"github.com/josegonzalez/safeclaw/internal/termtext"
)

// attachTerminal runs argv, a `docker exec -it ... tmux attach`, on a
// pseudo-terminal of its own instead of the caller's terminal, and relays
// between them with the caller's terminal in raw mode. Its output passes
// through termtext.Filter on the way, so the tmux server in the session,
// which the session's own code can drive, can't write the host clipboard
// or reach the host terminal with passthrough sequences.
func attachTerminal(argv []string) (int, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return 0, errors.New("attach needs a terminal on stdin")
	}
	old, err := term.MakeRaw(fd)
	if err != nil {
		return 0, err
	}
	defer func() { _ = term.Restore(fd, old) }()

	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	defer signal.Stop(winch)
	return relayPTY(argv, relayOptions{
		stdin:  os.Stdin,
		stdout: os.Stdout,
		size:   func() (*pty.Winsize, error) { return pty.GetsizeFull(os.Stdin) },
		winch:  winch,
	})
}

// relayOptions configures relayPTY.
type relayOptions struct {
	stdin  io.Reader
	stdout io.Writer
	// size returns the size to give the pseudo-terminal, at the start and
	// each time winch fires.
	size  func() (*pty.Winsize, error)
	winch <-chan os.Signal
}

// relayPTY runs argv on a new pseudo-terminal, copies stdin to it and its
// output through termtext.Filter to stdout, and resizes it from size each
// time winch fires, which the kernel passes on to the command as SIGWINCH.
// SIGINT, SIGTERM, SIGHUP and SIGQUIT sent to safeclaw are forwarded to the
// command (SIGHUP only when it wasn't ignored at start, see
// forwardedSignals), so the caller's terminal is restored when it exits. It returns
// the command's exit code as runChild does.
func relayPTY(argv []string, o relayOptions) (int, error) {
	c := exec.Command(argv[0], argv[1:]...)
	var ptmx *os.File
	var err error
	if ws, sizeErr := o.size(); sizeErr == nil {
		ptmx, err = pty.StartWithSize(c, ws)
	} else {
		ptmx, err = pty.Start(c)
	}
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
			case <-o.winch:
				if ws, err := o.size(); err == nil {
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
	if o.stdin != nil {
		// This copy ends only when stdin does, which for a terminal is
		// when safeclaw exits. A write after Close fails with
		// os.ErrClosed, which ends it.
		go func() { _, _ = io.Copy(ptmx, o.stdin) }()
	}

	// The copy ends once the command and anything it started have closed
	// the pseudo-terminal, which Linux reports as EIO rather than EOF.
	_, copyErr := io.Copy(termtext.NewFilter(o.stdout), ptmx)
	if copyErr != nil && !errors.Is(copyErr, syscall.EIO) {
		_ = c.Process.Kill()
	}
	waitErr := c.Wait()
	var exitErr *exec.ExitError
	if waitErr != nil && !errors.As(waitErr, &exitErr) {
		return 0, waitErr
	}
	if copyErr != nil && !errors.Is(copyErr, syscall.EIO) {
		return 0, copyErr
	}
	return exitCode(c.ProcessState), nil
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
