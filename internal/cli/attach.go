package cli

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"github.com/creack/pty"
	"golang.org/x/term"

	"github.com/josegonzalez/safeclaw/internal/hostterm"
)

// attachTerminal runs argv, a `docker exec -it ... tmux attach`, on a
// pseudo-terminal of its own instead of the caller's terminal, and relays
// between them with the caller's terminal in raw mode. Its output passes
// through termtext.Filter on the way, so the tmux server in the session,
// which the session's own code can drive, can't write the host clipboard
// or reach the host terminal with passthrough sequences, and the modes and
// titles it leaves set are undone after it detaches.
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
	return hostterm.Relay(context.Background(), argv, hostterm.Options{
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Size:   func() (*pty.Winsize, error) { return pty.GetsizeFull(os.Stdin) },
		Winch:  winch,
	})
}
