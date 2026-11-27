package hostterm

import (
	"context"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"

	"github.com/josegonzalez/safeclaw/internal/termtext"
)

func fixedSize(rows, cols uint16) func() (*pty.Winsize, error) {
	return func() (*pty.Winsize, error) { return &pty.Winsize{Rows: rows, Cols: cols}, nil }
}

// relayed wraps the output a relay writes around the command's own: the
// title push before it, and the restore and title pop after it.
func relayed(out, restore string) string {
	return termtext.TitlePush + out + restore + termtext.TitlePop
}

func TestRelayFiltersOutput(t *testing.T) {
	var out strings.Builder
	script := `printf 'a\033]52;c;QVVESVQ=\007\033[31mb\033Ptmux;\033\033]52;c;QVVESVQ=\007\033\\c\033[0m'; exit 3`
	code, err := Relay(context.Background(), []string{"sh", "-c", script}, Options{Stdout: &out, Size: fixedSize(24, 80)})
	if err != nil {
		t.Fatal(err)
	}
	if code != 3 {
		t.Errorf("code = %d, want 3", code)
	}
	if got, want := out.String(), relayed("a\x1b[31mbc\x1b[0m", ""); got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

// A command that exits with modes and titles set, as a tmux client does
// when its container is killed, has them undone after it.
func TestRelayRestoresTerminal(t *testing.T) {
	var out strings.Builder
	script := `printf '\033[22t\033]0;session\007\033[?1049h\033[?1000;1006h\033[?2004h\033[?25l\033=\033[>1u'; kill -9 $$`
	code, err := Relay(context.Background(), []string{"sh", "-c", script}, Options{Stdout: &out, Size: fixedSize(24, 80)})
	if err != nil {
		t.Fatal(err)
	}
	if code != 128+int(syscall.SIGKILL) {
		t.Errorf("code = %d, want %d", code, 128+int(syscall.SIGKILL))
	}
	const set = "\x1b[22t\x1b]0;session\x07\x1b[?1049h\x1b[?1000;1006h\x1b[?2004h\x1b[?25l\x1b=\x1b[>1u"
	const restore = "\x1b[<1u\x1b[?1000l\x1b[?1006l\x1b[?2004l\x1b>\x1b[?1049l\x1b[?25h" + termtext.TitlePop
	if got, want := out.String(), relayed(set, restore); got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

func TestRelayInput(t *testing.T) {
	var out strings.Builder
	// The terminal echoes the input, then head prints it back.
	code, err := Relay(context.Background(), []string{"head", "-n", "1"}, Options{
		Stdin:  strings.NewReader("hello\n"),
		Stdout: &out,
		Size:   fixedSize(24, 80),
	})
	if err != nil || code != 0 {
		t.Fatalf("code = %d, err = %v", code, err)
	}
	if got, want := out.String(), relayed("hello\r\nhello\r\n", ""); got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

// With HostStdin the command reads it directly, while its output still
// goes through the pseudo-terminal, which is its controlling terminal.
func TestRelayHostStdin(t *testing.T) {
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	if _, err := w.WriteString("hello\n"); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	var out strings.Builder
	script := `read line; echo "got $line"; [ -t 0 ] || echo "stdin not a tty"; [ -t 1 ] && stty size </dev/tty`
	code, err := Relay(context.Background(), []string{"sh", "-c", script}, Options{HostStdin: r, Stdout: &out, Size: fixedSize(30, 90)})
	if err != nil || code != 0 {
		t.Fatalf("code = %d, err = %v; output %q", code, err, out.String())
	}
	if got, want := out.String(), relayed("got hello\r\nstdin not a tty\r\n30 90\r\n", ""); got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

func TestRelayContextCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	ready := make(chan struct{})
	out := &readyWriter{ready: ready}
	go func() {
		<-ready
		cancel()
	}()
	code, err := Relay(ctx, []string{"sh", "-c", "echo ready; exec sleep 30"}, Options{Stdout: out, Size: fixedSize(24, 80)})
	if err != nil {
		t.Fatal(err)
	}
	if code != 128+int(syscall.SIGKILL) {
		t.Errorf("code = %d, want %d", code, 128+int(syscall.SIGKILL))
	}
	if !strings.HasSuffix(out.String(), termtext.TitlePop) {
		t.Errorf("output %q doesn't end with the title pop", out.String())
	}
}

func TestRelayResize(t *testing.T) {
	var mu sync.Mutex
	rows, cols := uint16(24), uint16(80)
	size := func() (*pty.Winsize, error) {
		mu.Lock()
		defer mu.Unlock()
		return &pty.Winsize{Rows: rows, Cols: cols}, nil
	}
	winch := make(chan os.Signal, 1)
	ready := make(chan struct{})
	out := &readyWriter{ready: ready}
	script := `trap 'stty size; exit 0' WINCH; stty size; echo ready; while :; do sleep 0.05; done`
	type result struct {
		code int
		err  error
	}
	res := make(chan result, 1)
	go func() {
		code, err := Relay(context.Background(), []string{"sh", "-c", script}, Options{Stdout: out, Size: size, Winch: winch})
		res <- result{code, err}
	}()
	select {
	case <-ready:
	case <-time.After(10 * time.Second):
		t.Fatal("command never became ready")
	}
	mu.Lock()
	rows, cols = 40, 100
	mu.Unlock()
	winch <- syscall.SIGWINCH
	select {
	case r := <-res:
		if r.err != nil || r.code != 0 {
			t.Fatalf("code = %d, err = %v; output %q", r.code, r.err, out.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("command never saw the resize; output %q", out.String())
	}
	if got, want := out.String(), relayed("24 80\r\nready\r\n40 100\r\n", ""); got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

func TestRelayMissingCommand(t *testing.T) {
	var out strings.Builder
	if _, err := Relay(context.Background(), []string{"safeclaw-no-such-command"}, Options{Stdout: &out, Size: fixedSize(24, 80)}); err == nil {
		t.Error("want an error for a missing command")
	}
	if out.Len() != 0 {
		t.Errorf("output = %q, want nothing when the command never started", out.String())
	}
}

// readyWriter closes ready the first time "ready" is written to it.
type readyWriter struct {
	mu    sync.Mutex
	b     strings.Builder
	ready chan struct{}
}

func (w *readyWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.b.Write(p)
	if w.ready != nil && strings.Contains(w.b.String(), "ready") {
		close(w.ready)
		w.ready = nil
	}
	return len(p), nil
}

func (w *readyWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}
