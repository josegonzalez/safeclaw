package cli

import (
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
)

func fixedSize(rows, cols uint16) func() (*pty.Winsize, error) {
	return func() (*pty.Winsize, error) { return &pty.Winsize{Rows: rows, Cols: cols}, nil }
}

func TestRelayPTYFiltersOutput(t *testing.T) {
	var out strings.Builder
	script := `printf 'a\033]52;c;QVVESVQ=\007\033[31mb\033Ptmux;\033\033]52;c;QVVESVQ=\007\033\\c\033[0m'; exit 3`
	code, err := relayPTY([]string{"sh", "-c", script}, relayOptions{stdout: &out, size: fixedSize(24, 80)})
	if err != nil {
		t.Fatal(err)
	}
	if code != 3 {
		t.Errorf("code = %d, want 3", code)
	}
	if got, want := out.String(), "a\x1b[31mbc\x1b[0m"; got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

func TestRelayPTYInput(t *testing.T) {
	var out strings.Builder
	// The terminal echoes the input, then head prints it back.
	code, err := relayPTY([]string{"head", "-n", "1"}, relayOptions{
		stdin:  strings.NewReader("hello\n"),
		stdout: &out,
		size:   fixedSize(24, 80),
	})
	if err != nil || code != 0 {
		t.Fatalf("code = %d, err = %v", code, err)
	}
	if got, want := out.String(), "hello\r\nhello\r\n"; got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

func TestRelayPTYResize(t *testing.T) {
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
		code, err := relayPTY([]string{"sh", "-c", script}, relayOptions{stdout: out, size: size, winch: winch})
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
	if got, want := out.String(), "24 80\r\nready\r\n40 100\r\n"; got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}

func TestRelayPTYMissingCommand(t *testing.T) {
	var out strings.Builder
	if _, err := relayPTY([]string{"safeclaw-no-such-command"}, relayOptions{stdout: &out, size: fixedSize(24, 80)}); err == nil {
		t.Error("want an error for a missing command")
	}
}
