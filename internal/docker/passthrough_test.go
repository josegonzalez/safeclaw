package docker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/creack/pty"

	"github.com/josegonzalez/safeclaw/internal/termtext"
)

const hostileScript = `printf 'a\033]52;c;QQ==\007b\n'; printf 'c\033Ptmux;x\033\\d\n' >&2; [ -t 1 ] && [ -t 2 ] && echo tty; exit 4`

// Without a terminal, stdout and stderr are each filtered.
func TestPassthroughFiltersPipes(t *testing.T) {
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	err = sh.passthrough(context.Background(), nil, outW, errW, []string{"-c", hostileScript})
	_ = outW.Close()
	_ = errW.Close()
	var de *Error
	if !errors.As(err, &de) || !strings.Contains(err.Error(), "exit status 4") {
		t.Errorf("err = %v, want an *Error with exit status 4", err)
	}
	stdout, _ := io.ReadAll(outR)
	stderr, _ := io.ReadAll(errR)
	if string(stdout) != "ab\n" {
		t.Errorf("stdout = %q, want %q", stdout, "ab\n")
	}
	if string(stderr) != "cd\n" {
		t.Errorf("stderr = %q, want %q", stderr, "cd\n")
	}
}

// On a terminal, docker gets a pseudo-terminal of its own, so it still
// sees a terminal, and its output is filtered on the way.
func TestPassthroughRelaysTerminal(t *testing.T) {
	ptmx, tty, err := pty.Open()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ptmx.Close() }()
	var got bytes.Buffer
	read := make(chan struct{})
	go func() {
		defer close(read)
		_, _ = io.Copy(&got, ptmx)
	}()
	err = sh.passthrough(context.Background(), nil, tty, tty, []string{"-c", hostileScript})
	_ = tty.Close()
	<-read
	var de *Error
	if !errors.As(err, &de) || !strings.Contains(err.Error(), "exit status 4") {
		t.Errorf("err = %v, want an *Error with exit status 4", err)
	}
	// The outer terminal adds a carriage return to each line ending.
	out := strings.ReplaceAll(got.String(), "\r", "")
	want := termtext.TitlePush + "ab\ncd\ntty\n" + termtext.TitlePop
	if out != want {
		t.Errorf("output = %q, want %q", out, want)
	}
}
