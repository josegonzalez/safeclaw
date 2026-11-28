package docker

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

// sh runs scripts in place of docker, so ExecRunner is tested against a
// real child process.
var sh = ExecRunner{Binary: "/bin/sh"}

func TestErrorEscapesControlCharacters(t *testing.T) {
	e := &Error{Args: []string{"exec"}, Stderr: "tar: \x1b]0;pwned\x07bad\r\nnext\tline\x9b\n", Err: errors.New("exit status 2")}
	want := `docker exec: tar: \x1b]0;pwned\x07bad\x0d` + "\nnext\tline" + `\x9b`
	if got := e.Error(); got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
	e = &Error{Args: []string{"exec"}, Err: errors.New("exit\x1b[2J")}
	if got := e.Error(); got != `docker exec: exit\x1b[2J` {
		t.Errorf("Error() without stderr = %q", got)
	}
}

func TestTailBuffer(t *testing.T) {
	b := &tailBuffer{max: 8}
	_, _ = b.Write([]byte("abc"))
	if got := b.String(); got != "abc" {
		t.Errorf("short = %q", got)
	}
	_, _ = b.Write([]byte("defgh"))
	if got := b.String(); got != "abcdefgh" {
		t.Errorf("full = %q", got)
	}
	_, _ = b.Write([]byte("ij"))
	if got := b.String(); got != "[earlier output truncated] cdefghij" {
		t.Errorf("over = %q", got)
	}
	n, err := b.Write([]byte("0123456789"))
	if n != 10 || err != nil {
		t.Errorf("Write = %d, %v", n, err)
	}
	if got := b.String(); got != "[earlier output truncated] 23456789" {
		t.Errorf("big write = %q", got)
	}
}

func TestOutputKeepsStderrTail(t *testing.T) {
	// Well over MaxStderr of filler, then the reason.
	script := `i=0; while [ $i -lt 2000 ]; do printf '%064d\n' 0 >&2; i=$((i+1)); done; echo reason >&2; exit 3`
	_, err := sh.Output(context.Background(), nil, "-c", script)
	var de *Error
	if !errors.As(err, &de) {
		t.Fatalf("err = %v, want *Error", err)
	}
	if len(de.Stderr) > MaxStderr+64 {
		t.Errorf("stderr kept %d bytes, want at most about %d", len(de.Stderr), MaxStderr)
	}
	if !strings.HasSuffix(de.Stderr, "reason\n") || !strings.HasPrefix(de.Stderr, "[earlier output truncated]") {
		t.Errorf("stderr = %q...%q", de.Stderr[:40], de.Stderr[len(de.Stderr)-20:])
	}
}

func TestOutputRefusesTooMuchStdout(t *testing.T) {
	// Writes forever; the cap has to stop it.
	out, err := sh.Output(context.Background(), nil, "-c", `while :; do printf '%01024d' 0; done`)
	if !errors.Is(err, ErrOutputTooLarge) {
		t.Fatalf("err = %v, want ErrOutputTooLarge", err)
	}
	if out != nil {
		t.Errorf("got %d bytes of output, want none", len(out))
	}
}

func TestOutputUnderLimit(t *testing.T) {
	out, err := sh.Output(context.Background(), strings.NewReader("hi"), "-c", "cat; echo warn >&2")
	if err != nil || string(out) != "hi" {
		t.Errorf("Output = %q, %v", out, err)
	}
}

func TestStreamKeepsStderrTail(t *testing.T) {
	script := `printf data; i=0; while [ $i -lt 2000 ]; do printf '%064d\n' 0 >&2; i=$((i+1)); done; echo reason >&2; exit 1`
	out, wait, err := sh.Stream(context.Background(), "-c", script)
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, out)
	err = wait()
	var de *Error
	if !errors.As(err, &de) {
		t.Fatalf("err = %v, want *Error", err)
	}
	if buf.String() != "data" {
		t.Errorf("stdout = %q", buf.String())
	}
	if len(de.Stderr) > MaxStderr+64 || !strings.HasSuffix(de.Stderr, "reason\n") {
		t.Errorf("stderr kept %d bytes, ending %q", len(de.Stderr), de.Stderr[len(de.Stderr)-20:])
	}
}

func TestOutputReturnsWhenStdinBlocks(t *testing.T) {
	// A stdin whose Read never returns would keep os/exec copying it
	// forever, so Output must stop waiting once its context kills docker.
	pr, pw := io.Pipe()
	defer pw.Close()
	r := ExecRunner{Binary: "/bin/sh", WaitDelay: 100 * time.Millisecond}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := r.Output(ctx, pr, "-c", "cat")
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Error("Output succeeded with a stdin that never ends")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Output still waiting on stdin after its context was done")
	}
}
