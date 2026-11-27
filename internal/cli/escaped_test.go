package cli

import (
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestRunEscaped(t *testing.T) {
	var out, errOut strings.Builder
	script := `printf 'ok \033[31mred\033]0;title\007\n'; printf 'bad\rname\t\302\233x\n' >&2; exit 3`
	code, err := runEscaped([]string{"sh", "-c", script}, nil, &out, &errOut, false)
	if err != nil {
		t.Fatal(err)
	}
	if code != 3 {
		t.Errorf("code = %d, want 3", code)
	}
	if got, want := out.String(), `ok \x1b[31mred\x1b]0;title\x07`+"\n"; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
	if got, want := errOut.String(), `bad\x0dname`+"\t"+`\u009bx`+"\n"; got != want {
		t.Errorf("stderr = %q, want %q", got, want)
	}
}

func TestRunEscapedStdin(t *testing.T) {
	var out strings.Builder
	code, err := runEscaped([]string{"cat"}, strings.NewReader("in\x1bput\n"), &out, &out, false)
	if err != nil || code != 0 {
		t.Fatalf("code = %d, err = %v", code, err)
	}
	if got, want := out.String(), `in\x1bput`+"\n"; got != want {
		t.Errorf("stdout = %q, want %q", got, want)
	}
}

func TestRunEscapedKilledBySignal(t *testing.T) {
	var out strings.Builder
	code, err := runEscaped([]string{"sh", "-c", "kill -TERM $$"}, nil, &out, &out, false)
	if err != nil {
		t.Fatal(err)
	}
	if code != 128+int(syscall.SIGTERM) {
		t.Errorf("code = %d, want %d", code, 128+int(syscall.SIGTERM))
	}
}

func TestRunEscapedMissingCommand(t *testing.T) {
	var out strings.Builder
	if _, err := runEscaped([]string{"safeclaw-no-such-command"}, nil, &out, &out, false); err == nil {
		t.Error("want an error for a missing command")
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

func TestRunEscapedForwardsSignals(t *testing.T) {
	for _, tc := range []struct {
		name       string
		sig        syscall.Signal
		shareGroup bool
		want       int
	}{
		{"own group, SIGTERM", syscall.SIGTERM, false, 7},
		{"own group, SIGINT", syscall.SIGINT, false, 8},
		{"shared group, SIGTERM", syscall.SIGTERM, true, 7},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ready := make(chan struct{})
			out := &readyWriter{ready: ready}
			script := `trap 'echo term; exit 7' TERM; trap 'echo int; exit 8' INT; echo ready; while :; do sleep 0.05; done`
			type result struct {
				code int
				err  error
			}
			res := make(chan result, 1)
			go func() {
				code, err := runEscaped([]string{"sh", "-c", script}, nil, out, out, tc.shareGroup)
				res <- result{code, err}
			}()
			select {
			case <-ready:
			case <-time.After(10 * time.Second):
				t.Fatal("command never became ready")
			}
			// runEscaped is notified of the signal, so sending it to the
			// test process forwards it instead of killing the test.
			if err := syscall.Kill(syscall.Getpid(), tc.sig); err != nil {
				t.Fatal(err)
			}
			select {
			case r := <-res:
				if r.err != nil || r.code != tc.want {
					t.Errorf("code = %d, err = %v, want %d; output %q", r.code, r.err, tc.want, out.String())
				}
			case <-time.After(10 * time.Second):
				t.Fatal("signal was not forwarded")
			}
		})
	}
}

func TestExitCodeError(t *testing.T) {
	if got := (exitCodeError{3}).Error(); got != "exit status 3" {
		t.Errorf("Error() = %q", got)
	}
}
