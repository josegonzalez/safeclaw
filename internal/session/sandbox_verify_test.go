package session

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
)

// verifyWorld is a world whose sandboxes inspect like goodSandbox and
// answer the probe with goodProbe, so they pass `sandbox verify` unless
// bad is set.
type verifyWorld struct {
	*world
	mu sync.Mutex
	// bad makes every sandbox attached to the bridge network.
	bad bool
	// onCall runs before each call is answered.
	onCall func(args []string)
}

func (w *verifyWorld) handle(args []string, stdin string) ([]byte, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.onCall != nil {
		w.onCall(args)
	}
	switch {
	case args[0] == "container" && args[1] == "inspect" && len(args) == 3:
		fc, ok := w.containers[args[2]]
		if !ok {
			return nil, dockertest.NotFound(args)
		}
		c := goodSandbox()
		c["Name"] = "/" + args[2]
		status := "exited"
		if fc.Running {
			status = "running"
		}
		c["State"] = map[string]any{"Status": status, "Running": fc.Running}
		hc := c["HostConfig"].(map[string]any)
		hc["AutoRemove"] = fc.AutoRemove
		if w.bad {
			hc["NetworkMode"] = "bridge"
			c["NetworkSettings"] = map[string]any{"Networks": map[string]any{"bridge": map[string]any{}}}
		}
		return json.Marshal([]any{c})
	case args[0] == "exec" && slices.Contains(args, sandboxProbe):
		return []byte(goodProbe), nil
	case args[0] == "exec" && slices.Contains(args, "touch"):
		return nil, nil
	}
	return w.world.handle(args, stdin)
}

func newVerifyManager(t *testing.T, w *verifyWorld) (*Manager, *dockertest.Runner, *strings.Builder) {
	t.Helper()
	m, r := newTestManager(t, w.world)
	r.Handler = w.handle
	out := &strings.Builder{}
	m.Out = out
	return m, r, out
}

func newVerifyWorld(containers map[string]*fakeContainer) *verifyWorld {
	if containers == nil {
		containers = map[string]*fakeContainer{}
	}
	return &verifyWorld{world: &world{image: "img", containers: containers}}
}

// callIndex returns the index of the first call starting with prefix, or
// -1.
func callIndex(r *dockertest.Runner, prefix string) int {
	return slices.IndexFunc(r.Commands(), func(c string) bool { return strings.HasPrefix(c, prefix) })
}

func TestEnsureSandboxVerifyPasses(t *testing.T) {
	for _, remove := range []bool{false, true} {
		w := newVerifyWorld(nil)
		m, r, out := newVerifyManager(t, w)
		res, err := m.EnsureSandbox(context.Background(), SandboxOptions{Name: "box", Remove: remove, Verify: true})
		if err != nil {
			t.Fatalf("remove=%v: %v", remove, err)
		}
		if res.Name != "box" {
			t.Errorf("result = %+v", res)
		}
		run, probe := callIndex(r, "run "), callIndex(r, "exec --user sandbox safeclaw-box /bin/sh -c ")
		if run < 0 || probe < run || hasCall(r, "rm ") {
			t.Errorf("remove=%v: calls = %v", remove, r.Commands())
		}
		if !strings.Contains(out.String(), "Verified sandbox: all 20 checks passed\n") {
			t.Errorf("remove=%v: out = %q", remove, out)
		}
		if _, ok := w.containers["safeclaw-box"]; !ok {
			t.Errorf("remove=%v: verified sandbox was removed", remove)
		}
	}
}

func TestEnsureSandboxWithoutVerifyRunsNothing(t *testing.T) {
	w := newVerifyWorld(nil)
	m, r, _ := newVerifyManager(t, w)
	if _, err := m.EnsureSandbox(context.Background(), SandboxOptions{Name: "box"}); err != nil {
		t.Fatal(err)
	}
	if hasCall(r, "exec ") {
		t.Errorf("verified without Verify: %v", r.Commands())
	}
}

func TestEnsureSandboxVerifyFailsRemoves(t *testing.T) {
	cases := []struct {
		name     string
		existing *fakeContainer
		opts     SandboxOptions
	}{
		{"new", nil, SandboxOptions{Name: "box"}},
		{"one-off", nil, SandboxOptions{Name: "box", Remove: true}},
		{"recreated", &fakeContainer{Running: true, Image: "img", Labels: sandboxLabels}, SandboxOptions{Name: "box", Volumes: []string{"/in:/in"}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			containers := map[string]*fakeContainer{}
			if tc.existing != nil {
				containers["safeclaw-box"] = tc.existing
			}
			w := newVerifyWorld(containers)
			w.bad = true
			m, r, out := newVerifyManager(t, w)
			tc.opts.Verify = true
			_, err := m.EnsureSandbox(context.Background(), tc.opts)
			var ve *SandboxVerifyError
			if !errors.As(err, &ve) || ve.Report == nil || ve.Kept || ve.RemoveErr != nil {
				t.Fatalf("err = %#v", err)
			}
			if !slices.Equal(ve.Report.Failed(), []string{"network"}) {
				t.Errorf("failed = %q", ve.Report.Failed())
			}
			if want := `sandbox "box" failed 1 check: network; it was removed`; err.Error() != want {
				t.Errorf("err = %q, want %q", err, want)
			}
			cmds := r.Commands()
			if last := cmds[len(cmds)-1]; last != "rm -v -f safeclaw-box" {
				t.Errorf("last call = %q, want the removal: %v", last, cmds)
			}
			if _, ok := w.containers["safeclaw-box"]; ok {
				t.Error("failed sandbox was kept")
			}
			if strings.Contains(out.String(), "Sandbox is ready") {
				t.Errorf("out = %q", out)
			}
		})
	}
}

func TestEnsureSandboxVerifyKeepsExisting(t *testing.T) {
	for _, running := range []bool{true, false} {
		w := newVerifyWorld(map[string]*fakeContainer{"safeclaw-box": {Running: running, Image: "img", Labels: sandboxLabels}})
		w.bad = true
		m, r, _ := newVerifyManager(t, w)
		_, err := m.EnsureSandbox(context.Background(), SandboxOptions{Name: "box", Verify: true})
		var ve *SandboxVerifyError
		if !errors.As(err, &ve) || !ve.Kept || ve.Report == nil {
			t.Fatalf("running=%v: err = %#v", running, err)
		}
		if !strings.HasSuffix(err.Error(), "; it existed before, so it was left as it was") {
			t.Errorf("err = %q", err)
		}
		if hasCall(r, "rm ") || hasCall(r, "stop ") {
			t.Errorf("running=%v: existing sandbox touched: %v", running, r.Commands())
		}
		if _, ok := w.containers["safeclaw-box"]; !ok {
			t.Errorf("running=%v: existing sandbox removed", running)
		}
	}
}

func TestEnsureSandboxVerifyInterrupted(t *testing.T) {
	// An interrupt while docker run creates the sandbox, or while it is
	// checked, removes it.
	for _, at := range []string{"run", "exec"} {
		t.Run(at, func(t *testing.T) {
			w := newVerifyWorld(nil)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			w.onCall = func(args []string) {
				if args[0] == at {
					cancel()
				}
			}
			m, r, _ := newVerifyManager(t, w)
			_, err := m.EnsureSandbox(ctx, SandboxOptions{Name: "box", Remove: true, Verify: true})
			var ve *SandboxVerifyError
			if !errors.As(err, &ve) || !errors.Is(err, context.Canceled) || ve.Kept {
				t.Fatalf("err = %v", err)
			}
			if !hasCall(r, "rm -v -f safeclaw-box") {
				t.Errorf("not removed: %v", r.Commands())
			}
			if _, ok := w.containers["safeclaw-box"]; ok {
				t.Error("interrupted sandbox was kept")
			}
		})
	}
}

func TestPrepareEphemeralVerifyGates(t *testing.T) {
	m, _, _ := newVerifyManager(t, newVerifyWorld(nil))
	argv, _, err := m.PrepareEphemeral(context.Background(), SandboxOptions{Name: "job", Verify: true}, ExecOptions{Timeout: time.Second}, []string{"cat", "-"})
	if err != nil {
		t.Fatal(err)
	}
	// The gate runs first, then the timeout, then the command.
	tail := []string{"/bin/sh", "-c", gateScript, "sh", "timeout", "--kill-after=5s", "--", "1s", "cat", "-"}
	if !slices.Equal(argv[len(argv)-len(tail):], tail) {
		t.Errorf("argv = %q", argv)
	}
	if !strings.Contains(gateScript, `rm -f `+verifiedFlag+`; umask 022; exec "$@"`) || !strings.Contains(gateScript, `-gt 600 ]`) {
		t.Errorf("gate = %q", gateScript)
	}
	argv, _, err = m.PrepareEphemeral(context.Background(), SandboxOptions{Name: "job"}, ExecOptions{}, []string{"cat"})
	if err != nil || slices.Contains(argv, gateScript) {
		t.Errorf("gated without Verify: %q %v", argv, err)
	}
}

func TestVerifyEphemeralPasses(t *testing.T) {
	w := newVerifyWorld(nil)
	// The sandbox appears only after a few polls, as if docker run were
	// still starting it.
	polls := 0
	w.onCall = func(args []string) {
		if args[0] == "container" && args[1] == "inspect" {
			if polls++; polls == 3 {
				w.containers["safeclaw-job"] = &fakeContainer{Running: true, AutoRemove: true}
			}
		}
	}
	old := runningPoll
	runningPoll = time.Millisecond
	t.Cleanup(func() { runningPoll = old })
	m, r, _ := newVerifyManager(t, w)
	if err := m.VerifyEphemeral(context.Background(), "job", make(chan struct{})); err != nil {
		t.Fatal(err)
	}
	probe := callIndex(r, "exec --user sandbox safeclaw-job /bin/sh -c ")
	release := callIndex(r, "exec --user sandbox safeclaw-job touch "+verifiedFlag)
	if probe < 0 || release < probe || hasCall(r, "rm ") {
		t.Errorf("the command must be let through only after the checks: %v", r.Commands())
	}
}

func TestVerifyEphemeralFailsRemoves(t *testing.T) {
	w := newVerifyWorld(map[string]*fakeContainer{"safeclaw-job": {Running: true, AutoRemove: true}})
	w.bad = true
	m, r, _ := newVerifyManager(t, w)
	err := m.VerifyEphemeral(context.Background(), "job", make(chan struct{}))
	var ve *SandboxVerifyError
	if !errors.As(err, &ve) || ve.Report == nil || ve.Kept {
		t.Fatalf("err = %v", err)
	}
	if hasCall(r, "exec --user sandbox safeclaw-job touch") {
		t.Errorf("failed sandbox's command was let through: %v", r.Commands())
	}
	if !hasCall(r, "rm -v -f safeclaw-job") {
		t.Errorf("failed sandbox not removed: %v", r.Commands())
	}
}

func TestVerifyEphemeralExited(t *testing.T) {
	m, r, _ := newVerifyManager(t, newVerifyWorld(nil))
	exited := make(chan struct{})
	close(exited)
	if err := m.VerifyEphemeral(context.Background(), "job", exited); !errors.Is(err, ErrExited) {
		t.Errorf("err = %v, want ErrExited", err)
	}
	if hasCall(r, "rm ") || hasCall(r, "exec ") {
		t.Errorf("calls = %v", r.Commands())
	}
}

func TestVerifyEphemeralInterrupted(t *testing.T) {
	old := runningPoll
	runningPoll = time.Millisecond
	t.Cleanup(func() { runningPoll = old })

	// Interrupted before docker run has created the sandbox: it is
	// removed once it exists, even before it runs.
	w := newVerifyWorld(nil)
	polls := 0
	w.onCall = func(args []string) {
		if args[0] == "container" && args[1] == "inspect" {
			if polls++; polls == 3 {
				w.containers["safeclaw-job"] = &fakeContainer{AutoRemove: true}
			}
		}
	}
	m, r, _ := newVerifyManager(t, w)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := m.VerifyEphemeral(ctx, "job", make(chan struct{}))
	var ve *SandboxVerifyError
	if !errors.Is(err, context.Canceled) || !errors.As(err, &ve) || ve.RemoveErr != nil || !hasCall(r, "rm -v -f safeclaw-job") || hasCall(r, "exec ") {
		t.Errorf("err = %v, calls = %v", err, r.Commands())
	}

	// Interrupted, and docker run exits without creating it.
	m, r, _ = newVerifyManager(t, newVerifyWorld(nil))
	exited := make(chan struct{})
	time.AfterFunc(10*time.Millisecond, func() { close(exited) })
	if err := m.VerifyEphemeral(ctx, "job", exited); !errors.Is(err, ErrExited) || hasCall(r, "rm ") {
		t.Errorf("err = %v, calls = %v", err, r.Commands())
	}

	// Interrupted, and docker run exits after creating it but before
	// starting it, which leaves it to be removed.
	m, r, _ = newVerifyManager(t, newVerifyWorld(map[string]*fakeContainer{"safeclaw-job": {AutoRemove: true}}))
	closed := make(chan struct{})
	close(closed)
	if err := m.VerifyEphemeral(ctx, "job", closed); !errors.Is(err, context.Canceled) || !hasCall(r, "rm -v -f safeclaw-job") {
		t.Errorf("err = %v, calls = %v", err, r.Commands())
	}

	// Interrupted during the checks.
	w = newVerifyWorld(map[string]*fakeContainer{"safeclaw-job": {Running: true, AutoRemove: true}})
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	w.onCall = func(args []string) {
		if args[0] == "exec" {
			cancel()
		}
	}
	m, r, _ = newVerifyManager(t, w)
	err = m.VerifyEphemeral(ctx, "job", make(chan struct{}))
	if !errors.Is(err, context.Canceled) || !hasCall(r, "rm -v -f safeclaw-job") || hasCall(r, "exec --user sandbox safeclaw-job touch") {
		t.Errorf("err = %v, calls = %v", err, r.Commands())
	}
}

func TestSandboxVerifyErrorMessages(t *testing.T) {
	e := &SandboxVerifyError{Name: "box", Err: context.Canceled}
	if got := e.Error(); got != `verify sandbox "box": context canceled; it was removed` {
		t.Errorf("Error() = %q", got)
	}
	e.RemoveErr = errors.New("boom")
	if got := e.Error(); got != `verify sandbox "box": context canceled; removing it failed: boom` {
		t.Errorf("Error() = %q", got)
	}
}
