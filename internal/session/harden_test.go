package session

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func dirPerm(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

// New sessions drop every capability, can't gain privileges, and keep
// their history readable only by the user.
func TestEnsureHardensSession(t *testing.T) {
	m, r := newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{}, native: true})
	if _, err := m.Ensure(context.Background(), Options{Name: "work", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	run, _ := r.Find("run ")
	if !strings.Contains(run.String(), " --label safeclaw.type=session --cap-drop ALL --security-opt no-new-privileges ") || strings.Contains(run.String(), "--cap-add") {
		t.Errorf("run = %q", run.String())
	}
	for _, d := range []string{m.SessionsDir, filepath.Join(m.SessionsDir, "work")} {
		if got := dirPerm(t, d); got != 0o700 {
			t.Errorf("%s: mode %#o, want 0700", d, got)
		}
	}
}

// History directories created open to others are restricted when a
// container is created for them.
func TestEnsureRestrictsOldHistory(t *testing.T) {
	m, _ := newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{}, native: true})
	dir := filepath.Join(m.SessionsDir, "work")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{m.SessionsDir, dir} {
		if err := os.Chmod(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := m.Ensure(context.Background(), Options{Name: "work", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{m.SessionsDir, dir} {
		if got := dirPerm(t, d); got != 0o700 {
			t.Errorf("%s: mode %#o, want 0700", d, got)
		}
	}
}

// A container created before sessions dropped their capabilities is kept
// with a warning, like one sharing the host's IPC namespace, and any
// recreate hardens it.
func TestEnsureUnhardenedSession(t *testing.T) {
	ctx := context.Background()
	legacy := func() *world {
		return &world{image: "img", containers: map[string]*fakeContainer{
			"safeclaw-old": {Running: true, Port: 7705, HostIP: "::1", Image: "img", Unhardened: true},
		}, native: true}
	}
	const warning = "Warning: session old keeps docker's default capabilities"

	m, r := newTestManager(t, legacy())
	var out bytes.Buffer
	m.Out = &out
	if _, err := m.Ensure(ctx, Options{Name: "old", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if hasCall(r, "rm ") || hasCall(r, "run ") || !strings.Contains(out.String(), warning) {
		t.Errorf("kept: calls %v\n%s", r.Commands(), out.String())
	}

	m, r = newTestManager(t, legacy())
	out.Reset()
	m.Out = &out
	if _, err := m.Ensure(ctx, Options{Name: "old", Volume: "/new:/home/sclaw/new", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	run, _ := r.Find("run ")
	if !hasCall(r, "rm -v -f safeclaw-old") || !strings.Contains(run.String(), "--cap-drop ALL --security-opt no-new-privileges") || strings.Contains(out.String(), warning) {
		t.Errorf("recreated: run %q\n%s", run.String(), out.String())
	}

	// A hardened container gets no warning.
	m, _ = newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-old": {Running: true, Port: 7705, HostIP: "::1", Image: "img"},
	}, native: true})
	out.Reset()
	m.Out = &out
	if _, err := m.Ensure(ctx, Options{Name: "old", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "Warning: ") {
		t.Errorf("hardened: %s", out.String())
	}
}

// A container restored after a failed recreate is hardened too.
func TestEnsureRestoreHardens(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-old": {Running: true, Port: 7705, Image: "img", Unhardened: true},
	}, native: true, runErrs: []runErr{{err: errors.New("docker run failed")}}}
	m, _ := newTestManager(t, w)
	if _, err := m.Ensure(context.Background(), Options{Name: "old", Volume: "/new:/home/sclaw/new", NoOpen: true}); err == nil {
		t.Fatal("no error")
	}
	if c := w.containers["safeclaw-old"]; c == nil || c.Unhardened {
		t.Errorf("restored: %+v", c)
	}
}

// A query starting with '-' is typed, not read as tmux options.
func TestEnsureQueryLikeOption(t *testing.T) {
	m, r := newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{}, native: true, prompt: true})
	if _, err := m.Ensure(context.Background(), Options{Name: "q", Query: "-t other -X cancel", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(r.Commands(), "exec safeclaw-q tmux send-keys -t main -l -- -t other -X cancel") {
		t.Errorf("commands %v", r.Commands())
	}
}
