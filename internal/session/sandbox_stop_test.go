package session

import (
	"context"
	"errors"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
)

// newStopWorld returns a manager seeing a running sandbox "up", a stopped
// sandbox "down", a running one-off sandbox "job", and an interactive
// session "chat".
func newStopWorld(t *testing.T) (*Manager, *dockertest.Runner, *world) {
	t.Helper()
	w := &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-up":   {Running: true, Labels: sandboxLabels},
		"safeclaw-down": {Labels: sandboxLabels},
		"safeclaw-job":  {Running: true, Labels: sandboxLabels, AutoRemove: true},
		"safeclaw-chat": {Running: true, Labels: map[string]string{"safeclaw.type": "session"}},
	}}
	m, r := newTestManager(t, w)
	return m, r, w
}

// vanishOn makes the docker command named verb find the container already
// removed, as when docker removes a one-off sandbox between the lookup and
// the call, failing with stderr.
func vanishOn(r *dockertest.Runner, w *world, verb, stderr string) {
	r.Handler = func(args []string, stdin string) ([]byte, error) {
		if args[0] == verb {
			delete(w.containers, args[len(args)-1])
			return nil, &docker.Error{Args: args, Stderr: stderr, Err: errors.New("exit status 1")}
		}
		return w.handle(args, stdin)
	}
}

const noSuchContainer = "Error response from daemon: No such container: safeclaw-job"

func TestStopSandbox(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name      string
		missingOK bool
		skipped   Skipped
		stops     bool
		err       error
	}{
		{"up", false, NotSkipped, true, nil},
		{"up", true, NotSkipped, true, nil},
		{"job", true, NotSkipped, true, nil},
		{"down", false, NotSkipped, true, nil},
		{"down", true, SkippedStopped, false, nil},
		{"gone", false, NotSkipped, false, ErrNotFound},
		{"gone", true, SkippedMissing, false, nil},
		{"chat", false, NotSkipped, false, ErrNotSandbox},
		{"chat", true, NotSkipped, false, ErrNotSandbox},
	} {
		m, r, _ := newStopWorld(t)
		skipped, err := m.StopSandbox(ctx, tc.name, SandboxStopOptions{MissingOK: tc.missingOK})
		if skipped != tc.skipped || !errors.Is(err, tc.err) || (tc.err == nil) != (err == nil) {
			t.Errorf("%s missing-ok=%v: %q, %v; want %q, %v", tc.name, tc.missingOK, skipped, err, tc.skipped, tc.err)
		}
		if got := hasCall(r, "stop "); got != tc.stops {
			t.Errorf("%s missing-ok=%v: docker stop called = %v, want %v", tc.name, tc.missingOK, got, tc.stops)
		}
	}
}

func TestStopSandboxRemovedMeanwhile(t *testing.T) {
	ctx := context.Background()
	m, r, w := newStopWorld(t)
	vanishOn(r, w, "stop", noSuchContainer)
	if skipped, err := m.StopSandbox(ctx, "job", SandboxStopOptions{MissingOK: true}); skipped != SkippedMissing || err != nil {
		t.Errorf("missing-ok: %q, %v; want missing", skipped, err)
	}

	// Without --missing-ok the docker error is returned, as before.
	m, r, w = newStopWorld(t)
	vanishOn(r, w, "stop", noSuchContainer)
	if skipped, err := m.StopSandbox(ctx, "job", SandboxStopOptions{}); skipped != NotSkipped || !docker.IsNotFound(err) {
		t.Errorf("without missing-ok: %q, %v; want the docker error", skipped, err)
	}

	// Other docker errors are never hidden.
	m, r, w = newStopWorld(t)
	vanishOn(r, w, "stop", "Error response from daemon: permission denied")
	if skipped, err := m.StopSandbox(ctx, "job", SandboxStopOptions{MissingOK: true}); skipped != NotSkipped || err == nil {
		t.Errorf("other error: %q, %v; want the docker error", skipped, err)
	}
}

func TestStopSandboxRefusesBadName(t *testing.T) {
	m, r, _ := newStopWorld(t)
	if _, err := m.StopSandbox(context.Background(), "a b", SandboxStopOptions{MissingOK: true}); err == nil {
		t.Error("an invalid name should be refused, not reported missing")
	}
	if len(r.Commands()) != 0 {
		t.Errorf("docker calls = %v", r.Commands())
	}
}

func TestDeleteSandbox(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name             string
		force, missingOK bool
		skipped          Skipped
		removes          bool
		err              error
	}{
		{"up", true, false, NotSkipped, true, nil},
		{"up", true, true, NotSkipped, true, nil},
		{"down", false, true, NotSkipped, true, nil},
		{"gone", false, false, NotSkipped, false, ErrNotFound},
		{"gone", false, true, SkippedMissing, false, nil},
		{"gone", true, true, SkippedMissing, false, nil},
		{"chat", true, false, NotSkipped, false, ErrNotSandbox},
		{"chat", true, true, NotSkipped, false, ErrNotSandbox},
	} {
		m, r, w := newStopWorld(t)
		skipped, err := m.DeleteSandbox(ctx, tc.name, SandboxStopOptions{Force: tc.force, MissingOK: tc.missingOK})
		if skipped != tc.skipped || !errors.Is(err, tc.err) || (tc.err == nil) != (err == nil) {
			t.Errorf("%s force=%v missing-ok=%v: %q, %v; want %q, %v", tc.name, tc.force, tc.missingOK, skipped, err, tc.skipped, tc.err)
		}
		if got := hasCall(r, "rm "); got != tc.removes {
			t.Errorf("%s force=%v missing-ok=%v: docker rm called = %v, want %v", tc.name, tc.force, tc.missingOK, got, tc.removes)
		}
		if tc.removes && w.containers["safeclaw-"+tc.name] != nil {
			t.Errorf("%s: not removed", tc.name)
		}
	}
	m, r, _ := newStopWorld(t)
	if _, err := m.DeleteSandbox(ctx, "up", SandboxStopOptions{Force: true}); err != nil || !hasCall(r, "rm -v -f safeclaw-up") {
		t.Errorf("force: %v, calls %v", err, r.Commands())
	}
}

func TestDeleteSandboxRemovedMeanwhile(t *testing.T) {
	ctx := context.Background()
	for _, stderr := range []string{noSuchContainer, "Error response from daemon: removal of container safeclaw-job is already in progress"} {
		m, r, w := newStopWorld(t)
		vanishOn(r, w, "rm", stderr)
		if skipped, err := m.DeleteSandbox(ctx, "job", SandboxStopOptions{Force: true, MissingOK: true}); skipped != SkippedMissing || err != nil {
			t.Errorf("%s: %q, %v; want missing", stderr, skipped, err)
		}

		m, r, w = newStopWorld(t)
		vanishOn(r, w, "rm", stderr)
		if skipped, err := m.DeleteSandbox(ctx, "job", SandboxStopOptions{Force: true}); skipped != NotSkipped || err == nil {
			t.Errorf("%s without missing-ok: %q, %v; want the docker error", stderr, skipped, err)
		}
	}

	// A running sandbox still needs -f: docker's refusal is not hidden.
	m, r, w := newStopWorld(t)
	vanishOn(r, w, "rm", "Error response from daemon: cannot remove container safeclaw-up: container is running: stop the container before removing or force remove")
	if skipped, err := m.DeleteSandbox(ctx, "up", SandboxStopOptions{MissingOK: true}); skipped != NotSkipped || err == nil {
		t.Errorf("running without -f: %q, %v; want the docker error", skipped, err)
	}
}
