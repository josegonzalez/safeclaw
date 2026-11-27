package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
)

// memoryCall returns the exec that wrote the session's auto memory setting,
// and its position among the recorded calls.
func memoryCall(t *testing.T, r *dockertest.Runner, container string) (dockertest.Call, int) {
	t.Helper()
	prefix := "exec -i --user root " + container + " /bin/sh -c "
	for i, c := range r.Calls {
		if strings.HasPrefix(c.String(), prefix) && strings.Contains(c.String(), "/etc/claude-code/managed-settings.d/safeclaw-session.json") {
			return c, i
		}
	}
	t.Fatalf("auto memory setting not written: %v", r.Commands())
	return dockertest.Call{}, 0
}

// ttydIndex returns the position of the call that starts ttyd.
func ttydIndex(t *testing.T, r *dockertest.Runner) int {
	t.Helper()
	i := slices.IndexFunc(r.Calls, func(c dockertest.Call) bool {
		return strings.HasPrefix(c.String(), "exec -d ") && strings.Contains(c.String(), "ttyd")
	})
	if i < 0 {
		t.Fatalf("ttyd not started: %v", r.Commands())
	}
	return i
}

// checkMemoryWrite checks that the session's setting was written as root,
// before ttyd and so Claude Code start, with auto memory off or on.
func checkMemoryWrite(t *testing.T, r *dockertest.Runner, container string, off bool) {
	t.Helper()
	c, i := memoryCall(t, r, container)
	if i > ttydIndex(t, r) {
		t.Errorf("setting written after ttyd started: %v", r.Commands())
	}
	var settings map[string]any
	if err := json.Unmarshal([]byte(c.Stdin), &settings); err != nil {
		t.Fatalf("settings %q: %v", c.Stdin, err)
	}
	if off {
		env, _ := settings["env"].(map[string]any)
		if settings["autoMemoryEnabled"] != false || env["CLAUDE_CODE_DISABLE_AUTO_MEMORY"] != "1" {
			t.Errorf("off settings = %s", c.Stdin)
		}
		if !strings.Contains(c.String(), "mkdir -p /etc/claude-code/managed-settings.d && cat > ") {
			t.Errorf("off script = %q", c.String())
		}
		return
	}
	if len(settings) != 0 {
		t.Errorf("on settings = %s", c.Stdin)
	}
	// Images without the file already leave memory on.
	if strings.Contains(c.String(), "mkdir") || !strings.Contains(c.String(), "if [ -f ") {
		t.Errorf("on script = %q", c.String())
	}
}

func TestEnsureMemoryNewSession(t *testing.T) {
	ctx := context.Background()
	// New sessions keep auto memory on.
	for _, noMemory := range []*bool{nil, boolPtr(false)} {
		m, r := newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{}, native: true})
		if _, err := m.Ensure(ctx, Options{Name: "on", NoMemory: noMemory, NoOpen: true}); err != nil {
			t.Fatal(err)
		}
		run, _ := r.Find("run ")
		if strings.Contains(run.String(), "safeclaw.memory") {
			t.Errorf("default run = %q", run.String())
		}
		checkMemoryWrite(t, r, "safeclaw-on", false)
	}

	// Turning it off records the choice and writes the managed setting.
	w := &world{image: "img", containers: map[string]*fakeContainer{}, native: true}
	m, r := newTestManager(t, w)
	if _, err := m.Ensure(ctx, Options{Name: "off", NoMemory: boolPtr(true), NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if got := w.containers["safeclaw-off"].Labels["safeclaw.memory"]; got != "off" {
		t.Errorf("label = %q", got)
	}
	checkMemoryWrite(t, r, "safeclaw-off", true)
}

func TestEnsureMemoryReuseAndRecreate(t *testing.T) {
	ctx := context.Background()
	existing := func(labels map[string]string) *world {
		return &world{image: "img", containers: map[string]*fakeContainer{
			"safeclaw-p": {Running: true, Port: 7705, Image: "img", Labels: labels,
				Mounts: []string{"/hist:/home/sclaw/.claude/projects", "/proj:/home/sclaw/proj"}},
		}, native: true}
	}
	on := func() *world { return existing(map[string]string{"safeclaw.secrets": ""}) }
	off := func() *world { return existing(map[string]string{"safeclaw.memory": "off", "safeclaw.secrets": ""}) }

	// Without a choice, or with the same one, the container is kept and the
	// setting rewritten.
	for _, tc := range []struct {
		w        func() *world
		noMemory *bool
		off      bool
	}{
		{on, nil, false},
		{on, boolPtr(false), false},
		{off, nil, true},
		{off, boolPtr(true), true},
	} {
		m, r := newTestManager(t, tc.w())
		var out bytes.Buffer
		m.Out = &out
		if _, err := m.Ensure(ctx, Options{Name: "p", NoMemory: tc.noMemory, NoOpen: true}); err != nil {
			t.Fatal(err)
		}
		if hasCall(r, "rm ") || hasCall(r, "run ") {
			t.Errorf("recreated: %v", r.Commands())
		}
		if strings.Contains(out.String(), "Auto memory") {
			t.Errorf("unexpected output: %s", out.String())
		}
		checkMemoryWrite(t, r, "safeclaw-p", tc.off)
	}

	// A different choice recreates it on the same port, keeping its mounts
	// and secrets.
	for _, tc := range []struct {
		w   func() *world
		off bool
		msg string
	}{
		{on, true, "Auto memory off requested"},
		{off, false, "Auto memory on requested"},
	} {
		w := tc.w()
		m, r := newTestManager(t, w)
		var out bytes.Buffer
		m.Out = &out
		res, err := m.Ensure(ctx, Options{Name: "p", NoMemory: boolPtr(tc.off), NoOpen: true})
		if err != nil {
			t.Fatal(err)
		}
		if !hasCall(r, "rm -v -f safeclaw-p") || res.Port != 7705 || !strings.Contains(out.String(), tc.msg) {
			t.Errorf("off %v: not recreated on the old port: %d %v\n%s", tc.off, res.Port, r.Commands(), out.String())
		}
		run, _ := r.Find("run ")
		if strings.Contains(run.String(), "--label safeclaw.memory=off ") != tc.off {
			t.Errorf("off %v: run = %q", tc.off, run.String())
		}
		if !strings.Contains(run.String(), "-v /proj:/home/sclaw/proj ") || !strings.Contains(run.String(), "--label safeclaw.secrets= ") {
			t.Errorf("off %v: run lost mounts or secrets: %q", tc.off, run.String())
		}
		checkMemoryWrite(t, r, "safeclaw-p", tc.off)
	}

	// Other recreates keep the choice.
	m, r := newTestManager(t, off())
	if _, err := m.Ensure(ctx, Options{Name: "p", Volume: "/new:/home/sclaw/new", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if run, _ := r.Find("run "); !strings.Contains(run.String(), "--label safeclaw.memory=off ") {
		t.Errorf("volume recreate run = %q", run.String())
	}
	checkMemoryWrite(t, r, "safeclaw-p", true)

	// An offline session is not recreated.
	w := on()
	w.containers["safeclaw-p"].Offline = true
	m, r = newTestManager(t, w)
	if _, err := m.Ensure(ctx, Options{Name: "p", NoMemory: boolPtr(true), NoOpen: true}); !errors.Is(err, ErrOffline) || hasCall(r, "rm ") {
		t.Errorf("offline: err = %v, calls %v", err, r.Commands())
	}
}

func TestEnsureFailedMemoryRecreateRestores(t *testing.T) {
	ctx := context.Background()
	w := &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-p": {Running: true, Port: 7705, Image: "img", Labels: map[string]string{"safeclaw.memory": "off"}},
	}, native: true, runErrs: []runErr{{err: errors.New("docker run failed")}}}
	m, r := newTestManager(t, w)
	if _, err := m.Ensure(ctx, Options{Name: "p", NoMemory: boolPtr(false), NoOpen: true}); err == nil {
		t.Fatal("no error")
	}
	c := w.containers["safeclaw-p"]
	if c == nil || c.Labels["safeclaw.memory"] != "off" || c.Port != 7705 {
		t.Errorf("not restored with auto memory off: %+v %v", c, r.Commands())
	}
}

// A session whose setting can't be written never starts Claude Code, so it
// never runs with auto memory on when the user turned it off.
func TestEnsureMemoryWriteFails(t *testing.T) {
	ctx := context.Background()
	m, r := newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{}, native: true, failMemory: true})
	if _, err := m.Ensure(ctx, Options{Name: "p", NoMemory: boolPtr(true), NoOpen: true}); err == nil || !strings.Contains(err.Error(), "auto memory setting") {
		t.Errorf("err = %v", err)
	}
	if slices.ContainsFunc(r.Calls, func(c dockertest.Call) bool { return strings.Contains(c.String(), "ttyd") }) {
		t.Errorf("ttyd started: %v", r.Commands())
	}
}
