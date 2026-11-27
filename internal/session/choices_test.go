package session

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
)

// recreateRun returns the `docker run` of the session's next container.
func recreateRun(t *testing.T, r *dockertest.Runner) string {
	t.Helper()
	run, ok := r.Find("run ")
	if !ok {
		t.Fatalf("no docker run: %v", r.Commands())
	}
	return run.String()
}

// A session's secrets and auto memory choices outlive its container, so one
// created again over its history after `safeclaw rm` or `build --recreate`
// keeps them.
func TestChoicesOutliveRemovedContainer(t *testing.T) {
	ctx := context.Background()
	remove := map[string]func(m *Manager, w *world) error{
		"rm": func(m *Manager, _ *world) error { return m.Delete(ctx, "triage", true) },
		"build --recreate": func(m *Manager, w *world) error {
			c, err := m.Docker.InspectOne(ctx, "safeclaw-triage")
			if err != nil || c == nil {
				t.Fatalf("inspect: %v %v", c, err)
			}
			removed, err := m.RemoveStale(ctx, *c)
			if !removed {
				t.Errorf("not removed")
			}
			return err
		},
	}
	for how, rm := range remove {
		w := &world{image: "img", containers: map[string]*fakeContainer{}, native: true}
		m, r := newTestManager(t, w)
		none := NoSecrets()
		if _, err := m.Ensure(ctx, Options{Name: "triage", Secrets: &none, NoMemory: boolPtr(true), NoOpen: true}); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(m.SessionsDir, "triage", "MEMORY.md"), []byte("injected\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := rm(m, w); err != nil {
			t.Fatalf("%s: %v", how, err)
		}
		if w.containers["safeclaw-triage"] != nil {
			t.Fatalf("%s: container not removed", how)
		}

		r.Calls = nil
		var out bytes.Buffer
		m.Out = &out
		if _, err := m.Ensure(ctx, Options{Name: "triage", NoOpen: true}); err != nil {
			t.Fatal(err)
		}
		run := recreateRun(t, r)
		if !strings.Contains(run, "--label safeclaw.memory=off ") || !strings.Contains(run, "--label safeclaw.secrets= ") {
			t.Errorf("%s: run lost the choices: %q", how, run)
		}
		checkMemoryWrite(t, r, "safeclaw-triage", true)
		if strings.Contains(out.String(), "Warning: session triage has history") {
			t.Errorf("%s: warned about remembered choices: %s", how, out.String())
		}

		// Giving a choice again changes what is kept.
		if err := m.Delete(ctx, "triage", true); err != nil {
			t.Fatal(err)
		}
		all := AllSecrets()
		out.Reset()
		if _, err := m.Ensure(ctx, Options{Name: "triage", Secrets: &all, NoMemory: boolPtr(false), NoOpen: true}); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "keeps the history its previous container wrote with none") {
			t.Errorf("%s: no warning about the changed secrets: %s", how, out.String())
		}
		if err := m.Delete(ctx, "triage", true); err != nil {
			t.Fatal(err)
		}
		r.Calls = nil
		if _, err := m.Ensure(ctx, Options{Name: "triage", NoOpen: true}); err != nil {
			t.Fatal(err)
		}
		if run := recreateRun(t, r); strings.Contains(run, "safeclaw.memory") || strings.Contains(run, "safeclaw.secrets") {
			t.Errorf("%s: run kept the old choices: %q", how, run)
		}
		checkMemoryWrite(t, r, "safeclaw-triage", false)
	}
}

// Choices of containers created before they were kept on the host are kept
// when the container is removed, or when it is next run.
func TestChoicesKeptForOlderContainers(t *testing.T) {
	ctx := context.Background()
	labels := func() map[string]string {
		return map[string]string{"safeclaw.memory": "off", "safeclaw.secrets": "GH_TOKEN"}
	}

	// Removed without being run again.
	w := &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-p": {Port: 7705, Image: "img", Labels: labels()},
	}, native: true}
	m, _ := newTestManager(t, w)
	if err := m.Delete(ctx, "p", true); err != nil {
		t.Fatal(err)
	}
	kept, err := m.readChoices("p")
	if err != nil || kept == nil || !kept.NoMemory || kept.Secrets == nil || strings.Join(*kept.Secrets, ",") != "GH_TOKEN" {
		t.Errorf("kept = %+v, %v", kept, err)
	}

	// Run again and kept.
	w = &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-p": {Running: true, Port: 7705, Image: "img", Labels: labels()},
	}, native: true}
	m, r := newTestManager(t, w)
	if _, err := m.Ensure(ctx, Options{Name: "p", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if hasCall(r, "rm ") {
		t.Errorf("recreated: %v", r.Commands())
	}
	if kept, err := m.readChoices("p"); err != nil || kept == nil || !kept.NoMemory {
		t.Errorf("kept = %+v, %v", kept, err)
	}

	// Sandboxes keep none.
	m, _ = newTestManager(t, w)
	var sandbox docker.Container
	sandbox.Config.Labels = map[string]string{"safeclaw.type": "sandbox"}
	if err := m.keepChoices("s", sandbox); err != nil {
		t.Fatal(err)
	}
	if kept, err := m.readChoices("s"); err != nil || kept != nil {
		t.Errorf("sandbox kept = %+v, %v", kept, err)
	}

	// A mixed-case container from an earlier version keeps none, so it
	// never replaces the lowercase session's record.
	var legacy docker.Container
	legacy.Config.Labels = labels()
	if err := m.keepChoices("Work", legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(m.choicesPath("Work")); !os.IsNotExist(err) {
		t.Errorf("mixed-case record written: %v", err)
	}
}

// A session with history but no kept choices, such as one removed before
// they were kept, is warned that auto memory is on.
func TestWarnHistoryWithoutKeptMemoryChoice(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		noMemory *bool
		warn     bool
	}{
		{nil, true},
		{boolPtr(false), false},
		{boolPtr(true), false},
	} {
		m, _ := newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{}, native: true})
		if err := os.MkdirAll(filepath.Join(m.SessionsDir, "old"), 0o700); err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		m.Out = &out
		if _, err := m.Ensure(ctx, Options{Name: "old", NoMemory: tc.noMemory, NoOpen: true}); err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(out.String(), "no auto memory choice is remembered"); got != tc.warn {
			t.Errorf("noMemory %v: warned %v: %s", tc.noMemory, got, out.String())
		}
	}

	// A new session has no history to warn about.
	m, _ := newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{}, native: true})
	var out bytes.Buffer
	m.Out = &out
	if _, err := m.Ensure(ctx, Options{Name: "new", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "auto memory") {
		t.Errorf("new session warned: %s", out.String())
	}
}

// A kept record that can't be read stops the run, rather than dropping the
// choices it holds.
func TestUnreadableChoicesRefused(t *testing.T) {
	ctx := context.Background()
	for _, content := range []string{"not json", `{"secrets": ["bad name"]}`} {
		m, r := newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{}, native: true})
		if err := os.MkdirAll(m.choicesDir(), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(m.choicesPath("p"), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := m.Ensure(ctx, Options{Name: "p", NoOpen: true}); err == nil || !strings.Contains(err.Error(), "choices kept for session p") {
			t.Errorf("%q: err = %v", content, err)
		}
		if hasCall(r, "run ") {
			t.Errorf("%q: created: %v", content, r.Commands())
		}
	}

	// A symlink is not a record.
	m, _ := newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{}, native: true})
	if err := os.MkdirAll(m.choicesDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "x")
	if err := os.WriteFile(target, []byte(`{"noMemory": true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, m.choicesPath("p")); err != nil {
		t.Fatal(err)
	}
	if kept, err := m.readChoices("p"); err != nil || kept != nil {
		t.Errorf("symlink kept = %+v, %v", kept, err)
	}
}

// The record lives outside the history directory that is mounted into the
// container, readable only by the user.
func TestChoicesOutsideHistory(t *testing.T) {
	m, _ := newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{}, native: true})
	if err := m.writeChoices("p", newChoices(NoSecrets(), true)); err != nil {
		t.Fatal(err)
	}
	path := m.choicesPath("p")
	if strings.HasPrefix(path, m.SessionsDir+string(filepath.Separator)) {
		t.Errorf("record %s is under the history directories %s", path, m.SessionsDir)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v", info.Mode().Perm())
	}
	b, _ := os.ReadFile(path)
	if string(b) != `{"secrets":[],"noMemory":true}`+"\n" {
		t.Errorf("record = %q", b)
	}
}
