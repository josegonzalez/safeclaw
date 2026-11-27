package session

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/secrets"
)

// Only canonical names are valid, so each session has one container,
// history directory, and state file.
func TestValidateNameCanonical(t *testing.T) {
	for _, ok := range []string{"work", "a.b_c-1", "0x", "default"} {
		if err := ValidateName(ok); err != nil {
			t.Errorf("ValidateName(%q) = %v", ok, err)
		}
	}
	for _, bad := range []string{"Work", "WORK", "safeclaw-x", "safeclaw-safeclaw-x", "x+y", "", "-x"} {
		if ValidateName(bad) == nil {
			t.Errorf("%q should be invalid", bad)
		}
	}
	err := ValidateName("Work")
	if !errors.Is(err, ErrLegacyName) || !strings.Contains(err.Error(), "docker rm -f safeclaw-Work") || !strings.Contains(err.Error(), `"work"`) {
		t.Errorf("err = %v, want ErrLegacyName naming the docker rm and the lowercase name", err)
	}
}

func TestResolveName(t *testing.T) {
	ctx := context.Background()
	w := &world{image: "img", containers: map[string]*fakeContainer{"safeclaw-Old": {}}}
	m, r := newTestManager(t, w)
	for in, want := range map[string]string{
		"work":          "work",
		"Work":          "work",
		"safeclaw-Work": "work",
		"safeclaw-work": "work",
		"old":           "old",
	} {
		got, err := m.ResolveName(ctx, in)
		if err != nil || got != want {
			t.Errorf("ResolveName(%q) = %q, %v, want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"safeclaw-safeclaw-x", "SAFECLAW-x", "a b", ""} {
		if got, err := m.ResolveName(ctx, bad); err == nil {
			t.Errorf("ResolveName(%q) = %q, want an error", bad, got)
		}
	}
	// A container made with exactly a mixed-case name is never mistaken
	// for the lowercase session.
	for _, in := range []string{"Old", "safeclaw-Old"} {
		if _, err := m.ResolveName(ctx, in); !errors.Is(err, ErrLegacyName) || !strings.Contains(err.Error(), "docker rm -f safeclaw-Old") {
			t.Errorf("ResolveName(%q): err = %v, want ErrLegacyName", in, err)
		}
	}
	// Lowercase names need no lookup.
	r.Calls = nil
	if _, err := m.ResolveName(ctx, "work"); err != nil || len(r.Calls) != 0 {
		t.Errorf("err = %v, calls = %v", err, r.Commands())
	}
}

// Names that are not canonical are refused before docker is asked to do
// anything, so a doubled prefix never reaches the session's container with
// another session's history and state.
func TestNonCanonicalNamesRefused(t *testing.T) {
	ctx := context.Background()
	for _, name := range []string{"safeclaw-safeclaw-work", "Work"} {
		w := &world{image: "img", containers: map[string]*fakeContainer{"safeclaw-work": {Running: true, Port: 7690}}, native: true}
		m, r := newTestManager(t, w)
		if _, err := m.Ensure(ctx, Options{Name: name, NoOpen: true}); err == nil {
			t.Errorf("Ensure(%q) succeeded", name)
		}
		if err := m.Stop(ctx, name); err == nil {
			t.Errorf("Stop(%q) succeeded", name)
		}
		if err := m.Delete(ctx, name, true); err == nil {
			t.Errorf("Delete(%q) succeeded", name)
		}
		if len(r.Calls) != 0 {
			t.Errorf("%q: docker called: %v", name, r.Commands())
		}
	}
	// The container name is still accepted for the session.
	w := &world{image: "img", containers: map[string]*fakeContainer{"safeclaw-work": {Running: true, Port: 7690}}, native: true}
	m, r := newTestManager(t, w)
	if err := m.Stop(ctx, "safeclaw-work"); err != nil || !hasCall(r, "stop -t 1 safeclaw-work") {
		t.Errorf("Stop = %v: %v", err, r.Commands())
	}
}

// A session whose secrets change is warned that it keeps the history its
// previous container wrote, as is one created with a chosen set over an
// earlier container's history.
func TestEnsureWarnsReusedHistory(t *testing.T) {
	ctx := context.Background()
	existing := func() map[string]*fakeContainer {
		return map[string]*fakeContainer{"safeclaw-work": {Running: true, Port: 7690, Image: "img",
			Labels: map[string]string{"safeclaw.secrets": secrets.ClaudeToken}}}
	}
	for _, tc := range []struct {
		name       string
		containers map[string]*fakeContainer
		history    bool
		opts       Options
		warn       string
	}{
		{"narrowed", existing(), true, Options{Secrets: ptr(NoSecrets())}, "keeps the history its previous container wrote with " + secrets.ClaudeToken},
		{"widened", existing(), true, Options{Secrets: ptr(AllSecrets())}, "keeps the history its previous container wrote with"},
		{"narrowed without history", existing(), false, Options{Secrets: ptr(NoSecrets())}, ""},
		{"same set", existing(), true, Options{Secrets: ptr(MustSecrets(t, secrets.ClaudeToken))}, ""},
		{"recreated for a volume", existing(), true, Options{Volume: "/host/p:/home/sclaw/p"}, ""},
		{"fresh history", existing(), true, Options{Secrets: ptr(NoSecrets()), FreshHistory: true}, ""},
		{"new over history", map[string]*fakeContainer{}, true, Options{Secrets: ptr(NoSecrets())}, "may have been written with other secrets"},
		{"new over history with all", map[string]*fakeContainer{}, true, Options{Secrets: ptr(AllSecrets())}, "may have been written with other secrets"},
		{"new", map[string]*fakeContainer{}, false, Options{Secrets: ptr(NoSecrets())}, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &world{image: "img", containers: tc.containers, native: true}
			m, _ := newTestManager(t, w)
			if tc.history {
				if err := os.MkdirAll(filepath.Join(m.SessionsDir, "work"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			var out bytes.Buffer
			m.Out = &out
			tc.opts.Name, tc.opts.NoOpen = "work", true
			if _, err := m.Ensure(ctx, tc.opts); err != nil {
				t.Fatal(err)
			}
			warned := strings.Contains(out.String(), "Warning: session work") && strings.Contains(out.String(), "history")
			if tc.warn == "" && warned {
				t.Errorf("warned: %s", out.String())
			}
			if tc.warn != "" && (!strings.Contains(out.String(), tc.warn) || !strings.Contains(out.String(), "--fresh-history")) {
				t.Errorf("want a warning with %q and --fresh-history: %s", tc.warn, out.String())
			}
		})
	}
}

// MustSecrets is OnlySecrets for tests.
func MustSecrets(t *testing.T, names ...string) SecretSet {
	t.Helper()
	s, err := OnlySecrets(names...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// archives returns the history directories moved aside for work.
func archives(t *testing.T, m *Manager) []string {
	t.Helper()
	got, err := filepath.Glob(filepath.Join(m.SessionsDir, "work.old-*"))
	if err != nil {
		t.Fatal(err)
	}
	return got
}

// FreshHistory moves the history aside, never deleting it, and gives the
// new container an empty one.
func TestEnsureFreshHistory(t *testing.T) {
	ctx := context.Background()
	withHistory := func(t *testing.T, m *Manager) string {
		t.Helper()
		dir := filepath.Join(m.SessionsDir, "work")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "MEMORY.md"), []byte("old"), 0o600); err != nil {
			t.Fatal(err)
		}
		return dir
	}
	moved := func(t *testing.T, m *Manager, dir string) {
		t.Helper()
		got := archives(t, m)
		if len(got) != 1 {
			t.Fatalf("archives = %v", got)
		}
		if b, err := os.ReadFile(filepath.Join(got[0], "MEMORY.md")); err != nil || string(b) != "old" {
			t.Errorf("archived memory = %q, %v", b, err)
		}
		// The archive is never another session's history.
		if ValidateName(filepath.Base(got[0])) == nil || ValidateName(strings.ToLower(filepath.Base(got[0]))) == nil {
			t.Errorf("archive %s is a valid session name", got[0])
		}
		if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
			t.Errorf("new history = %v, %v", entries, err)
		}
	}

	t.Run("new", func(t *testing.T) {
		w := &world{image: "img", containers: map[string]*fakeContainer{}, native: true}
		m, _ := newTestManager(t, w)
		dir := withHistory(t, m)
		var out bytes.Buffer
		m.Out = &out
		if _, err := m.Ensure(ctx, Options{Name: "work", FreshHistory: true, NoOpen: true}); err != nil {
			t.Fatal(err)
		}
		moved(t, m, dir)
		if !strings.Contains(out.String(), "Moved the history of session work to ") || strings.Contains(out.String(), "Warning: session work has history") {
			t.Errorf("out = %s", out.String())
		}
	})

	t.Run("without history", func(t *testing.T) {
		w := &world{image: "img", containers: map[string]*fakeContainer{}, native: true}
		m, _ := newTestManager(t, w)
		if _, err := m.Ensure(ctx, Options{Name: "work", FreshHistory: true, NoOpen: true}); err != nil {
			t.Fatal(err)
		}
		if got := archives(t, m); len(got) != 0 {
			t.Errorf("archives = %v", got)
		}
	})

	t.Run("recreates", func(t *testing.T) {
		w := &world{image: "img", containers: map[string]*fakeContainer{"safeclaw-work": {Running: true, Port: 7690, Image: "img",
			Labels: map[string]string{"safeclaw.secrets": secrets.ClaudeToken}}}, native: true}
		m, r := newTestManager(t, w)
		dir := withHistory(t, m)
		if _, err := m.Ensure(ctx, Options{Name: "work", FreshHistory: true, NoOpen: true}); err != nil {
			t.Fatal(err)
		}
		if !hasCall(r, "rm -v -f safeclaw-work") || !hasCall(r, "run ") {
			t.Errorf("not recreated: %v", r.Commands())
		}
		moved(t, m, dir)
		// The recreated container keeps its port and secrets.
		c := w.containers["safeclaw-work"]
		if c == nil || c.Port != 7690 || c.Labels["safeclaw.secrets"] != secrets.ClaudeToken {
			t.Errorf("container = %+v", c)
		}
	})

	t.Run("failed create", func(t *testing.T) {
		runFailed := errors.New("docker run failed")
		w := &world{image: "img", containers: map[string]*fakeContainer{"safeclaw-work": {Running: true, Port: 7690, Image: "img"}}, native: true}
		w.runErrs = []runErr{{err: runFailed}}
		m, _ := newTestManager(t, w)
		dir := withHistory(t, m)
		if _, err := m.Ensure(ctx, Options{Name: "work", FreshHistory: true, NoOpen: true}); !errors.Is(err, runFailed) {
			t.Fatalf("err = %v", err)
		}
		if got := archives(t, m); len(got) != 0 {
			t.Errorf("archives = %v", got)
		}
		if b, err := os.ReadFile(filepath.Join(dir, "MEMORY.md")); err != nil || string(b) != "old" {
			t.Errorf("history not restored: %q, %v", b, err)
		}
		if c := w.containers["safeclaw-work"]; c == nil || c.Port != 7690 {
			t.Errorf("previous container not restored: %+v", c)
		}
	})

	t.Run("offline", func(t *testing.T) {
		w := &world{image: "img", containers: map[string]*fakeContainer{"safeclaw-work": {Running: true, Port: 7690, Image: "img", Offline: true}}, native: true}
		m, r := newTestManager(t, w)
		dir := withHistory(t, m)
		if _, err := m.Ensure(ctx, Options{Name: "work", FreshHistory: true, NoOpen: true}); !errors.Is(err, ErrOffline) {
			t.Fatalf("err = %v", err)
		}
		if hasCall(r, "rm ") || len(archives(t, m)) != 0 {
			t.Errorf("acted on an offline session: %v", r.Commands())
		}
		if _, err := os.Stat(filepath.Join(dir, "MEMORY.md")); err != nil {
			t.Error(err)
		}
	})
}
