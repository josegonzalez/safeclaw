package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
	"github.com/josegonzalez/safeclaw/internal/session"
)

func TestNetCommands(t *testing.T) {
	root := NewRootCommand()
	off, _, err := root.Find([]string{"net", "off"})
	if err != nil || off.Name() != "off" {
		t.Fatalf("net off: %v", err)
	}
	for _, f := range []string{"owner", "reason"} {
		if off.Flags().Lookup(f) == nil {
			t.Errorf("net off lacks --%s", f)
		}
	}
	on, _, err := root.Find([]string{"net", "on"})
	if err != nil || on.Name() != "on" {
		t.Fatalf("net on: %v", err)
	}
	for _, f := range []string{"owner", "force"} {
		if on.Flags().Lookup(f) == nil {
			t.Errorf("net on lacks --%s", f)
		}
	}
	if err := on.Args(on, nil); err == nil {
		t.Error("net on accepted no name")
	}
}

// rm refuses a session held offline, naming its holders, and removes it
// with --release-holds. -f alone only covers a running session.
func TestRemoveHeldSession(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	exists := true
	r := &dockertest.Runner{Handler: func(args []string, _ string) ([]byte, error) {
		switch {
		case len(args) > 2 && args[0] == "container" && args[1] == "inspect" && args[2] == "safeclaw-work" && exists:
			return []byte(`[{"Id":"id","Name":"/safeclaw-work","State":{"Status":"running","Running":true}}]`), nil
		case len(args) > 0 && args[0] == "rm":
			exists = false
			return nil, nil
		}
		return nil, dockertest.NotFound(args)
	}}
	netDir, choicesDir, ttydDir := t.TempDir(), t.TempDir(), t.TempDir()
	orig := newManager
	t.Cleanup(func() { newManager = orig })
	newManager = func() *session.Manager {
		return &session.Manager{Docker: r.Client(), NetworkDir: netDir, ChoicesDir: choicesDir, TTYDDir: ttydDir}
	}
	state := filepath.Join(netDir, "work.json")
	if err := os.WriteFile(state, []byte(`{"containerId":"id","networks":[],"holds":[{"owner":"triage","since":"2026-01-01T00:00:00Z"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := run(t, NewRootCommand(), "rm", "-f", "work")
	if !errors.Is(err, session.ErrHeld) || !strings.Contains(err.Error(), "by triage") {
		t.Fatalf("rm -f: err = %v, want it held by triage", err)
	}
	if !exists {
		t.Fatal("rm -f removed a held session")
	}
	if _, err := run(t, NewRootCommand(), "rm", "-f", "--release-holds", "work"); err != nil {
		t.Fatal(err)
	}
	if exists {
		t.Error("rm --release-holds kept the session")
	}
	if _, err := os.Stat(state); !os.IsNotExist(err) {
		t.Errorf("state kept: %v", err)
	}
}
