//go:build integration

package session

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/secrets"
)

// TestIntegrationSandboxStopMissingOK checks `sandbox stop --missing-ok`
// and `sandbox rm --missing-ok` against real sandboxes: a one-off one
// stopped, then stopped and removed again once docker has removed it, and
// a named one stopped twice and removed.
func TestIntegrationSandboxStopMissingOK(t *testing.T) {
	d := docker.New()
	ctx := context.Background()
	if id, err := d.ImageID(ctx, config.ImageName); err != nil || id == "" {
		t.Skip("safeclaw image not built; run `safeclaw build` first")
	}
	dir := t.TempDir()
	m := &Manager{
		Docker:      d,
		Secrets:     secrets.FileStore{Dir: filepath.Join(dir, ".secrets")},
		SessionsDir: filepath.Join(dir, "sessions"),
		TTYDDir:     filepath.Join(dir, "ttyd"),
		NetworkDir:  filepath.Join(dir, "network"),
		ChoicesDir:  filepath.Join(dir, "choices"),
		Out:         os.Stdout,
	}
	ok := SandboxStopOptions{MissingOK: true}

	// docker's own errors for a container that is gone count as missing.
	missing := config.ContainerName(fmt.Sprintf("itest-gone-%d", rand.IntN(1_000_000)))
	if err := d.Stop(ctx, missing, 1); !gone(err) {
		t.Errorf("docker stop of a missing container: %v, want gone", err)
	}
	if err := d.Remove(ctx, missing, false); !gone(err) {
		t.Errorf("docker rm of a missing container: %v, want gone", err)
	}
	// Recent docker's rm -f succeeds for one, so a race with it exits 0
	// either way.
	if err := d.Remove(ctx, missing, true); err != nil && !gone(err) {
		t.Errorf("docker rm -f of a missing container: %v", err)
	}

	res, err := m.EnsureSandbox(ctx, SandboxOptions{Remove: true, Variant: config.BaseVariant})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Remove(ctx, res.Container, true) })
	if skipped, err := m.StopSandbox(ctx, res.Name, ok); skipped != NotSkipped || err != nil {
		t.Fatalf("stop: %q, %v", skipped, err)
	}
	waitGone(t, d, res.Container)
	if skipped, err := m.StopSandbox(ctx, res.Name, ok); skipped != SkippedMissing || err != nil {
		t.Errorf("stop again: %q, %v; want missing", skipped, err)
	}
	if skipped, err := m.DeleteSandbox(ctx, res.Name, SandboxStopOptions{Force: true, MissingOK: true}); skipped != SkippedMissing || err != nil {
		t.Errorf("rm -f: %q, %v; want missing", skipped, err)
	}
	if _, err := m.StopSandbox(ctx, res.Name, SandboxStopOptions{}); !errors.Is(err, ErrNotFound) {
		t.Errorf("stop without missing-ok: %v, want ErrNotFound", err)
	}

	name := fmt.Sprintf("itest-stop-%d", rand.IntN(1_000_000))
	t.Cleanup(func() { _ = d.Remove(ctx, config.ContainerName(name), true) })
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: name, Variant: config.BaseVariant}); err != nil {
		t.Fatal(err)
	}
	if skipped, err := m.StopSandbox(ctx, name, ok); skipped != NotSkipped || err != nil {
		t.Fatalf("stop: %q, %v", skipped, err)
	}
	if skipped, err := m.StopSandbox(ctx, name, ok); skipped != SkippedStopped || err != nil {
		t.Errorf("stop again: %q, %v; want already stopped", skipped, err)
	}
	if skipped, err := m.DeleteSandbox(ctx, name, ok); skipped != NotSkipped || err != nil {
		t.Errorf("rm: %q, %v", skipped, err)
	}
	if skipped, err := m.DeleteSandbox(ctx, name, ok); skipped != SkippedMissing || err != nil {
		t.Errorf("rm again: %q, %v; want missing", skipped, err)
	}
}
