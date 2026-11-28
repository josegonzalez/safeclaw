//go:build integration

package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/secrets"
	"github.com/josegonzalez/safeclaw/internal/session"
	"github.com/josegonzalez/safeclaw/internal/version"
)

// TestIntegrationSandboxProfile creates a sandbox with a named profile and
// checks that its limits were applied and the profile recorded, that
// naming it again keeps the sandbox, that a flag on the command line wins,
// and that `exec --ephemeral` gets the run section's limits too.
func TestIntegrationSandboxProfile(t *testing.T) {
	d := docker.New()
	ctx := context.Background()
	if id, err := d.ImageID(ctx, config.ImageName); err != nil || id == "" {
		t.Skip("safeclaw image not built; run `safeclaw build` first")
	}
	// require fails on a development build, which the test binary is.
	old := version.Version
	t.Cleanup(func() { version.Version = old })
	version.Version = "0.6.0"

	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	path := filepath.Join(dir, "safeclaw", "profiles", "itest.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	data := "require: 0.6.0\nrun:\n  variant: base\n  memory: 300m\n  pids-limit: 77\n  cpus: 0.5\n  disk: 16m\n  verify: true\nexec:\n  escape-controls: true\n  timeout: 2m\n"
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	m := &session.Manager{Docker: d, Secrets: secrets.FileStore{Dir: filepath.Join(dir, ".secrets")}, CopyDir: filepath.Join(dir, "copy")}
	orig := newManager
	t.Cleanup(func() { newManager = orig })
	newManager = func() *session.Manager { return m }

	name := fmt.Sprintf("itest-profile-%d", rand.IntN(1_000_000))
	container := config.ContainerName(name)
	t.Cleanup(func() { _ = d.Remove(context.Background(), container, true) })

	run := func(args ...string) string {
		t.Helper()
		out, stderr, err := runStderr(args...)
		if err != nil {
			t.Fatalf("%q: %v\n%s%s", args, err, out, stderr)
		}
		return out
	}
	inspect := func() session.SandboxInfo {
		t.Helper()
		var info session.SandboxInfo
		if err := json.Unmarshal([]byte(run("sandbox", "inspect", name)), &info); err != nil {
			t.Fatal(err)
		}
		return info
	}

	run("sandbox", "run", "-s", name, "--profile", "itest")
	info := inspect()
	want := session.SandboxLimits{MemoryBytes: 300 << 20, CPUs: 0.5, Pids: 77, DiskBytes: 16 << 20}
	if info.Limits != want {
		t.Errorf("limits = %+v, want %+v", info.Limits, want)
	}
	if info.Variant != config.BaseVariant {
		t.Errorf("variant = %q", info.Variant)
	}
	if info.Profile == nil || info.Profile.Ref != "itest" || len(info.Profile.SHA256) != 64 {
		t.Errorf("profile = %+v", info.Profile)
	}
	id := info.ID

	// The same profile again keeps the sandbox and what is in it.
	run("sandbox", "exec", "--profile", "itest", name, "--", "sh", "-c", "echo kept > /sandbox/f")
	run("sandbox", "run", "-s", name, "--profile", "itest")
	if got := inspect().ID; got != id {
		t.Errorf("naming the same profile again recreated the sandbox")
	}
	if out := run("sandbox", "exec", "--profile", "itest", name, "--", "cat", "/sandbox/f"); out != "kept\n" {
		t.Errorf("file = %q", out)
	}

	// A limit on the command line wins, and recreates it.
	run("sandbox", "run", "-s", name, "--profile", "itest", "--pids-limit", "99")
	info = inspect()
	if info.ID == id || info.Limits.Pids != 99 || info.Limits.MemoryBytes != 300<<20 {
		t.Errorf("after --pids-limit 99: id changed = %v, limits = %+v", info.ID != id, info.Limits)
	}

	// exec --ephemeral gets the run section, escaped output, and the
	// timeout.
	out := run("sandbox", "exec", "--profile", "itest", "--ephemeral", "--", "sh", "-c", "cat /sys/fs/cgroup/memory.max /sys/fs/cgroup/pids.max; printf '\\033[2J'")
	if !strings.HasPrefix(out, fmt.Sprintf("%d\n77\n", 300<<20)) || !strings.Contains(out, `\x1b[2J`) {
		t.Errorf("ephemeral output = %q", out)
	}
}
