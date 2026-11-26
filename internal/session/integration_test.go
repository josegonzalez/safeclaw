//go:build integration

package session

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/secrets"
)

// TestIntegrationLifecycle runs a real session against the local safeclaw
// image: create, check ttyd answers, stop, start, and delete.
func TestIntegrationLifecycle(t *testing.T) {
	d := docker.New()
	ctx := context.Background()
	if id, err := d.ImageID(ctx, config.ImageName); err != nil || id == "" {
		t.Skip("safeclaw image not built; run `safeclaw build` first")
	}

	dir := t.TempDir()
	store := secrets.Store{Dir: filepath.Join(dir, ".secrets")}
	if _, err := store.Set(secrets.ClaudeToken, "integration-dummy"); err != nil {
		t.Fatal(err)
	}
	m := &Manager{
		Docker:      d,
		Secrets:     store,
		SessionsDir: filepath.Join(dir, "sessions"),
		Out:         os.Stdout,
		OpenBrowser: func(string) error { return nil },
	}
	name := fmt.Sprintf("itest-%d", rand.IntN(1_000_000))
	t.Cleanup(func() { _ = d.Remove(ctx, config.ContainerName(name), true) })

	res, err := m.Ensure(ctx, Options{Name: name, NoOpen: true})
	if err != nil {
		t.Fatal(err)
	}
	waitHTTP(t, res.URL)

	if err := m.Stop(ctx, name); err != nil {
		t.Fatal(err)
	}
	res2, err := m.Ensure(ctx, Options{Name: name, NoOpen: true})
	if err != nil {
		t.Fatal(err)
	}
	if res2.Port != res.Port {
		t.Errorf("restart changed port %d -> %d", res.Port, res2.Port)
	}
	waitHTTP(t, res2.URL)

	if err := m.Stop(ctx, name); err != nil {
		t.Fatal(err)
	}
	if err := m.Delete(ctx, name, false); err != nil {
		t.Fatal(err)
	}
	if ok, _ := m.Exists(ctx, name); ok {
		t.Error("container still exists after delete")
	}
}

func waitHTTP(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("ttyd did not answer at %s", url)
}

// TestIntegrationSandbox runs a real sandbox against the local safeclaw
// image and checks its isolation from inside and outside the container.
func TestIntegrationSandbox(t *testing.T) {
	d := docker.New()
	ctx := context.Background()
	if id, err := d.ImageID(ctx, config.ImageName); err != nil || id == "" {
		t.Skip("safeclaw image not built; run `safeclaw build` first")
	}

	dir := t.TempDir()
	in := filepath.Join(dir, "in")
	if err := os.MkdirAll(in, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(in, "doc.txt"), []byte("untrusted\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := &Manager{
		Docker:      d,
		Secrets:     secrets.Store{Dir: filepath.Join(dir, ".secrets")},
		SessionsDir: filepath.Join(dir, "sessions"),
		Out:         os.Stdout,
	}
	name := fmt.Sprintf("itest-sandbox-%d", rand.IntN(1_000_000))
	container := config.ContainerName(name)
	t.Cleanup(func() { _ = d.Remove(ctx, container, true) })

	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: name, Volume: in + ":/in"}); err != nil {
		t.Fatal(err)
	}

	run := func(cmd ...string) (string, error) {
		out, err := d.Exec(ctx, container, docker.ExecOptions{}, cmd...)
		return strings.TrimSpace(string(out)), err
	}
	if out, err := run("id", "-un"); err != nil || out != config.SandboxUser {
		t.Errorf("exec user = %q, %v", out, err)
	}
	if out, err := run("cat", "/in/doc.txt"); err != nil || out != "untrusted" {
		t.Errorf("read mounted file = %q, %v", out, err)
	}
	for _, cmd := range [][]string{
		{"ls", "/home/sclaw"},
		{"touch", "/in/x"},
		{"touch", "/x"},
		{"bash", "-c", "exec 3<>/dev/tcp/1.1.1.1/80"},
	} {
		if _, err := run(cmd...); err == nil {
			t.Errorf("%v should fail in a sandbox", cmd)
		}
	}
	// With --network none, loopback is the only interface.
	if out, err := run("ls", "/sys/class/net"); err != nil || out != "lo" {
		t.Errorf("network interfaces = %q, %v", out, err)
	}
	for _, cmd := range [][]string{
		{"touch", "/sandbox/x"},
		{"touch", "/tmp/x"},
	} {
		if _, err := run(cmd...); err != nil {
			t.Errorf("%v: %v", cmd, err)
		}
	}

	c, err := d.InspectOne(ctx, container)
	if err != nil || c == nil {
		t.Fatalf("inspect: %v", err)
	}
	if TypeOf(*c) != config.TypeSandbox || c.HostPort(config.TTYDPort) != 0 {
		t.Errorf("type = %q, port = %d", TypeOf(*c), c.HostPort(config.TTYDPort))
	}
	out, err := d.R.Output(ctx, nil, "container", "inspect", "--format",
		"{{.HostConfig.NetworkMode}} {{.HostConfig.IpcMode}} {{.HostConfig.CapDrop}} {{.HostConfig.ReadonlyRootfs}}", container)
	if got := strings.TrimSpace(string(out)); err != nil || got != "none private [ALL] true" {
		t.Errorf("host config = %q, %v", got, err)
	}

	// docker cp works into the /sandbox volume.
	if _, err := d.R.Output(ctx, nil, "cp", filepath.Join(in, "doc.txt"), container+":/sandbox/copied.txt"); err != nil {
		t.Errorf("docker cp: %v", err)
	}
	if out, err := run("cat", "/sandbox/copied.txt"); err != nil || out != "untrusted" {
		t.Errorf("copied file = %q, %v", out, err)
	}

	// Removing the sandbox removes its anonymous volume too.
	out, err = d.R.Output(ctx, nil, "container", "inspect", "--format", `{{range .Mounts}}{{if eq .Destination "/sandbox"}}{{.Name}}{{end}}{{end}}`, container)
	volume := strings.TrimSpace(string(out))
	if err != nil || volume == "" {
		t.Fatalf("sandbox volume = %q, %v", volume, err)
	}
	if err := m.Delete(ctx, name, true); err != nil {
		t.Fatal(err)
	}
	if _, err := d.R.Output(ctx, nil, "volume", "inspect", volume); err == nil {
		t.Errorf("volume %s survived sandbox removal", volume)
	}
}
