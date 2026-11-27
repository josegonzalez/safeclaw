//go:build integration

package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/secrets"
	"github.com/josegonzalez/safeclaw/internal/variant"
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

	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: name, Volume: in + ":/in", Variant: config.BaseVariant}); err != nil {
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

// waitGone polls until a container no longer exists.
func waitGone(t *testing.T, d *docker.Client, container string) {
	t.Helper()
	ctx := context.Background()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		c, err := d.InspectOne(ctx, container)
		if err != nil {
			t.Fatal(err)
		}
		if c == nil {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Errorf("%s still exists", container)
}

// TestIntegrationSandboxRemove checks that a one-off sandbox from
// `sandbox run --rm` is removed, with its volume, when it stops.
func TestIntegrationSandboxRemove(t *testing.T) {
	d := docker.New()
	ctx := context.Background()
	if id, err := d.ImageID(ctx, config.ImageName); err != nil || id == "" {
		t.Skip("safeclaw image not built; run `safeclaw build` first")
	}
	dir := t.TempDir()
	m := &Manager{
		Docker:      d,
		Secrets:     secrets.Store{Dir: filepath.Join(dir, ".secrets")},
		SessionsDir: filepath.Join(dir, "sessions"),
		Out:         os.Stdout,
	}
	res, err := m.EnsureSandbox(ctx, SandboxOptions{Remove: true, Variant: config.BaseVariant})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Remove(ctx, res.Container, true) })
	if !strings.HasPrefix(res.Name, "tmp-") {
		t.Errorf("name = %q", res.Name)
	}

	s, err := m.Get(ctx, res.Name)
	if err != nil || !s.IsOneOff() {
		t.Fatalf("get = %+v, %v", s, err)
	}
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: res.Name, Remove: true}); !errors.Is(err, ErrExists) {
		t.Errorf("reusing the name: err = %v, want ErrExists", err)
	}
	if out, err := d.Exec(ctx, res.Container, docker.ExecOptions{}, "id", "-un"); err != nil || strings.TrimSpace(string(out)) != config.SandboxUser {
		t.Errorf("exec user = %q, %v", out, err)
	}

	out, err := d.R.Output(ctx, nil, "container", "inspect", "--format", `{{range .Mounts}}{{if eq .Destination "/sandbox"}}{{.Name}}{{end}}{{end}}`, res.Container)
	volume := strings.TrimSpace(string(out))
	if err != nil || volume == "" {
		t.Fatalf("sandbox volume = %q, %v", volume, err)
	}
	if err := m.Stop(ctx, res.Name); err != nil {
		t.Fatal(err)
	}
	waitGone(t, d, res.Container)
	if _, err := d.R.Output(ctx, nil, "volume", "inspect", volume); err == nil {
		t.Errorf("volume %s survived one-off sandbox removal", volume)
	}
}

// TestIntegrationSandboxEphemeral runs `sandbox exec --ephemeral`'s argv
// and checks the command's input, output, user, and exit code pass through
// and that nothing is left behind.
func TestIntegrationSandboxEphemeral(t *testing.T) {
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
	m := &Manager{Docker: d}
	run := func(opts SandboxOptions, stdin string, cmd ...string) (string, error) {
		t.Helper()
		if opts.Variant == "" {
			opts.Variant = config.BaseVariant
		}
		argv, name, err := m.PrepareEphemeral(ctx, opts, stdin != "", false, cmd)
		if err != nil {
			t.Fatal(err)
		}
		container := config.ContainerName(name)
		t.Cleanup(func() { _ = d.Remove(ctx, container, true) })
		var r io.Reader
		if stdin != "" {
			r = strings.NewReader(stdin)
		}
		out, err := d.R.Output(ctx, r, argv[1:]...)
		waitGone(t, d, container)
		return strings.TrimSpace(string(out)), err
	}

	if out, err := run(SandboxOptions{}, "from stdin\n", "cat"); err != nil || out != "from stdin" {
		t.Errorf("stdin = %q, %v", out, err)
	}
	if out, err := run(SandboxOptions{}, "", "id", "-un"); err != nil || out != config.SandboxUser {
		t.Errorf("user = %q, %v", out, err)
	}
	name := fmt.Sprintf("itest-ephemeral-%d", rand.IntN(1_000_000))
	if out, err := run(SandboxOptions{Name: name, Volume: in + ":/in"}, "", "cat", "/in/doc.txt"); err != nil || out != "untrusted" {
		t.Errorf("mounted file = %q, %v", out, err)
	}
	if _, err := run(SandboxOptions{Volume: in + ":/in"}, "", "touch", "/in/x"); err == nil {
		t.Error("the volume should be read-only")
	}
	_, err := run(SandboxOptions{}, "", "sh", "-c", "exit 3")
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 3 {
		t.Errorf("exit code: err = %v, want exit status 3", err)
	}
}

// TestIntegrationSandboxVariant checks that the built-in sandbox variant has
// the document extraction tools, that sandboxes use it by default, and that
// it keeps the sandbox isolation.
func TestIntegrationSandboxVariant(t *testing.T) {
	d := docker.New()
	ctx := context.Background()
	if id, err := d.ImageID(ctx, variant.Image(variant.Sandbox)); err != nil || id == "" {
		t.Skip("sandbox variant not built; run `safeclaw build --variant sandbox` first")
	}
	m := &Manager{Docker: d}
	run := func(cmd ...string) (string, error) {
		t.Helper()
		argv, name, err := m.PrepareEphemeral(ctx, SandboxOptions{}, false, false, cmd)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(argv, variant.Image(variant.Sandbox)) {
			t.Errorf("argv does not use the sandbox variant: %v", argv)
		}
		container := config.ContainerName(name)
		t.Cleanup(func() { _ = d.Remove(ctx, container, true) })
		out, err := d.R.Output(ctx, nil, argv[1:]...)
		waitGone(t, d, container)
		return string(out), err
	}
	for _, cmd := range [][]string{
		{"pdftotext", "-v"},
		{"pdfinfo", "-v"},
		{"pdftoppm", "-v"},
		{"7z", "i"},
		{"file", "--version"},
	} {
		if _, err := run(cmd...); err != nil {
			t.Errorf("%v: %v", cmd, err)
		}
	}
	if out, err := run("tesseract", "--list-langs"); err != nil || !strings.Contains(out, "eng") {
		t.Errorf("tesseract languages = %q, %v", out, err)
	}
	if out, err := run("file", "--brief", "/etc/hostname"); err != nil || strings.TrimSpace(out) == "" {
		t.Errorf("file = %q, %v", out, err)
	}

	res, err := m.EnsureSandbox(ctx, SandboxOptions{Remove: true})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Remove(ctx, res.Container, true) })
	c, err := d.InspectOne(ctx, res.Container)
	if err != nil || c == nil {
		t.Fatalf("inspect = %v, %v", c, err)
	}
	if c.Label(config.LabelVariant) != variant.Sandbox || c.Label(config.LabelType) != config.TypeSandbox {
		t.Errorf("labels = %v", c.Config.Labels)
	}
	if out, err := d.Exec(ctx, res.Container, docker.ExecOptions{}, "id", "-un"); err != nil || strings.TrimSpace(string(out)) != config.SandboxUser {
		t.Errorf("exec user = %q, %v", out, err)
	}
	if out, err := d.Exec(ctx, res.Container, docker.ExecOptions{}, "ls", "/sys/class/net"); err != nil || strings.TrimSpace(string(out)) != "lo" {
		t.Errorf("network interfaces = %q, %v", out, err)
	}
	if err := m.Stop(ctx, res.Name); err != nil {
		t.Fatal(err)
	}
	waitGone(t, d, res.Container)
}

// TestIntegrationSecrets checks that a session's env only has the secrets
// chosen for it, and that a different set recreates it.
func TestIntegrationSecrets(t *testing.T) {
	d := docker.New()
	ctx := context.Background()
	if id, err := d.ImageID(ctx, config.ImageName); err != nil || id == "" {
		t.Skip("safeclaw image not built; run `safeclaw build` first")
	}

	dir := t.TempDir()
	store := secrets.Store{Dir: filepath.Join(dir, ".secrets")}
	for k, v := range map[string]string{secrets.ClaudeToken: "integration-dummy", "KEPT": "kept", "LEFT_OUT": "left-out"} {
		if _, err := store.Set(k, v); err != nil {
			t.Fatal(err)
		}
	}
	m := &Manager{
		Docker:      d,
		Secrets:     store,
		SessionsDir: filepath.Join(dir, "sessions"),
		Out:         os.Stdout,
		OpenBrowser: func(string) error { return nil },
	}
	name := fmt.Sprintf("itest-secrets-%d", rand.IntN(1_000_000))
	container := config.ContainerName(name)
	t.Cleanup(func() { _ = d.Remove(ctx, container, true) })

	// env reads the variables a `docker exec bash` sees through BASH_ENV.
	env := func() string {
		t.Helper()
		out, err := d.Exec(ctx, container, docker.ExecOptions{}, "bash", "-c", `echo "$CLAUDE_CODE_OAUTH_TOKEN|$KEPT|$LEFT_OUT"`)
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(out))
	}

	set, err := OnlySecrets(secrets.ClaudeToken, "KEPT")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Ensure(ctx, Options{Name: name, Secrets: &set, NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if got := env(); got != "integration-dummy|kept|" {
		t.Errorf("env = %q", got)
	}

	// Reusing the session keeps its set.
	if _, err := m.Ensure(ctx, Options{Name: name, NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if got := env(); got != "integration-dummy|kept|" {
		t.Errorf("env after reuse = %q", got)
	}

	none := NoSecrets()
	if _, err := m.Ensure(ctx, Options{Name: name, Secrets: &none, NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if got := env(); got != "||" {
		t.Errorf("env with no secrets = %q", got)
	}
	s, err := m.Get(ctx, name)
	if err != nil || !s.Secrets.Equal(NoSecrets()) {
		t.Errorf("session = %+v, %v", s, err)
	}
}
