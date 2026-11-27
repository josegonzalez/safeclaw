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
	store := secrets.FileStore{Dir: filepath.Join(dir, ".secrets")}
	if err := store.Set(secrets.ClaudeToken, "integration-dummy"); err != nil {
		t.Fatal(err)
	}
	m := &Manager{
		Docker:      d,
		Secrets:     store,
		SessionsDir: filepath.Join(dir, "sessions"),
		TTYDDir:     filepath.Join(dir, "ttyd"),
		NetworkDir:  filepath.Join(dir, "network"),
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
	if c, err := d.InspectOne(ctx, res.Container); err != nil || c == nil || c.HostConfig.IpcMode == config.IPCHost {
		t.Errorf("session shares the host IPC namespace: %+v, %v", c, err)
	}
	// Without the credential, ttyd refuses the request, and nothing
	// answers on the dashboard cookie's host.
	if resp, err := http.Get(URLFor(res.Port)); err != nil || resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("ttyd without the credential: %v, %v", resp, err)
	} else {
		_ = resp.Body.Close()
	}
	if resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", res.Port)); err == nil {
		_ = resp.Body.Close()
		t.Errorf("session terminal answered on 127.0.0.1: %d", resp.StatusCode)
	}

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
		Secrets:     secrets.FileStore{Dir: filepath.Join(dir, ".secrets")},
		SessionsDir: filepath.Join(dir, "sessions"),
		TTYDDir:     filepath.Join(dir, "ttyd"),
		NetworkDir:  filepath.Join(dir, "network"),
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
		Secrets:     secrets.FileStore{Dir: filepath.Join(dir, ".secrets")},
		SessionsDir: filepath.Join(dir, "sessions"),
		TTYDDir:     filepath.Join(dir, "ttyd"),
		NetworkDir:  filepath.Join(dir, "network"),
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
	if out, err := run(SandboxOptions{}, "", "sh", "-c", "umask"); err != nil || out != "0022" {
		t.Errorf("umask = %q, %v", out, err)
	}
	if out, err := run(SandboxOptions{}, "", "printf", "[%s]", "", "-n", "--", "a b", "$HOME"); err != nil || out != "[][-n][--][a b][$HOME]" {
		t.Errorf("args = %q, %v", out, err)
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
	store := secrets.FileStore{Dir: filepath.Join(dir, ".secrets")}
	for k, v := range map[string]string{secrets.ClaudeToken: "integration-dummy", "KEPT": "kept", "LEFT_OUT": "left-out"} {
		if err := store.Set(k, v); err != nil {
			t.Fatal(err)
		}
	}
	m := &Manager{
		Docker:      d,
		Secrets:     store,
		SessionsDir: filepath.Join(dir, "sessions"),
		TTYDDir:     filepath.Join(dir, "ttyd"),
		NetworkDir:  filepath.Join(dir, "network"),
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

// TestIntegrationNetwork takes a real session offline, checks its web
// terminal is unreachable and that a restart keeps it offline, then brings
// it back and checks docker published its port again.
func TestIntegrationNetwork(t *testing.T) {
	d := docker.New()
	ctx := context.Background()
	if id, err := d.ImageID(ctx, config.ImageName); err != nil || id == "" {
		t.Skip("safeclaw image not built; run `safeclaw build` first")
	}
	dir := t.TempDir()
	store := secrets.FileStore{Dir: filepath.Join(dir, ".secrets")}
	if err := store.Set(secrets.ClaudeToken, "integration-dummy"); err != nil {
		t.Fatal(err)
	}
	m := &Manager{
		Docker:      d,
		Secrets:     store,
		SessionsDir: filepath.Join(dir, "sessions"),
		TTYDDir:     filepath.Join(dir, "ttyd"),
		NetworkDir:  filepath.Join(dir, "network"),
		Out:         os.Stdout,
		OpenBrowser: func(string) error { return nil },
	}
	name := fmt.Sprintf("itest-net-%d", rand.IntN(1_000_000))
	container := config.ContainerName(name)
	t.Cleanup(func() { _ = d.Remove(ctx, container, true) })

	res, err := m.Ensure(ctx, Options{Name: name, NoOpen: true})
	if err != nil {
		t.Fatal(err)
	}
	waitHTTP(t, res.URL)

	if _, err := m.NetOff(ctx, name, NetOffOptions{Owner: "itest"}); err != nil {
		t.Fatal(err)
	}
	offline := func(when string) {
		t.Helper()
		c, err := d.InspectOne(ctx, container)
		if err != nil || c == nil {
			t.Fatalf("%s: inspect: %v", when, err)
		}
		if !Offline(*c) {
			t.Errorf("%s: still attached to %v", when, attached(*c))
		}
		client := http.Client{Timeout: 2 * time.Second}
		if resp, err := client.Get(res.URL); err == nil {
			_ = resp.Body.Close()
			t.Errorf("%s: web terminal answered %d while offline", when, resp.StatusCode)
		}
	}
	offline("after net off")

	if err := m.Stop(ctx, name); err != nil {
		t.Fatal(err)
	}
	if res2, err := m.Ensure(ctx, Options{Name: name, NoOpen: true}); err != nil || !res2.Offline {
		t.Fatalf("restart = %+v, %v", res2, err)
	}
	offline("after restart")

	if _, err := m.NetOn(ctx, name, NetOnOptions{}); !errors.Is(err, ErrHeld) {
		t.Errorf("unnamed net on err = %v, want ErrHeld", err)
	}
	on, err := m.NetOn(ctx, name, NetOnOptions{Owner: "itest"})
	if err != nil || on.Offline {
		t.Fatalf("net on = %+v, %v", on, err)
	}
	waitHTTP(t, res.URL)
}

// TestIntegrationSandboxCopy checks cp-in and cp-out against a real
// sandbox: ownership, numbering, and what is refused or dropped each way.
func TestIntegrationSandboxCopy(t *testing.T) {
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
		CopyDir:     filepath.Join(dir, "copy"),
		Out:         os.Stdout,
	}
	name := fmt.Sprintf("itest-cp-%d", rand.IntN(1_000_000))
	container := config.ContainerName(name)
	t.Cleanup(func() { _ = d.Remove(ctx, container, true) })
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: name, Variant: config.BaseVariant}); err != nil {
		t.Fatal(err)
	}
	run := func(cmd ...string) (string, error) {
		out, err := d.Exec(ctx, container, copyExec, cmd...)
		return strings.TrimSpace(string(out)), err
	}

	// Two host files with the same name, one private to the host user.
	src := filepath.Join(dir, "src")
	for sub, body := range map[string]string{"a": "first", "b": "second"} {
		if err := os.MkdirAll(filepath.Join(src, sub), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(src, sub, "report.txt"), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	a, b := filepath.Join(src, "a", "report.txt"), filepath.Join(src, "b", "report.txt")
	link := filepath.Join(src, "link.txt")
	if err := os.Symlink(a, link); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CopyIn(ctx, name, []string{a, link}, ""); !errors.Is(err, ErrSymlink) {
		t.Errorf("symlink: err = %v, want ErrSymlink", err)
	}
	paths, err := m.CopyIn(ctx, name, []string{a, b}, "")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"/sandbox/in/1-report.txt", "/sandbox/in/2-report.txt"}; !slices.Equal(paths, want) {
		t.Errorf("paths = %v, want %v", paths, want)
	}
	if out, err := run("stat", "-c", "%u:%g %a", paths[0]); err != nil || out != "2000:2000 644" {
		t.Errorf("owner and mode = %q, %v", out, err)
	}
	if out, err := run("cat", paths[0], paths[1]); err != nil || out != "firstsecond" {
		t.Errorf("contents = %q, %v", out, err)
	}
	// A later copy continues the numbering, and --to picks the directory.
	if paths, err := m.CopyIn(ctx, name, []string{a}, ""); err != nil || !slices.Equal(paths, []string{"/sandbox/in/3-report.txt"}) {
		t.Errorf("second copy = %v, %v", paths, err)
	}
	if paths, err := m.CopyIn(ctx, name, []string{a}, "jobs/1"); err != nil || !slices.Equal(paths, []string{"/sandbox/jobs/1/1-report.txt"}) {
		t.Errorf("--to = %v, %v", paths, err)
	}

	// Results with a match, a non-match, a link out of the sandbox, a
	// directory, and a nested match.
	if _, err := run("sh", "-c", "mkdir -p out/sub out/dir.txt && printf hi > out/a.txt && printf no > out/b.log && "+
		"printf nested > out/sub/c.txt && ln -s /etc/passwd out/p.txt && chmod 4755 out/a.txt"); err != nil {
		t.Fatal(err)
	}
	host := filepath.Join(dir, "host")
	if err := os.Mkdir(host, 0o755); err != nil {
		t.Fatal(err)
	}
	opts := CopyOutOptions{Only: []string{"*.txt"}}
	got, err := m.CopyOut(ctx, name, "/sandbox/out", host, opts)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{filepath.Join(host, "a.txt")}; !slices.Equal(got, want) {
		t.Errorf("cp-out = %v, want %v", got, want)
	}
	entries, _ := os.ReadDir(host)
	if len(entries) != 1 {
		t.Errorf("host dir has %d entries, want 1", len(entries))
	}
	fi, err := os.Lstat(filepath.Join(host, "a.txt"))
	if err != nil || !fi.Mode().IsRegular() || fi.Mode()&0o7111 != 0 {
		t.Errorf("a.txt = %v, %v", fi, err)
	}
	if body, _ := os.ReadFile(filepath.Join(host, "a.txt")); string(body) != "hi" {
		t.Errorf("a.txt = %q", body)
	}

	// An existing name is refused without --force and replaced with it.
	if _, err := m.CopyOut(ctx, name, "/sandbox/out", host, opts); !errors.Is(err, ErrFileExists) {
		t.Errorf("clash: err = %v, want ErrFileExists", err)
	}
	opts.Force = true
	if _, err := m.CopyOut(ctx, name, "/sandbox/out", host, opts); err != nil {
		t.Errorf("--force: %v", err)
	}
	opts = CopyOutOptions{Only: []string{"*"}, MaxSize: 1}
	if _, err := m.CopyOut(ctx, name, "/sandbox/out", t.TempDir(), opts); !errors.Is(err, ErrTooLarge) {
		t.Errorf("--max-size: err = %v, want ErrTooLarge", err)
	}
	// The sandbox user can't read /home/sclaw, so neither can cp-out.
	if _, err := m.CopyOut(ctx, name, "/home/sclaw", t.TempDir(), CopyOutOptions{Only: []string{"*"}}); err == nil {
		t.Error("cp-out of /home/sclaw should fail")
	}

	// A stopped sandbox is refused.
	if err := m.Stop(ctx, name); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CopyIn(ctx, name, []string{a}, ""); !errors.Is(err, ErrNotRunning) {
		t.Errorf("stopped: err = %v, want ErrNotRunning", err)
	}
}

// TestIntegrationSetupTokenRecording checks that the image has what
// `safeclaw auth login` needs, and that a token printed under script, the
// way SetupToken records `claude setup-token`, is read back. The real
// sign-in needs a person, so a printed fake token stands in for it.
func TestIntegrationSetupTokenRecording(t *testing.T) {
	d := docker.New()
	ctx := context.Background()
	if id, err := d.ImageID(ctx, config.ImageName); err != nil || id == "" {
		t.Skip("safeclaw image not built; run `safeclaw build` first")
	}
	id, err := d.Run(ctx, "-d", "--label", config.LabelAuth+"=integration", config.ImageName, "sleep", "infinity")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Remove(context.Background(), id, true) })

	if out, err := d.Exec(ctx, id, docker.ExecOptions{}, "bash", "-c", "command -v claude script"); err != nil || strings.Count(string(out), "\n") != 2 {
		t.Fatalf("image lacks claude or script: %q, %v", out, err)
	}
	const tok = "sk-ant-oat01-integration_Test-0123456789"
	cmd := `printf '\033[1m%s\033[0m\n' ` + tok
	if _, err := d.Exec(ctx, id, docker.ExecOptions{Stdin: strings.NewReader("")}, "script", "-qec", cmd, setupTokenLog); err != nil {
		t.Fatal(err)
	}
	out, err := d.Exec(ctx, id, docker.ExecOptions{}, "cat", setupTokenLog)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseSetupToken(out)
	if err != nil || got != tok {
		t.Errorf("parsed %q, %v from %q", got, err, out)
	}
}
