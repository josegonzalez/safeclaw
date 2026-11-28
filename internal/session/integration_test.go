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
	"strconv"
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
	imageID, err := d.ImageID(ctx, config.ImageName)
	if err != nil || imageID == "" {
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
		Network:     itestNetwork(t),
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
	} else if !hardened(*c) {
		t.Errorf("session keeps its capabilities: %v %v", c.HostConfig.CapDrop, c.HostConfig.SecurityOpt)
	} else if c.Config.User != config.SessionUser || c.Image != imageID || c.Label(config.LabelImage) != config.ImageName {
		t.Errorf("session runs as %q from %q (%q), want %s from %s (%s)", c.Config.User, c.Image, c.Label(config.LabelImage), config.SessionUser, imageID, config.ImageName)
	}
	// Its processes have no capabilities and can't gain privileges, and its
	// private history directory is still writable from inside.
	out, err := d.Exec(ctx, res.Container, docker.ExecOptions{}, "sh", "-c", `grep -E '^(CapBnd|NoNewPrivs)' /proc/self/status && touch `+config.ProjectsMount+`/.itest && rm `+config.ProjectsMount+`/.itest`)
	if err != nil || !strings.Contains(string(out), "CapBnd:\t0000000000000000") || !strings.Contains(string(out), "NoNewPrivs:\t1") {
		t.Errorf("session privileges = %q, %v", out, err)
	}
	if info, err := os.Stat(filepath.Join(m.SessionsDir, name)); err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("history dir: %v, %v", info, err)
	}
	// Without the credential, ttyd refuses the request, and nothing
	// answers on the dashboard cookie's host. Every response, the refusal,
	// the logged-in page and a missing one alike, refuses to be framed.
	for url, code := range map[string]int{URLFor(res.Port): http.StatusUnauthorized, res.URL: http.StatusOK, res.URL + "/token": http.StatusOK, res.URL + "/missing": http.StatusNotFound} {
		resp, err := http.Get(url)
		if err != nil {
			t.Errorf("GET ttyd: %v", err)
			continue
		}
		_ = resp.Body.Close()
		xfo, csp := resp.Header.Values("X-Frame-Options"), resp.Header.Values("Content-Security-Policy")
		if resp.StatusCode != code || len(xfo) != 1 || xfo[0] != "DENY" || len(csp) != 1 || csp[0] != "frame-ancestors 'none'" {
			t.Errorf("GET %s = %d, X-Frame-Options %q, Content-Security-Policy %q; want %d, DENY, frame-ancestors 'none'", resp.Request.URL.Redacted(), resp.StatusCode, xfo, csp, code)
		}
	}
	if resp, err := http.Get(fmt.Sprintf("http://127.0.0.1:%d/", res.Port)); err == nil {
		_ = resp.Body.Close()
		t.Errorf("session terminal answered on 127.0.0.1: %d", resp.StatusCode)
	}
	// ttyd reads the credential from its file, so it is not in ttyd's
	// command line, which every local user can read.
	cred, err := m.Credential(name)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := d.Exec(ctx, res.Container, docker.ExecOptions{}, "sh", "-c", `tr '\0' ' ' < /proc/$(pgrep -o -x ttyd)/cmdline`); err != nil || !strings.Contains(string(out), "--credential-file") || strings.Contains(string(out), cred.Password) {
		t.Errorf("ttyd command line = %q, %v; want --credential-file and no credential", out, err)
	}
	// ttyd and the tmux server Claude Code runs in have umask 022,
	// whatever umask docker exec gives them.
	if _, err := d.Exec(ctx, res.Container, docker.ExecOptions{}, "safeclaw", "ttyd-wrapper", "--no-attach"); err != nil {
		t.Fatal(err)
	}
	for _, proc := range []string{"ttyd", "tmux -f /dev/null new"} {
		out, err := d.Exec(ctx, res.Container, docker.ExecOptions{}, "sh", "-c", `grep Umask /proc/$(pgrep -o -f "^$1")/status`, "sh", proc)
		if err != nil || !strings.Contains(string(out), "0022") {
			t.Errorf("%s umask = %q, %v, want 0022", proc, out, err)
		}
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
	// The restart rotated the credential, so one that an open tab may have
	// sent to whatever held the released port no longer opens the terminal.
	if res2.URL == res.URL {
		t.Errorf("restart kept the credential")
	}
	if resp, err := http.Get(res.URL); err != nil {
		t.Errorf("GET with the credential from before the stop: %v", err)
	} else {
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET with the credential from before the stop = %d, want 401", resp.StatusCode)
		}
	}

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
	// The comma has to be quoted in the --mount value.
	in := filepath.Join(dir, "in, box")
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

	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: name, Volumes: []string{in + ":/in"}, Variant: config.BaseVariant, Disk: "8m"}); err != nil {
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

	// /sandbox is a tmpfs of --disk bytes owned by the sandbox user, with
	// no docker volume behind it.
	if out, err := run("stat", "-f", "-c", "%T", "/sandbox"); err != nil || out != "tmpfs" {
		t.Errorf("/sandbox filesystem = %q, %v", out, err)
	}
	if out, err := run("stat", "-c", "%U %a", "/sandbox"); err != nil || out != config.SandboxUser+" 700" {
		t.Errorf("/sandbox owner and mode = %q, %v", out, err)
	}
	if len(c.Mounts) != 1 || c.Mounts[0].Destination != "/in" {
		t.Errorf("mounts = %+v, want only the -v bind mount", c.Mounts)
	}
	// Writes within the size work, and writes past it fail.
	if _, err := run("dd", "if=/dev/zero", "of=/sandbox/small", "bs=1M", "count=4"); err != nil {
		t.Errorf("write within --disk: %v", err)
	}
	if _, err := run("dd", "if=/dev/zero", "of=/sandbox/big", "bs=1M", "count=16"); err == nil {
		t.Error("write past --disk succeeded")
	}
	if out, err := run("sh", "-c", "rm /sandbox/big && printf x > /sandbox/kept && cat /sandbox/kept"); err != nil || out != "x" {
		t.Errorf("write after freeing space = %q, %v", out, err)
	}

	// Stopping the sandbox empties /sandbox, and starting it again keeps
	// its size.
	if err := m.Stop(ctx, name); err != nil {
		t.Fatal(err)
	}
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: name}); err != nil {
		t.Fatal(err)
	}
	if out, err := run("ls", "-A", "/sandbox"); err != nil || out != "" {
		t.Errorf("/sandbox after a restart = %q, %v", out, err)
	}
	if out, err := run("df", "-k", "--output=size", "/sandbox"); err != nil || !strings.HasSuffix(out, "8192") {
		t.Errorf("/sandbox size after a restart = %q, %v", out, err)
	}

	// A real sandbox passes every verify check, and inspect reports its
	// --disk.
	info, err := m.InspectSandbox(ctx, name)
	if err != nil || info.Limits.DiskBytes != 8<<20 || !info.Running || len(info.Mounts) != 1 || !info.Mounts[0].RecursiveReadOnly {
		t.Errorf("inspect = %+v, %v", info, err)
	}
	report, err := m.VerifySandbox(ctx, name)
	if err != nil || !report.OK {
		t.Errorf("verify = %+v, %v", report, err)
	}

	if err := m.Delete(ctx, name, true); err != nil {
		t.Fatal(err)
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
// `sandbox run --rm` is removed when it stops.
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

	if err := m.Stop(ctx, res.Name); err != nil {
		t.Fatal(err)
	}
	waitGone(t, d, res.Container)
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
		argv, name, err := m.PrepareEphemeral(ctx, opts, ExecOptions{Interactive: stdin != ""}, cmd)
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
	if out, err := run(SandboxOptions{Name: name, Volumes: []string{in + ":/in"}}, "", "cat", "/in/doc.txt"); err != nil || out != "untrusted" {
		t.Errorf("mounted file = %q, %v", out, err)
	}
	if _, err := run(SandboxOptions{Volumes: []string{in + ":/in"}}, "", "touch", "/in/x"); err == nil {
		t.Error("the volume should be read-only")
	}
	_, err := run(SandboxOptions{}, "", "sh", "-c", "exit 3")
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 3 {
		t.Errorf("exit code: err = %v, want exit status 3", err)
	}

	// Several read-only mounts.
	if out, err := run(SandboxOptions{Volumes: []string{in + ":/in", in + ":/opt/in"}}, "", "sh", "-c", "cat /in/doc.txt /opt/in/doc.txt; touch /opt/in/x || echo ro"); err != nil || out != "untrusted\nuntrusted\nro" {
		t.Errorf("two mounts = %q, %v", out, err)
	}

	// The command's environment comes from an env file on an inherited
	// fd, and a timeout ends it with coreutils timeout's 124.
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(wr, "PASSWORD=p a ss\n"); err != nil {
		t.Fatal(err)
	}
	_ = wr.Close()
	defer rd.Close()
	argv, ename, err := m.PrepareEphemeral(ctx, SandboxOptions{Variant: config.BaseVariant}, ExecOptions{EnvFile: "/dev/fd/3", Timeout: time.Second}, []string{"sh", "-c", `echo "$PASSWORD"; sleep 30`})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Remove(ctx, config.ContainerName(ename), true) })
	c := exec.Command(argv[0], argv[1:]...)
	c.ExtraFiles = []*os.File{rd}
	start := time.Now()
	out, err := c.Output()
	if !errors.As(err, &exit) || exit.ExitCode() != 124 || strings.TrimSpace(string(out)) != "p a ss" {
		t.Errorf("timed out command: out = %q, err = %v, want the password and exit 124", out, err)
	}
	if took := time.Since(start); took > 20*time.Second {
		t.Errorf("timeout took %s", took)
	}
	waitGone(t, d, config.ContainerName(ename))
}

// TestIntegrationSandboxVariant checks that the built-in sandbox variant has
// the document extraction tools, that sandboxes use it by default, and that
// it keeps the sandbox isolation.
func TestIntegrationSandboxVariant(t *testing.T) {
	d := docker.New()
	ctx := context.Background()
	sandboxID, err := d.ImageID(ctx, variant.Image(variant.Sandbox))
	if err != nil || sandboxID == "" {
		t.Skip("sandbox variant not built; run `safeclaw build --variant sandbox` first")
	}
	m := &Manager{Docker: d}
	run := func(cmd ...string) (string, error) {
		t.Helper()
		argv, name, err := m.PrepareEphemeral(ctx, SandboxOptions{}, ExecOptions{}, cmd)
		if err != nil {
			t.Fatal(err)
		}
		// It runs the checked image's ID, and records the tag.
		if !slices.Contains(argv, sandboxID) || !slices.Contains(argv, config.LabelImage+"="+variant.Image(variant.Sandbox)) {
			t.Errorf("argv does not use the sandbox variant's ID %s: %v", sandboxID, argv)
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
	for k, v := range map[string]string{secrets.ClaudeToken: "integration-dummy", "KEPT": "kept", secrets.GitHubToken: "integration-gh", "LEFT_OUT": "left-out"} {
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
		Network:     itestNetwork(t),
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

	set, err := OnlySecrets(secrets.ClaudeToken, "KEPT", secrets.GitHubToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Ensure(ctx, Options{Name: name, Secrets: &set, NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if got := env(); got != "integration-dummy|kept|" {
		t.Errorf("env = %q", got)
	}

	// The env file and git config are root-owned, and sclaw can't change or
	// replace them. Interactive shells, which don't read BASH_ENV, still get
	// the env through .bashrc.
	for _, c := range []struct{ script, want string }{
		{"stat -c '%U:%G %a' " + config.EnvFile, "root:sclaw 640"},
		{"stat -c '%U:%G %a' /etc/gitconfig ~/.gitconfig ~/.config/git", "root:root 644\nroot:root 644\nroot:root 755"},
		{"bash -ic 'echo $KEPT' 2>/dev/null", "kept"},
		{"echo 'export CLAUDE_CONFIG_DIR=/tmp' >> " + config.EnvFile + " 2>/dev/null || echo refused", "refused"},
		{"git config --global core.pager evil 2>/dev/null || echo refused", "refused"},
		{"touch ~/.config/git/config 2>/dev/null || echo refused", "refused"},
		{"mv ~/.gitconfig ~/.gitconfig.old 2>/dev/null || mv ~/.config/git ~/.config/old 2>/dev/null || echo refused", "refused"},
		{"git init -q /tmp/repo && git -C /tmp/repo config user.name local && git -C /tmp/repo config user.name", "local"},
		// With GH_TOKEN, git gets it for github.com through gh, from the
		// system config. Nothing is pushed.
		{"git config --show-origin --get credential.https://github.com.helper", "file:/etc/gitconfig\t!/usr/bin/gh auth git-credential"},
		{"printf 'protocol=https\\nhost=github.com\\n\\n' | GIT_TERMINAL_PROMPT=0 git credential fill | grep '^password='", "password=integration-gh"},
	} {
		// bash, so the env file is sourced through BASH_ENV.
		out, err := d.Exec(ctx, container, docker.ExecOptions{}, "bash", "-c", c.script)
		if got := strings.TrimSpace(string(out)); err != nil || got != c.want {
			t.Errorf("%s = %q, %v; want %q", c.script, got, err, c.want)
		}
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

// TestIntegrationMemory turns a real session's auto memory off and back on,
// and checks that the managed settings file holding the choice is
// root-owned and that sclaw can't change, replace, or add to it.
func TestIntegrationMemory(t *testing.T) {
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
		OpenBrowser: func(string) error { return nil },
		Network:     itestNetwork(t),
	}
	name := fmt.Sprintf("itest-memory-%d", rand.IntN(1_000_000))
	container := config.ContainerName(name)
	t.Cleanup(func() { _ = d.Remove(ctx, container, true) })

	none := NoSecrets()
	settings := func() string {
		t.Helper()
		out, err := d.Exec(ctx, container, docker.ExecOptions{}, "cat", config.SessionSettingsFile)
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(out))
	}

	if _, err := m.Ensure(ctx, Options{Name: name, Secrets: &none, NoMemory: boolPtr(true), NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if got := settings(); !strings.Contains(got, `"autoMemoryEnabled": false`) || !strings.Contains(got, `"CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1"`) {
		t.Errorf("off settings = %q", got)
	}
	for _, c := range []struct{ script, want string }{
		{"stat -c '%U:%G %a' " + config.ManagedSettingsDir + " " + config.SessionSettingsFile, "root:root 755\nroot:root 644"},
		{"echo '{}' > " + config.SessionSettingsFile + " 2>/dev/null || echo refused", "refused"},
		{"mv " + config.SessionSettingsFile + " /tmp/s.json 2>/dev/null || echo refused", "refused"},
		{"echo '{}' > " + config.ManagedSettingsDir + "/zz.json 2>/dev/null || echo refused", "refused"},
	} {
		out, err := d.Exec(ctx, container, docker.ExecOptions{}, "bash", "-c", c.script)
		if got := strings.TrimSpace(string(out)); err != nil || got != c.want {
			t.Errorf("%s = %q, %v; want %q", c.script, got, err, c.want)
		}
	}

	// Reusing the session keeps it off; turning it back on recreates it.
	if _, err := m.Ensure(ctx, Options{Name: name, NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if got := settings(); !strings.Contains(got, `"autoMemoryEnabled": false`) {
		t.Errorf("settings after reuse = %q", got)
	}
	// So does running it again after `safeclaw rm`.
	if err := m.Delete(ctx, name, true); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Ensure(ctx, Options{Name: name, NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if got := settings(); !strings.Contains(got, `"autoMemoryEnabled": false`) {
		t.Errorf("settings after rm and run = %q", got)
	}
	if c, err := d.InspectOne(ctx, container); err != nil || c == nil || !noMemoryOf(*c) || !secretsOf(*c).Equal(none) {
		t.Errorf("container after rm and run = %+v, %v", c, err)
	}
	if _, err := m.Ensure(ctx, Options{Name: name, NoMemory: boolPtr(false), NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if got := settings(); got != "{}" {
		t.Errorf("on settings = %q", got)
	}
	if c, err := d.InspectOne(ctx, container); err != nil || c == nil || noMemoryOf(*c) {
		t.Errorf("container after turning memory on = %+v, %v", c, err)
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
		Network:     itestNetwork(t),
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
	before := res.URL
	if res, err = m.Ensure(ctx, Options{Name: name, NoOpen: true}); err != nil || !res.Offline {
		t.Fatalf("restart = %+v, %v", res, err)
	}
	offline("after restart")

	if _, err := m.Terminal(ctx, name); !errors.Is(err, ErrNoTerminal) {
		t.Errorf("terminal while offline: err = %v, want ErrNoTerminal", err)
	}
	if err := m.Delete(ctx, name, true); !errors.Is(err, ErrHeld) || !strings.Contains(err.Error(), "by itest") {
		t.Errorf("rm while held: err = %v, want ErrHeld naming itest", err)
	}
	if c, err := d.InspectOne(ctx, container); err != nil || c == nil {
		t.Fatalf("held session removed: %v", err)
	}

	if _, err := m.NetOn(ctx, name, NetOnOptions{}); !errors.Is(err, ErrHeld) {
		t.Errorf("unnamed net on err = %v, want ErrHeld", err)
	}
	on, err := m.NetOn(ctx, name, NetOnOptions{Owner: "itest"})
	if err != nil || on.Offline {
		t.Fatalf("net on = %+v, %v", on, err)
	}
	waitHTTP(t, res.URL)
	// The restart rotated the credential.
	if resp, err := http.Get(before); err != nil {
		t.Errorf("GET with the credential from before the restart: %v", err)
	} else {
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET with the credential from before the restart = %d, want 401", resp.StatusCode)
		}
	}
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
	// The directories cp-in creates get umask 022, whatever umask docker
	// exec gives it.
	for _, p := range []string{"/sandbox/in", "/sandbox/jobs", "/sandbox/jobs/1"} {
		if out, err := run("stat", "-c", "%u:%g %a", p); err != nil || out != "2000:2000 755" {
			t.Errorf("%s owner and mode = %q, %v", p, out, err)
		}
	}
	if out, err := run("stat", "-c", "%a", "/sandbox/jobs/1/1-report.txt"); err != nil || out != "644" {
		t.Errorf("--to file mode = %q, %v", out, err)
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
	args := append([]string{"-d", "--label", config.LabelAuth + "=integration"}, hardenArgs...)
	id, err := d.Run(ctx, append(args, config.ImageName, "sleep", "infinity")...)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Remove(context.Background(), id, true) })

	if out, err := d.Exec(ctx, id, docker.ExecOptions{}, "bash", "-c", "command -v claude script"); err != nil || strings.Count(string(out), "\n") != 2 {
		t.Fatalf("image lacks claude or script: %q, %v", out, err)
	}
	// Claude Code starts without capabilities, under script's pty, the
	// way the sign-in runs it.
	if out, err := d.Exec(ctx, id, docker.ExecOptions{Stdin: strings.NewReader("")}, "script", "-qec", "claude --version", "/dev/null"); err != nil || !strings.Contains(string(out), "Claude Code") {
		t.Errorf("claude --version under script: %q, %v", out, err)
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

// TestIntegrationTTYDCredentialNotInArgv starts the image's ttyd the way
// startTTYD does, in a throwaway container with no network and a dummy
// credential, and checks that neither ps nor /proc/PID/cmdline shows the
// credential, that ttyd doesn't log it, and that basic auth still works.
func TestIntegrationTTYDCredentialNotInArgv(t *testing.T) {
	d := docker.New()
	ctx := context.Background()
	if id, err := d.ImageID(ctx, config.ImageName); err != nil || id == "" {
		t.Skip("safeclaw image not built; run `safeclaw build` first")
	}
	id, err := d.Run(ctx, "-d", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", config.ImageName, "sleep", "infinity")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Remove(context.Background(), id, true) })

	cred := Credential{User: config.TTYDUser, Password: "integration-dummy-password"}
	if _, err := d.Exec(ctx, id, docker.ExecOptions{Stdin: strings.NewReader(cred.String())}, "sh", "-c", writeCredentialScript); err != nil {
		t.Fatal(err)
	}
	const log = "/tmp/ttyd-itest.log"
	if _, err := d.Exec(ctx, id, docker.ExecOptions{Detach: true}, "sh", "-c", startTTYDScript+" 2>"+log, "ttyd", "-W", "-O", "-p", strconv.Itoa(config.TTYDPort), "sleep", "infinity"); err != nil {
		t.Fatal(err)
	}
	status := func(auth bool) string {
		u := ""
		if auth {
			u = `-u "$(cat ` + config.TTYDCredentialFile + `)"`
		}
		script := `for i in $(seq 50); do c=$(curl -s -o /dev/null -w '%{http_code}' ` + u + ` http://127.0.0.1:` + strconv.Itoa(config.TTYDPort) + `/); [ "$c" != 000 ] && break; sleep 0.2; done; echo "$c"`
		out, err := d.Exec(ctx, id, docker.ExecOptions{}, "sh", "-c", script)
		if err != nil {
			t.Errorf("curl: %v", err)
		}
		return strings.TrimSpace(string(out))
	}
	if got := status(false); got != "401" {
		t.Errorf("GET without the credential = %s, want 401", got)
	}
	if got := status(true); got != "200" {
		t.Errorf("GET with the credential = %s, want 200", got)
	}

	out, err := d.Exec(ctx, id, docker.ExecOptions{}, "sh", "-c", `pid=$(pgrep -o -x ttyd) && ps -o args= -p "$pid" && tr '\0' ' ' < /proc/$pid/cmdline && echo && cat `+log)
	if err != nil {
		t.Fatalf("read ttyd's command line: %q, %v", out, err)
	}
	if !strings.Contains(string(out), "ttyd --credential-file "+config.TTYDCredentialFile) {
		t.Errorf("ttyd not started with --credential-file: %q", out)
	}
	for _, secret := range []string{cred.Password, cred.Token()} {
		if strings.Contains(string(out), secret) {
			t.Errorf("ttyd's command line or log shows the credential: %q", out)
		}
	}
}

// TestIntegrationTTYDRestart checks stopTTYD and checkTTYDAnswers against
// the image's ttyd in a throwaway container with no network: the running
// ttyd answers its own credential and refuses another, stopTTYD leaves no
// ttyd and nothing on its port, and a new ttyd then takes the port.
func TestIntegrationTTYDRestart(t *testing.T) {
	d := docker.New()
	ctx := context.Background()
	if id, err := d.ImageID(ctx, config.ImageName); err != nil || id == "" {
		t.Skip("safeclaw image not built; run `safeclaw build` first")
	}
	id, err := d.Run(ctx, "-d", "--network", "none", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", config.ImageName, "sleep", "infinity")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = d.Remove(context.Background(), id, true) })
	m := &Manager{Docker: d}

	start := func(c Credential) {
		t.Helper()
		if _, err := d.Exec(ctx, id, docker.ExecOptions{Stdin: strings.NewReader(c.String())}, "sh", "-c", writeCredentialScript); err != nil {
			t.Fatal(err)
		}
		if _, err := d.Exec(ctx, id, docker.ExecOptions{Detach: true}, "sh", "-c", startTTYDScript, "ttyd", "-W", "-O", "-p", strconv.Itoa(config.TTYDPort), "sleep", "infinity"); err != nil {
			t.Fatal(err)
		}
	}
	old := Credential{User: config.TTYDUser, Password: "integration-old"}
	other := Credential{User: config.TTYDUser, Password: "integration-new"}

	// Nothing to stop yet.
	if err := m.stopTTYD(ctx, "itest", id); err != nil {
		t.Fatalf("stop with no ttyd: %v", err)
	}
	start(old)
	if err := m.checkTTYDAnswers(ctx, "itest", id, old); err != nil {
		t.Fatalf("ttyd refused its own credential: %v", err)
	}
	if err := m.checkTTYDAnswers(ctx, "itest", id, other); !errors.Is(err, ErrTTYDRestart) || !strings.Contains(err.Error(), "refused the new credential") {
		t.Fatalf("ttyd with another credential = %v", err)
	}
	if out, err := d.Exec(ctx, id, docker.ExecOptions{}, "sh", "-c", ttydGoneScript); err != nil || !strings.Contains(string(out), "still running") {
		t.Fatalf("running ttyd reported as %q, %v", out, err)
	}

	if err := m.stopTTYD(ctx, "itest", id); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if out, err := d.Exec(ctx, id, docker.ExecOptions{}, "sh", "-c", ttydGoneScript); err != nil || len(out) != 0 {
		t.Fatalf("stopped ttyd reported as %q, %v", out, err)
	}
	start(other)
	if err := m.checkTTYDAnswers(ctx, "itest", id, other); err != nil {
		t.Fatalf("new ttyd: %v", err)
	}

	// Something else holding the port counts as not gone, even with no
	// ttyd process. SO_REUSEADDR lets it bind past the checks' connections
	// in TIME_WAIT, as ttyd's own listener does.
	if err := m.stopTTYD(ctx, "itest", id); err != nil {
		t.Fatalf("stop: %v", err)
	}
	if _, err := d.Exec(ctx, id, docker.ExecOptions{Detach: true}, "python3", "-c", "import socket,time;s=socket.socket(socket.AF_INET6);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('::',"+strconv.Itoa(config.TTYDPort)+"));s.listen();time.sleep(600)"); err != nil {
		t.Fatal(err)
	}
	var out []byte
	for range 50 {
		if out, err = d.Exec(ctx, id, docker.ExecOptions{}, "sh", "-c", ttydGoneScript); err != nil || len(out) != 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil || !strings.Contains(string(out), "listens on port") {
		t.Fatalf("held port reported as %q, %v", out, err)
	}
}
