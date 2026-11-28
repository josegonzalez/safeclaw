//go:build integration

package session

import (
	"context"
	"fmt"
	"math/rand/v2"
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
)

// itestNetwork returns a session network name of the test's own, removed
// once the test's containers are, so tests leave the host's safeclaw
// network alone. Call it before registering container cleanups, which run
// first.
func itestNetwork(t *testing.T) string {
	t.Helper()
	name := fmt.Sprintf("safeclaw-itest-%d", rand.IntN(1_000_000))
	t.Cleanup(func() { _ = exec.Command("docker", "network", "rm", name).Run() })
	return name
}

// dockerOut runs the docker CLI and returns its trimmed stdout.
func dockerOut(args ...string) (string, error) {
	out, err := exec.Command("docker", args...).Output()
	return strings.TrimSpace(string(out)), err
}

// containerIP returns a container's IPv4 address on a network.
func containerIP(t *testing.T, container, network string) string {
	t.Helper()
	ip, err := dockerOut("container", "inspect", "-f", `{{(index .NetworkSettings.Networks "`+network+`").IPAddress}}`, container)
	if err != nil || ip == "" {
		t.Fatalf("address of %s on %s = %q, %v", container, network, ip, err)
	}
	return ip
}

// waitLocal waits for a server in a container to answer on its own
// loopback.
func waitLocal(t *testing.T, container string, port int) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err := dockerOut("exec", container, "curl", "-sf", "-m", "2", "-o", "/dev/null", fmt.Sprintf("http://127.0.0.1:%d/", port)); err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("server in %s did not answer on port %d", container, port)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// iccEnforced reports whether the docker runtime blocks traffic between two
// containers on a bridge created with enable_icc=false. OrbStack, and
// docker with `iptables: false`, create the network but let the traffic
// through.
func iccEnforced(t *testing.T) bool {
	t.Helper()
	n := rand.IntN(1_000_000)
	network := fmt.Sprintf("safeclaw-itest-icc-%d", n)
	server := fmt.Sprintf("safeclaw-itest-icc-server-%d", n)
	if _, err := dockerOut("network", "create", "--opt", config.BridgeICCOption+"=false", network); err != nil {
		t.Fatalf("create control network: %v", err)
	}
	t.Cleanup(func() {
		_ = exec.Command("docker", "rm", "-f", server).Run()
		_ = exec.Command("docker", "network", "rm", network).Run()
	})
	harden := []string{"--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", config.SessionUser}
	run := append(append([]string{"run", "-d", "--name", server, "--network", network}, harden...), "--entrypoint", "python3", config.ImageName, "-m", "http.server", "8000")
	if _, err := dockerOut(run...); err != nil {
		t.Fatalf("run control server: %v", err)
	}
	waitLocal(t, server, 8000)
	ip := containerIP(t, server, network)
	probe := append(append([]string{"run", "--rm", "--network", network}, harden...), "--entrypoint", "curl", config.ImageName, "-sf", "-m", "3", "-o", "/dev/null", "http://"+ip+":8000/")
	_, err := dockerOut(probe...)
	return err != nil
}

// TestIntegrationSessionIsolation starts two sessions and checks they are on
// the session network, created with traffic between them off, and, where
// the runtime enforces that, that one can't reach a service the other runs
// or its ttyd.
func TestIntegrationSessionIsolation(t *testing.T) {
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
	n := rand.IntN(1_000_000)
	a, b := fmt.Sprintf("itest-iso-a-%d", n), fmt.Sprintf("itest-iso-b-%d", n)
	for _, name := range []string{a, b} {
		t.Cleanup(func() { _ = d.Remove(ctx, config.ContainerName(name), true) })
		res, err := m.Ensure(ctx, Options{Name: name, NoOpen: true})
		if err != nil {
			t.Fatal(err)
		}
		// Its terminal is still published from the session network.
		waitHTTP(t, res.URL)
		c, err := d.InspectOne(ctx, res.Container)
		if err != nil || c == nil || c.HostConfig.NetworkMode != m.Network || !slices.Equal(attached(*c), []string{m.Network}) {
			t.Fatalf("%s network = %+v, %v", name, c, err)
		}
	}
	nw, err := d.NetworkInspect(ctx, m.Network)
	if err != nil || nw == nil || checkSessionNetwork(nw) != nil {
		t.Fatalf("session network = %+v, %v", nw, err)
	}

	if !iccEnforced(t) {
		t.Skip("this docker runtime lets traffic through a bridge with enable_icc=false (OrbStack, or iptables off), so isolation can't be checked here")
	}

	ca, cb := config.ContainerName(a), config.ContainerName(b)
	if _, err := d.Exec(ctx, ca, docker.ExecOptions{Detach: true, User: config.SessionUser}, "python3", "-m", "http.server", "8000"); err != nil {
		t.Fatal(err)
	}
	waitLocal(t, ca, 8000)
	ip := containerIP(t, ca, m.Network)
	for _, port := range []int{8000, config.TTYDPort} {
		url := fmt.Sprintf("http://%s:%d/", ip, port)
		if out, err := d.Exec(ctx, cb, docker.ExecOptions{User: config.SessionUser}, "curl", "-s", "-m", "3", "-o", "/dev/null", "-w", "%{http_code}", url); err == nil {
			t.Errorf("second session reached %s in the first: %s", url, out)
		}
	}
}
