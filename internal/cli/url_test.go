package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
	"github.com/josegonzalez/safeclaw/internal/session"
)

// urlContainers answers `docker container inspect` for a few sessions.
func urlContainers(args []string, _ string) ([]byte, error) {
	if len(args) < 3 || args[0] != "container" || args[1] != "inspect" {
		return nil, nil
	}
	bindings := map[string]any{"7681/tcp": []map[string]string{{"HostIp": "::1", "HostPort": "7685"}}}
	state := func(running bool) map[string]any {
		status := "exited"
		if running {
			status = "running"
		}
		return map[string]any{"Status": status, "Running": running}
	}
	var c map[string]any
	switch args[2] {
	case "safeclaw-work":
		c = map[string]any{"State": state(true), "Config": map[string]any{"Labels": map[string]string{config.LabelBracketedHostTTYD: "1"}}, "HostConfig": map[string]any{"PortBindings": bindings, "NetworkMode": "bridge"},
			"NetworkSettings": map[string]any{"Networks": map[string]any{"bridge": map[string]any{}}}}
	case "safeclaw-oldttyd":
		// Published on [::1] from an image whose ttyd refuses [::1] URLs.
		c = map[string]any{"State": state(true), "HostConfig": map[string]any{"PortBindings": bindings, "NetworkMode": "bridge"},
			"NetworkSettings": map[string]any{"Networks": map[string]any{"bridge": map[string]any{}}}}
	case "safeclaw-stopped":
		c = map[string]any{"State": state(false), "HostConfig": map[string]any{"PortBindings": bindings, "NetworkMode": "bridge"}}
	case "safeclaw-box":
		c = map[string]any{"State": state(true), "Config": map[string]any{"Labels": map[string]string{"safeclaw.type": "sandbox"}},
			"HostConfig": map[string]any{"NetworkMode": "none"}}
	default:
		return nil, dockertest.NotFound(args)
	}
	c["Name"] = "/" + args[2]
	return json.Marshal([]any{c})
}

func TestURLCommand(t *testing.T) {
	r := &dockertest.Runner{Handler: urlContainers}
	dir := t.TempDir()
	ttyd := filepath.Join(dir, "ttyd")
	if err := os.MkdirAll(ttyd, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ttyd, "work"), []byte("safeclaw:pw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var opened []string
	orig := newManager
	t.Cleanup(func() { newManager = orig })
	newManager = func() *session.Manager {
		return &session.Manager{
			Docker:       r.Client(),
			TTYDDir:      ttyd,
			DashboardDir: filepath.Join(dir, "dashboard"),
			OpenBrowser:  func(u string) error { opened = append(opened, u); return nil },
		}
	}

	out, err := run(t, NewRootCommand(), "url", "work")
	if err != nil || out != "http://safeclaw:pw@[::1]:7685\n" {
		t.Errorf("url work = %q, %v", out, err)
	}
	if len(opened) != 0 {
		t.Errorf("opened %q without --open", opened)
	}
	for _, c := range r.Commands() {
		if !strings.HasPrefix(c, "container inspect ") && !strings.HasPrefix(c, "ps ") {
			t.Errorf("url touched the session: %q", c)
		}
	}

	out, err = run(t, NewRootCommand(), "url", "work", "--open")
	if err != nil || out != "http://safeclaw:pw@[::1]:7685\n" || !slices.Equal(opened, []string{"http://safeclaw:pw@[::1]:7685"}) {
		t.Errorf("url work --open = %q, %v, opened %q", out, err, opened)
	}

	for name, why := range map[string]string{
		"stopped": "it is stopped",
		"box":     "it is a sandbox",
		"missing": "it does not exist",
	} {
		out, err := run(t, NewRootCommand(), "url", name)
		if !errors.Is(err, session.ErrNoTerminal) || !strings.Contains(err.Error(), why) || out != "" {
			t.Errorf("url %s = %q, %v, want an error saying %q", name, out, err, why)
		}
	}
	// A session whose ttyd refuses [::1] URLs gets no localhost URL, which
	// a browser could send to another local user's listener on 127.0.0.1.
	if err := os.WriteFile(filepath.Join(ttyd, "oldttyd"), []byte("safeclaw:pw\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	opened = nil
	out, err = run(t, NewRootCommand(), "url", "oldttyd", "--open")
	if !errors.Is(err, session.ErrOldTTYD) || out != "" || len(opened) != 0 {
		t.Errorf("url oldttyd --open = %q, %v, opened %q", out, err, opened)
	}

	if _, err := run(t, NewRootCommand(), "url"); err == nil {
		t.Error("url accepted no name")
	}
}
