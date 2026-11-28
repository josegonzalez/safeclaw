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

// currentTTYD is the labels of a container or image whose ttyd accepts [::1]
// URLs and reads its credential from a file.
var currentTTYD = map[string]string{config.LabelBracketedHostTTYD: "1", config.LabelCredentialFileTTYD: "1"}

// urlContainers answers `docker container inspect` for a few sessions, and
// `docker image inspect` for the base image with *imageLabels.
func urlContainers(imageLabels *map[string]string) func([]string, string) ([]byte, error) {
	return func(args []string, _ string) ([]byte, error) {
		if len(args) == 5 && args[0] == "image" && args[1] == "inspect" && args[4] == config.ImageName {
			return json.Marshal(map[string]any{"Id": "sha256:img", "Config": map[string]any{"Labels": *imageLabels}})
		}
		if len(args) < 3 || args[0] != "container" || args[1] != "inspect" {
			return nil, nil
		}
		return urlContainer(args[2])
	}
}

func urlContainer(name string) ([]byte, error) {
	bindings := map[string]any{"7681/tcp": []map[string]string{{"HostIp": "::1", "HostPort": "7685"}}}
	legacyBindings := map[string]any{"7681/tcp": []map[string]string{{"HostIp": "127.0.0.1", "HostPort": "7686"}}}
	networks := map[string]any{"Networks": map[string]any{"bridge": map[string]any{}}}
	state := func(running bool) map[string]any {
		status := "exited"
		if running {
			status = "running"
		}
		return map[string]any{"Status": status, "Running": running}
	}
	var c map[string]any
	switch name {
	case "safeclaw-work":
		c = map[string]any{"State": state(true), "Config": map[string]any{"Labels": currentTTYD}, "HostConfig": map[string]any{"PortBindings": bindings, "NetworkMode": "bridge"},
			"NetworkSettings": networks}
	case "safeclaw-oldttyd":
		// Published on [::1] from an image whose ttyd refuses [::1] URLs.
		c = map[string]any{"State": state(true), "HostConfig": map[string]any{"PortBindings": bindings, "NetworkMode": "bridge"},
			"NetworkSettings": networks}
	case "safeclaw-legacy":
		// Created before terminals moved to [::1], from an image whose ttyd
		// refuses [::1] URLs but reads its credential from a file.
		c = map[string]any{"State": state(true), "Config": map[string]any{"Labels": map[string]string{config.LabelCredentialFileTTYD: "1"}}, "HostConfig": map[string]any{"PortBindings": legacyBindings, "NetworkMode": "bridge"},
			"NetworkSettings": networks}
	case "safeclaw-argv":
		// Created before terminals moved to [::1], from an image whose ttyd
		// takes its credential on its command line.
		c = map[string]any{"State": state(true), "HostConfig": map[string]any{"PortBindings": legacyBindings, "NetworkMode": "bridge"},
			"NetworkSettings": networks}
	case "safeclaw-stopped":
		c = map[string]any{"State": state(false), "HostConfig": map[string]any{"PortBindings": bindings, "NetworkMode": "bridge"}}
	case "safeclaw-box":
		c = map[string]any{"State": state(true), "Config": map[string]any{"Labels": map[string]string{"safeclaw.type": "sandbox"}},
			"HostConfig": map[string]any{"NetworkMode": "none"}}
	default:
		return nil, dockertest.NotFound([]string{"container", "inspect", name})
	}
	c["Name"] = "/" + name
	return json.Marshal([]any{c})
}

func TestURLCommand(t *testing.T) {
	imageLabels := currentTTYD
	r := &dockertest.Runner{Handler: urlContainers(&imageLabels)}
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

	// Without a dashboard, the credential stays off the opener's command
	// line, and stderr says how to log in.
	out, errOut, err := runWithStderr(t, "url", "work", "--open")
	if err != nil || out != "http://safeclaw:pw@[::1]:7685\n" || !slices.Equal(opened, []string{"http://[::1]:7685"}) || !strings.Contains(errOut, "Log in as safeclaw with the password in the printed URL") || strings.Contains(errOut, "pw") {
		t.Errorf("url work --open = %q, %q, %v, opened %q", out, errOut, err, opened)
	}

	// A legacy session on 127.0.0.1 gets the warnings `run` gives, on
	// stderr, saying to update the image while its ttyd refuses [::1] URLs.
	for _, name := range []string{"legacy", "argv"} {
		if err := os.WriteFile(filepath.Join(ttyd, name), []byte("safeclaw:pw\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	const legacyWarning = "Warning: session legacy publishes its terminal on 127.0.0.1, the dashboard's cookie host, because it was created before terminals moved to [::1], and its image's ttyd refuses [::1] URLs. Update the image with `safeclaw pull` or `safeclaw build`, then run `safeclaw run -s legacy` again to recreate it on [::1]\n"
	imageLabels = map[string]string{config.LabelCredentialFileTTYD: "1"}
	opened = nil
	out, errOut, err = runWithStderr(t, "url", "legacy", "--open")
	if err != nil || out != "http://safeclaw:pw@127.0.0.1:7686\n" || !strings.HasPrefix(errOut, legacyWarning) || strings.Contains(errOut, "command line, which") || !slices.Equal(opened, []string{"http://127.0.0.1:7686"}) {
		t.Errorf("url legacy --open = %q, %q, %v, opened %q", out, errOut, err, opened)
	}
	out, errOut, err = runWithStderr(t, "url", "argv")
	if err != nil || out != "http://safeclaw:pw@127.0.0.1:7686\n" ||
		!strings.Contains(errOut, "Warning: session argv publishes its terminal on 127.0.0.1") ||
		!strings.Contains(errOut, "Warning: session argv's ttyd takes its credential on its command line, which other local users can read on a native Linux docker host, because it was created from an older image. Update the image with `safeclaw pull` or `safeclaw build`, then run `safeclaw run -s argv` to recreate the session from it\n") {
		t.Errorf("url argv = %q, %q, %v", out, errOut, err)
	}
	// Once the image is updated, they say `run` recreates the session.
	imageLabels = currentTTYD
	out, errOut, err = runWithStderr(t, "url", "argv")
	if err != nil || out != "http://safeclaw:pw@127.0.0.1:7686\n" || errOut != "Warning: session argv publishes its terminal on 127.0.0.1, the dashboard's cookie host, because it was created before terminals moved to [::1]. Run `safeclaw run -s argv` to recreate it there\n"+
		"Warning: session argv's ttyd takes its credential on its command line, which other local users can read on a native Linux docker host, because it was created from an older image. Run `safeclaw run -s argv` to recreate it from the updated image, whose ttyd reads it from a file\n" {
		t.Errorf("url argv with an updated image = %q, %q, %v", out, errOut, err)
	}
	// A current session gets none.
	if out, errOut, err := runWithStderr(t, "url", "work"); err != nil || out == "" || errOut != "" {
		t.Errorf("url work = %q, %q, %v", out, errOut, err)
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

// runWithStderr runs the root command with args and returns its stdout and
// stderr.
func runWithStderr(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	var out, errOut strings.Builder
	cmd := NewRootCommand()
	cmd.SetArgs(args)
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	err := cmd.Execute()
	return out.String(), errOut.String(), err
}
