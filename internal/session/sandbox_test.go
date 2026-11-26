package session

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/secrets"
)

var sandboxLabels = map[string]string{"safeclaw.type": "sandbox"}

const sandboxRunPrefix = "run -d --name safeclaw-box --label safeclaw.type=sandbox --network none --user sandbox --workdir /sandbox" +
	" --env HOME=/sandbox --env BASH_ENV= --env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" +
	" --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,nosuid,nodev,size=256m -v /sandbox"

func TestEnsureSandboxCreates(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{}}
	m, r := newTestManager(t, w)
	// A sandbox must not need, or receive, any secret.
	_ = m.Secrets.Delete(secrets.ClaudeToken)
	_, _ = m.Secrets.Set(secrets.GitHubToken, "gh-secret")

	res, err := m.EnsureSandbox(context.Background(), SandboxOptions{Name: "box"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Container != "safeclaw-box" || res.Port != 0 || res.URL != "" {
		t.Errorf("result = %+v", res)
	}
	run, ok := r.Find("run ")
	if !ok {
		t.Fatal("no docker run")
	}
	want := sandboxRunPrefix + " --memory 1g --pids-limit 256 --cpus 1 safeclaw sleep infinity"
	if run.String() != want {
		t.Errorf("run = %q\nwant  %q", run.String(), want)
	}
	for _, c := range r.Commands() {
		if strings.HasPrefix(c, "exec ") {
			t.Errorf("sandbox should run nothing in the container: %q", c)
		}
		if strings.Contains(c, "gh-secret") || strings.Contains(c, "--ipc") || strings.Contains(c, " -p ") {
			t.Errorf("unexpected docker call: %q", c)
		}
	}
	if _, err := os.Stat(filepath.Join(m.SessionsDir, "box")); !os.IsNotExist(err) {
		t.Errorf("sandbox should not get a history dir: %v", err)
	}
}

func TestEnsureSandboxLimitsAndVolume(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{}}
	m, r := newTestManager(t, w)
	_, err := m.EnsureSandbox(context.Background(), SandboxOptions{
		Name: "box", Volume: "/in:/in:rw,z", Memory: "512m", PidsLimit: 64, CPUs: "0.5",
	})
	if err != nil {
		t.Fatal(err)
	}
	run, _ := r.Find("run ")
	want := sandboxRunPrefix + " --memory 512m --pids-limit 64 --cpus 0.5 -v /in:/in:ro,z safeclaw sleep infinity"
	if run.String() != want {
		t.Errorf("run = %q\nwant  %q", run.String(), want)
	}
}

func TestEnsureSandboxReuse(t *testing.T) {
	cases := []struct {
		name    string
		running bool
		opts    SandboxOptions
		want    string // call that must be made
		wantNot []string
	}{
		{"running", true, SandboxOptions{Name: "box"}, "", []string{"run ", "start ", "rm "}},
		{"stopped", false, SandboxOptions{Name: "box"}, "start safeclaw-box", []string{"run ", "rm "}},
		{"volume", true, SandboxOptions{Name: "box", Volume: "/in:/in"}, "rm -v -f safeclaw-box", nil},
		{"limits", false, SandboxOptions{Name: "box", Memory: "2g", Recreate: true}, "rm -v -f safeclaw-box", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &world{image: "img", containers: map[string]*fakeContainer{
				"safeclaw-box": {Running: tc.running, Image: "img", Labels: sandboxLabels},
			}}
			m, r := newTestManager(t, w)
			if _, err := m.EnsureSandbox(context.Background(), tc.opts); err != nil {
				t.Fatal(err)
			}
			if tc.want != "" && !hasCall(r, tc.want) {
				t.Errorf("missing %q in %v", tc.want, r.Commands())
			}
			for _, p := range tc.wantNot {
				if hasCall(r, p) {
					t.Errorf("unexpected %q in %v", p, r.Commands())
				}
			}
			if tc.opts.Volume != "" || tc.opts.Recreate {
				run, ok := r.Find("run ")
				if !ok || !strings.Contains(run.String(), "--label safeclaw.type=sandbox") {
					t.Errorf("not recreated as a sandbox: %v", r.Commands())
				}
			}
		})
	}
}

func TestEnsureSandboxErrors(t *testing.T) {
	ctx := context.Background()
	m, r := newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-work": {Running: true, Port: 7681, Image: "img"},
	}})
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{}); !errors.Is(err, ErrSandboxName) {
		t.Errorf("err = %v, want ErrSandboxName", err)
	}
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: "bad name"}); err == nil {
		t.Error("invalid name accepted")
	}
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: "work", Volume: "/in:/in"}); !errors.Is(err, ErrNotSandbox) {
		t.Errorf("err = %v, want ErrNotSandbox", err)
	}
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: "box", PidsLimit: -1}); err == nil {
		t.Error("negative pids limit accepted")
	}
	if hasCall(r, "rm ") || hasCall(r, "run ") {
		t.Errorf("should not touch containers: %v", r.Commands())
	}

	m, _ = newTestManager(t, &world{containers: map[string]*fakeContainer{}})
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: "box"}); !errors.Is(err, ErrNoImage) {
		t.Errorf("err = %v, want ErrNoImage", err)
	}
}

func TestEnsureRefusesSandbox(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-box": {Running: true, Image: "img", Labels: sandboxLabels},
	}}
	m, r := newTestManager(t, w)
	// The sandbox error wins over a missing token.
	_ = m.Secrets.Delete(secrets.ClaudeToken)
	_, err := m.Ensure(context.Background(), Options{Name: "box", Volume: "/in:/in", NoOpen: true})
	if !errors.Is(err, ErrIsSandbox) {
		t.Fatalf("err = %v, want ErrIsSandbox", err)
	}
	if !strings.Contains(err.Error(), `"box"`) {
		t.Errorf("error should name the session: %v", err)
	}
	for _, c := range r.Commands() {
		if !strings.HasPrefix(c, "image inspect") && !strings.HasPrefix(c, "container inspect") {
			t.Errorf("unexpected docker call: %q", c)
		}
	}
}

func TestRequireType(t *testing.T) {
	ctx := context.Background()
	m, _ := newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-box":  {Labels: sandboxLabels},
		"safeclaw-work": {Port: 7681},
	}})
	cases := []struct {
		name, want string
		err        error
	}{
		{"box", config.TypeSandbox, nil},
		{"work", config.TypeSession, nil},
		{"box", config.TypeSession, ErrIsSandbox},
		{"work", config.TypeSandbox, ErrNotSandbox},
		{"safeclaw-box", config.TypeSandbox, nil},
		{"missing", config.TypeSession, ErrNotFound},
	}
	for _, tc := range cases {
		err := m.RequireType(ctx, tc.name, tc.want)
		if (tc.err == nil && err != nil) || (tc.err != nil && !errors.Is(err, tc.err)) {
			t.Errorf("RequireType(%q, %q) = %v, want %v", tc.name, tc.want, err, tc.err)
		}
	}
}

func TestReadOnlyVolume(t *testing.T) {
	home, _ := os.UserHomeDir()
	cases := map[string]string{
		"/in:/in":          "/in:/in:ro",
		"/in:/in:ro":       "/in:/in:ro",
		"/in:/in:rw":       "/in:/in:ro",
		"/in:/in:rw,z":     "/in:/in:ro,z",
		"/in:/in:z,ro":     "/in:/in:ro,z",
		"~/inbox:/in":      filepath.Join(home, "inbox") + ":/in:ro",
		"/in:/in:cached,Z": "/in:/in:ro,cached,Z",
	}
	for in, want := range cases {
		if got, err := ReadOnlyVolume(in); err != nil || got != want {
			t.Errorf("ReadOnlyVolume(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"/in", ":/in", "/in:", "/in::ro"} {
		if _, err := ReadOnlyVolume(bad); err == nil {
			t.Errorf("ReadOnlyVolume(%q) should fail", bad)
		}
	}
}
