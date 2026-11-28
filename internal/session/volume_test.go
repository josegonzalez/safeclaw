package session

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeHome points HOME at a new directory with a safeclaw config directory
// in its default place, clears the variables that move it or name a
// runtime socket, and returns the home and config directory.
func fakeHome(t *testing.T) (home, dir string) {
	t.Helper()
	home = t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("DOCKER_HOST", "")
	dir = filepath.Join(home, ".config", "safeclaw")
	for _, d := range []string{filepath.Join(dir, "ttyd"), filepath.Join(home, "proj")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return home, dir
}

func TestCheckVolumeRefusesConfigDir(t *testing.T) {
	home, dir := fakeHome(t)
	links := t.TempDir()
	for link, target := range map[string]string{"home": home, "config": filepath.Join(home, ".config"), "ttyd": filepath.Join(dir, "ttyd")} {
		if err := os.Symlink(target, filepath.Join(links, link)); err != nil {
			t.Fatal(err)
		}
	}
	for _, v := range []string{
		"~:/home/sclaw/home",
		"~/:/home/sclaw/home:ro",
		home + ":/h",
		"~/.config:/c",
		"~/.config/safeclaw:/s",
		dir + "/:/s:ro",
		"~/.config/safeclaw/ttyd:/t",
		"~/.config/safeclaw/missing/dir:/t",
		"~/proj/../.config:/c",
		filepath.Join(links, "home") + ":/h",
		filepath.Join(links, "config") + ":/c",
		filepath.Join(links, "ttyd") + ":/t",
		filepath.Join(links, "ttyd", "missing") + ":/t",
		"/:/host",
	} {
		_, _, err := CheckVolume(v)
		if !errors.Is(err, ErrUnsafeVolume) {
			t.Errorf("CheckVolume(%q) = %v, want ErrUnsafeVolume", v, err)
		}
	}
}

func TestCheckVolumeHonorsXDGConfigHome(t *testing.T) {
	home, _ := fakeHome(t)
	xdg := filepath.Join(home, "xdg")
	if err := os.MkdirAll(filepath.Join(xdg, "safeclaw"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", xdg)
	if _, _, err := CheckVolume(xdg + ":/x"); !errors.Is(err, ErrUnsafeVolume) {
		t.Errorf("XDG_CONFIG_HOME mount = %v, want ErrUnsafeVolume", err)
	}
	if _, _, err := CheckVolume("~/.config:/c"); err != nil {
		t.Errorf("~/.config without the config dir = %v", err)
	}
}

func TestCheckVolumeCaseInsensitive(t *testing.T) {
	home, _ := fakeHome(t)
	if _, err := os.Stat(filepath.Join(home, ".CONFIG")); err != nil {
		t.Skip("case-sensitive filesystem")
	}
	if _, _, err := CheckVolume("~/.CONFIG/SafeClaw:/s"); !errors.Is(err, ErrUnsafeVolume) {
		t.Errorf("other spelling = %v, want ErrUnsafeVolume", err)
	}
}

func TestCheckVolumeAcceptsProjects(t *testing.T) {
	home, _ := fakeHome(t)
	link := filepath.Join(t.TempDir(), "proj")
	if err := os.Symlink(filepath.Join(home, "proj"), link); err != nil {
		t.Fatal(err)
	}
	for v, want := range map[string]string{
		"~/proj:/home/sclaw/proj":         filepath.Join(home, "proj") + ":/home/sclaw/proj",
		"~/proj:/home/sclaw/proj:ro":      filepath.Join(home, "proj") + ":/home/sclaw/proj:ro",
		"~/new/proj:/p":                   filepath.Join(home, "new", "proj") + ":/p",
		"~/.config/other:/o":              filepath.Join(home, ".config", "other") + ":/o",
		"~/.config/safeclaw-old:/o":       filepath.Join(home, ".config", "safeclaw-old") + ":/o",
		link + ":/p":                      link + ":/p",
		"cache:/home/sclaw/.cache":        "cache:/home/sclaw/.cache",
		"/srv/does/not/exist:/home/sclaw": "/srv/does/not/exist:/home/sclaw",
	} {
		got, warnings, err := CheckVolume(v)
		if err != nil || got != want || len(warnings) > 0 {
			t.Errorf("CheckVolume(%q) = %q, %v, %v; want %q", v, got, warnings, err, want)
		}
	}
}

func TestCheckVolumeRefusesBrokenSymlink(t *testing.T) {
	fakeHome(t)
	link := filepath.Join(t.TempDir(), "broken")
	if err := os.Symlink(filepath.Join(t.TempDir(), "gone", "dir"), link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := CheckVolume(link + ":/x"); err == nil || !strings.Contains(err.Error(), "broken symlink") {
		t.Errorf("broken symlink = %v", err)
	}
}

func TestCheckVolumeWarnsAboutRuntimeSockets(t *testing.T) {
	home, _ := fakeHome(t)
	run := filepath.Join(home, "run")
	sock := filepath.Join(run, "docker.sock")
	if err := os.MkdirAll(run, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_HOST", "unix://"+sock)
	link := filepath.Join(t.TempDir(), "docker.sock")
	if err := os.Symlink(sock, link); err != nil {
		t.Fatal(err)
	}
	for _, v := range []string{sock + ":/var/run/docker.sock", run + ":/run", link + ":/var/run/docker.sock"} {
		_, warnings, err := CheckVolume(v)
		if err != nil || len(warnings) != 1 || !strings.Contains(warnings[0], sock) {
			t.Errorf("CheckVolume(%q) = %v, %v; want one warning naming %s", v, warnings, err, sock)
		}
	}
	if _, warnings, err := CheckVolume("~/proj:/p"); err != nil || len(warnings) > 0 {
		t.Errorf("project mount = %v, %v", warnings, err)
	}
}

func TestEnsureRefusesConfigDirVolume(t *testing.T) {
	fakeHome(t)
	m, r := newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{}, native: true})
	_, err := m.Ensure(context.Background(), Options{Name: "p", Volume: "~:/home/sclaw/home", NoOpen: true})
	if !errors.Is(err, ErrUnsafeVolume) {
		t.Fatalf("Ensure = %v, want ErrUnsafeVolume", err)
	}
	if cmds := r.Commands(); len(cmds) > 0 {
		t.Errorf("docker was called: %v", cmds)
	}
}

// A session whose kept mount exposes the config directory, mounted before
// such mounts were refused, is kept with a warning, isn't recreated with
// it, and can be recreated with another mount.
func TestEnsureKeptConfigDirMount(t *testing.T) {
	home, _ := fakeHome(t)
	ctx := context.Background()
	legacy := func() *world {
		return &world{image: "img", native: true, containers: map[string]*fakeContainer{
			"safeclaw-p": {Running: true, Port: 7705, HostIP: "::1", Image: "img", Mounts: []string{"/s:/home/sclaw/.claude/projects", home + ":/home/sclaw/home"}},
		}}
	}
	var out strings.Builder
	m, r := newTestManager(t, legacy())
	m.Out = &out
	if _, err := m.Ensure(ctx, Options{Name: "p", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if hasCall(r, "rm ") || !strings.Contains(out.String(), "Warning: session p keeps a mount") {
		t.Errorf("kept: calls %v\n%s", r.Commands(), out.String())
	}

	m, r = newTestManager(t, legacy())
	_, err := m.Ensure(ctx, Options{Name: "p", FreshHistory: true, NoOpen: true})
	if !errors.Is(err, ErrUnsafeVolume) || !strings.Contains(err.Error(), "-v and another host path") {
		t.Errorf("recreate = %v, want ErrUnsafeVolume naming -v", err)
	}
	if hasCall(r, "rm ") || hasCall(r, "run ") {
		t.Errorf("recreate changed the container: %v", r.Commands())
	}

	m, r = newTestManager(t, legacy())
	if _, err := m.Ensure(ctx, Options{Name: "p", Volume: "~/proj:/home/sclaw/proj", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if run, _ := r.Find("run "); !strings.Contains(run.String(), filepath.Join(home, "proj")+":/home/sclaw/proj") || strings.Contains(run.String(), ":/home/sclaw/home") {
		t.Errorf("replaced: run %q", run.String())
	}
}

func TestEnsureWarnsAboutRuntimeSocket(t *testing.T) {
	home, _ := fakeHome(t)
	sock := filepath.Join(home, "docker.sock")
	if err := os.WriteFile(sock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_HOST", "unix://"+sock)
	var out strings.Builder
	m, _ := newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{}, native: true})
	m.Out = &out
	if _, err := m.Ensure(context.Background(), Options{Name: "p", Volume: sock + ":/var/run/docker.sock", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Warning: volume") || !strings.Contains(out.String(), "container runtime socket "+sock) {
		t.Errorf("no warning:\n%s", out.String())
	}
}

func TestSandboxRefusesConfigDirVolume(t *testing.T) {
	fakeHome(t)
	if _, err := ReadOnlyVolume("~/.config:/in"); !errors.Is(err, ErrUnsafeVolume) {
		t.Errorf("ReadOnlyVolume = %v, want ErrUnsafeVolume", err)
	}
}
