package dashboard

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// devDir copies the embedded templates and static files into a new
// directory with the modes a checkout has, and returns it.
func devDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "dashboard")
	err := fs.WalkDir(assets, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		dst := filepath.Join(dir, path)
		if d.IsDir() {
			if err := os.MkdirAll(dst, 0o755); err != nil {
				return err
			}
			return os.Chmod(dst, 0o755)
		}
		b, err := assets.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(dst, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	return dir
}

// newDevServer returns a --dev server over dir, or New's error.
func newDevServer(dir string) (*Server, error) {
	return New(Options{Sessions: &fakeSessions{}, Token: testToken, TokenFile: "unused", Dev: true, DevDir: dir})
}

// mustDevServer returns a --dev server over dir.
func mustDevServer(t *testing.T, dir string) *Server {
	t.Helper()
	s, err := newDevServer(dir)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// authorized returns a function that sends authorized requests to s.
func authorized(s *Server) func(method, target string) (int, string) {
	h := s.Handler()
	return func(method, target string) (int, string) {
		rec := do(h, method, target, nil, map[string]string{"Authorization": "Bearer " + testToken})
		return rec.Code, rec.Body.String()
	}
}

// TestDevServesDirectory checks that --dev serves a directory the user
// owns, reading edits on every request, and follows symlinks that stay in
// it.
func TestDevServesDirectory(t *testing.T) {
	dir := devDir(t)
	get := authorized(mustDevServer(t, dir))
	if code, body := get("GET", "/"); code != 200 || !strings.Contains(body, "/static/app.js") {
		t.Fatalf("GET / = %d %q", code, body)
	}
	if err := os.WriteFile(filepath.Join(dir, "static", "app.js"), []byte("edited"), 0o644); err != nil {
		t.Fatal(err)
	}
	if code, body := get("GET", "/static/app.js"); code != 200 || body != "edited" {
		t.Errorf("GET /static/app.js after an edit = %d %q", code, body)
	}
	if err := os.Symlink("app.js", filepath.Join(dir, "static", "alias.js")); err != nil {
		t.Fatal(err)
	}
	if code, body := get("GET", "/static/alias.js"); code != 200 || body != "edited" {
		t.Errorf("GET a symlink inside the directory = %d %q", code, body)
	}
}

// TestDevRefusesSymlinksOut checks that a symlink out of the dev directory
// is never followed, whether it is a static file, a template, or a whole
// subdirectory.
func TestDevRefusesSymlinksOut(t *testing.T) {
	outside := t.TempDir()
	secret := filepath.Join(outside, "secret.html")
	if err := os.WriteFile(secret, []byte("outside the dev directory"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("static file", func(t *testing.T) {
		dir := devDir(t)
		if err := os.Symlink(secret, filepath.Join(dir, "static", "evil.js")); err != nil {
			t.Fatal(err)
		}
		get := authorized(mustDevServer(t, dir))
		if code, body := get("GET", "/static/evil.js"); code == 200 || strings.Contains(body, "outside") {
			t.Errorf("GET a symlink out of the directory = %d %q", code, body)
		}
		if code, _ := get("GET", "/static/app.js"); code != 200 {
			t.Errorf("GET /static/app.js = %d", code)
		}
	})

	t.Run("template", func(t *testing.T) {
		dir := devDir(t)
		if err := os.Symlink(secret, filepath.Join(dir, "templates", "evil.html")); err != nil {
			t.Fatal(err)
		}
		if _, err := newDevServer(dir); err == nil || !strings.Contains(err.Error(), "escapes") {
			t.Errorf("New with a template symlinked out = %v", err)
		}
	})

	t.Run("subdirectory", func(t *testing.T) {
		dir := devDir(t)
		static := filepath.Join(dir, "static")
		if err := os.RemoveAll(static); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, static); err != nil {
			t.Fatal(err)
		}
		if _, err := newDevServer(dir); err == nil || !strings.Contains(err.Error(), "escapes") {
			t.Errorf("New with static symlinked out = %v", err)
		}
	})
}

// TestDevRefusesWritableDirectories checks that --dev refuses a directory
// that someone other than the user could write to.
func TestDevRefusesWritableDirectories(t *testing.T) {
	for _, sub := range []string{".", "templates", "static"} {
		for _, mode := range []os.FileMode{0o775, 0o757, 0o777} {
			t.Run(sub+"/"+mode.String(), func(t *testing.T) {
				dir := devDir(t)
				path := filepath.Join(dir, sub)
				if err := os.Chmod(path, mode); err != nil {
					t.Fatal(err)
				}
				_, err := newDevServer(dir)
				if err == nil || !strings.Contains(err.Error(), "group- or world-writable") || !strings.Contains(err.Error(), path) {
					t.Errorf("New with %s at %v = %v", sub, mode, err)
				}
			})
		}
	}
}

// TestDevRefusesMissingDirectories checks that --dev names the directory
// it needs when one is missing or not a directory.
func TestDevRefusesMissingDirectories(t *testing.T) {
	if _, err := newDevServer(filepath.Join(t.TempDir(), "missing")); err == nil || !strings.Contains(err.Error(), "repository root") {
		t.Errorf("New with a missing directory = %v", err)
	}
	dir := devDir(t)
	templates := filepath.Join(dir, "templates")
	if err := os.RemoveAll(templates); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(templates, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := newDevServer(dir); err == nil || !strings.Contains(err.Error(), templates+" to be a directory") {
		t.Errorf("New with templates a file = %v", err)
	}
}

// fakeDirInfo is a directory's FileInfo with a chosen owner and mode.
type fakeDirInfo struct {
	fs.FileInfo
	uid  uint32
	mode fs.FileMode
}

func (f fakeDirInfo) IsDir() bool       { return true }
func (f fakeDirInfo) Mode() fs.FileMode { return fs.ModeDir | f.mode }
func (f fakeDirInfo) Sys() any          { return &syscall.Stat_t{Uid: f.uid} }

// TestCheckDevDirOwner checks that a directory owned by another user is
// refused, which a test can't set up on disk without root.
func TestCheckDevDirOwner(t *testing.T) {
	me := uint32(os.Getuid())
	if err := checkDevDir("/d", fakeDirInfo{uid: me, mode: 0o755}); err != nil {
		t.Errorf("own directory = %v", err)
	}
	err := checkDevDir("/d", fakeDirInfo{uid: me + 1, mode: 0o755})
	if err == nil || !strings.Contains(err.Error(), "/d: it is owned by uid") {
		t.Errorf("another user's directory = %v", err)
	}
}

// TestDevPrintsAbsoluteDirectory checks that a --dev dashboard started
// with a relative directory prints the absolute one it reads from.
func TestDevPrintsAbsoluteDirectory(t *testing.T) {
	dir := devDir(t)
	t.Chdir(filepath.Dir(dir))
	port := loopbackPort(t)
	s, err := New(Options{Sessions: &fakeSessions{}, Port: port, TokenFile: filepath.Join(t.TempDir(), "port.token"), Dev: true, DevDir: filepath.Base(dir)})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	out := &syncBuffer{}
	done := make(chan error, 1)
	go func() { done <- s.ListenAndServe(ctx, out) }()
	for i := 0; i < 200 && !strings.Contains(out.String(), "API token"); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	if want := "Dev files: " + abs + "\n"; !strings.Contains(out.String(), want) {
		t.Errorf("printed %q, want %q", out.String(), want)
	}
}
