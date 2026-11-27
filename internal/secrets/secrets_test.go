package secrets

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/zalando/go-keyring"
)

// testStore checks the behavior every Store shares.
func testStore(t *testing.T, s Store) {
	t.Helper()
	if keys, err := s.Keys(); err != nil || len(keys) != 0 {
		t.Fatalf("Keys on an empty store = %v, %v", keys, err)
	}
	before := time.Now().Add(-time.Second)
	if err := s.Set("GH_TOKEN", "abc"); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("A_KEY", "x"); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.Get("GH_TOKEN"); v != "abc" {
		t.Errorf("Get = %q", v)
	}
	keys, _ := s.Keys()
	if !reflect.DeepEqual(keys, []string{"A_KEY", "GH_TOKEN"}) {
		t.Errorf("Keys = %v", keys)
	}
	all, err := s.All()
	if err != nil || !reflect.DeepEqual(all, []Secret{{"A_KEY", "x"}, {"GH_TOKEN", "abc"}}) {
		t.Errorf("All = %+v, %v", all, err)
	}
	if !s.Has("A_KEY") || s.Has("NOPE") {
		t.Error("Has is wrong")
	}
	if at, err := s.SetAt("A_KEY"); err != nil || at.Before(before) || at.After(time.Now().Add(time.Second)) {
		t.Errorf("SetAt = %v, %v", at, err)
	}
	if _, err := s.SetAt("NOPE"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("SetAt on a missing secret = %v, want ErrNotExist", err)
	}
	if _, err := s.Get("NOPE"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Get on a missing secret = %v, want ErrNotExist", err)
	}
	if err := s.Delete("A_KEY"); err != nil || s.Has("A_KEY") {
		t.Errorf("Delete: %v", err)
	}
	if err := s.Delete("A_KEY"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Delete of a missing secret = %v, want ErrNotExist", err)
	}
	if err := s.Delete("../escape"); err == nil {
		t.Error("Delete should reject invalid names")
	}
	if err := s.Set("../escape", "x"); err == nil {
		t.Error("Set should reject invalid names")
	}
}

func TestFileStore(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".secrets")
	s := FileStore{Dir: dir}
	testStore(t, s)

	if err := s.Set("NL", "abc\n"); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(filepath.Join(dir, "NL"))
	if info.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %v, want 0600", info.Mode().Perm())
	}
	dinfo, _ := os.Stat(dir)
	if dinfo.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v, want 0700", dinfo.Mode().Perm())
	}
	if v, _ := s.Get("NL"); v != "abc" {
		t.Errorf("Get = %q, want trailing newline trimmed", v)
	}
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	_ = os.Chtimes(filepath.Join(dir, "NL"), at, at)
	if got, _ := s.SetAt("NL"); !got.Equal(at) {
		t.Errorf("SetAt = %v, want the file's mtime %v", got, at)
	}
}

func TestFileStoreRejectsTraversalNames(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, ".secrets")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	// A readable file outside the store that a traversal name would reach.
	if err := os.WriteFile(filepath.Join(base, "OUTSIDE"), []byte("leak"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := FileStore{Dir: dir}
	for _, name := range []string{"../OUTSIDE", "/etc/hosts", "a/b", "", "."} {
		if s.Has(name) {
			t.Errorf("Has(%q) = true", name)
		}
		if v, err := s.Get(name); err == nil || errors.Is(err, os.ErrNotExist) || v != "" {
			t.Errorf("Get(%q) = %q, %v, want an invalid name error", name, v, err)
		}
		if _, err := s.SetAt(name); err == nil || errors.Is(err, os.ErrNotExist) {
			t.Errorf("SetAt(%q) = %v, want an invalid name error", name, err)
		}
	}
}

func TestFileStoreIgnoresSymlinks(t *testing.T) {
	base := t.TempDir()
	dir := filepath.Join(base, ".secrets")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "target")
	if err := os.WriteFile(target, []byte("outside"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "LINKED")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "SUBDIR"), 0o700); err != nil {
		t.Fatal(err)
	}
	// A FIFO is refused without blocking the open.
	if err := syscall.Mkfifo(filepath.Join(dir, "FIFO"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := FileStore{Dir: dir}
	for _, name := range []string{"LINKED", "SUBDIR", "FIFO"} {
		if s.Has(name) {
			t.Errorf("Has(%s) = true for a non-regular entry", name)
		}
		if v, err := s.Get(name); !errors.Is(err, os.ErrNotExist) || v != "" {
			t.Errorf("Get(%s) = %q, %v, want ErrNotExist", name, v, err)
		}
		if _, err := s.SetAt(name); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("SetAt(%s) = %v, want ErrNotExist", name, err)
		}
	}
	if keys, _ := s.Keys(); len(keys) != 0 {
		t.Errorf("Keys = %v", keys)
	}
	if all, err := s.All(); err != nil || len(all) != 0 {
		t.Errorf("All = %+v, %v", all, err)
	}

	// Set replaces the symlink with a file rather than writing through it.
	if err := s.Set("LINKED", "new"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(target); string(b) != "outside" {
		t.Errorf("Set wrote through the symlink: target = %q", b)
	}
	info, err := os.Lstat(filepath.Join(dir, "LINKED"))
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
		t.Errorf("LINKED after Set = %v, %v, want a 0600 regular file", info, err)
	}
	if v, _ := s.Get("LINKED"); v != "new" {
		t.Errorf("Get after Set = %q", v)
	}
}

func TestFileStoreSetReplacesLooseFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".secrets")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "LOOSE")
	if err := os.WriteFile(path, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	s := FileStore{Dir: dir}
	if err := s.Set("LOOSE", "new"); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %v, want 0600", info.Mode().Perm())
	}
	if v, _ := s.Get("LOOSE"); v != "new" {
		t.Errorf("Get = %q", v)
	}
	// No temp file is left behind.
	if entries, _ := os.ReadDir(dir); len(entries) != 1 {
		t.Errorf("dir has %d entries, want 1", len(entries))
	}
}

func TestFileStoreTightensDirectory(t *testing.T) {
	for _, mode := range []os.FileMode{0o755, 0o750, 0o777, 0o701} {
		dir := filepath.Join(t.TempDir(), ".secrets")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		// Chmod, since Mkdir's mode is filtered by the umask.
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if err := (FileStore{Dir: dir}).Set("A", "1"); err != nil {
			t.Fatal(err)
		}
		if info, _ := os.Stat(dir); info.Mode().Perm() != 0o700 {
			t.Errorf("dir %v after Set = %v, want 0700", mode, info.Mode().Perm())
		}
	}
}

func TestOpenTightensFileStoreDirectory(t *testing.T) {
	keyring.MockInitWithError(errors.New("no dbus"))
	t.Cleanup(keyring.MockInit)
	dir := filepath.Join(t.TempDir(), ".secrets")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	Open(dir, filepath.Join(t.TempDir(), "secrets.lock"), io.Discard)
	if info, _ := os.Stat(dir); info.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v, want 0700", info.Mode().Perm())
	}

	// A missing directory isn't created just by opening the store.
	missing := filepath.Join(t.TempDir(), "missing")
	Open(missing, filepath.Join(t.TempDir(), "secrets.lock"), io.Discard)
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Open created %s: %v", missing, err)
	}
}

func TestKeyringStore(t *testing.T) {
	keyring.MockInit()
	s := KeyringStore{LockPath: filepath.Join(t.TempDir(), "secrets.lock")}
	testStore(t, s)

	if err := s.Set("MULTI", "line1\nline2\n"); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.Get("MULTI"); v != "line1\nline2\n" {
		t.Errorf("Get = %q, want the value unchanged", v)
	}
	// The index item is never listed as a secret.
	if keys, _ := s.Keys(); !reflect.DeepEqual(keys, []string{"GH_TOKEN", "MULTI"}) {
		t.Errorf("Keys = %v", keys)
	}
	// A secret removed outside safeclaw is skipped, not an error.
	_ = keyring.Delete(Service, "MULTI")
	if all, err := s.All(); err != nil || len(all) != 1 || all[0].Name != "GH_TOKEN" {
		t.Errorf("All after an outside delete = %+v, %v", all, err)
	}
	if err := s.Delete("MULTI"); err != nil || s.Has("MULTI") {
		t.Errorf("Delete of an indexed but missing secret = %v", err)
	}
	if !strings.Contains(s.Location(), "keychain") {
		t.Errorf("Location = %q", s.Location())
	}
}

func TestKeyringStoreErrors(t *testing.T) {
	keyring.MockInitWithError(errors.New("no dbus"))
	t.Cleanup(keyring.MockInit)
	s := KeyringStore{LockPath: filepath.Join(t.TempDir(), "secrets.lock")}
	if err := s.Set("A", "1"); err == nil {
		t.Error("Set should fail when the keychain does")
	}
	if _, err := s.Keys(); err == nil {
		t.Error("Keys should fail when the keychain does")
	}
	if s.Has("A") {
		t.Error("Has should be false when the keychain fails")
	}
}

func TestOpenFallsBackToFiles(t *testing.T) {
	keyring.MockInitWithError(errors.New("no dbus"))
	t.Cleanup(keyring.MockInit)
	dir := filepath.Join(t.TempDir(), ".secrets")
	var warn bytes.Buffer
	s := Open(dir, filepath.Join(t.TempDir(), "secrets.lock"), &warn)
	if fs, ok := s.(FileStore); !ok || fs.Dir != dir {
		t.Fatalf("Open = %#v, want the file store", s)
	}
	if !strings.Contains(warn.String(), "keychain is unavailable (no dbus)") {
		t.Errorf("warning = %q", warn.String())
	}
}

func TestOpenMigratesFiles(t *testing.T) {
	keyring.MockInit()
	dir := filepath.Join(t.TempDir(), ".secrets")
	files := FileStore{Dir: dir}
	_ = files.Set(ClaudeToken, "tok\n")
	_ = files.Set(GitHubToken, "gh")
	at := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	_ = os.Chtimes(filepath.Join(dir, ClaudeToken), at, at)

	var warn bytes.Buffer
	s := Open(dir, filepath.Join(t.TempDir(), "secrets.lock"), &warn)
	if _, ok := s.(KeyringStore); !ok {
		t.Fatalf("Open = %#v, want the keychain store", s)
	}
	if v, _ := s.Get(ClaudeToken); v != "tok" {
		t.Errorf("migrated value = %q", v)
	}
	if got, _ := s.SetAt(ClaudeToken); !got.Equal(at) {
		t.Errorf("migrated SetAt = %v, want the file's mtime %v", got, at)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("secrets dir should be removed once empty: %v", err)
	}
	if !strings.Contains(warn.String(), "Moved 2 secret(s)") {
		t.Errorf("message = %q", warn.String())
	}

	// Opening again finds nothing to move.
	warn.Reset()
	_ = Open(dir, filepath.Join(t.TempDir(), "secrets.lock"), &warn)
	if warn.Len() != 0 {
		t.Errorf("second Open said %q", warn.String())
	}
	_ = keyring.DeleteAll(Service)
}

func TestOpenLeavesInvalidNames(t *testing.T) {
	keyring.MockInit()
	t.Cleanup(func() { _ = keyring.DeleteAll(Service) })
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "GOOD"), []byte("1"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "bad-name"), []byte("2"), 0o600)
	var warn bytes.Buffer
	s := Open(dir, filepath.Join(t.TempDir(), "secrets.lock"), &warn)
	if v, _ := s.Get("GOOD"); v != "1" {
		t.Errorf("GOOD = %q", v)
	}
	if _, err := os.Stat(filepath.Join(dir, "bad-name")); err != nil {
		t.Errorf("bad-name should be left in place: %v", err)
	}
	if !strings.Contains(warn.String(), "not valid env var names") {
		t.Errorf("warning = %q", warn.String())
	}
}

func TestAllSkipsInvalidNames(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "GOOD"), []byte("1"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "bad-name"), []byte("2"), 0o600)
	_ = os.Mkdir(filepath.Join(dir, "SUBDIR"), 0o700)
	all, err := FileStore{Dir: dir}.All()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(all, []Secret{{Name: "GOOD", Value: "1"}}) {
		t.Errorf("All = %+v", all)
	}
}
func TestValidateName(t *testing.T) {
	for _, ok := range []string{"A", "_x", "OPENAI_API_KEY", "a1"} {
		if ValidateName(ok) != nil {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "1A", "A-B", "A B", "../x"} {
		if ValidateName(bad) == nil {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestRenderEnvIsShellSafe(t *testing.T) {
	values := []Secret{
		{Name: "PLAIN", Value: "abc"},
		{Name: "QUOTES", Value: `it's "quoted" $HOME`},
		{Name: "MULTI", Value: "line1\nline2"},
	}
	env := RenderEnv(values)
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	script := env + `printf '%s|%s|%s' "$PLAIN" "$QUOTES" "$MULTI"`
	out, err := exec.Command(sh, "-c", script).Output()
	if err != nil {
		t.Fatal(err)
	}
	if want := "abc|it's \"quoted\" $HOME|line1\nline2"; string(out) != want {
		t.Errorf("sourced values = %q, want %q", out, want)
	}
}
