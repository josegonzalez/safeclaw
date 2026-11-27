package config

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func perm(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}

func TestSecureDir(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", base)
	dir := filepath.Join(base, "safeclaw")
	var out bytes.Buffer

	// A missing directory is not created.
	if err := SecureDir(&out); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); !errors.Is(err, os.ErrNotExist) || out.Len() > 0 {
		t.Fatalf("missing dir: %v %q", err, out.String())
	}

	// One open to others is restricted to its owner, with a note.
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := SecureDir(&out); err != nil {
		t.Fatal(err)
	}
	if got := perm(t, dir); got != 0o700 || !strings.Contains(out.String(), "Restricted "+dir+" to its owner (mode 0700, was 0755)") {
		t.Errorf("mode %#o, out %q", got, out.String())
	}

	// A private one is left alone.
	out.Reset()
	if err := SecureDir(&out); err != nil || out.Len() > 0 {
		t.Errorf("private dir: %v %q", err, out.String())
	}

	// A symlink's target is checked and restricted.
	target := filepath.Join(base, "elsewhere")
	if err := os.Mkdir(target, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, dir); err != nil {
		t.Fatal(err)
	}
	if err := SecureDir(&out); err != nil {
		t.Fatal(err)
	}
	if got := perm(t, target); got != 0o700 {
		t.Errorf("symlink target mode %#o", got)
	}

	// A file is refused.
	if err := os.Remove(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := SecureDir(&out); !errors.Is(err, ErrUnsafeDir) {
		t.Errorf("file: err = %v", err)
	}
}

func TestSecureDirForeignOwner(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", base)
	dir := filepath.Join(base, "safeclaw")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	orig := fileOwner
	t.Cleanup(func() { fileOwner = orig })
	fileOwner = func(os.FileInfo) (int, bool) { return os.Geteuid() + 1, true }

	var out bytes.Buffer
	err := SecureDir(&out)
	if !errors.Is(err, ErrUnsafeDir) || !strings.Contains(err.Error(), "XDG_CONFIG_HOME") {
		t.Errorf("err = %v", err)
	}
	// It is refused before anything changes.
	if got := perm(t, dir); got != 0o755 || out.Len() > 0 {
		t.Errorf("mode %#o, out %q", got, out.String())
	}
}
