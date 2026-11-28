package session

import (
	"archive/tar"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

var mkdirTar = []entry{
	{"./", tar.TypeDir, "", 0o755},
	{"./a.txt", tar.TypeReg, "alpha", 0o644},
	{"./b.txt", tar.TypeReg, "beta", 0o644},
}

func mkdirOpts() CopyOutOptions {
	return CopyOutOptions{NoScan: true, Only: []string{"*.txt"}, Mkdir: true}
}

func TestCopyOutMkdirCreates(t *testing.T) {
	old := syscall.Umask(0o022)
	t.Cleanup(func() { syscall.Umask(old) })
	for _, rel := range []string{"new", filepath.Join("x", "y", "new")} {
		t.Run(rel, func(t *testing.T) {
			base := t.TempDir()
			host := filepath.Join(base, rel)
			m, _ := newCopyManager(t, &copyFake{tarOut: makeTar(t, mkdirTar...)})
			paths, err := m.CopyOut(context.Background(), "box", "out", host, mkdirOpts())
			if err != nil {
				t.Fatal(err)
			}
			want := []string{filepath.Join(host, "a.txt"), filepath.Join(host, "b.txt")}
			if !reflect.DeepEqual(paths, want) {
				t.Errorf("paths = %v, want %v", paths, want)
			}
			if got := dirContents(t, host); !reflect.DeepEqual(got, map[string]string{"a.txt": "alpha", "b.txt": "beta"}) {
				t.Errorf("host dir = %v", got)
			}
			for p := host; p != base; p = filepath.Dir(p) {
				fi, err := os.Lstat(p)
				if err != nil {
					t.Fatal(err)
				}
				if !fi.IsDir() || fi.Mode().Perm() != 0o755 {
					t.Errorf("%s mode = %v, want a 0755 directory", p, fi.Mode())
				}
			}
			// Only the new tree is left in the existing ancestor: the
			// temporary directory is gone.
			top := strings.SplitN(rel, string(filepath.Separator), 2)[0]
			if got := dirContents(t, base); len(got) != 1 || got[top] != "" {
				t.Errorf("ancestor = %v, want only %s", got, top)
			}
		})
	}
}

func TestCopyOutMkdirNothingMatched(t *testing.T) {
	host := filepath.Join(t.TempDir(), "new")
	m, _ := newCopyManager(t, &copyFake{tarOut: makeTar(t, mkdirTar[0])})
	if _, err := m.CopyOut(context.Background(), "box", "out", host, mkdirOpts()); err != nil {
		t.Fatal(err)
	}
	if got := dirContents(t, host); len(got) != 0 {
		t.Errorf("host dir = %v, want empty", got)
	}
}

func TestCopyOutMkdirExisting(t *testing.T) {
	host := t.TempDir()
	writeFile(t, filepath.Join(host, "a.txt"), "old a")
	writeFile(t, filepath.Join(host, "keep.log"), "keep")

	// An existing directory is used as it is, with the usual rules.
	m, _ := newCopyManager(t, &copyFake{tarOut: makeTar(t, mkdirTar...)})
	if _, err := m.CopyOut(context.Background(), "box", "out", host, mkdirOpts()); !errors.Is(err, ErrFileExists) {
		t.Errorf("err = %v, want ErrFileExists", err)
	}
	opts := mkdirOpts()
	opts.Replace = true
	m, _ = newCopyManager(t, &copyFake{tarOut: makeTar(t, mkdirTar...)})
	if _, err := m.CopyOut(context.Background(), "box", "out", host, opts); err != nil {
		t.Fatal(err)
	}
	if got := dirContents(t, host); !reflect.DeepEqual(got, map[string]string{"a.txt": "alpha", "b.txt": "beta", "keep.log": "keep"}) {
		t.Errorf("host dir = %v", got)
	}

	// So is a symlink to a directory, with or without --mkdir.
	for _, mkdir := range []bool{false, true} {
		target := t.TempDir()
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		opts := mkdirOpts()
		opts.Mkdir = mkdir
		m, _ := newCopyManager(t, &copyFake{tarOut: makeTar(t, mkdirTar...)})
		if _, err := m.CopyOut(context.Background(), "box", "out", link, opts); err != nil {
			t.Fatalf("mkdir=%v: %v", mkdir, err)
		}
		if got := dirContents(t, target); len(got) != 2 {
			t.Errorf("mkdir=%v: link target = %v", mkdir, got)
		}
	}
}

func TestCopyOutMkdirRefuses(t *testing.T) {
	cases := []struct {
		name  string
		setup func(t *testing.T, base string) string
		want  string
	}{
		{"file", func(t *testing.T, base string) string {
			return writeFile(t, filepath.Join(base, "f"), "x")
		}, "is not a directory"},
		{"file parent", func(t *testing.T, base string) string {
			return filepath.Join(writeFile(t, filepath.Join(base, "f"), "x"), "sub", "new")
		}, "not a directory"},
		{"dangling link", func(t *testing.T, base string) string {
			link := filepath.Join(base, "link")
			if err := os.Symlink(filepath.Join(base, "missing"), link); err != nil {
				t.Fatal(err)
			}
			return link
		}, ErrSymlink.Error()},
		{"link to file", func(t *testing.T, base string) string {
			link := filepath.Join(base, "link")
			if err := os.Symlink(writeFile(t, filepath.Join(base, "f"), "x"), link); err != nil {
				t.Fatal(err)
			}
			return link
		}, "is not a directory"},
		{"dangling link parent", func(t *testing.T, base string) string {
			link := filepath.Join(base, "link")
			if err := os.Symlink(filepath.Join(base, "missing"), link); err != nil {
				t.Fatal(err)
			}
			return filepath.Join(link, "new")
		}, ErrSymlink.Error()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			host := tc.setup(t, base)
			before := hostEntries(t, base)
			m, r := newCopyManager(t, &copyFake{tarOut: makeTar(t, mkdirTar...)})
			_, err := m.CopyOut(context.Background(), "box", "out", host, mkdirOpts())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
			if hasExec(r) {
				t.Error("read the sandbox before refusing")
			}
			if got := hostEntries(t, base); !reflect.DeepEqual(got, before) {
				t.Errorf("base = %v, want %v", got, before)
			}
			if _, err := os.Lstat(filepath.Join(base, "missing")); err == nil {
				t.Error("created the dangling link's target")
			}
		})
	}
}

func TestCopyOutMissingWithoutMkdir(t *testing.T) {
	base := t.TempDir()
	m, r := newCopyManager(t, &copyFake{tarOut: makeTar(t, mkdirTar...)})
	_, err := m.CopyOut(context.Background(), "box", "out", filepath.Join(base, "new"), CopyOutOptions{NoScan: true, Only: []string{"*"}})
	if err == nil || !strings.Contains(err.Error(), "--mkdir") {
		t.Errorf("err = %v, want a hint at --mkdir", err)
	}
	if hasExec(r) || len(dirContents(t, base)) != 0 {
		t.Error("copied without HOST_DIR")
	}
}

// TestCopyOutMkdirFailureLeavesNothing checks that a copy that fails or is
// refused at any stage creates no directories.
func TestCopyOutMkdirFailureLeavesNothing(t *testing.T) {
	check := func(t *testing.T, base string, err error, want string) {
		t.Helper()
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("err = %v, want %q", err, want)
		}
		if got := dirContents(t, base); len(got) != 0 {
			t.Errorf("left %v behind", got)
		}
	}

	t.Run("stream", func(t *testing.T) {
		base := t.TempDir()
		m, _ := newCopyManager(t, &copyFake{tarOut: makeTar(t, mkdirTar...), tarErr: errors.New("tar failed")})
		_, err := m.CopyOut(context.Background(), "box", "out", filepath.Join(base, "x", "new"), mkdirOpts())
		check(t, base, err, "tar failed")
	})

	t.Run("limit", func(t *testing.T) {
		base := t.TempDir()
		opts := mkdirOpts()
		opts.MaxFiles = 1
		m, _ := newCopyManager(t, &copyFake{tarOut: makeTar(t, mkdirTar...)})
		_, err := m.CopyOut(context.Background(), "box", "out", filepath.Join(base, "x", "new"), opts)
		check(t, base, err, ErrTooManyFiles.Error())
	})

	t.Run("flagged", func(t *testing.T) {
		base := t.TempDir()
		m, _ := newScanManager(t, &copyFake{tarOut: makeTar(t, scanTar...)}, nil)
		_, err := m.CopyOut(context.Background(), "box", "out", filepath.Join(base, "x", "new"), CopyOutOptions{Only: []string{"*.txt"}, Mkdir: true})
		check(t, base, err, `"bad.txt": infected`)
	})

	t.Run("move", func(t *testing.T) {
		base := t.TempDir()
		orig := renameDir
		renameDir = func(string, string) error { return syscall.EIO }
		t.Cleanup(func() { renameDir = orig })
		m, _ := newCopyManager(t, &copyFake{tarOut: makeTar(t, mkdirTar...)})
		_, err := m.CopyOut(context.Background(), "box", "out", filepath.Join(base, "x", "new"), mkdirOpts())
		check(t, base, err, syscall.EIO.Error())
	})

	t.Run("created meanwhile", func(t *testing.T) {
		base := t.TempDir()
		orig := renameDir
		renameDir = func(from, to string) error {
			writeFile(t, filepath.Join(to, "theirs.txt"), "theirs")
			return orig(from, to)
		}
		t.Cleanup(func() { renameDir = orig })
		m, _ := newCopyManager(t, &copyFake{tarOut: makeTar(t, mkdirTar...)})
		_, err := m.CopyOut(context.Background(), "box", "out", filepath.Join(base, "new"), mkdirOpts())
		if err == nil || !strings.Contains(err.Error(), "created during the copy") {
			t.Errorf("err = %v", err)
		}
		if got := dirContents(t, filepath.Join(base, "new")); !reflect.DeepEqual(got, map[string]string{"theirs.txt": "theirs"}) {
			t.Errorf("new = %v", got)
		}
	})
}

// TestCopyOutMkdirScansStaged checks that the scan of files bound for a new
// HOST_DIR sees them, and that they are placed once clean.
func TestCopyOutMkdirScansStaged(t *testing.T) {
	host := filepath.Join(t.TempDir(), "x", "new")
	m, r := newScanManager(t, &copyFake{tarOut: makeTar(t, scanTar[0], scanTar[1], scanTar[3])}, nil)
	res, err := m.CopyOutReport(context.Background(), "box", "out", host, CopyOutOptions{Only: []string{"*.txt"}, Mkdir: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Scan == nil || len(res.Scan.Results) != 2 || len(res.Scan.Flagged()) != 0 {
		t.Errorf("scan = %+v", res.Scan)
	}
	if !hasCall(r, "run ") {
		t.Error("no scan container")
	}
	if got := dirContents(t, host); !reflect.DeepEqual(got, map[string]string{"a.txt": "alpha", "c.txt": "gamma"}) {
		t.Errorf("host dir = %v", got)
	}
}

// TestCopyOutMkdirRelative checks a relative HOST_DIR whose nearest existing
// ancestor is the working directory.
func TestCopyOutMkdirRelative(t *testing.T) {
	base := t.TempDir()
	t.Chdir(base)
	m, _ := newScanManager(t, &copyFake{tarOut: makeTar(t, mkdirTar...)}, nil)
	paths, err := m.CopyOut(context.Background(), "box", "out", filepath.Join("x", "new"), CopyOutOptions{Only: []string{"*.txt"}, Mkdir: true})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{filepath.Join("x", "new", "a.txt"), filepath.Join("x", "new", "b.txt")}; !reflect.DeepEqual(paths, want) {
		t.Errorf("paths = %v, want %v", paths, want)
	}
	if got := dirContents(t, filepath.Join(base, "x", "new")); len(got) != 2 {
		t.Errorf("host dir = %v", got)
	}
}

// TestCopyOutMkdirLinkedParent checks that a symlink among the existing
// parents is followed, as mkdir -p does, so the new directory is created
// in its target.
func TestCopyOutMkdirLinkedParent(t *testing.T) {
	target := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	m, _ := newCopyManager(t, &copyFake{tarOut: makeTar(t, mkdirTar...)})
	if _, err := m.CopyOut(context.Background(), "box", "out", filepath.Join(link, "new"), mkdirOpts()); err != nil {
		t.Fatal(err)
	}
	if got := dirContents(t, filepath.Join(target, "new")); len(got) != 2 {
		t.Errorf("new = %v", got)
	}
}
