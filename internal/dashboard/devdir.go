package dashboard

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// defaultDevDir is where --dev reads templates and static files from,
// relative to the working directory.
const defaultDevDir = "internal/dashboard"

// devSubdirs are the directories under the dev directory that the
// dashboard reads from.
var devSubdirs = []string{"templates", "static"}

// openDevDir opens dir for --dev and returns it with its absolute path.
// Files are read through the returned root, so a symlink that leads out of
// dir is refused, and swapping dir or one of its parents for another
// directory once it is open changes nothing. dir, templates, and static
// must be directories owned by the current user that no one else can
// write to, since whatever is in them is served with the dashboard's token.
func openDevDir(dir string) (*os.Root, string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, "", fmt.Errorf("--dev: %w", err)
	}
	root, err := os.OpenRoot(abs)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, "", fmt.Errorf("--dev needs %s; run it from the repository root: %w", abs, err)
		}
		return nil, "", fmt.Errorf("--dev: %w", err)
	}
	check := func(name, path string) error {
		fi, err := root.Stat(name)
		if err != nil {
			return fmt.Errorf("--dev needs %s: %w", path, err)
		}
		return checkDevDir(path, fi)
	}
	if err := check(".", abs); err != nil {
		_ = root.Close()
		return nil, "", err
	}
	for _, sub := range devSubdirs {
		if err := check(sub, filepath.Join(abs, sub)); err != nil {
			_ = root.Close()
			return nil, "", err
		}
	}
	return root, abs, nil
}

// checkDevDir returns an error unless fi, the directory at path, is owned
// by the current user and is neither group- nor world-writable.
func checkDevDir(path string, fi fs.FileInfo) error {
	if !fi.IsDir() {
		return fmt.Errorf("--dev needs %s to be a directory", path)
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("--dev can't tell who owns %s", path)
	}
	if uid := os.Getuid(); st.Uid != uint32(uid) {
		return fmt.Errorf("--dev refuses %s: it is owned by uid %d, not the current user (uid %d)", path, st.Uid, uid)
	}
	if perm := fi.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("--dev refuses %s: it is group- or world-writable (mode %#o); run chmod go-w %s", path, perm, path)
	}
	return nil
}
