package config

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// ErrUnsafeDir is wrapped by the error SecureDir returns for a config
// directory another user controls.
var ErrUnsafeDir = errors.New("config directory is not safe to use")

// fileOwner returns the uid owning a file. Tests replace it.
var fileOwner = ownerOf

// SecureDir makes sure the config directory, if it exists, is a directory
// only the current user can open. It holds session history, ttyd
// credentials, and dashboard tokens. One owned by the user but open to
// others, for example one created with `mkdir -p` to write config.yaml, is
// restricted to 0700, with a note on out. One owned by another user is
// refused: they could read or replace what safeclaw keeps there. A symlink
// is followed, and its target is checked. A missing directory is left to be
// created, with 0700, when something is first written there.
func SecureDir(out io.Writer) error {
	return secureDir(Dir(), out)
}

func secureDir(dir string, out io.Writer) error {
	info, err := os.Stat(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrUnsafeDir, dir)
	}
	if uid, ok := fileOwner(info); ok && uid != os.Geteuid() {
		return fmt.Errorf("%w: %s is owned by uid %d, not by you (uid %d). Remove it, or set XDG_CONFIG_HOME to a directory you own", ErrUnsafeDir, dir, uid, os.Geteuid())
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		if err := os.Chmod(dir, 0o700); err != nil {
			return fmt.Errorf("restricting %s to its owner: %w", dir, err)
		}
		_, _ = fmt.Fprintf(out, "Restricted %s to its owner (mode %#o, was %#o)\n", dir, 0o700, perm)
	}
	return nil
}
