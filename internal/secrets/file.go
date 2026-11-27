package secrets

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

// FileStore is a secrets directory. Each file is one env var: the filename is
// the name and the contents are the value. It is used when no keychain is
// available.
//
// Only regular files are secrets. The store checks names itself and never
// follows a symlink in the directory, so it doesn't rely on its callers for
// either.
type FileStore struct {
	Dir string
}

var _ Store = FileStore{}

// Keys implements Store.
func (s FileStore) Keys() ([]string, error) {
	entries, err := os.ReadDir(s.Dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var keys []string
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		keys = append(keys, e.Name())
	}
	sort.Strings(keys)
	return keys, nil
}

// open opens a secret's file for reading. An invalid name is an error, and
// an entry that is not a regular file, such as a symlink, is treated as not
// set: the error wraps os.ErrNotExist, matching Keys.
func (s FileStore) open(name string) (*os.File, os.FileInfo, error) {
	if err := ValidateName(name); err != nil {
		return nil, nil, fmt.Errorf("invalid key %q: %w", name, err)
	}
	path := filepath.Join(s.Dir, name)
	// O_NONBLOCK keeps a FIFO from blocking the open; it is refused below.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, syscall.ELOOP) {
		return nil, nil, notRegular(path)
	}
	if err != nil {
		return nil, nil, err
	}
	info, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		_ = f.Close()
		return nil, nil, notRegular(path)
	}
	return f, info, nil
}

func notRegular(path string) error {
	return fmt.Errorf("%s is not a regular file: %w", path, os.ErrNotExist)
}

// Has implements Store.
func (s FileStore) Has(name string) bool {
	f, _, err := s.open(name)
	if err != nil {
		return false
	}
	_ = f.Close()
	return true
}

// Get returns a secret value with trailing newlines removed, matching the
// shell's `$(cat file)`.
func (s FileStore) Get(name string) (string, error) {
	f, _, err := s.open(name)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(f)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

// All implements Store. Files whose names are not valid env var names are
// skipped.
func (s FileStore) All() ([]Secret, error) {
	keys, err := s.Keys()
	if err != nil {
		return nil, err
	}
	return all(s, keys)
}

// Set writes a secret to a new 0600 file and renames it into place, so the
// value is never readable with an older file's mode and a symlink in its
// place is replaced rather than followed. The directory is created with
// 0700, or tightened to 0700 if it already exists with looser permissions.
func (s FileStore) Set(name, value string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	if err := s.tighten(); err != nil {
		return err
	}
	// The leading dot makes the temp file's name invalid, so one left by a
	// crash is never read as a secret.
	f, err := os.CreateTemp(s.Dir, "."+name+".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if _, err := f.WriteString(value); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(s.Dir, name))
}

// tighten removes group and other permissions from the directory if it
// exists.
func (s FileStore) tighten() error {
	info, err := os.Stat(s.Dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", s.Dir)
	}
	if info.Mode().Perm()&0o077 == 0 {
		return nil
	}
	if err := os.Chmod(s.Dir, 0o700); err != nil {
		return fmt.Errorf("restrict %s to its owner: %w", s.Dir, err)
	}
	return nil
}

// Delete implements Store.
func (s FileStore) Delete(name string) error {
	if err := ValidateName(name); err != nil {
		return fmt.Errorf("invalid key %q: %w", name, err)
	}
	return os.Remove(filepath.Join(s.Dir, name))
}

// SetAt returns the file's modification time.
func (s FileStore) SetAt(name string) (time.Time, error) {
	f, info, err := s.open(name)
	if err != nil {
		return time.Time{}, err
	}
	_ = f.Close()
	return info.ModTime(), nil
}

// Location implements Store.
func (s FileStore) Location() string { return s.Dir }

func isNotExist(err error) bool { return errors.Is(err, os.ErrNotExist) }
