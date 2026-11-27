package secrets

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// FileStore is a secrets directory. Each file is one env var: the filename is
// the name and the contents are the value. It is used when no keychain is
// available.
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

// Has implements Store.
func (s FileStore) Has(name string) bool {
	info, err := os.Stat(filepath.Join(s.Dir, name))
	return err == nil && info.Mode().IsRegular()
}

// Get returns a secret value with trailing newlines removed, matching the
// shell's `$(cat file)`.
func (s FileStore) Get(name string) (string, error) {
	b, err := os.ReadFile(filepath.Join(s.Dir, name))
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

// Set writes a secret with 0600 permissions, creating the directory with 0700.
func (s FileStore) Set(name, value string) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return err
	}
	path := filepath.Join(s.Dir, name)
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		return err
	}
	// WriteFile keeps the mode of an existing file; force 0600.
	return os.Chmod(path, 0o600)
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
	info, err := os.Stat(filepath.Join(s.Dir, name))
	if err != nil {
		return time.Time{}, err
	}
	return info.ModTime(), nil
}

// Location implements Store.
func (s FileStore) Location() string { return s.Dir }

func isNotExist(err error) bool { return errors.Is(err, os.ErrNotExist) }
