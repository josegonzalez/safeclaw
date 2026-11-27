package secrets

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/zalando/go-keyring"
)

// Service is the keychain service secrets are stored under.
const Service = "safeclaw"

// indexItem is the keychain item listing every secret and when it was set,
// since the keychain can't list items or say when they were written. It is
// not a valid env var name, so no secret can use it.
const indexItem = ".index"

// KeyringStore keeps each secret as an item in the system keychain (the
// macOS keychain, Secret Service on Linux, or the Windows credential
// manager).
type KeyringStore struct {
	// Service is the keychain service. Defaults to Service.
	Service string
	// LockPath is the file locked while the index is updated, so separate
	// safeclaw processes don't lose each other's changes.
	LockPath string
}

var _ Store = KeyringStore{}

func (s KeyringStore) service() string {
	if s.Service == "" {
		return Service
	}
	return s.Service
}

// index returns the stored names and set times.
func (s KeyringStore) index() (map[string]time.Time, error) {
	raw, err := keyring.Get(s.service(), indexItem)
	if errors.Is(err, keyring.ErrNotFound) {
		return map[string]time.Time{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read keychain: %w", err)
	}
	idx := map[string]time.Time{}
	if err := json.Unmarshal([]byte(raw), &idx); err != nil {
		return nil, fmt.Errorf("read keychain index: %w", err)
	}
	return idx, nil
}

func (s KeyringStore) writeIndex(idx map[string]time.Time) error {
	b, err := json.Marshal(idx)
	if err != nil {
		return err
	}
	if err := keyring.Set(s.service(), indexItem, string(b)); err != nil {
		return fmt.Errorf("write keychain index: %w", err)
	}
	return nil
}

// update changes the index under the lock.
func (s KeyringStore) update(fn func(idx map[string]time.Time) error) error {
	unlock, err := lock(s.LockPath)
	if err != nil {
		return err
	}
	defer unlock()
	idx, err := s.index()
	if err != nil {
		return err
	}
	if err := fn(idx); err != nil {
		return err
	}
	return s.writeIndex(idx)
}

// Keys implements Store.
func (s KeyringStore) Keys() ([]string, error) {
	idx, err := s.index()
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(idx))
	for k := range idx {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys, nil
}

// Has implements Store.
func (s KeyringStore) Has(name string) bool {
	idx, err := s.index()
	if err != nil {
		return false
	}
	_, ok := idx[name]
	return ok
}

// Get implements Store.
func (s KeyringStore) Get(name string) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", fmt.Errorf("invalid key %q: %w", name, err)
	}
	v, err := keyring.Get(s.service(), name)
	if errors.Is(err, keyring.ErrNotFound) {
		return "", fmt.Errorf("secret %s: %w", name, os.ErrNotExist)
	}
	if err != nil {
		return "", fmt.Errorf("read %s from the keychain: %w", name, err)
	}
	return v, nil
}

// All implements Store.
func (s KeyringStore) All() ([]Secret, error) {
	keys, err := s.Keys()
	if err != nil {
		return nil, err
	}
	return all(s, keys)
}

// Set implements Store.
func (s KeyringStore) Set(name, value string) error {
	return s.setAt(name, value, time.Now())
}

func (s KeyringStore) setAt(name, value string, at time.Time) error {
	if err := ValidateName(name); err != nil {
		return err
	}
	return s.update(func(idx map[string]time.Time) error {
		if err := keyring.Set(s.service(), name, value); err != nil {
			if errors.Is(err, keyring.ErrSetDataTooBig) {
				return fmt.Errorf("%s is too long to store in the keychain", name)
			}
			return fmt.Errorf("store %s in the keychain: %w", name, err)
		}
		idx[name] = at.UTC()
		return nil
	})
}

// Delete implements Store.
func (s KeyringStore) Delete(name string) error {
	if err := ValidateName(name); err != nil {
		return fmt.Errorf("invalid key %q: %w", name, err)
	}
	return s.update(func(idx map[string]time.Time) error {
		_, listed := idx[name]
		delete(idx, name)
		err := keyring.Delete(s.service(), name)
		switch {
		case errors.Is(err, keyring.ErrNotFound):
			if !listed {
				return fmt.Errorf("secret %s: %w", name, os.ErrNotExist)
			}
		case err != nil:
			return fmt.Errorf("delete %s from the keychain: %w", name, err)
		}
		return nil
	})
}

// SetAt implements Store.
func (s KeyringStore) SetAt(name string) (time.Time, error) {
	idx, err := s.index()
	if err != nil {
		return time.Time{}, err
	}
	at, ok := idx[name]
	if !ok {
		return time.Time{}, fmt.Errorf("secret %s: %w", name, os.ErrNotExist)
	}
	return at, nil
}

// Location implements Store.
func (s KeyringStore) Location() string {
	return fmt.Sprintf("the system keychain (service %q)", s.service())
}

// lock takes an exclusive lock on path, creating it and its directory if
// needed. An empty path takes no lock.
func lock(path string) (func(), error) {
	if path == "" {
		return func() {}, nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return func() {
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
