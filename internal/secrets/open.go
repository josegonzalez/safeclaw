package secrets

import (
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/zalando/go-keyring"
)

// Open returns the keychain store when the system keychain is usable, and
// otherwise the file store in dir, warning on warn. When the keychain is
// usable, secrets left in dir by earlier versions are moved into it and dir
// is removed once empty; a secret that can't be moved stays in dir, with a
// warning, and is retried next time. lockPath is the file locked while the
// keychain index changes.
func Open(dir, lockPath string, warn io.Writer) Store {
	if warn == nil {
		warn = io.Discard
	}
	ks := KeyringStore{LockPath: lockPath}
	if err := Available(ks.service()); err != nil {
		fmt.Fprintf(warn, "Warning: the system keychain is unavailable (%v), so secrets are stored in %s\n", err, dir)
		return FileStore{Dir: dir}
	}
	if err := migrate(FileStore{Dir: dir}, ks, warn); err != nil {
		fmt.Fprintf(warn, "Warning: could not move secrets from %s into the keychain: %v\n", dir, err)
	}
	return ks
}

// Available returns nil if the keychain can be read.
func Available(service string) error {
	_, err := keyring.Get(service, indexItem)
	if err == nil || errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}

// migrate moves every file secret into the keychain, keeping its set time,
// and removes the directory once it is empty.
func migrate(from FileStore, to KeyringStore, out io.Writer) error {
	keys, err := from.Keys()
	if err != nil || len(keys) == 0 {
		return err
	}
	moved := 0
	defer func() {
		if moved > 0 {
			fmt.Fprintf(out, "Moved %d secret(s) from %s into %s\n", moved, from.Dir, to.Location())
		}
	}()
	for _, k := range keys {
		if ValidateName(k) != nil {
			continue
		}
		v, err := from.Get(k)
		if err != nil {
			return err
		}
		at, err := from.SetAt(k)
		if err != nil {
			return err
		}
		if err := to.setAt(k, v, at); err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
		// Only drop the file once the keychain has it.
		if err := from.Delete(k); err != nil {
			return err
		}
		moved++
	}
	if rest, _ := from.Keys(); len(rest) > 0 {
		fmt.Fprintf(out, "Warning: %s has files that are not valid env var names, so they were left there\n", from.Dir)
		return nil
	}
	// Best effort: anything else left in the directory keeps it.
	_ = os.Remove(from.Dir)
	return nil
}
