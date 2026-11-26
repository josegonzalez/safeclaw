// Package secrets manages the host-side secrets directory. Each file is one
// env var: the filename is the name and the contents are the value.
package secrets

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Well-known secret names.
const (
	ClaudeToken = "CLAUDE_CODE_OAUTH_TOKEN"
	GitHubToken = "GH_TOKEN"
)

var nameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ValidateName checks that name is usable as an env var name.
func ValidateName(name string) error {
	if name == "" {
		return errors.New("name is required")
	}
	if !nameRe.MatchString(name) {
		return errors.New("use letters, numbers, and underscores only")
	}
	return nil
}

// Store is a secrets directory.
type Store struct {
	Dir string
}

// Secret is one env var.
type Secret struct {
	Name  string
	Value string
}

// Keys returns the names of all secrets, sorted.
func (s Store) Keys() ([]string, error) {
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

// Has reports whether a secret file exists.
func (s Store) Has(name string) bool {
	info, err := os.Stat(filepath.Join(s.Dir, name))
	return err == nil && info.Mode().IsRegular()
}

// Get returns a secret value with trailing newlines removed, matching the
// shell's `$(cat file)`.
func (s Store) Get(name string) (string, error) {
	b, err := os.ReadFile(filepath.Join(s.Dir, name))
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}

// All returns every secret that can be used as an env var, sorted by name.
// Files whose names are not valid env var names are skipped.
func (s Store) All() ([]Secret, error) {
	keys, err := s.Keys()
	if err != nil {
		return nil, err
	}
	var out []Secret
	for _, k := range keys {
		if ValidateName(k) != nil {
			continue
		}
		v, err := s.Get(k)
		if err != nil {
			return nil, err
		}
		out = append(out, Secret{Name: k, Value: v})
	}
	return out, nil
}

// Set writes a secret with 0600 permissions, creating the directory with 0700.
func (s Store) Set(name, value string) (string, error) {
	if err := ValidateName(name); err != nil {
		return "", err
	}
	if err := os.MkdirAll(s.Dir, 0o700); err != nil {
		return "", err
	}
	path := filepath.Join(s.Dir, name)
	if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
		return "", err
	}
	// WriteFile keeps the mode of an existing file; force 0600.
	if err := os.Chmod(path, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

// Delete removes a secret.
func (s Store) Delete(name string) error {
	if err := ValidateName(name); err != nil {
		return fmt.Errorf("invalid key %q: %w", name, err)
	}
	return os.Remove(filepath.Join(s.Dir, name))
}

// ShellQuote quotes s for POSIX sh using single quotes.
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// RenderEnv renders secrets as an env file of `export NAME='value'` lines.
func RenderEnv(secrets []Secret) string {
	var b strings.Builder
	for _, s := range secrets {
		fmt.Fprintf(&b, "export %s=%s\n", s.Name, ShellQuote(s.Value))
	}
	return b.String()
}
