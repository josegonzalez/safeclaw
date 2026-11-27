// Package secrets manages the host-side secrets that are injected into
// sessions as env vars. They are kept in the system keychain when one is
// available, and otherwise in a directory with one file per env var.
package secrets

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
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

// Store holds secrets. Reading or deleting a secret that is not set returns
// an error wrapping os.ErrNotExist.
type Store interface {
	// Keys returns the names of all secrets, sorted.
	Keys() ([]string, error)
	// Has reports whether a secret is set.
	Has(name string) bool
	// Get returns a secret's value.
	Get(name string) (string, error)
	// All returns every secret that can be used as an env var, sorted by
	// name.
	All() ([]Secret, error)
	// Set stores a secret, replacing any earlier value.
	Set(name, value string) error
	// Delete removes a secret.
	Delete(name string) error
	// SetAt returns when a secret was last stored.
	SetAt(name string) (time.Time, error)
	// Location describes where secrets are kept, for messages.
	Location() string
}

// Secret is one env var.
type Secret struct {
	Name  string
	Value string
}

// all returns every secret in keys with a valid env var name, skipping ones
// that disappeared since the keys were listed.
func all(s Store, keys []string) ([]Secret, error) {
	var out []Secret
	for _, k := range keys {
		if ValidateName(k) != nil {
			continue
		}
		v, err := s.Get(k)
		if err != nil {
			if isNotExist(err) {
				continue
			}
			return nil, err
		}
		out = append(out, Secret{Name: k, Value: v})
	}
	return out, nil
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
