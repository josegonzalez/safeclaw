package session

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/secrets"
)

// ErrNoSecret is wrapped by the error returned when a session is asked for a
// secret that is not in the secrets directory.
var ErrNoSecret = errors.New("secret not found")

// SecretSet picks the secrets a session receives. The zero value is every
// secret, including ones added later.
type SecretSet struct {
	// Limited gives the session only Names instead of every secret.
	Limited bool
	// Names are the only secrets a limited set gives, sorted. Empty means
	// none.
	Names []string
}

// AllSecrets returns the set of every secret.
func AllSecrets() SecretSet { return SecretSet{} }

// NoSecrets returns the empty set.
func NoSecrets() SecretSet { return SecretSet{Limited: true} }

// All reports whether the set is every secret.
func (s SecretSet) All() bool { return !s.Limited }

// OnlySecrets returns the set of the named secrets. Names are checked,
// trimmed, deduplicated, and sorted.
func OnlySecrets(names ...string) (SecretSet, error) {
	var out []string
	for _, n := range names {
		n = strings.TrimSpace(n)
		if err := secrets.ValidateName(n); err != nil {
			return SecretSet{}, fmt.Errorf("invalid secret name %q: %w", n, err)
		}
		out = append(out, n)
	}
	slices.Sort(out)
	return SecretSet{Limited: true, Names: slices.Compact(out)}, nil
}

// Includes reports whether the set gives the session the named secret.
func (s SecretSet) Includes(name string) bool {
	return s.All() || slices.Contains(s.Names, name)
}

// Equal reports whether two sets give a session the same secrets.
func (s SecretSet) Equal(o SecretSet) bool {
	if s.All() || o.All() {
		return s.All() == o.All()
	}
	return slices.Equal(s.Names, o.Names)
}

// String returns "all", "none", or the names joined with commas.
func (s SecretSet) String() string {
	switch {
	case s.All():
		return "all"
	case len(s.Names) == 0:
		return "none"
	}
	return strings.Join(s.Names, ",")
}

// secretsOf returns the secrets a session container receives. Containers
// without the label, such as ones created before it existed, get every
// secret; an empty label means none.
func secretsOf(c docker.Container) SecretSet {
	v, ok := c.LookupLabel(config.LabelSecrets)
	if !ok {
		return AllSecrets()
	}
	if v == "" {
		return NoSecrets()
	}
	s, err := OnlySecrets(strings.Split(v, ",")...)
	if err != nil {
		// Only safeclaw writes the label; treat a broken one as none.
		return NoSecrets()
	}
	return s
}

// sessionSecrets returns the secrets a container of either type receives.
// Sandboxes never receive any.
func sessionSecrets(c docker.Container) SecretSet {
	if TypeOf(c) == config.TypeSandbox {
		return NoSecrets()
	}
	return secretsOf(c)
}

// secretArgs returns the `docker run` label that records a set, none for
// every secret.
func secretArgs(s SecretSet) []string {
	if s.All() {
		return nil
	}
	return []string{"--label", config.LabelSecrets + "=" + strings.Join(s.Names, ",")}
}

// SecretNames returns the names of the secrets that can be given to a
// session, sorted.
func (m *Manager) SecretNames() ([]string, error) {
	keys, err := m.Secrets.Keys()
	if err != nil {
		return nil, err
	}
	out := []string{}
	for _, k := range keys {
		if secrets.ValidateName(k) == nil {
			out = append(out, k)
		}
	}
	return out, nil
}

// checkSecrets returns an error wrapping ErrNoSecret for the first name in
// the set that is not in the secrets directory. It uses the store's list of
// names, as selectSecrets does, so an entry the store doesn't treat as a
// secret, such as a symlink in the file store, fails here instead of being
// skipped later.
func (m *Manager) checkSecrets(s SecretSet) error {
	if len(s.Names) == 0 {
		return nil
	}
	keys, err := m.Secrets.Keys()
	if err != nil {
		return err
	}
	for _, n := range s.Names {
		if !slices.Contains(keys, n) {
			return fmt.Errorf("%w: %s. Add it with `safeclaw env set %s`", ErrNoSecret, n, n)
		}
	}
	return nil
}

// selectSecrets returns the secrets in the set, warning about any that are no
// longer in the secrets directory.
func (m *Manager) selectSecrets(s SecretSet) ([]secrets.Secret, error) {
	all, err := m.Secrets.All()
	if err != nil {
		return nil, err
	}
	if s.All() {
		return all, nil
	}
	var out []secrets.Secret
	for _, n := range s.Names {
		i := slices.IndexFunc(all, func(x secrets.Secret) bool { return x.Name == n })
		if i < 0 {
			m.printf("Warning: secret %s is no longer set, skipping it\n", n)
			continue
		}
		out = append(out, all[i])
	}
	return out, nil
}
