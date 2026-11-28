package session

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

// MaxExecEnvBytes bounds the rendered `sandbox exec -e` variables. They
// reach docker through a pipe written before docker starts, so they must
// fit in its buffer (16 KiB on macOS, 64 KiB on Linux).
const MaxExecEnvBytes = 8 << 10

// envName is a portable environment variable name.
var envName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ErrSecretEnv is returned when `sandbox exec -e` names a secret.
var ErrSecretEnv = errors.New("is the name of a safeclaw secret, which sandboxes never receive")

// ExecEnv checks `sandbox exec -e` specs and `--env-if-set` names and
// returns them as a docker --env-file. Each spec is NAME=VALUE, or NAME to
// take the value from lookup (the caller's environment); a NAME lookup
// doesn't find is refused rather than left unset. Each ifSet name takes
// its value from lookup the same way, but is left out when lookup doesn't
// find it; a variable set to "" counts as set. Names must be portable,
// appear once across both lists, and not be a stored secret's or a
// token's, so a sandbox can't be handed a secret by mistake; these checks
// apply to ifSet names whether or not they are set. Values must be valid
// UTF-8 without newlines, carriage returns, or NUL bytes, which an env
// file can't hold, and the whole file must fit in MaxExecEnvBytes. Empty
// specs and ifSet give "".
func (m *Manager) ExecEnv(specs, ifSet []string, lookup func(string) (string, bool)) (string, error) {
	if len(specs) == 0 && len(ifSet) == 0 {
		return "", nil
	}
	secretNames, err := m.secretNameSet()
	if err != nil {
		return "", fmt.Errorf("could not list the stored secrets to check -e against: %w", err)
	}
	var b strings.Builder
	seen := map[string]bool{}
	// claim checks a name before its value is looked up.
	claim := func(flag, name string) error {
		if seen[name] {
			return fmt.Errorf("%s %s: %s is given more than once across -e and --env-if-set", flag, name, name)
		}
		seen[name] = true
		if secretNames[name] {
			return fmt.Errorf("%s %s %w", flag, name, ErrSecretEnv)
		}
		return nil
	}
	write := func(flag, name, value string) error {
		if !utf8.ValidString(value) || strings.ContainsAny(value, "\n\r\x00") {
			return fmt.Errorf("%s %s: the value must be UTF-8 text without newlines, carriage returns, or NUL bytes", flag, name)
		}
		b.WriteString(name + "=" + value + "\n")
		return nil
	}
	for _, spec := range specs {
		name, value, ok := strings.Cut(spec, "=")
		if !envName.MatchString(name) {
			return "", fmt.Errorf("invalid -e %q: expected NAME=VALUE or NAME, where NAME is letters, digits, and _", name)
		}
		if err := claim("-e", name); err != nil {
			return "", err
		}
		if !ok {
			if value, ok = lookup(name); !ok {
				return "", fmt.Errorf("-e %s: %s is not set in the environment", name, name)
			}
		}
		if err := write("-e", name, value); err != nil {
			return "", err
		}
	}
	for _, name := range ifSet {
		// Never echo what follows an "=", which may be a value.
		if before, _, ok := strings.Cut(name, "="); ok {
			return "", fmt.Errorf("invalid --env-if-set %q: it takes a NAME only, with no =VALUE; use -e NAME=VALUE to set a value", before)
		}
		if !envName.MatchString(name) {
			return "", fmt.Errorf("invalid --env-if-set %q: expected NAME, where NAME is letters, digits, and _", name)
		}
		if err := claim("--env-if-set", name); err != nil {
			return "", err
		}
		if value, ok := lookup(name); ok {
			if err := write("--env-if-set", name, value); err != nil {
				return "", err
			}
		}
	}
	if b.Len() > MaxExecEnvBytes {
		return "", fmt.Errorf("-e and --env-if-set values take %d bytes, more than the %d allowed", b.Len(), MaxExecEnvBytes)
	}
	return b.String(), nil
}
