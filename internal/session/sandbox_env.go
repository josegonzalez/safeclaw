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

// ExecEnv checks `sandbox exec -e` specs and returns them as a docker
// --env-file. Each spec is NAME=VALUE, or NAME to take the value from
// lookup (the caller's environment); a NAME lookup doesn't find is
// refused rather than left unset. Names must be portable, appear once,
// and not be a stored secret's or a token's, so a sandbox can't be handed
// a secret by mistake. Values must be valid UTF-8 without newlines,
// carriage returns, or NUL bytes, which an env file can't hold, and the
// whole file must fit in MaxExecEnvBytes. An empty specs gives "".
func (m *Manager) ExecEnv(specs []string, lookup func(string) (string, bool)) (string, error) {
	if len(specs) == 0 {
		return "", nil
	}
	secretNames, err := m.secretNameSet()
	if err != nil {
		return "", fmt.Errorf("could not list the stored secrets to check -e against: %w", err)
	}
	var b strings.Builder
	seen := map[string]bool{}
	for _, spec := range specs {
		name, value, ok := strings.Cut(spec, "=")
		if !envName.MatchString(name) {
			return "", fmt.Errorf("invalid -e %q: expected NAME=VALUE or NAME, where NAME is letters, digits, and _", name)
		}
		if seen[name] {
			return "", fmt.Errorf("-e %s is given more than once", name)
		}
		seen[name] = true
		if secretNames[name] {
			return "", fmt.Errorf("-e %s %w", name, ErrSecretEnv)
		}
		if !ok {
			if value, ok = lookup(name); !ok {
				return "", fmt.Errorf("-e %s: %s is not set in the environment", name, name)
			}
		}
		if !utf8.ValidString(value) || strings.ContainsAny(value, "\n\r\x00") {
			return "", fmt.Errorf("-e %s: the value must be UTF-8 text without newlines, carriage returns, or NUL bytes", name)
		}
		b.WriteString(name + "=" + value + "\n")
	}
	if b.Len() > MaxExecEnvBytes {
		return "", fmt.Errorf("-e values take %d bytes, more than the %d allowed", b.Len(), MaxExecEnvBytes)
	}
	return b.String(), nil
}
