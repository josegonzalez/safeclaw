package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
)

// choices are the policy choices a session's container records in its
// labels, kept on the host as well so they outlive the container. A session
// whose container was removed, by `safeclaw rm` or `build --recreate`, gets
// them back when it is created again over the history it left.
type choices struct {
	// Secrets are the only secrets the session receives, sorted. Nil means
	// every secret, and empty none.
	Secrets *[]string `json:"secrets"`
	// NoMemory is set when the session's auto memory is off.
	NoMemory bool `json:"noMemory"`
}

// newChoices returns the choices of a session receiving set, with auto
// memory off when noMemory is set.
func newChoices(set SecretSet, noMemory bool) choices {
	c := choices{NoMemory: noMemory}
	if !set.All() {
		names := append([]string{}, set.Names...)
		c.Secrets = &names
	}
	return c
}

// choicesOf returns the choices a session container's labels record.
func choicesOf(c docker.Container) choices {
	return newChoices(secretsOf(c), noMemoryOf(c))
}

// secretSet returns the secrets the choices give the session.
func (c choices) secretSet() (SecretSet, error) {
	if c.Secrets == nil {
		return AllSecrets(), nil
	}
	return OnlySecrets(*c.Secrets...)
}

// choicesDir returns the directory holding each session's choices. It is
// kept apart from SessionsDir's history directories, which are mounted into
// the containers, so the agent can't change them. Without ChoicesDir it is
// the choices directory next to SessionsDir, which for the default
// SessionsDir is config.ChoicesDir().
func (m *Manager) choicesDir() string {
	if m.ChoicesDir != "" {
		return m.ChoicesDir
	}
	if m.SessionsDir != "" {
		return filepath.Join(filepath.Dir(m.SessionsDir), "choices")
	}
	return config.ChoicesDir()
}

func (m *Manager) choicesPath(name string) string {
	return filepath.Join(m.choicesDir(), name+".json")
}

// readChoices returns a session's kept choices, nil if none are kept. A
// record that can't be read is an error, so a choice is never dropped
// silently.
func (m *Manager) readChoices(name string) (*choices, error) {
	b, err := readRegular(m.choicesPath(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read the choices kept for session %s: %w", name, err)
	}
	var c choices
	err = json.Unmarshal(b, &c)
	if err == nil {
		_, err = c.secretSet()
	}
	if err != nil {
		return nil, fmt.Errorf("read the choices kept for session %s from %s: %w. Fix or remove the file, then give the choices again", name, m.choicesPath(name), err)
	}
	return &c, nil
}

// writeChoices keeps a session's choices on the host, readable only by the
// user.
func (m *Manager) writeChoices(name string, c choices) error {
	b, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err := writePrivate(m.choicesPath(name), string(b)+"\n"); err != nil {
		return fmt.Errorf("keep the choices of session %s: %w", name, err)
	}
	return nil
}

// keepChoices keeps the choices of a session container about to be
// removed, so they outlive it. Sandboxes keep none, and neither does a
// container whose name is not a canonical session name, such as a mixed
// case one made by an earlier version, whose record would replace the
// lowercase session's on a case-insensitive filesystem.
func (m *Manager) keepChoices(name string, c docker.Container) error {
	if TypeOf(c) != config.TypeSession || ValidateName(name) != nil {
		return nil
	}
	return m.writeChoices(name, choicesOf(c))
}
