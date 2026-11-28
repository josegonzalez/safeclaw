package session

import (
	"context"
	"errors"
	"strings"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
)

// Skipped says why StopSandbox or DeleteSandbox did nothing.
type Skipped string

const (
	// NotSkipped means the sandbox was stopped or removed.
	NotSkipped Skipped = ""
	// SkippedMissing means no container had the name, including a one-off
	// sandbox docker removed between the lookup and the stop or rm.
	SkippedMissing Skipped = "missing"
	// SkippedStopped means the sandbox was already stopped.
	SkippedStopped Skipped = "already stopped"
)

// SandboxStopOptions configures StopSandbox and DeleteSandbox.
type SandboxStopOptions struct {
	// Force removes a running sandbox too. DeleteSandbox only.
	Force bool
	// MissingOK does nothing, instead of failing, when the sandbox doesn't
	// exist or, for StopSandbox, is already stopped. A name that belongs to
	// an interactive session is still refused.
	MissingOK bool
}

// StopSandbox stops the named sandbox; docker removes a one-off one once
// it stops. A name that doesn't exist fails with an error wrapping
// ErrNotFound, and one that isn't a sandbox with ErrNotSandbox or
// ErrNotManaged. With opts.MissingOK, a missing sandbox, including one
// removed between the lookup and the stop, returns SkippedMissing, and a
// stopped one SkippedStopped without running docker stop.
func (m *Manager) StopSandbox(ctx context.Context, name string, opts SandboxStopOptions) (Skipped, error) {
	name = config.SessionName(name)
	if err := ValidateName(name); err != nil {
		return NotSkipped, err
	}
	_, c, err := m.getSandbox(ctx, name)
	if err != nil {
		if opts.MissingOK && errors.Is(err, ErrNotFound) {
			return SkippedMissing, nil
		}
		return NotSkipped, err
	}
	if opts.MissingOK && !c.State.Running {
		return SkippedStopped, nil
	}
	if err := m.Docker.Stop(ctx, config.ContainerName(name), 1); err != nil {
		if opts.MissingOK && gone(err) {
			return SkippedMissing, nil
		}
		return NotSkipped, err
	}
	return NotSkipped, nil
}

// DeleteSandbox removes the named sandbox, as DeleteWith does after
// checking that it is one. With opts.MissingOK, a missing sandbox,
// including one removed between the lookup and the rm, returns
// SkippedMissing. A running sandbox still needs opts.Force.
func (m *Manager) DeleteSandbox(ctx context.Context, name string, opts SandboxStopOptions) (Skipped, error) {
	name = config.SessionName(name)
	if err := ValidateName(name); err != nil {
		return NotSkipped, err
	}
	if _, _, err := m.getSandbox(ctx, name); err != nil {
		if opts.MissingOK && errors.Is(err, ErrNotFound) {
			return SkippedMissing, nil
		}
		return NotSkipped, err
	}
	if err := m.DeleteWith(ctx, name, DeleteOptions{Force: opts.Force}); err != nil {
		if opts.MissingOK && gone(err) {
			return SkippedMissing, nil
		}
		return NotSkipped, err
	}
	return NotSkipped, nil
}

// gone reports whether a docker stop or rm failed because the container no
// longer exists or docker is already removing it, as it does with a
// one-off sandbox once it stops.
func gone(err error) bool {
	if docker.IsNotFound(err) {
		return true
	}
	var de *docker.Error
	if !errors.As(err, &de) {
		return false
	}
	s := strings.ToLower(de.Stderr)
	return strings.Contains(s, "removal of container") && strings.Contains(s, "already in progress")
}
