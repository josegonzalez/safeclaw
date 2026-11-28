package session

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
)

// Err returns the error `safeclaw sandbox verify` exits with, naming the
// failed checks, or nil when every check passed.
func (r SandboxReport) Err() error {
	if r.OK {
		return nil
	}
	failed, skipped := r.Failed(), r.Skipped()
	msg := fmt.Sprintf("sandbox %q failed %d %s: %s", r.Name, len(failed), plural(len(failed), "check"), strings.Join(failed, ", "))
	if len(skipped) > 0 {
		msg += fmt.Sprintf(" (%d %s skipped)", len(skipped), plural(len(skipped), "check"))
	}
	return errors.New(msg)
}

func plural(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

// SandboxVerifyError is returned when a sandbox created or started with
// SandboxOptions.Verify fails its checks, or when they could not finish,
// for example because ctx was done first.
type SandboxVerifyError struct {
	Name string
	// Report is the failed report, nil when the checks could not finish.
	Report *SandboxReport
	// Err is why the checks could not finish.
	Err error
	// Kept is set for a sandbox that existed before, which is left as it
	// was. Otherwise the sandbox was removed, unless RemoveErr says why
	// that failed.
	Kept      bool
	RemoveErr error
}

func (e *SandboxVerifyError) Error() string {
	var msg string
	if e.Report != nil {
		msg = e.Report.Err().Error()
	} else {
		msg = fmt.Sprintf("verify sandbox %q: %v", e.Name, e.Err)
	}
	switch {
	case e.Kept:
		return msg + "; it existed before, so it was left as it was"
	case e.RemoveErr != nil:
		return fmt.Sprintf("%s; removing it failed: %v", msg, e.RemoveErr)
	default:
		return msg + "; it was removed"
	}
}

func (e *SandboxVerifyError) Unwrap() error { return e.Err }

// createSandboxVerified creates a sandbox to be verified. docker run is not
// stopped partway when ctx is done, so the sandbox exists or not by the
// time it returns, and when ctx was done meanwhile it is removed.
func (m *Manager) createSandboxVerified(ctx context.Context, name, container string, opts SandboxOptions) error {
	err := m.createSandbox(context.WithoutCancel(ctx), container, opts)
	if ctx.Err() == nil {
		return err
	}
	return m.verifyFailed(ctx, name, nil, ctx.Err(), false)
}

// verifyStarted runs the `sandbox verify` checks on a sandbox EnsureSandbox
// just started. When a check fails, or ctx is done first, a sandbox it
// created is removed and one that existed before is kept.
func (m *Manager) verifyStarted(ctx context.Context, name string, created bool) error {
	m.printf("Verifying sandbox: %s\n", config.ContainerName(name))
	report, err := m.VerifySandbox(ctx, name)
	if ctx.Err() != nil {
		report, err = nil, ctx.Err()
	}
	if err != nil || !report.OK {
		return m.verifyFailed(ctx, name, report, err, !created)
	}
	m.printf("Verified sandbox: all %d checks passed\n", len(report.Checks))
	return nil
}

// verifyFailed removes the sandbox unless kept, and returns the
// SandboxVerifyError for report or err.
func (m *Manager) verifyFailed(ctx context.Context, name string, report *SandboxReport, err error, kept bool) error {
	e := &SandboxVerifyError{Name: name, Report: report, Err: err, Kept: kept}
	if !kept {
		e.RemoveErr = m.Docker.Remove(context.WithoutCancel(ctx), config.ContainerName(name), true)
	}
	return e
}

// ErrExited is returned by VerifyEphemeral when the one-off sandbox's
// docker run exits before the sandbox is verified.
var ErrExited = errors.New("the sandbox exited before it was verified")

// verifiedFlag is the file whose creation lets a verified one-off
// sandbox's command start. The gate removes it before the command runs.
const verifiedFlag = "/tmp/.safeclaw-verified"

// Gate timing: the gate checks for verifiedFlag every gatePoll, and gives
// up after gateTimeout, so a one-off sandbox whose caller died before
// verifying it exits, and docker removes it.
const (
	gatePoll    = 100 * time.Millisecond
	gateTimeout = 60 * time.Second
)

// gateExitCode is what a one-off sandbox's gate exits with when it is not
// let through in time.
const gateExitCode = 125

// gateScript waits for verifiedFlag, removes it, sets the umask, and
// replaces the shell with the command given as its positional parameters,
// leaving them untouched. It runs before anything else in the sandbox.
var gateScript = fmt.Sprintf(`i=0; while [ ! -e %[1]s ]; do i=$((i+1)); if [ "$i" -gt %[2]d ]; then echo "safeclaw: the sandbox was not verified in time" >&2; exit %[3]d; fi; sleep %[4]s; done; rm -f %[1]s; `,
	verifiedFlag, int(gateTimeout/gatePoll), gateExitCode, strconv.FormatFloat(gatePoll.Seconds(), 'f', -1, 64)) + sandboxUmaskScript

// runningPoll is how often VerifyEphemeral checks whether the one-off
// sandbox is running yet.
var runningPoll = 50 * time.Millisecond

// VerifyEphemeral verifies a one-off sandbox started from a
// PrepareEphemeral argv with SandboxOptions.Verify, whose command waits
// until it is let through. It waits for the sandbox to be running, runs the
// `sandbox verify` checks, and lets the command start only when every check
// passed. Otherwise, or when ctx is done first, it removes the sandbox and
// returns a SandboxVerifyError. exited is closed when docker run exits: if
// that happens before the sandbox is verified, ErrExited is returned and
// nothing is removed, since docker already removed it.
func (m *Manager) VerifyEphemeral(ctx context.Context, name string, exited <-chan struct{}) error {
	container := config.ContainerName(name)
	fail := func(report *SandboxReport, err error) error {
		select {
		case <-exited:
			// An interrupted docker run can exit after creating the
			// container but before starting it, and docker only removes
			// containers that ran.
			if ctx.Err() == nil {
				return ErrExited
			}
			if c, _ := m.Docker.InspectOne(context.WithoutCancel(ctx), container); c == nil {
				return ErrExited
			}
		default:
		}
		if ctx.Err() != nil {
			report, err = nil, ctx.Err()
		}
		return m.verifyFailed(ctx, name, report, err, false)
	}
	if err := m.waitRunning(ctx, container, exited); err != nil {
		return fail(nil, err)
	}
	report, err := m.VerifySandbox(ctx, name)
	if ctx.Err() != nil {
		report, err = nil, ctx.Err()
	}
	if err != nil || !report.OK {
		return fail(report, err)
	}
	opts := docker.ExecOptions{User: config.SandboxUser}
	if _, err := m.Docker.Exec(ctx, container, opts, "touch", verifiedFlag); err != nil {
		return fail(nil, fmt.Errorf("start the command: %w", err))
	}
	return nil
}

// waitRunning waits until container is running or exited is closed. Once
// ctx is done it returns ctx's error as soon as the container exists, so
// it can be removed: docker run may still be creating it.
func (m *Manager) waitRunning(ctx context.Context, container string, exited <-chan struct{}) error {
	wctx := context.WithoutCancel(ctx)
	for {
		c, err := m.Docker.InspectOne(wctx, container)
		if err != nil {
			return err
		}
		if c != nil && (c.State.Running || ctx.Err() != nil) {
			return ctx.Err()
		}
		select {
		case <-exited:
			return ErrExited
		case <-time.After(runningPoll):
		}
	}
}
