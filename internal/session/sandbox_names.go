package session

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
)

// prefixTime is the layout of the UTC timestamp in a prefixed one-off
// sandbox name, which sorts by creation time.
const prefixTime = "20060102-150405"

// prefixAttempts is how many names a prefixed one-off sandbox tries: the
// timestamped name, then it with -2 to -9. Single-digit suffixes keep the
// names sorting in the order they were made.
const prefixAttempts = 9

// MaxNamePrefix is the longest name prefix, leaving room in MaxName for
// the timestamp and the longest suffix.
const MaxNamePrefix = MaxName - len("-"+prefixTime) - len("-9")

// ResolveNamePrefix returns the canonical form of a one-off sandbox name
// prefix, like ResolveName: one container prefix is removed and letters are
// lowercased. It must then be a valid session name of at most
// MaxNamePrefix characters.
func ResolveNamePrefix(prefix string) (string, error) {
	p := strings.ToLower(config.SessionName(prefix))
	if !nameRe.MatchString(p) {
		return "", fmt.Errorf("invalid name prefix %q: use lowercase letters, numbers, '.', '_' and '-', starting with a letter or number", prefix)
	}
	if strings.HasPrefix(p, config.ContainerPrefix) {
		return "", fmt.Errorf("invalid name prefix %q: session names may not start with %q", prefix, config.ContainerPrefix)
	}
	if len(p) > MaxNamePrefix {
		return "", fmt.Errorf("invalid name prefix %q: it can be at most %d characters, leaving room for the timestamp", prefix, MaxNamePrefix)
	}
	return p, nil
}

// prefixedName returns the name for the attempt'th try (from 0) at naming
// a one-off sandbox with prefix at t: PREFIX-YYYYMMDD-HHMMSS in UTC, so
// names sort the same across time zones and DST changes, followed by -2,
// -3, and so on for later attempts.
func prefixedName(prefix string, t time.Time, attempt int) string {
	name := prefix + "-" + t.UTC().Format(prefixTime)
	if attempt > 0 {
		name += "-" + strconv.Itoa(attempt+1)
	}
	return name
}

// resolveNamePrefix replaces a name prefix with its canonical form,
// refusing an invalid one, one given with a name, and one for a sandbox
// that isn't one-off.
func (o *SandboxOptions) resolveNamePrefix() error {
	switch {
	case o.NamePrefix == "":
		return nil
	case o.Name != "":
		return errors.New("a sandbox name and a name prefix can't both be given")
	case !o.Remove:
		return errors.New("a name prefix is only for one-off sandboxes")
	}
	p, err := ResolveNamePrefix(o.NamePrefix)
	o.NamePrefix = p
	return err
}

func (m *Manager) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// createOneOff creates a new one-off sandbox and returns its name. With a
// name prefix it is named by prefixedName, trying the next suffix while
// the name is taken: by a container that exists, or by one created
// meanwhile, which docker refuses the name for, or, with keepInputsUnder,
// by a record in the directory named after it. The time is read once, so
// every attempt has the same timestamp. opts.NamePrefix must already be
// resolved.
func (m *Manager) createOneOff(ctx context.Context, opts SandboxOptions) (string, error) {
	if opts.NamePrefix == "" {
		name, err := m.pickName(ctx, opts.Name)
		if err != nil {
			return "", err
		}
		return name, m.startOneOff(ctx, name, opts)
	}
	prefix := opts.NamePrefix
	at := m.now()
	for attempt := range prefixAttempts {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		name := prefixedName(prefix, at, attempt)
		if err := ValidateNewName(name); err != nil {
			return "", err
		}
		c, err := m.Docker.InspectOne(ctx, config.ContainerName(name))
		if err != nil {
			return "", err
		}
		if c != nil {
			continue
		}
		err = m.startOneOff(ctx, name, opts)
		switch {
		case docker.IsNameConflict(err):
			m.printf("Name taken meanwhile: %s\n", config.ContainerName(name))
			continue
		case errors.Is(err, errHoldsRecord):
			m.printf("Name taken by a record: %s\n", filepath.Join(opts.keepInputsUnder.parent, name))
			continue
		}
		return name, err
	}
	return "", fmt.Errorf("could not pick an unused sandbox name: %s through %s are taken",
		prefixedName(prefix, at, 0), prefixedName(prefix, at, prefixAttempts-1))
}

// startOneOff creates the one-off sandbox name.
//
// With keepInputsUnder, its record is started in the directory named
// after it once docker has accepted the name, since only the run whose
// container has the name may start that record. A directory that already
// holds a record refuses the name before docker run, and one that came to
// hold a record meanwhile removes the new sandbox again, both with an
// error wrapping errHoldsRecord. When the record can't be started for any
// other reason, the new sandbox is removed too.
func (m *Manager) startOneOff(ctx context.Context, name string, opts SandboxOptions) error {
	container := config.ContainerName(name)
	under := opts.keepInputsUnder
	if under != nil {
		opts.keepInputs = filepath.Join(under.parent, name)
		if err := checkNoRecord(opts.keepInputs); err != nil {
			return err
		}
	}
	m.printf("Creating one-off sandbox: %s\n", container)
	if err := m.newSandbox(ctx, name, container, opts); err != nil || under == nil {
		return err
	}
	if err := under.start(ctx, opts.keepInputs, opts.Verify); err != nil {
		if rerr := m.Docker.Remove(context.WithoutCancel(ctx), container, true); rerr != nil {
			// Not wrapping err, so a name prefix doesn't go on to the
			// next name past a sandbox left behind.
			return fmt.Errorf("%s, and sandbox %q could not be removed: %w", err, name, rerr)
		}
		return fmt.Errorf("%w, so sandbox %q was removed", err, name)
	}
	m.printf("Recording its inputs in %s\n", filepath.Join(opts.keepInputs, InputsFile))
	return nil
}
