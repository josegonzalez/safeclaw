package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/charmbracelet/x/ansi"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/secrets"
)

const (
	// TokenLifetime is how long a `claude setup-token` token is valid.
	TokenLifetime = 365 * 24 * time.Hour
	// TokenWarnWindow is how long before a token expires to start warning.
	TokenWarnWindow = 30 * 24 * time.Hour
)

// TokenState describes the stored Claude Code token.
type TokenState string

// Token states.
const (
	TokenMissing  TokenState = "missing"
	TokenValid    TokenState = "valid"
	TokenExpiring TokenState = "expiring"
	TokenExpired  TokenState = "expired"
)

// TokenStatus is the state of the stored Claude Code token. The expiry is
// estimated from when the token was stored, since the token itself doesn't
// say.
type TokenStatus struct {
	State     TokenState
	SetAt     time.Time
	ExpiresAt time.Time
	// DaysLeft is the number of days until ExpiresAt, rounded up, and
	// negative once it has passed.
	DaysLeft int
}

// NeedsAttention reports whether the token is missing, expired, or expiring.
func (s TokenStatus) NeedsAttention() bool { return s.State != TokenValid }

// ClaudeTokenStatus returns the state of the stored Claude Code token at now.
func (m *Manager) ClaudeTokenStatus(now time.Time) (TokenStatus, error) {
	return tokenStatus(m.Secrets, now)
}

func tokenStatus(store secrets.Store, now time.Time) (TokenStatus, error) {
	at, err := store.SetAt(secrets.ClaudeToken)
	if errors.Is(err, os.ErrNotExist) {
		return TokenStatus{State: TokenMissing}, nil
	}
	if err != nil {
		return TokenStatus{}, err
	}
	exp := at.Add(TokenLifetime)
	left := exp.Sub(now)
	st := TokenStatus{SetAt: at, ExpiresAt: exp, DaysLeft: int(math.Ceil(left.Hours() / 24))}
	switch {
	case left <= 0:
		st.State = TokenExpired
	case left <= TokenWarnWindow:
		st.State = TokenExpiring
	default:
		st.State = TokenValid
	}
	return st, nil
}

// warnToken prints a warning when the stored Claude Code token is expired or
// expiring.
func (m *Manager) warnToken() {
	st, err := m.ClaudeTokenStatus(time.Now())
	if err != nil {
		return
	}
	switch st.State {
	case TokenExpired:
		m.printf("Warning: the Claude Code token expired on %s. Run `safeclaw auth login` to replace it\n", st.ExpiresAt.Format(time.DateOnly))
	case TokenExpiring:
		m.printf("Warning: the Claude Code token expires on %s (in %d days). Run `safeclaw auth login` to replace it\n", st.ExpiresAt.Format(time.DateOnly), st.DaysLeft)
	}
}

// setupTokenLog is where the auth container records the setup-token
// session.
const setupTokenLog = "/tmp/setup-token.log"

var tokenRe = regexp.MustCompile(`sk-ant-oat01-[A-Za-z0-9_-]+`)

// ParseSetupToken returns the token `claude setup-token` printed in a
// terminal recording, with terminal escapes removed. The token is printed on
// one line and left to the terminal to wrap, so the recording never splits
// it. The last token printed wins.
func ParseSetupToken(typescript []byte) (string, error) {
	all := tokenRe.FindAllString(ansi.Strip(string(typescript)), -1)
	if len(all) == 0 {
		return "", errors.New("no token found in the `claude setup-token` output. If it printed one, copy it and pipe it to `safeclaw auth set`")
	}
	return all[len(all)-1], nil
}

// SetupToken runs `claude setup-token` in a short-lived container from the
// base image, attached to this terminal, and returns the token it prints.
// The container gets no secrets, mounts, ports, or capabilities, and is
// removed afterwards, whether the sign-in succeeds, fails, or ctx is
// cancelled.
func (m *Manager) SetupToken(ctx context.Context) (string, error) {
	image, err := m.checkImage(ctx, "")
	if err != nil {
		return "", err
	}
	cleanup := context.WithoutCancel(ctx)
	m.RemoveStaleAuthContainers(cleanup)

	// The owner lock is held for as long as the container may exist, so
	// other safeclaw processes can tell this login is still running. It is
	// released after the container is removed.
	owner := authOwner()
	release, err := m.holdAuthOwner(owner)
	if err != nil {
		return "", fmt.Errorf("start the sign-in: %w", err)
	}
	defer release()

	name := authName()
	args := []string{"-d", "--name", name, "--label", config.LabelAuth + "=" + owner}
	args = append(args, userArgs...)
	args = append(args, hardenArgs...)
	args = append(args, imageArgs(config.ImageName, image)...)
	id, err := m.Docker.Run(ctx, append(args, "sleep", "infinity")...)
	if err != nil {
		// A cancelled run may have created the container before docker
		// printed its ID.
		_ = m.Docker.Remove(cleanup, name, true)
		return "", fmt.Errorf("start the sign-in container: %w", err)
	}
	defer func() { _ = m.Docker.Remove(cleanup, id, true) }()

	// script records the session so the token can be read back after
	// claude exits, while the terminal stays attached to claude.
	if err := m.Docker.R.Passthrough(ctx, "exec", "-it", "--user", config.SessionUser, id, "script", "-qec", "claude setup-token", setupTokenLog); err != nil {
		return "", fmt.Errorf("claude setup-token: %w", err)
	}
	out, err := m.Docker.Exec(ctx, id, asSclaw(docker.ExecOptions{}), "cat", setupTokenLog)
	// Drop the recording, which holds the token, as soon as it is read, so
	// it doesn't outlive this process if it is killed before the container
	// is removed.
	_, _ = m.Docker.Exec(cleanup, id, asSclaw(docker.ExecOptions{}), "rm", "-f", setupTokenLog)
	if err != nil {
		return "", fmt.Errorf("read the setup-token output: %w", err)
	}
	return ParseSetupToken(out)
}

// RemoveStaleAuthContainers removes sign-in containers left by an earlier
// login that was killed before it could clean up. Each is labeled with a
// random owner ID, and the login that started it holds a lock on a host
// file named after that ID until the container is gone. The kernel drops
// the lock when that process exits, however it exits, so a container whose
// lock can be taken, or whose file is missing, is stale, and another login
// still running is left alone. Unlike a PID, the ID is never reused.
// Containers labeled by versions that recorded a PID instead are stale
// too, since their PID can't tell a live login from a reused one. Docker
// copies image labels onto containers, so a container counts only when its
// name is a sign-in container's too, and a session made from an image
// carrying the label is never removed. It is best effort and costs one
// `docker ps`.
func (m *Manager) RemoveStaleAuthContainers(ctx context.Context) {
	out, err := m.Docker.R.Output(ctx, nil, "ps", "-a", "--filter", "label="+config.LabelAuth, "--format", `{{.ID}} {{.Names}} {{.Label "`+config.LabelAuth+`"}}`)
	if err != nil {
		return
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		id, rest, _ := strings.Cut(line, " ")
		name, owner, _ := strings.Cut(rest, " ")
		if id == "" || !strings.HasPrefix(name, config.AuthContainerPrefix) {
			continue
		}
		release, stale := m.claimStaleAuthOwner(owner)
		if !stale {
			continue
		}
		_ = m.Docker.Remove(ctx, id, true)
		release()
	}
}

// authOwnerRe matches the owner IDs authOwner makes. Owner IDs name files
// on the host, so nothing else is ever used as one.
var authOwnerRe = regexp.MustCompile(`^[0-9a-f]{32}$`)

// authOwner returns a new random owner ID for a sign-in container.
var authOwner = func() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// authName returns a name for a sign-in container.
var authName = func() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return config.AuthContainerPrefix + hex.EncodeToString(b)
}

func (m *Manager) authDir() string {
	if m.AuthDir != "" {
		return m.AuthDir
	}
	return config.AuthDir()
}

func (m *Manager) authOwnerPath(owner string) string {
	return filepath.Join(m.authDir(), owner+".lock")
}

// holdAuthOwner creates the owner file for a new sign-in container and
// locks it. The returned function removes the file and releases the lock.
func (m *Manager) holdAuthOwner(owner string) (func(), error) {
	if !authOwnerRe.MatchString(owner) {
		return nil, fmt.Errorf("invalid sign-in owner %q", owner)
	}
	if err := os.MkdirAll(m.authDir(), 0o700); err != nil {
		return nil, err
	}
	path := m.authOwnerPath(owner)
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			_ = os.Remove(path)
			_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			_ = f.Close()
		})
	}, nil
}

// claimStaleAuthOwner reports whether the login that owns a sign-in
// container is gone. When it is and its owner file is still there, the
// file stays locked, so no other process removes the container at the same
// time, until the returned function removes the file and unlocks it. A
// file that can't be checked for another reason counts as a live owner.
func (m *Manager) claimStaleAuthOwner(owner string) (release func(), stale bool) {
	none := func() {}
	if !authOwnerRe.MatchString(owner) {
		return none, true
	}
	path := m.authOwnerPath(owner)
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if errors.Is(err, os.ErrNotExist) {
		return none, true
	}
	if err != nil {
		return none, false
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		return none, false
	}
	return func() {
		_ = os.Remove(path)
		_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
		_ = f.Close()
	}, true
}
