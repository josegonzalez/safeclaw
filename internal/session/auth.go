package session

import (
	"context"
	"errors"
	"fmt"
	"math"
	"os"
	"regexp"
	"strconv"
	"strings"
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
// The container gets no secrets, mounts, or ports, and is removed
// afterwards.
func (m *Manager) SetupToken(ctx context.Context) (string, error) {
	if err := m.checkImage(ctx, ""); err != nil {
		return "", err
	}
	cleanup := context.WithoutCancel(ctx)
	m.RemoveStaleAuthContainers(cleanup)

	id, err := m.Docker.Run(ctx, "-d", "--label", config.LabelAuth+"="+strconv.Itoa(os.Getpid()), config.ImageName, "sleep", "infinity")
	if err != nil {
		return "", fmt.Errorf("start the sign-in container: %w", err)
	}
	defer func() { _ = m.Docker.Remove(cleanup, id, true) }()

	// script records the session so the token can be read back after
	// claude exits, while the terminal stays attached to claude.
	if err := m.Docker.R.Passthrough(ctx, "exec", "-it", id, "script", "-qec", "claude setup-token", setupTokenLog); err != nil {
		return "", fmt.Errorf("claude setup-token: %w", err)
	}
	out, err := m.Docker.Exec(ctx, id, docker.ExecOptions{}, "cat", setupTokenLog)
	// Drop the recording, which holds the token, as soon as it is read, so
	// it doesn't outlive this process if it is killed before the container
	// is removed.
	_, _ = m.Docker.Exec(cleanup, id, docker.ExecOptions{}, "rm", "-f", setupTokenLog)
	if err != nil {
		return "", fmt.Errorf("read the setup-token output: %w", err)
	}
	return ParseSetupToken(out)
}

// RemoveStaleAuthContainers removes sign-in containers left by an earlier
// login that was killed before it could clean up. Each is labeled with the
// PID of the safeclaw process that started it, so another login still
// running is left alone. It is best effort and costs one `docker ps`.
func (m *Manager) RemoveStaleAuthContainers(ctx context.Context) {
	out, err := m.Docker.R.Output(ctx, nil, "ps", "-a", "--filter", "label="+config.LabelAuth, "--format", `{{.ID}} {{.Label "`+config.LabelAuth+`"}}`)
	if err != nil {
		return
	}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		id, pid, _ := strings.Cut(line, " ")
		if id == "" || m.processAlive(pid) {
			continue
		}
		_ = m.Docker.Remove(ctx, id, true)
	}
}

// processAlive reports whether pid names a running process.
func (m *Manager) processAlive(pid string) bool {
	if m.ProcessAlive != nil {
		return m.ProcessAlive(pid)
	}
	n, err := strconv.Atoi(pid)
	if err != nil || n <= 0 {
		return false
	}
	err = syscall.Kill(n, 0)
	return err == nil || errors.Is(err, syscall.EPERM)
}
