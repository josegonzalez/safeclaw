// Package session holds the session lifecycle logic shared by the CLI and the
// dashboard.
package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/secrets"
)

// gitConfigScript sets the container's git identity from the GitHub account.
const gitConfigScript = `
if gh auth status >/dev/null 2>&1; then
    USER_DATA=$(gh api user 2>/dev/null)
    if [ -n "$USER_DATA" ]; then
        NAME=$(echo "$USER_DATA" | jq -r ".name // .login")
        LOGIN=$(echo "$USER_DATA" | jq -r ".login")
        EMAIL=$(echo "$USER_DATA" | jq -r ".email // empty")
        # Use noreply email if no public email
        [ -z "$EMAIL" ] && EMAIL="${LOGIN}@users.noreply.github.com"
        git config --global user.name "$NAME"
        git config --global user.email "$EMAIL"
    fi
fi
`

// legacyTmuxScript starts the tmux session in containers built from the
// upstream image, which do not ship the safeclaw binary.
const legacyTmuxScript = `
if ! tmux has-session -t main 2>/dev/null; then
    tmux -f /dev/null new -d -s main
    tmux set -t main status off
    tmux set -t main mouse on
    tmux send-keys -t main "claude --dangerously-skip-permissions" Enter
fi
`

// writeEnvScript replaces the env file with stdin, readable only by its owner.
const writeEnvScript = `umask 077 && cat > ` + config.EnvFile + ` && chmod 600 ` + config.EnvFile

var nameRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]*$`)

// ErrNoImage is returned when the safeclaw image is missing.
var ErrNoImage = fmt.Errorf("image '%s' not found. Run `safeclaw build` or `safeclaw pull` first", config.ImageName)

// ErrNoClaudeToken is returned by non-interactive runs without a Claude token.
var ErrNoClaudeToken = errors.New("no Claude Code token found. Run `safeclaw run` first to set up authentication")

// ValidateName checks that a session name makes a valid container name.
func ValidateName(name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("invalid session name %q: use letters, numbers, '.', '_' and '-', starting with a letter or number", name)
	}
	return nil
}

// NormalizeName applies the dashboard's name rules: spaces become dashes,
// letters are lowercased, and an empty name means the default session.
func NormalizeName(name string) string {
	name = strings.TrimSpace(strings.ToLower(strings.ReplaceAll(name, " ", "-")))
	name = strings.Trim(name, "-")
	if name == "" {
		return config.DefaultSession
	}
	return name
}

// Prompter asks the user for missing tokens.
type Prompter interface {
	// ClaudeToken must return a non-empty token or an error.
	ClaudeToken() (string, error)
	// GitHubToken may return "" to skip.
	GitHubToken() (string, error)
}

// Manager runs session operations.
type Manager struct {
	Docker      *docker.Client
	Secrets     secrets.Store
	SessionsDir string
	// Out receives progress messages. Defaults to io.Discard.
	Out io.Writer
	// Prompter is used for interactive runs.
	Prompter Prompter

	// PortFree reports whether a host port can be bound. Defaults to a
	// net.Listen probe.
	PortFree func(port int) bool
	// Sleep defaults to time.Sleep.
	Sleep func(time.Duration)
	// OpenBrowser defaults to open/xdg-open.
	OpenBrowser func(url string) error
	// PromptTimeout bounds how long a query waits for Claude Code's prompt.
	PromptTimeout time.Duration

	mu sync.Mutex
}

// NewManager returns a Manager using the real docker CLI and config paths.
func NewManager(out io.Writer) *Manager {
	return &Manager{
		Docker:      docker.New(),
		Secrets:     secrets.Store{Dir: config.SecretsDir()},
		SessionsDir: config.SessionsDir(),
		Out:         out,
	}
}

func (m *Manager) out() io.Writer {
	if m.Out == nil {
		return io.Discard
	}
	return m.Out
}

func (m *Manager) printf(format string, args ...any) {
	fmt.Fprintf(m.out(), format, args...)
}

func (m *Manager) sleep(d time.Duration) {
	if m.Sleep != nil {
		m.Sleep(d)
		return
	}
	time.Sleep(d)
}

func (m *Manager) portFree(port int) bool {
	if m.PortFree != nil {
		return m.PortFree(port)
	}
	l, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		return false
	}
	_ = l.Close()
	return true
}

func (m *Manager) openBrowser(url string) error {
	if m.OpenBrowser != nil {
		return m.OpenBrowser(url)
	}
	return OpenBrowser(url)
}

// OpenBrowser opens url with the platform's opener, if there is one.
func OpenBrowser(url string) error {
	for _, bin := range []string{"open", "xdg-open"} {
		if runtime.GOOS != "darwin" && bin == "open" {
			continue
		}
		if path, err := exec.LookPath(bin); err == nil {
			return exec.Command(path, url).Start()
		}
	}
	return nil
}

// Options configures Ensure.
type Options struct {
	// Name is the session name. Empty means "default".
	Name string
	// Volume is an optional host:container bind mount. Setting it recreates
	// an existing container.
	Volume string
	// Query is sent to Claude Code once it is ready.
	Query string
	// NoOpen skips opening the browser.
	NoOpen bool
	// Interactive allows prompting for missing tokens.
	Interactive bool
}

// Result describes a running session.
type Result struct {
	Name      string
	Container string
	Port      int
	URL       string
}

// URLFor returns the session URL for a host port.
func URLFor(port int) string {
	return fmt.Sprintf("http://localhost:%d", port)
}

// Ensure creates, starts, or refreshes a session container and starts ttyd
// in it. It is the equivalent of upstream's run.sh.
func (m *Manager) Ensure(ctx context.Context, opts Options) (*Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	name := opts.Name
	if name == "" {
		name = config.DefaultSession
	}
	name = config.SessionName(name)
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	container := config.ContainerName(name)

	imageID, err := m.Docker.ImageID(ctx, config.ImageName)
	if err != nil {
		return nil, err
	}
	if imageID == "" {
		return nil, ErrNoImage
	}

	existing, err := m.Docker.InspectOne(ctx, container)
	if err != nil {
		return nil, err
	}
	if existing != nil && TypeOf(*existing) == config.TypeSandbox {
		return nil, wrongType(name, ErrIsSandbox)
	}

	if err := m.ensureTokens(opts.Interactive); err != nil {
		return nil, err
	}

	port := 0
	if existing != nil {
		port = existing.HostPort(config.TTYDPort)
	}

	if opts.Volume != "" && existing != nil {
		m.printf("Volume mount requested. Removing existing container...\n")
		if err := m.Docker.Remove(ctx, container, true); err != nil {
			return nil, err
		}
		existing = nil
	}

	if port == 0 {
		port, err = m.allocatePort(ctx)
		if err != nil {
			return nil, err
		}
	}

	switch {
	case existing != nil && existing.State.Running:
		m.printf("Reusing running container: %s\n", container)
		// Restart ttyd/tmux so fresh env vars take effect.
		_, _ = m.Docker.Exec(ctx, container, docker.ExecOptions{}, "pkill", "-f", "ttyd")
		_, _ = m.Docker.Exec(ctx, container, docker.ExecOptions{}, "tmux", "kill-server")
		m.sleep(time.Second)
	case existing != nil:
		m.printf("Starting existing container: %s\n", container)
		if err := m.Docker.Start(ctx, container); err != nil {
			return nil, err
		}
	default:
		m.printf("Creating container: %s\n", container)
		if err := m.create(ctx, name, container, port, opts.Volume); err != nil {
			return nil, err
		}
	}

	if err := m.writeEnv(ctx, container); err != nil {
		return nil, err
	}

	if m.Secrets.Has(secrets.GitHubToken) {
		_, _ = m.Docker.Exec(ctx, container, docker.ExecOptions{}, "bash", "-c", gitConfigScript)
	}

	native := m.hasNativeWrapper(ctx, container)
	if err := m.startTTYD(ctx, name, container, native); err != nil {
		return nil, err
	}

	res := &Result{Name: name, Container: container, Port: port, URL: URLFor(port)}
	m.printf("\nSafeClaw is running at: %s\n", res.URL)

	if opts.Query != "" {
		m.printf("Starting session and sending query...\n")
		if err := m.sendQuery(ctx, container, native, opts.Query); err != nil {
			return res, err
		}
		m.printf("Query sent: %s\n", opts.Query)
	}

	m.printf("\nTo stop: safeclaw stop %s\n", name)

	if !opts.NoOpen {
		_ = m.openBrowser(res.URL)
	}
	return res, nil
}

func (m *Manager) ensureTokens(interactive bool) error {
	if !m.Secrets.Has(secrets.ClaudeToken) {
		if !interactive || m.Prompter == nil {
			return ErrNoClaudeToken
		}
		tok, err := m.Prompter.ClaudeToken()
		if err != nil {
			return err
		}
		if _, err := m.Secrets.Set(secrets.ClaudeToken, tok); err != nil {
			return err
		}
	}
	if !m.Secrets.Has(secrets.GitHubToken) && interactive && m.Prompter != nil {
		tok, err := m.Prompter.GitHubToken()
		if err != nil {
			return err
		}
		if tok != "" {
			if _, err := m.Secrets.Set(secrets.GitHubToken, tok); err != nil {
				return err
			}
		}
	}
	return nil
}

// allocatePort returns the lowest port from FirstSessionPort that no
// safeclaw container has reserved and that is free on the host.
func (m *Manager) allocatePort(ctx context.Context) (int, error) {
	cs, err := m.Docker.List(ctx, config.ContainerPrefix)
	if err != nil {
		return 0, err
	}
	reserved := map[int]bool{}
	for _, c := range cs {
		if p := c.HostPort(config.TTYDPort); p > 0 {
			reserved[p] = true
		}
	}
	for port := config.FirstSessionPort; port < 65535; port++ {
		if reserved[port] {
			continue
		}
		if m.portFree(port) {
			return port, nil
		}
	}
	return 0, errors.New("no free port available")
}

func (m *Manager) create(ctx context.Context, name, container string, port int, volume string) error {
	dataDir := filepath.Join(m.SessionsDir, name)
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}
	args := []string{
		"-d", "--ipc=host",
		"--name", container,
		"-p", fmt.Sprintf("127.0.0.1:%d:%d", port, config.TTYDPort),
		"-v", dataDir + ":" + config.ProjectsMount,
	}
	if volume != "" {
		v, err := ExpandVolume(volume)
		if err != nil {
			return err
		}
		m.printf("Mounting volume: %s\n", v)
		args = append(args, "-v", v)
	}
	args = append(args, config.ImageName, "sleep", "infinity")
	_, err := m.Docker.Run(ctx, args...)
	return err
}

// ExpandVolume expands a leading ~ and relative paths in the host part of a
// host:container[:options] volume spec.
func ExpandVolume(v string) (string, error) {
	host, rest, ok := strings.Cut(v, ":")
	if !ok || host == "" || rest == "" {
		return "", fmt.Errorf("invalid volume %q: expected /host/path:/container/path", v)
	}
	switch {
	case host == "~" || strings.HasPrefix(host, "~/"):
		home, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		host = filepath.Join(home, strings.TrimPrefix(host, "~"))
	case host == "." || host == ".." || strings.HasPrefix(host, "./") || strings.HasPrefix(host, "../"):
		abs, err := filepath.Abs(host)
		if err != nil {
			return "", err
		}
		host = abs
	}
	return host + ":" + rest, nil
}

func (m *Manager) writeEnv(ctx context.Context, container string) error {
	all, err := m.Secrets.All()
	if err != nil {
		return err
	}
	_, err = m.Docker.Exec(ctx, container, docker.ExecOptions{Stdin: strings.NewReader(secrets.RenderEnv(all))}, "sh", "-c", writeEnvScript)
	return err
}

func (m *Manager) hasNativeWrapper(ctx context.Context, container string) bool {
	_, err := m.Docker.Exec(ctx, container, docker.ExecOptions{}, "sh", "-c", "command -v safeclaw")
	return err == nil
}

func (m *Manager) startTTYD(ctx context.Context, name, container string, native bool) error {
	args := []string{"ttyd", "-W", "-t", "titleFixed=SafeClaw - " + name, "-p", strconv.Itoa(config.TTYDPort)}
	if native {
		args = append(args, "safeclaw", "ttyd-wrapper")
	} else {
		args = append(args, config.LegacyWrapper)
	}
	_, err := m.Docker.Exec(ctx, container, docker.ExecOptions{Detach: true}, args...)
	return err
}

func (m *Manager) sendQuery(ctx context.Context, container string, native bool, query string) error {
	var err error
	if native {
		_, err = m.Docker.Exec(ctx, container, docker.ExecOptions{}, "safeclaw", "ttyd-wrapper", "--no-attach")
	} else {
		_, err = m.Docker.Exec(ctx, container, docker.ExecOptions{}, "bash", "-c", legacyTmuxScript)
	}
	if err != nil {
		return err
	}

	if !m.waitForPrompt(ctx, container) {
		m.printf("Claude Code prompt not detected yet, sending query anyway\n")
	}

	tmux := func(keys ...string) error {
		args := append([]string{"tmux", "send-keys", "-t", config.TmuxSession}, keys...)
		_, err := m.Docker.Exec(ctx, container, docker.ExecOptions{}, args...)
		return err
	}
	if err := tmux("-l", query); err != nil {
		return err
	}
	if err := tmux("Enter"); err != nil {
		return err
	}
	m.sleep(500 * time.Millisecond)
	return tmux("Enter")
}

// promptRe matches Claude Code's input line. Selection menus also use
// "❯" (e.g. "  ❯ No, exit") but indent it; the input line starts at column 0
// and may carry placeholder text after a non-breaking space.
var promptRe = regexp.MustCompile(`(?m)^❯(?:[\s\x{00a0}]|$)`)

// PromptReady reports whether a captured pane shows an empty input prompt.
func PromptReady(pane string) bool {
	return promptRe.MatchString(pane)
}

// waitForPrompt polls the tmux pane until Claude Code's input prompt shows.
func (m *Manager) waitForPrompt(ctx context.Context, container string) bool {
	timeout := m.PromptTimeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	const interval = 500 * time.Millisecond
	for waited := time.Duration(0); waited <= timeout; waited += interval {
		out, err := m.Docker.Exec(ctx, container, docker.ExecOptions{}, "tmux", "capture-pane", "-t", config.TmuxSession, "-p")
		if err == nil && PromptReady(string(out)) {
			return true
		}
		if ctx.Err() != nil {
			return false
		}
		m.sleep(interval)
	}
	return false
}

// Session is a session as shown in listings.
type Session struct {
	// Container is the full container name, e.g. safeclaw-work.
	Container string `json:"name"`
	// Name is the short session name, e.g. work.
	Name   string `json:"-"`
	Port   int    `json:"port,omitempty"`
	URL    string `json:"url,omitempty"`
	Volume string `json:"volume"`
	Active bool   `json:"active"`
	Status string `json:"-"`
	// Type is config.TypeSession or config.TypeSandbox.
	Type string `json:"type"`
	// AutoRemove is set for one-off sandboxes, which docker removes when
	// they stop.
	AutoRemove bool `json:"autoRemove"`
}

// IsOneOff reports whether the session is a one-off sandbox.
func (s Session) IsOneOff() bool {
	return s.IsSandbox() && s.AutoRemove
}

// IsSandbox reports whether the session is a headless sandbox.
func (s Session) IsSandbox() bool {
	return s.Type == config.TypeSandbox
}

// TypeOf returns a container's session type. Containers without a type label
// are interactive sessions.
func TypeOf(c docker.Container) string {
	if t := c.Label(config.LabelType); t != "" {
		return t
	}
	return config.TypeSession
}

// List returns all sessions, active first, then by name.
func (m *Manager) List(ctx context.Context) ([]Session, error) {
	cs, err := m.Docker.List(ctx, config.ContainerPrefix)
	if err != nil {
		return nil, err
	}
	out := make([]Session, 0, len(cs))
	for _, c := range cs {
		name := c.ShortName()
		if !strings.HasPrefix(name, config.ContainerPrefix) {
			continue
		}
		s := Session{
			Container:  name,
			Name:       config.SessionName(name),
			Active:     c.State.Running,
			Status:     c.State.Status,
			Volume:     "-",
			Type:       TypeOf(c),
			AutoRemove: c.HostConfig.AutoRemove,
		}
		if mounts := c.BindMounts(config.ProjectsMount); len(mounts) > 0 {
			s.Volume = strings.Join(mounts, ", ")
		}
		if s.Active {
			if p := c.HostPort(config.TTYDPort); p > 0 {
				s.Port = p
				s.URL = URLFor(p)
			}
		}
		out = append(out, s)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Active != out[j].Active {
			return out[i].Active
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// Exists reports whether a session container exists.
func (m *Manager) Exists(ctx context.Context, name string) (bool, error) {
	c, err := m.Docker.InspectOne(ctx, config.ContainerName(name))
	return c != nil, err
}

// Stop stops a session container.
func (m *Manager) Stop(ctx context.Context, name string) error {
	return m.Docker.Stop(ctx, config.ContainerName(name), 1)
}

// Delete removes a session container. Its history stays on the host.
func (m *Manager) Delete(ctx context.Context, name string, force bool) error {
	return m.Docker.Remove(ctx, config.ContainerName(name), force)
}
