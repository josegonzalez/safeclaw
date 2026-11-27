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
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/secrets"
	"github.com/josegonzalez/safeclaw/internal/variant"
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

// ErrNoImage is wrapped by the error returned when a session's image is
// missing.
var ErrNoImage = errors.New("image not found")

// noImageError names the missing image and how to get it.
type noImageError struct{ variant string }

func (e noImageError) Error() string {
	flag := ""
	if e.variant != "" {
		flag = " --variant " + e.variant
	}
	return fmt.Sprintf("image '%s' not found. Run `safeclaw pull%s` or `safeclaw build%s` first", variant.Image(e.variant), flag, flag)
}

func (e noImageError) Unwrap() error { return ErrNoImage }

// checkImage returns an error wrapping ErrNoImage unless the image for a
// variant ("" for the base image) exists.
func (m *Manager) checkImage(ctx context.Context, name string) error {
	imageID, err := m.Docker.ImageID(ctx, variant.Image(name))
	if err != nil {
		return err
	}
	if imageID == "" {
		return noImageError{variant: name}
	}
	return nil
}

// ErrNoClaudeToken is returned by non-interactive runs without a Claude token.
var ErrNoClaudeToken = errors.New("no Claude Code token found. Run `safeclaw auth login` to create one, or pipe one to `safeclaw auth set`")

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
	// NetworkDir holds the saved state of offline sessions. Defaults to
	// config.NetworkDir().
	NetworkDir string
	// CopyDir holds the lock that serializes copies into sandboxes.
	// Defaults to config.CopyDir().
	CopyDir string
	// TTYDDir holds each session's ttyd credential. Defaults to
	// config.TTYDDir().
	TTYDDir string
	// Out receives progress messages. Defaults to io.Discard.
	Out io.Writer
	// Prompter is used for interactive runs.
	Prompter Prompter

	// PortFree reports whether a host port can be bound. Defaults to a
	// net.Listen probe.
	PortFree func(port int) bool
	// ProcessAlive reports whether a host PID is running. Defaults to a
	// signal 0 probe.
	ProcessAlive func(pid string) bool
	// Sleep defaults to time.Sleep.
	Sleep func(time.Duration)
	// OpenBrowser defaults to open/xdg-open.
	OpenBrowser func(url string) error
	// PromptTimeout bounds how long a query waits for Claude Code's prompt.
	PromptTimeout time.Duration
	// LoadVariants returns the known image variants. It is called whenever
	// a variant is resolved, so config file edits apply without a restart.
	// Defaults to the built-in variants alone.
	LoadVariants func() (*variant.Set, error)

	mu sync.Mutex
}

// NewManager returns a Manager using the real docker CLI and config paths.
func NewManager(out io.Writer) *Manager {
	return &Manager{
		Docker:      docker.New(),
		Secrets:     secrets.Open(config.SecretsDir(), config.SecretsLockPath(), os.Stderr),
		SessionsDir: config.SessionsDir(),
		NetworkDir:  config.NetworkDir(),
		CopyDir:     config.CopyDir(),
		TTYDDir:     config.TTYDDir(),
		Out:         out,
		LoadVariants: func() (*variant.Set, error) {
			return variant.Load(config.File())
		},
	}
}

// Variants returns the known image variants and defaults.
func (m *Manager) Variants() (*variant.Set, error) {
	if m.LoadVariants == nil {
		return variant.Default(), nil
	}
	return m.LoadVariants()
}

// variantOf returns the variant a container runs, "" for the base image.
func variantOf(c docker.Container) string {
	return c.Label(config.LabelVariant)
}

// pickVariant returns the variant a container of type typ should run: the
// requested one, else the existing container's, else the default for typ.
// It also reports whether the request changes an existing container's
// variant.
func (m *Manager) pickVariant(requested, typ string, existing *docker.Container) (string, bool, error) {
	set, err := m.Variants()
	if err != nil {
		return "", false, err
	}
	if requested == "" {
		if existing != nil {
			return variantOf(*existing), false, nil
		}
		return set.DefaultFor(typ), false, nil
	}
	name, err := set.Resolve(requested)
	if err != nil {
		return "", false, err
	}
	return name, existing != nil && name != variantOf(*existing), nil
}

// variantArgs returns the `docker run` label for a variant, none for the
// base image.
func variantArgs(name string) []string {
	if name == "" || name == config.BaseVariant {
		return nil
	}
	return []string{"--label", config.LabelVariant + "=" + name}
}

// hostIPCOf reports whether the user opted a container into the host's IPC
// namespace. Containers without the label, including ones created before
// private namespaces became the default, have not.
func hostIPCOf(c docker.Container) bool {
	return c.Label(config.LabelIPC) == config.IPCHost
}

// sharesHostIPC reports whether a container is in the host's IPC namespace.
func sharesHostIPC(c docker.Container) bool {
	return c.HostConfig.IpcMode == config.IPCHost
}

// ipcArgs returns the `docker run` flags for a session's IPC namespace:
// docker's default private one, or the host's with a label recording the
// choice.
func ipcArgs(host bool) []string {
	if !host {
		return nil
	}
	return []string{"--ipc=" + config.IPCHost, "--label", config.LabelIPC + "=" + config.IPCHost}
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
	// Sessions are published on PublishHost, but browsers may try either
	// address for localhost, so both must be free.
	for _, host := range []string{PublishHost, legacyPublishHost} {
		l, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			return false
		}
		_ = l.Close()
	}
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
	// Variant is the image variant, config.BaseVariant for the base image.
	// Empty keeps an existing container's variant, or uses the configured
	// default for a new one. A different variant recreates an existing
	// container.
	Variant string
	// Secrets picks the secrets the session receives. Nil keeps an existing
	// container's set, or gives a new one every secret. A different set
	// recreates an existing container. Names it lists must exist.
	Secrets *SecretSet
	// HostIPC shares the docker host's IPC namespace and /dev/shm with the
	// session when true, and gives it a private one when false. Nil keeps an
	// existing container's choice, or gives a new one a private namespace.
	// A different choice recreates an existing container.
	HostIPC *bool
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
	// URL is the session URL with its ttyd credential in it.
	URL string
	// Offline is set when the session is disconnected from every network,
	// so its web terminal is unreachable.
	Offline bool
}

// URLFor returns the session URL for a host port, without the credential
// ttyd requires; see URLWithCredential.
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

	// The network lock keeps `net off` and `net on` from changing the
	// container between the offline check and the remove or start below.
	unlock, err := m.netLock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	existing, err := m.Docker.InspectOne(ctx, container)
	if err != nil {
		return nil, err
	}
	if existing != nil && TypeOf(*existing) == config.TypeSandbox {
		return nil, wrongType(name, ErrIsSandbox)
	}

	want, changed, err := m.pickVariant(opts.Variant, config.TypeSession, existing)
	if err != nil {
		return nil, err
	}
	if err := m.checkImage(ctx, want); err != nil {
		return nil, err
	}

	set := AllSecrets()
	if existing != nil {
		set = secretsOf(*existing)
	}
	secretsChanged := false
	if opts.Secrets != nil {
		secretsChanged = existing != nil && !opts.Secrets.Equal(set)
		set = *opts.Secrets
	}

	hostIPC := existing != nil && hostIPCOf(*existing)
	ipcChanged := false
	if opts.HostIPC != nil {
		// Recreate when either the recorded choice or the container itself
		// differs, so a container created with host IPC before the label
		// existed can be moved to a private namespace, or have its choice
		// recorded.
		ipcChanged = existing != nil && (*opts.HostIPC != hostIPC || *opts.HostIPC != sharesHostIPC(*existing))
		hostIPC = *opts.HostIPC
	}

	if err := m.ensureTokens(opts.Interactive, set); err != nil {
		return nil, err
	}
	if set.Includes(secrets.ClaudeToken) {
		m.warnToken()
	}
	if opts.Secrets != nil {
		if err := m.checkSecrets(set); err != nil {
			return nil, err
		}
	}

	port := 0
	if existing != nil {
		port = existing.HostPort(config.TTYDPort)
	}

	// A recreated container keeps whatever this run does not change.
	var volumes []string
	if opts.Volume != "" {
		volumes = []string{opts.Volume}
	}
	// A held session stays offline even if something reconnected it.
	offline := existing != nil && (Offline(*existing) || len(m.holdsFor(name, *existing)) > 0)
	// restore recreates the removed container if its replacement can't be
	// created, so a failed recreate never leaves the session without its
	// container and the secret set recorded in its label.
	var restore func() error
	if existing != nil && (opts.Volume != "" || changed || secretsChanged || ipcChanged) {
		if offline {
			return nil, fmt.Errorf("session %q %w: run `safeclaw net on %s` before changing its volume, variant, secrets, or IPC namespace", name, ErrOffline, name)
		}
		oldVolumes := existing.BindSpecs(config.ProjectsMount)
		if opts.Volume == "" {
			volumes = oldVolumes
		}
		// Check every volume before anything is removed.
		for _, v := range volumes {
			if _, err := ExpandVolume(v); err != nil {
				return nil, err
			}
		}
		switch {
		case opts.Volume != "":
			m.printf("Volume mount requested. Removing existing container...\n")
		case changed:
			m.printf("Variant %s requested. Removing existing container...\n", variant.Label(want))
		case secretsChanged:
			m.printf("Secrets changed to %s. Removing existing container...\n", set)
		case hostIPC:
			m.printf("Host IPC namespace requested. Removing existing container...\n")
		default:
			m.printf("Private IPC namespace requested. Removing existing container...\n")
		}
		// The restored container keeps the recorded IPC choice, so one that
		// shared the host's without opting in comes back private.
		oldVariant, oldSet, oldHostIPC := variantOf(*existing), secretsOf(*existing), hostIPCOf(*existing)
		if err := m.Docker.Remove(ctx, container, true); err != nil {
			return nil, err
		}
		existing = nil
		restore = func() error {
			m.printf("Restoring the previous container: %s\n", container)
			// A failed start leaves the new container behind, created but
			// not running.
			c, err := m.Docker.InspectOne(ctx, container)
			if err != nil {
				return err
			}
			if c != nil {
				if err := m.Docker.Remove(ctx, container, true); err != nil {
					return err
				}
			}
			return m.create(ctx, name, container, port, oldVariant, oldSet, oldHostIPC, oldVolumes)
		}
	}

	// A kept container that shares the host's IPC namespace without opting
	// in predates private namespaces becoming the default.
	if existing != nil && !hostIPC && sharesHostIPC(*existing) {
		m.printf("Warning: session %s shares the host's IPC namespace because it was created before private namespaces became the default. Run with --host-ipc=false to recreate it with a private one, or --host-ipc to keep sharing it\n", name)
	}
	if existing != nil && existing.HostPort(config.TTYDPort) > 0 && publishedOnCookieHost(*existing) {
		m.printf("Warning: session %s publishes its terminal on 127.0.0.1, the dashboard's cookie host, because it was created before terminals moved to [::1]. Recreate it, for example with -v or `safeclaw rm`, to move it\n", name)
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
		offline = Offline(*existing)
		// Restart ttyd/tmux so fresh env vars take effect.
		_, _ = m.Docker.Exec(ctx, container, docker.ExecOptions{}, "pkill", "-f", "ttyd")
		_, _ = m.Docker.Exec(ctx, container, docker.ExecOptions{}, "tmux", "kill-server")
		m.sleep(time.Second)
	case existing != nil:
		m.printf("Starting existing container: %s\n", container)
		if err := m.Docker.Start(ctx, container); err != nil {
			return nil, err
		}
		if offline {
			if err := m.keepOffline(ctx, container); err != nil {
				return nil, err
			}
		}
	default:
		if restore == nil && opts.Secrets == nil && set.All() && m.hasHistory(name) {
			m.printf("Warning: session %s has history from an earlier container, but no secret selection is remembered, so it receives every secret. Use --secrets or --no-secrets to limit it\n", name)
		}
		m.printf("Creating container: %s\n", container)
		if err := m.create(ctx, name, container, port, want, set, hostIPC, volumes); err != nil {
			if restore != nil {
				if rerr := restore(); rerr != nil {
					return nil, fmt.Errorf("%w (restoring the previous container also failed: %w)", err, rerr)
				}
			}
			return nil, err
		}
		// Any saved state belonged to an earlier container.
		if err := m.removeState(name); err != nil {
			return nil, err
		}
	}
	unlock()

	written, err := m.writeEnv(ctx, container, set)
	if err != nil {
		return nil, err
	}
	if !slices.ContainsFunc(written, func(s secrets.Secret) bool { return s.Name == secrets.ClaudeToken }) {
		m.printf("Warning: this session does not receive %s, so Claude Code will not be logged in\n", secrets.ClaudeToken)
	}

	if slices.ContainsFunc(written, func(s secrets.Secret) bool { return s.Name == secrets.GitHubToken }) {
		_, _ = m.Docker.Exec(ctx, container, docker.ExecOptions{}, "bash", "-c", gitConfigScript)
	}

	native := m.hasNativeWrapper(ctx, container)
	cred, err := m.startTTYD(ctx, name, container, native)
	if err != nil {
		return nil, err
	}

	res := &Result{Name: name, Container: container, Port: port, URL: URLWithCredential(port, cred), Offline: offline}
	m.printf("\nSafeClaw is running at: %s\n", res.URL)
	if offline {
		m.printf("Warning: this session is offline, so its web terminal is unreachable until: safeclaw net on %s\n", name)
	}

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

// ensureTokens makes sure the well-known tokens a session receives exist,
// prompting for them in interactive runs. Tokens the set leaves out are
// neither required nor prompted for.
func (m *Manager) ensureTokens(interactive bool, set SecretSet) error {
	if set.Includes(secrets.ClaudeToken) && !m.Secrets.Has(secrets.ClaudeToken) {
		if !interactive || m.Prompter == nil {
			return ErrNoClaudeToken
		}
		tok, err := m.Prompter.ClaudeToken()
		if err != nil {
			return err
		}
		if err := m.Secrets.Set(secrets.ClaudeToken, tok); err != nil {
			return err
		}
	}
	if set.Includes(secrets.GitHubToken) && !m.Secrets.Has(secrets.GitHubToken) && interactive && m.Prompter != nil {
		tok, err := m.Prompter.GitHubToken()
		if err != nil {
			return err
		}
		if tok != "" {
			if err := m.Secrets.Set(secrets.GitHubToken, tok); err != nil {
				return err
			}
		}
	}
	return nil
}

// allocatePort returns the lowest port from FirstSessionPort that no
// safeclaw container has reserved and that is free on the host.
func (m *Manager) allocatePort(ctx context.Context) (int, error) {
	if m.PortFree == nil {
		l, err := net.Listen("tcp", net.JoinHostPort(PublishHost, "0"))
		if err != nil {
			return 0, fmt.Errorf("session terminals are published on [%s], which this host can't listen on: %w", PublishHost, err)
		}
		_ = l.Close()
	}
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

// hasHistory reports whether the session's history directory exists, which
// means a container of that name existed before.
func (m *Manager) hasHistory(name string) bool {
	_, err := os.Stat(filepath.Join(m.SessionsDir, name))
	return err == nil
}

// create runs a session container. It gets docker's default private IPC
// namespace and /dev/shm unless hostIPC is set: Playwright launches Chromium
// with --disable-dev-shm-usage, so the default 64 MiB /dev/shm is enough.
func (m *Manager) create(ctx context.Context, name, container string, port int, variantName string, set SecretSet, hostIPC bool, volumes []string) error {
	dataDir := filepath.Join(m.SessionsDir, name)
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return err
	}
	args := []string{"-d"}
	args = append(args, ipcArgs(hostIPC)...)
	args = append(args,
		"--name", container,
	)
	args = append(args, publishArgs(port)...)
	args = append(args, "-v", dataDir+":"+config.ProjectsMount)
	args = append(args, variantArgs(variantName)...)
	args = append(args, secretArgs(set)...)
	for _, volume := range volumes {
		v, err := ExpandVolume(volume)
		if err != nil {
			return err
		}
		m.printf("Mounting volume: %s\n", v)
		args = append(args, "-v", v)
	}
	args = append(args, variant.Image(variantName), "sleep", "infinity")
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

// writeEnv replaces the container's env file with the secrets in the set and
// returns the ones it wrote. Secrets left out of the set are not written, so
// they are dropped from a container that had them.
func (m *Manager) writeEnv(ctx context.Context, container string, set SecretSet) ([]secrets.Secret, error) {
	selected, err := m.selectSecrets(set)
	if err != nil {
		return nil, err
	}
	_, err = m.Docker.Exec(ctx, container, docker.ExecOptions{Stdin: strings.NewReader(secrets.RenderEnv(selected))}, "sh", "-c", writeEnvScript)
	return selected, err
}

func (m *Manager) hasNativeWrapper(ctx context.Context, container string) bool {
	_, err := m.Docker.Exec(ctx, container, docker.ExecOptions{}, "sh", "-c", "command -v safeclaw")
	return err == nil
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
	// Variant is the image variant, "" for the base image.
	Variant string `json:"variant"`
	// AutoRemove is set for one-off sandboxes, which docker removes when
	// they stop.
	AutoRemove bool `json:"autoRemove"`
	// Secrets are the secrets the session receives. Sandboxes receive none.
	Secrets SecretSet `json:"-"`
	// Network is NetOnline, NetOffline, NetNone, NetHost, or NetShared.
	Network string `json:"network"`
	// Holds are the holds keeping an interactive session offline.
	Holds []Hold `json:"-"`
}

// IsOffline reports whether the session is disconnected from every network.
func (s Session) IsOffline() bool {
	return s.Network == NetOffline
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
			Variant:    variantOf(c),
			AutoRemove: c.HostConfig.AutoRemove,
			Secrets:    sessionSecrets(c),
			Network:    NetworkStatus(c),
			Holds:      m.holdsFor(config.SessionName(name), c),
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

// Delete removes a session container, its saved network state, and its
// ttyd credential. Its history stays on the host.
func (m *Manager) Delete(ctx context.Context, name string, force bool) error {
	if err := m.Docker.Remove(ctx, config.ContainerName(name), force); err != nil {
		return err
	}
	unlock, err := m.netLock()
	if err != nil {
		return err
	}
	defer unlock()
	if err := m.removeState(config.SessionName(name)); err != nil {
		return err
	}
	return m.removeCredential(name)
}
