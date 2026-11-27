// Package session holds the session lifecycle logic shared by the CLI and the
// dashboard.
package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
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

// sessionUmask starts every script that creates files in a session, or
// starts processes that do: `docker exec` does not inherit the container's
// umask on every engine, and some run commands with 0000.
const sessionUmask = "umask 022"

// rootShell runs a script as root by absolute path, so docker does not look
// sh up in a PATH that, in older images, has a folder sclaw can write.
var rootShell = []string{"/bin/sh", "-c"}

// rootPath is the PATH for scripts run as root. It leaves out sclaw's
// folders for the same reason.
const rootPath = "export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// gitIdentity sets the container's git identity from the GitHub account, in
// the given git config scope.
func gitIdentity(scope string) string {
	return `
if gh auth status >/dev/null 2>&1; then
    USER_DATA=$(gh api user 2>/dev/null)
    if [ -n "$USER_DATA" ]; then
        NAME=$(echo "$USER_DATA" | jq -r ".name // .login")
        LOGIN=$(echo "$USER_DATA" | jq -r ".login")
        EMAIL=$(echo "$USER_DATA" | jq -r ".email // empty")
        # Use noreply email if no public email
        [ -z "$EMAIL" ] && EMAIL="${LOGIN}@users.noreply.github.com"
        git config ` + scope + ` user.name "$NAME"
        git config ` + scope + ` user.email "$EMAIL"
    fi
fi
`
}

// gitCredentialHelper makes git use gh, and so GH_TOKEN, for GitHub over
// https. With ~/.gitconfig root-owned, `gh auth setup-git` can't set it.
const gitCredentialHelper = "!/usr/bin/gh auth git-credential"

// gitConfigScript runs as root and writes the GitHub credential helper and
// the git identity to the root-owned /etc/gitconfig, with GH_TOKEN from the
// root-owned env file. Running as root, gh uses root's home and not sclaw's
// gh config.
var gitConfigScript = sessionUmask + "\n" + rootPath + "\n. " + config.EnvFile +
	"\ngit config --system credential.https://github.com.helper '" + gitCredentialHelper + "'" +
	gitIdentity("--system")

// legacyGitConfigScript writes the git identity to sclaw's ~/.gitconfig in
// containers from images without the root-owned env file. It runs as sclaw
// under bash, which sources the env file through BASH_ENV.
var legacyGitConfigScript = sessionUmask + gitIdentity("--global")

// legacyTmuxScript starts the tmux session in containers built from the
// upstream image, which do not ship the safeclaw binary.
const legacyTmuxScript = sessionUmask + `
if ! tmux has-session -t main 2>/dev/null; then
    tmux -f /dev/null new -d -s main
    tmux set -t main status off
    tmux set -t main mouse on
    tmux send-keys -t main "claude --dangerously-skip-permissions" Enter
fi
`

// envLayoutScript prints "root" when the image has the root-owned env file
// and "user" when it only sources sclaw's ~/.env. It runs as root.
const envLayoutScript = rootPath + "\nif [ -f " + config.EnvFile + " ]; then echo root; else echo user; fi"

// writeEnvScript replaces the root-owned env file's contents with stdin. It
// runs as root, which has no capabilities in a session and so can't chown,
// so the file is rewritten in place to keep the root:sclaw 0640 the image
// created it with.
const writeEnvScript = rootPath + "\numask 077 && cat > " + config.EnvFile

// legacyWriteEnvScript replaces sclaw's ~/.env with stdin, readable only by
// sclaw, in containers from images without the root-owned env file.
const legacyWriteEnvScript = `umask 077 && cat > ` + config.LegacyEnvFile + ` && chmod 600 ` + config.LegacyEnvFile

var nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]*$`)

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

// ErrImageLabel is wrapped by the error returned when an image carries a
// safeclaw label that only safeclaw may set on containers.
var ErrImageLabel = errors.New("image carries a safeclaw label")

// checkImage returns an error wrapping ErrNoImage unless the image for a
// variant ("" for the base image) exists, and one wrapping ErrImageLabel if
// it carries safeclaw labels other than its own variant's.
func (m *Manager) checkImage(ctx context.Context, name string) error {
	_, err := m.checkedImageLabels(ctx, name)
	return err
}

// checkedImageLabels checks the image for a variant like checkImage and
// returns its labels.
func (m *Manager) checkedImageLabels(ctx context.Context, name string) (map[string]string, error) {
	img, err := m.Docker.InspectImage(ctx, variant.Image(name))
	if err != nil {
		return nil, err
	}
	if img == nil {
		return nil, noImageError{variant: name}
	}
	return img.Config.Labels, checkImageLabels(variant.Image(name), name, img.Config.Labels)
}

// checkImageLabels refuses an image carrying any safeclaw label except the
// safeclaw.variant label naming its own variant. Docker copies an image's
// labels onto every container made from it, so without this an image could
// mark the containers safeclaw creates from it as sandboxes, sign-in
// containers, or sessions with host IPC or a different secret set.
func checkImageLabels(image, name string, labels map[string]string) error {
	if name == config.BaseVariant {
		name = ""
	}
	for _, k := range slices.Sorted(maps.Keys(labels)) {
		if !strings.HasPrefix(k, config.LabelPrefix) {
			continue
		}
		if k == config.LabelVariant && name != "" && labels[k] == name {
			continue
		}
		return fmt.Errorf("%w: image '%s' has the label %s=%q, which only safeclaw sets on containers. Rebuild the image without it", ErrImageLabel, image, k, labels[k])
	}
	return nil
}

// ErrNoClaudeToken is returned by non-interactive runs without a Claude token.
var ErrNoClaudeToken = errors.New("no Claude Code token found. Run `safeclaw auth login` to create one, or pipe one to `safeclaw auth set`")

// ErrLegacyName is wrapped by the error returned for a session name with
// uppercase letters.
var ErrLegacyName = errors.New("session names are lowercase")

// ValidateName checks that a session name is canonical: lowercase, without
// the container prefix, and a valid container name. Each session then has
// one container, history directory, and state file, even on a
// case-insensitive filesystem.
func ValidateName(name string) error {
	if nameRe.MatchString(strings.ToLower(name)) && strings.ToLower(name) != name {
		return legacyNameError(name)
	}
	if !nameRe.MatchString(name) {
		return fmt.Errorf("invalid session name %q: use lowercase letters, numbers, '.', '_' and '-', starting with a letter or number", name)
	}
	if strings.HasPrefix(name, config.ContainerPrefix) {
		return fmt.Errorf("invalid session name %q: session names may not start with %q", name, config.ContainerPrefix)
	}
	return nil
}

// legacyNameError explains a session name with uppercase letters, which
// earlier versions accepted.
func legacyNameError(name string) error {
	return fmt.Errorf("invalid session name %q: %w. A container made with this name before names were lowercased can only be removed with `docker rm -f %s`, then created again as %q", name, ErrLegacyName, config.ContainerName(name), strings.ToLower(name))
}

// ResolveName returns the canonical session name for a name given on the
// command line: one container prefix is removed and letters are lowercased,
// as the dashboard does. A name with uppercase letters is refused if a
// container was made with exactly that name before names were lowercased,
// so a command meant for it never acts on the lowercase session instead.
func (m *Manager) ResolveName(ctx context.Context, name string) (string, error) {
	name = config.SessionName(name)
	if lower := strings.ToLower(name); lower != name {
		if nameRe.MatchString(lower) {
			c, err := m.Docker.InspectOne(ctx, config.ContainerName(name))
			if err != nil {
				return "", err
			}
			if c != nil && c.ShortName() == config.ContainerName(name) {
				return "", legacyNameError(name)
			}
		}
		name = lower
	}
	if err := ValidateName(name); err != nil {
		return "", err
	}
	return name, nil
}

// NormalizeName applies the dashboard's name rules: spaces become dashes,
// letters are lowercased, one container prefix is removed as Ensure and
// the CLI do, and an empty name means the default session. The result
// still needs ValidateName, which refuses a name left with the prefix.
func NormalizeName(name string) string {
	name = strings.TrimSpace(strings.ToLower(strings.ReplaceAll(name, " ", "-")))
	name = config.SessionName(strings.Trim(name, "-"))
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
	// ChoicesDir holds each session's policy choices, kept so they outlive
	// its container. Defaults to the choices directory next to SessionsDir.
	ChoicesDir string
	// CopyDir holds the per-sandbox locks that serialize copies into each
	// sandbox. Defaults to config.CopyDir().
	CopyDir string
	// TTYDDir holds each session's ttyd credential. Defaults to
	// config.TTYDDir().
	TTYDDir string
	// DashboardDir holds the token file of each running dashboard, which
	// OpenTerminal looks for. Defaults to config.DashboardDir().
	DashboardDir string
	// Out receives progress messages. Defaults to io.Discard.
	Out io.Writer
	// Prompter is used for interactive runs.
	Prompter Prompter

	// PortFree reports whether a host port can be bound. Defaults to a
	// net.Listen probe.
	PortFree func(port int) bool
	// AuthDir holds the owner files that running logins lock for as long
	// as their sign-in containers exist. Defaults to config.AuthDir().
	AuthDir string
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
		Docker:       docker.New(),
		Secrets:      secrets.Open(config.SecretsDir(), config.SecretsLockPath(), os.Stderr),
		SessionsDir:  config.SessionsDir(),
		NetworkDir:   config.NetworkDir(),
		CopyDir:      config.CopyDir(),
		TTYDDir:      config.TTYDDir(),
		DashboardDir: config.DashboardDir(),
		AuthDir:      config.AuthDir(),
		Out:          out,
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

// noMemoryOf reports whether the user turned a container's auto memory off.
// Containers without the label keep it on.
func noMemoryOf(c docker.Container) bool {
	return c.Label(config.LabelMemory) == config.MemoryOff
}

// memoryArgs returns the `docker run` label recording that a session's auto
// memory is off, none when it is on.
func memoryArgs(noMemory bool) []string {
	if !noMemory {
		return nil
	}
	return []string{"--label", config.LabelMemory + "=" + config.MemoryOff}
}

// memoryOffSettings turn Claude Code's auto memory off from managed
// settings. The env var is set too, because one set to 0 in the
// environment would otherwise turn it back on; managed env wins over it.
const memoryOffSettings = `{"autoMemoryEnabled": false, "env": {"CLAUDE_CODE_DISABLE_AUTO_MEMORY": "1"}}` + "\n"

// memoryOnSettings leave auto memory to Claude Code's default, on.
const memoryOnSettings = "{}\n"

// writeMemoryOffScript replaces the session settings file's contents with
// stdin, as root. The image creates it root:root 0644; for older images
// root creates it, which needs no capability since root owns /etc.
const writeMemoryOffScript = rootPath + "\numask 022 && mkdir -p " + config.ManagedSettingsDir + " && cat > " + config.SessionSettingsFile

// writeMemoryOnScript replaces the session settings file's contents with
// stdin, as root, if the image has it. Older images without it already
// leave auto memory on.
const writeMemoryOnScript = rootPath + "\numask 022 && if [ -f " + config.SessionSettingsFile + " ]; then cat > " + config.SessionSettingsFile + "; fi"

// writeMemorySetting writes the session's auto memory choice to the
// root-owned managed settings file before Claude Code starts, so sclaw can't
// turn it back on.
func (m *Manager) writeMemorySetting(ctx context.Context, container string, noMemory bool) error {
	settings, script := memoryOnSettings, writeMemoryOnScript
	if noMemory {
		settings, script = memoryOffSettings, writeMemoryOffScript
	}
	_, err := m.Docker.Exec(ctx, container, docker.ExecOptions{User: "root", Stdin: strings.NewReader(settings)}, append(slices.Clone(rootShell), script)...)
	if err != nil {
		return fmt.Errorf("writing the auto memory setting in %s: %w", container, err)
	}
	return nil
}

// hardenArgs are the `docker run` flags that take every capability from a
// session and keep its processes from gaining privileges, for example from
// setuid binaries. Sessions run everything as the unprivileged sclaw user,
// which needs no capabilities: Playwright starts Chromium with --no-sandbox,
// and nothing in a session uses sudo, su, or ping.
var hardenArgs = []string{"--cap-drop", "ALL", "--security-opt", "no-new-privileges"}

// hardened reports whether a container was created with hardenArgs.
// Containers created before sessions dropped their capabilities were not.
func hardened(c docker.Container) bool {
	return slices.ContainsFunc(c.HostConfig.CapDrop, func(s string) bool { return strings.EqualFold(s, "ALL") }) &&
		slices.ContainsFunc(c.HostConfig.SecurityOpt, func(s string) bool {
			return s == "no-new-privileges" || s == "no-new-privileges:true" || s == "no-new-privileges=true"
		})
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
	// Sessions are published on PublishHost, and their URLs name it, but a
	// port another program holds on 127.0.0.1 is skipped too, so a session
	// port means the same thing on either loopback address.
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
	// container's set, or the set kept for a session whose container was
	// removed, or gives a new session every secret. A different set
	// recreates an existing container. Names it lists must exist.
	Secrets *SecretSet
	// HostIPC shares the docker host's IPC namespace and /dev/shm with the
	// session when true, and gives it a private one when false. Nil keeps an
	// existing container's choice, or gives a new one a private namespace.
	// A different choice recreates an existing container.
	HostIPC *bool
	// NoMemory turns Claude Code's auto memory off for the session when
	// true, through a root-owned managed settings file, and back on when
	// false. Nil keeps an existing container's choice, or the choice kept
	// for a session whose container was removed, or leaves it on for a new
	// session. A different choice recreates an existing container.
	NoMemory *bool
	// FreshHistory moves the session's history directory aside, to
	// NAME.old-TIMESTAMP next to it, so the new container starts with an
	// empty one. It recreates an existing container.
	FreshHistory bool
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

// URLFor returns the URL of a session published on PublishHost at a host
// port, without the credential ttyd requires; see URLWithCredential.
func URLFor(port int) string {
	return urlOn(PublishHost, port, nil)
}

// Ensure creates, starts, or refreshes a session container and starts ttyd
// in it. It is the equivalent of upstream's run.sh.
//
// Locks are taken in one order, and none is taken while a later one is
// held, so they never deadlock: the session's own Ensure lock (see
// ensureLock), then m.mu, then the network lock. Delete, `net off`, and
// `net on` take only the network lock.
func (m *Manager) Ensure(ctx context.Context, opts Options) (*Result, error) {
	name := opts.Name
	if name == "" {
		name = config.DefaultSession
	}
	name = config.SessionName(name)
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	container := config.ContainerName(name)

	release, err := m.ensureLock(ctx, name)
	if err != nil {
		return nil, err
	}
	defer release()

	m.mu.Lock()
	defer m.mu.Unlock()

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
	imageLabels, err := m.checkedImageLabels(ctx, want)
	if err != nil {
		return nil, err
	}

	// A session without a container gets back the choices its last one
	// recorded, kept on the host when it was created or removed.
	var kept *choices
	if existing == nil {
		if kept, err = m.readChoices(name); err != nil {
			return nil, err
		}
	}

	set := AllSecrets()
	switch {
	case existing != nil:
		set = secretsOf(*existing)
	case kept != nil:
		// readChoices checked the names.
		set, _ = kept.secretSet()
	}
	oldSet := set
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

	noMemory := (existing != nil && noMemoryOf(*existing)) || (kept != nil && kept.NoMemory)
	memoryChanged := false
	if opts.NoMemory != nil {
		memoryChanged = existing != nil && *opts.NoMemory != noMemory
		noMemory = *opts.NoMemory
	}

	explicit := opts.Volume != "" || changed || secretsChanged || ipcChanged || memoryChanged || opts.FreshHistory
	// A session published on the dashboard's cookie host, as ones created
	// before terminals moved to PublishHost are, is moved there, but only
	// when its image's ttyd accepts the [::1] URLs that then name it.
	legacyPublish := existing != nil && existing.HostPort(config.TTYDPort) > 0 && publishedOnCookieHost(*existing)
	// A session published on PublishHost from an image whose ttyd refuses
	// [::1] URLs has no safe URL, so it is recreated from the image once
	// that is updated.
	oldTTYD := existing != nil && existing.HostPort(config.TTYDPort) > 0 && !legacyPublish && !acceptsBracketedHost(existing.Config.Labels)
	imageTTYD := acceptsBracketedHost(imageLabels)
	// Every container created here is published on PublishHost, so its
	// image must accept [::1] URLs. Only a kept legacy session can go on
	// without one, on the address it is published on.
	if !imageTTYD && (existing == nil || explicit || oldTTYD) {
		return nil, oldTTYDError(name, want, oldTTYD && !explicit)
	}
	// A kept container whose ttyd takes its credential on its command line
	// is recreated from the image, so the credential leaves ttyd's command
	// line, which every local user can read on a native Linux docker host.
	argvCredential := existing != nil && !readsCredentialFile(existing.Config.Labels)
	movePublish := legacyPublish && imageTTYD
	recreate := existing != nil && (explicit || movePublish || oldTTYD || argvCredential)
	// So every ttyd started here, in a new container or a kept one, reads
	// its credential from a file, and nothing is refused after the
	// container it would replace is removed.
	if !readsCredentialFile(imageLabels) && (existing == nil || recreate) {
		return nil, argvCredentialError(name, want, recreate && !explicit)
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
	// A held session stays offline even if something reconnected it. One
	// whose saved state can't be read may be held, so it is refused rather
	// than started or recreated online.
	offline := false
	if existing != nil {
		if offline, err = m.OfflineOrHeld(*existing); err != nil {
			return nil, err
		}
	}
	// restore recreates the removed container if its replacement can't be
	// created, so a failed recreate never leaves the session without its
	// container and the secret set recorded in its label.
	var restore func() error
	if recreate {
		if offline && !explicit {
			why := "its ttyd takes its credential on its command line, and starting it recreates it from the updated image, whose ttyd reads it from a file"
			switch {
			case movePublish:
				why = fmt.Sprintf("its terminal is published on %s, the dashboard's cookie host, and starting it recreates it on [%s]", legacyPublishHost, PublishHost)
			case oldTTYD:
				why = fmt.Sprintf("its ttyd refuses [%s] URLs, and starting it recreates it from the updated image", PublishHost)
			}
			return nil, fmt.Errorf("session %q %w: %s. Run `safeclaw net on %s` first", name, ErrOffline, why, name)
		}
		if offline {
			return nil, fmt.Errorf("session %q %w: run `safeclaw net on %s` before changing its volume, variant, secrets, IPC namespace, auto memory, or history", name, ErrOffline, name)
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
		case ipcChanged && hostIPC:
			m.printf("Host IPC namespace requested. Removing existing container...\n")
		case ipcChanged:
			m.printf("Private IPC namespace requested. Removing existing container...\n")
		case memoryChanged && noMemory:
			m.printf("Auto memory off requested. Removing existing container...\n")
		case memoryChanged:
			m.printf("Auto memory on requested. Removing existing container...\n")
		case movePublish && !opts.FreshHistory:
			m.printf("Session %s publishes its terminal on %s, the dashboard's cookie host, because it was created before terminals moved to [%s]. Removing existing container to recreate it there...\n", name, legacyPublishHost, PublishHost)
		case oldTTYD && !opts.FreshHistory:
			m.printf("Session %s's ttyd refuses [%s] URLs because it was created from an older image. Removing existing container to recreate it from the updated one...\n", name, PublishHost)
		case !opts.FreshHistory:
			m.printf("Session %s's ttyd takes its credential on its command line because it was created from an older image. Removing existing container to recreate it from the updated one, whose ttyd reads it from a file...\n", name)
		default:
			m.printf("Fresh history requested. Removing existing container...\n")
		}
		// The restored container keeps the recorded IPC choice, so one that
		// shared the host's without opting in comes back private.
		oldVariant, oldSet, oldHostIPC, oldNoMemory := variantOf(*existing), secretsOf(*existing), hostIPCOf(*existing), noMemoryOf(*existing)
		// Kept first, so they outlive the container even if neither it nor
		// its replacement can be created.
		if err := m.keepChoices(name, *existing); err != nil {
			return nil, err
		}
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
			if err := m.checkImage(ctx, oldVariant); err != nil {
				return err
			}
			return m.create(ctx, name, container, port, oldVariant, oldSet, oldHostIPC, oldNoMemory, oldVolumes)
		}
	}

	// A kept container that shares the host's IPC namespace without opting
	// in predates private namespaces becoming the default.
	if existing != nil && !hostIPC && sharesHostIPC(*existing) {
		m.printf("Warning: session %s shares the host's IPC namespace because it was created before private namespaces became the default. Run with --host-ipc=false to recreate it with a private one, or --host-ipc to keep sharing it\n", name)
	}
	// A kept container keeps its address, which its URL names; a new one is
	// published on PublishHost. Either way its ttyd accepts the URL: one on
	// PublishHost whose ttyd refuses [::1] URLs was refused or recreated
	// above.
	host := PublishHost
	if existing != nil && existing.HostPort(config.TTYDPort) > 0 {
		host = publishedHost(*existing)
	}
	// Only a kept legacy session is still published there: its image's
	// ttyd refuses the [::1] URLs a recreated one would get. Its own ttyd
	// reads its credential from a file, or it was refused above.
	if existing != nil && legacyPublish {
		m.printf("Warning: session %s publishes its terminal on %s, the dashboard's cookie host, because it was created before terminals moved to [%s], and its image's ttyd refuses [%s] URLs. Update the image with %s, then run `safeclaw run -s %s` again to recreate it on [%s]\n", name, legacyPublishHost, PublishHost, PublishHost, updateImageCommands(want), name, PublishHost)
	}
	if existing != nil && !hardened(*existing) {
		m.printf("Warning: session %s keeps docker's default capabilities and can gain privileges, because it was created before sessions dropped them. Recreate it, for example with -v or `safeclaw rm`, to drop them\n", name)
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
		// A held session still attached to a network, for example after a
		// failed disconnect, is taken offline again.
		if offline {
			if err := m.keepOffline(ctx, container); err != nil {
				return nil, err
			}
		}
		// Restart ttyd/tmux so fresh env vars take effect. The old ttyd
		// must be gone before its credential is rotated and a new one
		// starts; tmux has no server when nothing is attached, so its
		// error is ignored.
		if err := m.stopTTYD(ctx, name, container); err != nil {
			return nil, err
		}
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
		archived := ""
		if opts.FreshHistory {
			if archived, err = m.archiveHistory(name); err != nil {
				if restore != nil {
					if rerr := restore(); rerr != nil {
						return nil, fmt.Errorf("%w (restoring the previous container also failed: %w)", err, rerr)
					}
				}
				return nil, err
			}
		} else {
			m.warnHistory(name, historyChoices{
				recreated:      restore != nil,
				kept:           kept != nil,
				givenSecrets:   opts.Secrets != nil,
				givenMemory:    opts.NoMemory != nil,
				secretsChanged: secretsChanged,
				oldSet:         oldSet,
				set:            set,
				noMemory:       noMemory,
			})
		}
		m.printf("Creating container: %s\n", container)
		if err := m.create(ctx, name, container, port, want, set, hostIPC, noMemory, volumes); err != nil {
			// The previous container gets its own history back.
			if archived != "" {
				if rerr := m.unarchiveHistory(name, archived); rerr != nil {
					return nil, fmt.Errorf("%w (moving the history back from %s also failed: %w)", err, archived, rerr)
				}
			}
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
	// The container's labels hold the choices while it exists; the copy on
	// the host gives them back to the next one if it is removed. A kept
	// container's are kept too, so ones created before choices were kept
	// on the host get them.
	if err := m.writeChoices(name, newChoices(set, noMemory)); err != nil {
		return nil, err
	}
	unlock()

	written, rootOwned, err := m.writeEnv(ctx, container, set)
	if err != nil {
		return nil, err
	}
	if !slices.ContainsFunc(written, func(s secrets.Secret) bool { return s.Name == secrets.ClaudeToken }) {
		m.printf("Warning: this session does not receive %s, so Claude Code will not be logged in\n", secrets.ClaudeToken)
	}

	if slices.ContainsFunc(written, func(s secrets.Secret) bool { return s.Name == secrets.GitHubToken }) {
		m.writeGitConfig(ctx, container, rootOwned)
	}

	// Claude Code reads the setting when it starts, which is after ttyd
	// starts and the terminal connects, or when a query is sent.
	if err := m.writeMemorySetting(ctx, container, noMemory); err != nil {
		return nil, err
	}

	native := m.hasNativeWrapper(ctx, container)
	// A kept container runs its own image's ttyd; a new one, the image's.
	ttydLabels := imageLabels
	if existing != nil {
		ttydLabels = existing.Config.Labels
	}
	// Every path here starts ttyd with a new credential: a new container,
	// a stopped one started again, and a running one whose ttyd was killed
	// above.
	cred, err := m.startTTYD(ctx, name, want, container, native, ttydLabels)
	if err != nil {
		return nil, err
	}

	res := &Result{Name: name, Container: container, Port: port, URL: urlOn(host, port, &cred), Offline: offline}
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

	if !opts.NoOpen && !offline {
		_ = m.OpenTerminal(ctx, name, res.URL)
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

// historyChoices describe the choices a new container is created with,
// for warnHistory.
type historyChoices struct {
	// recreated is set when the container replaces one this run removed.
	recreated bool
	// kept is set when the choices of the session's last container were
	// kept on the host.
	kept bool
	// givenSecrets and givenMemory are set when this run picks the secrets
	// or the auto memory choice.
	givenSecrets, givenMemory bool
	// secretsChanged is set when this run recreates the container with a
	// different set of secrets.
	secretsChanged bool
	// oldSet is the set the history was written with, when it is known,
	// and set the one the new container receives.
	oldSet, set SecretSet
	// noMemory is set when the new container's auto memory is off.
	noMemory bool
}

// warnHistory warns when a new container reuses history, including the
// transcripts and memory Claude Code reads, that an earlier container wrote
// with a different or unknown set of secrets, or whose auto memory choice
// is unknown.
func (m *Manager) warnHistory(name string, c historyChoices) {
	if !m.hasHistory(name) {
		return
	}
	switch {
	case c.secretsChanged || (c.kept && c.givenSecrets && !c.set.Equal(c.oldSet)):
		m.printf("Warning: session %s keeps the history its previous container wrote with %s, including transcripts and memory that Claude Code reads, and now receives %s. Use --fresh-history to start with an empty one\n", name, c.oldSet, c.set)
	case c.recreated || c.kept:
		// The secrets are the ones the history was written with.
	case !c.givenSecrets && c.set.All():
		m.printf("Warning: session %s has history from an earlier container, but no secret selection is remembered, so it receives every secret. Use --secrets or --no-secrets to limit it, or --fresh-history to start with an empty history\n", name)
	case c.givenSecrets:
		m.printf("Warning: session %s has history from an earlier container, including transcripts and memory that Claude Code reads, which may have been written with other secrets than %s. Use --fresh-history to start with an empty one\n", name, c.set)
	}
	if !c.recreated && !c.kept && !c.givenMemory && !c.noMemory {
		m.printf("Warning: session %s has history from an earlier container, but no auto memory choice is remembered, so auto memory is on and Claude Code loads the MEMORY.md it left. Use --no-memory to keep it off, or --fresh-history to start with an empty history\n", name)
	}
}

// archiveTime formats the time in the name a history directory is moved
// to. Its UTC offset is written as +0000, and no session name may contain
// '+' or uppercase letters, so a moved directory is never the history of
// another session, even on a case-insensitive filesystem.
const archiveTime = "20060102T150405-0700"

// archiveHistory moves a session's history directory aside, to
// NAME.old-TIMESTAMP, returning its new path, or "" if it had none.
func (m *Manager) archiveHistory(name string) (string, error) {
	dir := filepath.Join(m.SessionsDir, name)
	if _, err := os.Lstat(dir); errors.Is(err, os.ErrNotExist) {
		return "", nil
	} else if err != nil {
		return "", err
	}
	to := dir + ".old-" + time.Now().UTC().Format(archiveTime)
	if _, err := os.Lstat(to); err == nil {
		return "", fmt.Errorf("can't move the history of session %s aside: %s already exists", name, to)
	}
	if err := os.Rename(dir, to); err != nil {
		return "", fmt.Errorf("moving the history of session %s aside: %w", name, err)
	}
	m.printf("Moved the history of session %s to %s\n", name, to)
	return to, nil
}

// unarchiveHistory moves a history directory back after the new container
// could not be created, removing the empty one made for it first.
func (m *Manager) unarchiveHistory(name, archived string) error {
	dir := filepath.Join(m.SessionsDir, name)
	if err := os.Remove(dir); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(archived, dir)
}

// create runs a session container. It gets docker's default private IPC
// namespace and /dev/shm unless hostIPC is set: Playwright launches Chromium
// with --disable-dev-shm-usage, so the default 64 MiB /dev/shm is enough.
//
// The history mount is a plain bind mount: docker's bind mounts take no
// nosuid or nodev option, but hardenArgs cover both, since setuid bits are
// ignored with no-new-privileges and device nodes can't be made without
// CAP_MKNOD.
func (m *Manager) create(ctx context.Context, name, container string, port int, variantName string, set SecretSet, hostIPC, noMemory bool, volumes []string) error {
	dataDir, err := m.historyDir(name)
	if err != nil {
		return err
	}
	args := []string{"-d"}
	args = append(args, ipcArgs(hostIPC)...)
	args = append(args,
		"--name", container,
		"--label", config.LabelType+"="+config.TypeSession,
	)
	args = append(args, hardenArgs...)
	args = append(args, publishArgs(port)...)
	args = append(args, "-v", dataDir+":"+config.ProjectsMount)
	args = append(args, variantArgs(variantName)...)
	args = append(args, secretArgs(set)...)
	args = append(args, memoryArgs(noMemory)...)
	for _, volume := range volumes {
		v, err := ExpandVolume(volume)
		if err != nil {
			return err
		}
		m.printf("Mounting volume: %s\n", v)
		args = append(args, "-v", v)
	}
	args = append(args, variant.Image(variantName), "sleep", "infinity")
	_, err = m.Docker.Run(ctx, args...)
	return err
}

// historyDir creates a session's history directory, and the directory
// holding every session's, readable only by the user: they hold transcripts
// and memory. Ones created open to others, before history was kept private,
// are restricted too.
func (m *Manager) historyDir(name string) (string, error) {
	dir := filepath.Join(m.SessionsDir, name)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	for _, d := range []string{m.SessionsDir, dir} {
		if err := os.Chmod(d, 0o700); err != nil {
			return "", err
		}
	}
	return dir, nil
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

// rootOwnedEnv reports whether the container's image has the root-owned env
// file, rather than only sourcing sclaw's ~/.env like older images.
func (m *Manager) rootOwnedEnv(ctx context.Context, container string) (bool, error) {
	out, err := m.Docker.Exec(ctx, container, docker.ExecOptions{User: "root"}, append(slices.Clone(rootShell), envLayoutScript)...)
	if err != nil {
		return false, err
	}
	switch strings.TrimSpace(string(out)) {
	case "root":
		return true, nil
	case "user":
		return false, nil
	}
	return false, fmt.Errorf("checking the env file in %s: unexpected output %q", container, out)
}

// writeEnv replaces the container's env file with the secrets in the set and
// returns the ones it wrote. Secrets left out of the set are not written, so
// they are dropped from a container that had them. In images with the
// root-owned env file it is written as root, so the agent can't change it;
// older images get sclaw's ~/.env. rootOwned says which was written.
func (m *Manager) writeEnv(ctx context.Context, container string, set SecretSet) (written []secrets.Secret, rootOwned bool, err error) {
	selected, err := m.selectSecrets(set)
	if err != nil {
		return nil, false, err
	}
	rootOwned, err = m.rootOwnedEnv(ctx, container)
	if err != nil {
		return nil, false, err
	}
	in := docker.ExecOptions{Stdin: strings.NewReader(secrets.RenderEnv(selected))}
	if rootOwned {
		in.User = "root"
		_, err = m.Docker.Exec(ctx, container, in, append(slices.Clone(rootShell), writeEnvScript)...)
	} else {
		_, err = m.Docker.Exec(ctx, container, in, "sh", "-c", legacyWriteEnvScript)
	}
	return selected, rootOwned, err
}

// writeGitConfig sets the container's git identity from the GitHub account:
// in the root-owned /etc/gitconfig as root, or in sclaw's ~/.gitconfig in
// older images. Failures are ignored, as the session works without it.
func (m *Manager) writeGitConfig(ctx context.Context, container string, rootOwned bool) {
	if rootOwned {
		_, _ = m.Docker.Exec(ctx, container, docker.ExecOptions{User: "root"}, append(slices.Clone(rootShell), gitConfigScript)...)
		return
	}
	_, _ = m.Docker.Exec(ctx, container, docker.ExecOptions{}, "bash", "-c", legacyGitConfigScript)
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
	// -- keeps a query starting with '-' from being read as options.
	if err := tmux("-l", "--", query); err != nil {
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

// TypeOf returns a container's session type. safeclaw labels every session
// and sandbox it creates with its type, and refuses images that carry the
// label, so the label is never inherited from an image. Containers without
// it, created by versions that left it off sessions, are interactive
// sessions.
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
			Holds:      m.listedHolds(config.SessionName(name), c),
		}
		if mounts := c.BindMounts(config.ProjectsMount); len(mounts) > 0 {
			s.Volume = strings.Join(mounts, ", ")
		}
		if s.Active {
			if p := c.HostPort(config.TTYDPort); p > 0 {
				s.Port = p
				// A session without a safe URL is listed without one.
				if host, ok := containerURLHost(c); ok {
					s.URL = urlOn(host, p, nil)
				}
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
	name = config.SessionName(name)
	if err := ValidateName(name); err != nil {
		return err
	}
	return m.Docker.Stop(ctx, config.ContainerName(name), 1)
}

// DeleteOptions configures DeleteWith.
type DeleteOptions struct {
	// Force removes a running container too.
	Force bool
	// ReleaseHolds removes a session held offline, releasing every hold,
	// and one whose saved state can't be read.
	ReleaseHolds bool
}

// Delete removes a session container, as DeleteWith does without releasing
// holds.
func (m *Manager) Delete(ctx context.Context, name string, force bool) error {
	return m.DeleteWith(ctx, name, DeleteOptions{Force: force})
}

// DeleteWith removes a session container, its saved network state, and its
// ttyd credential. Its history stays on the host, and so do its secrets and
// auto memory choices, which the next container created with its name gets
// back. A session held offline is refused with an error wrapping ErrHeld
// that names its holders, unless opts.ReleaseHolds is set, so removing it
// can't take it from a job that relies on it being offline. It all happens
// under the network lock, so a container created and taken offline under
// the same name meanwhile keeps its hold.
func (m *Manager) DeleteWith(ctx context.Context, name string, opts DeleteOptions) error {
	name = config.SessionName(name)
	if err := ValidateName(name); err != nil {
		return err
	}
	unlock, err := m.netLock()
	if err != nil {
		return err
	}
	defer unlock()

	c, err := m.Docker.InspectOne(ctx, config.ContainerName(name))
	if err != nil {
		return err
	}
	if c == nil {
		// docker reports the missing container.
		return m.Docker.Remove(ctx, config.ContainerName(name), opts.Force)
	}
	holds, err := m.holdsFor(name, *c)
	if err != nil && !opts.ReleaseHolds {
		return err
	}
	if len(holds) > 0 && !opts.ReleaseHolds {
		return fmt.Errorf("session %q %w by %s: release the holds with `safeclaw net on %s --owner OWNER` first, or remove it anyway with `safeclaw rm --release-holds %s`", name, ErrHeld, strings.Join(HoldLabels(holds), ", "), name, name)
	}
	if err := m.keepChoices(name, *c); err != nil {
		return err
	}
	if err := m.Docker.Remove(ctx, config.ContainerName(name), opts.Force); err != nil {
		return err
	}
	if err := m.removeRemovedState(ctx, name, opts.ReleaseHolds); err != nil {
		return err
	}
	return m.removeCredential(name)
}
