package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
)

// PublishHost is the host address session terminals are published on. It
// must differ from the dashboard's cookie host, 127.0.0.1: cookies are not
// scoped by port, so a session that replaced its own ttyd and got the
// browser to load http://127.0.0.1:PORT would otherwise receive the
// dashboard's cookie. Session URLs name it too, as [::1], rather than
// localhost: a browser sends a page on localhost the cookies every other
// local app set for localhost, and may connect to 127.0.0.1 for it, where
// nothing holds the port.
const PublishHost = "::1"

// legacyPublishHost is where sessions created before PublishHost were
// published.
const legacyPublishHost = "127.0.0.1"

// ErrNoTerminal is returned by Terminal for a session without a reachable
// web terminal: missing, stopped, offline, or a sandbox.
var ErrNoTerminal = errors.New("has no running web terminal")

// startTTYDScript starts ttyd reading the credential from
// config.TTYDCredentialFile with the image's patched --credential-file
// (setup/ttyd), so it is in no command line, including ttyd's own, which
// every local user can read on a native Linux docker host. It sets
// sessionUmask, which the wrapper, tmux, and Claude Code inherit.
const startTTYDScript = sessionUmask + `; exec ttyd --credential-file ` + config.TTYDCredentialFile + ` "$@"`

// legacyStartTTYDScript is startTTYDScript for images whose ttyd has no
// --credential-file. The credential stays out of the docker exec command
// line, but is in ttyd's.
const legacyStartTTYDScript = sessionUmask + `; exec ttyd -c "$(cat ` + config.TTYDCredentialFile + `)" "$@"`

// writeCredentialScript replaces the container's credential file with
// stdin, readable only by its owner.
const writeCredentialScript = `umask 077 && cat > ` + config.TTYDCredentialFile + ` && chmod 600 ` + config.TTYDCredentialFile

// Credential is the basic auth credential a session's ttyd requires.
type Credential struct {
	User     string
	Password string
}

// String returns the credential as ttyd's -c takes it, user:password.
func (c Credential) String() string {
	return c.User + ":" + c.Password
}

// Token returns the credential as ttyd expects it in a WebSocket's
// AuthToken and in the Authorization header after "Basic ".
func (c Credential) Token() string {
	return base64.StdEncoding.EncodeToString([]byte(c.String()))
}

// URLWithCredential returns the URL of a session published on PublishHost
// at a host port, with the credential in it, which logs a browser in to
// ttyd directly.
func URLWithCredential(port int, c Credential) string {
	return urlOn(PublishHost, port, &c)
}

// urlOn returns the URL of a terminal published on host at port, with the
// credential in it unless c is nil.
func urlOn(host string, port int, c *Credential) string {
	u := url.URL{Scheme: "http", Host: net.JoinHostPort(host, strconv.Itoa(port))}
	if c != nil {
		u.User = url.UserPassword(c.User, c.Password)
	}
	return u.String()
}

// publishArgs returns the `docker run` flags publishing a session's ttyd on
// a host port.
func publishArgs(port int) []string {
	return []string{"-p", fmt.Sprintf("[%s]:%d:%d", PublishHost, port, config.TTYDPort)}
}

// publishedOnCookieHost reports whether a container's terminal is published
// on 127.0.0.1, as sessions created before PublishHost were.
func publishedOnCookieHost(c docker.Container) bool {
	return publishedHost(c) == legacyPublishHost
}

// publishedHost returns the loopback address a container's terminal is
// published on, which its URLs name: PublishHost, or legacyPublishHost for
// a session created before it, including one published on every address.
func publishedHost(c docker.Container) string {
	switch ip := c.HostIP(config.TTYDPort); ip {
	case "", "0.0.0.0":
		return legacyPublishHost
	case "::":
		return PublishHost
	default:
		return ip
	}
}

// acceptsBracketedHost reports whether a container's or image's labels
// mark a ttyd that accepts a bracketed IPv6 Host such as [::1]:PORT in its
// origin check. Older ttyd's check never passes for [::1]:PORT, so a
// session published on PublishHost from such an image has no URL that is
// both usable and safe: one naming localhost lets a browser fall back to
// 127.0.0.1:PORT, which nothing holds and another local user can bind, and
// publishing the session there too would hand it the dashboard's cookie.
// Such sessions are refused, or recreated from an updated image.
func acceptsBracketedHost(labels map[string]string) bool {
	return labels[config.LabelBracketedHostTTYD] != ""
}

// containerURLHost returns the host a container's terminal URLs name, the
// address it is published on, or false when it has no safe URL: it is
// published on PublishHost and its ttyd refuses [::1] URLs.
func containerURLHost(c docker.Container) (string, bool) {
	host := publishedHost(c)
	if host == PublishHost && !acceptsBracketedHost(c.Config.Labels) {
		return "", false
	}
	return host, true
}

// updateImageCommands returns the commands that update a variant's image.
func updateImageCommands(name string) string {
	if name != "" && name != config.BaseVariant {
		return "`safeclaw pull --variant " + name + "` or `safeclaw build --variant " + name + "`"
	}
	return "`safeclaw pull` or `safeclaw build`"
}

// ErrOldTTYD is wrapped by the errors for a session whose image's ttyd
// refuses [::1] URLs; see acceptsBracketedHost.
var ErrOldTTYD = errors.New("its image's ttyd refuses [::1] URLs")

func (m *Manager) ttydDir() string {
	if m.TTYDDir != "" {
		return m.TTYDDir
	}
	return config.TTYDDir()
}

func (m *Manager) credentialPath(name string) string {
	return filepath.Join(m.ttydDir(), config.SessionName(name))
}

// Credential returns the session's ttyd credential, or an error wrapping
// os.ErrNotExist if it has none yet. A symlink or other entry that is not a
// regular file counts as none, and is replaced when one is made.
func (m *Manager) Credential(name string) (Credential, error) {
	if err := ValidateName(config.SessionName(name)); err != nil {
		return Credential{}, err
	}
	b, err := readRegular(m.credentialPath(name))
	if err != nil {
		return Credential{}, err
	}
	user, pass, ok := strings.Cut(strings.TrimSpace(string(b)), ":")
	if !ok || user == "" || pass == "" {
		return Credential{}, fmt.Errorf("invalid ttyd credential in %s", m.credentialPath(name))
	}
	return Credential{User: user, Password: pass}, nil
}

// rotateCredential replaces the session's ttyd credential with a new random
// one. It is kept on the host, readable only by the user, where the
// dashboard's relay and `safeclaw url` read it. The file is replaced in one
// rename, so it is never missing or partly written.
func (m *Manager) rotateCredential(name string) (Credential, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return Credential{}, err
	}
	c := Credential{User: config.TTYDUser, Password: base64.RawURLEncoding.EncodeToString(b)}
	if err := writePrivate(m.credentialPath(name), c.String()+"\n"); err != nil {
		return Credential{}, fmt.Errorf("write ttyd credential: %w", err)
	}
	return c, nil
}

// readRegular reads path without following a symlink at it. An entry that
// is not a regular file is reported as not existing.
func readRegular(path string) ([]byte, error) {
	// O_NONBLOCK keeps a FIFO from blocking the open; it is refused below.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, syscall.ELOOP) {
		return nil, fmt.Errorf("%s is not a regular file: %w", path, os.ErrNotExist)
	}
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file: %w", path, os.ErrNotExist)
	}
	return io.ReadAll(io.LimitReader(f, 4096))
}

// removeCredential removes the session's ttyd credential.
func (m *Manager) removeCredential(name string) error {
	err := os.Remove(m.credentialPath(name))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	return err
}

// writePrivate replaces path with content, readable only by the user, in a
// directory only the user can open.
func writePrivate(path, content string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := io.WriteString(f, content); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// startTTYD starts ttyd requiring a new credential and refusing WebSocket
// clients from other origins (-O). Every start rotates the credential, so
// one that an earlier container could read, or that a browser sent to
// whatever held the session's port while its ttyd was down, never opens the
// terminal again: a stopped container's published port is released, and
// another local user can bind it and answer an open tab's reconnect, which
// carries the browser's cached credential. The credential goes to the
// container on stdin, and ttyd reads it from a file, so it is on no command
// line. labels are the container's, which it copied from its image: an
// image without config.LabelCredentialFileTTYD has a ttyd that takes the
// credential only with -c, on its command line, and the user is warned.
// The image's ttyd is also patched to refuse framing on every response
// (setup/ttyd), which needs no flag, so older images' ttyd still starts
// with these arguments.
func (m *Manager) startTTYD(ctx context.Context, name, container string, native bool, labels map[string]string) (Credential, error) {
	cred, err := m.rotateCredential(name)
	if err != nil {
		return Credential{}, err
	}
	if _, err := m.Docker.Exec(ctx, container, docker.ExecOptions{Stdin: strings.NewReader(cred.String())}, "sh", "-c", writeCredentialScript); err != nil {
		return Credential{}, err
	}
	script := startTTYDScript
	if labels[config.LabelCredentialFileTTYD] == "" {
		script = legacyStartTTYDScript
		m.printf("Warning: session %s's ttyd takes its credential on its command line, which other local users can read on a Linux host, because its image's ttyd has no --credential-file. Update the image with `safeclaw pull` or `safeclaw build`, then recreate the session, for example with -v or `safeclaw rm`\n", name)
	}
	args := []string{"sh", "-c", script, "ttyd", "-W", "-O", "-t", "titleFixed=SafeClaw - " + name, "-p", strconv.Itoa(config.TTYDPort)}
	if native {
		args = append(args, "safeclaw", "ttyd-wrapper")
	} else {
		args = append(args, config.LegacyWrapper)
	}
	_, err = m.Docker.Exec(ctx, container, docker.ExecOptions{Detach: true}, args...)
	return cred, err
}

// Terminal is where a running session's ttyd can be reached from the host.
type Terminal struct {
	// Addr is the host:port the terminal is published on, which its URL
	// names and the dashboard's relay dials.
	Addr string
	// Host is the Host and Origin the relay sends, localhost:PORT. ttyd's
	// origin check compares Origin's host, stripped of brackets, with the
	// Host header as sent, so it never passes for a bracketed address such
	// as [::1]:PORT. The relay's headers never reach a browser, so they
	// carry no cookies.
	Host string
	// Port is the host port, which session URLs name.
	Port       int
	Credential Credential

	// browserHost is the host its URL names, or "" when it has none; see
	// containerURLHost.
	browserHost string
	// name and variant are the session's, for the error URL returns.
	name, variant string
}

// URL returns the terminal's URL with its credential in it, on the address
// it is published on. A terminal published on PublishHost whose ttyd
// refuses [::1] URLs has none, and gets an error wrapping ErrOldTTYD that
// says how to recreate it; the dashboard's relay still reaches it, since no
// browser connects to it there.
func (t *Terminal) URL() (string, error) {
	if t.browserHost == "" {
		return "", oldTTYDError(t.name, t.variant, true)
	}
	return urlOn(t.browserHost, t.Port, &t.Credential), nil
}

// oldTTYDError returns the error for session name, whose variant's image
// has a ttyd that refuses [::1] URLs. kept says the session's own container
// is the one refused, so it is recreated once the image is updated.
func oldTTYDError(name, variant string, kept bool) error {
	then := "then run it again"
	if kept {
		then = "then run `safeclaw run -s " + name + "` to recreate the session from it"
	}
	return fmt.Errorf("session %q: %w, so its terminal URL would have to name localhost, where a browser can fall back to 127.0.0.1, which another local user can listen on. Update the image with %s, %s", name, ErrOldTTYD, updateImageCommands(variant), then)
}

// Terminal returns where to reach a running, online interactive session's
// ttyd, and its credential. A session without one gets an error wrapping
// ErrNoTerminal that says why.
func (m *Manager) Terminal(ctx context.Context, name string) (*Terminal, error) {
	name = config.SessionName(name)
	c, err := m.Docker.InspectOne(ctx, config.ContainerName(name))
	if err != nil {
		return nil, err
	}
	noTerminal := func(why string) error {
		return fmt.Errorf("session %q %w: %s", name, ErrNoTerminal, why)
	}
	switch {
	case c == nil:
		return nil, noTerminal("it does not exist")
	case TypeOf(*c) != config.TypeSession:
		return nil, noTerminal("it is a sandbox")
	case !c.State.Running:
		return nil, noTerminal("it is stopped; start it with `safeclaw run -s " + name + "`")
	case Offline(*c):
		return nil, noTerminal("it is offline; bring it back with `safeclaw net on " + name + "`")
	}
	port := c.HostPort(config.TTYDPort)
	if port == 0 {
		return nil, noTerminal("it has no published port")
	}
	cred, err := m.Credential(name)
	if err != nil {
		return nil, fmt.Errorf("session %q: read ttyd credential: %w", name, err)
	}
	browserHost, _ := containerURLHost(*c)
	return &Terminal{
		Addr:        net.JoinHostPort(publishedHost(*c), strconv.Itoa(port)),
		Host:        "localhost:" + strconv.Itoa(port),
		Port:        port,
		Credential:  cred,
		browserHost: browserHost,
		name:        name,
		variant:     variantOf(*c),
	}, nil
}
