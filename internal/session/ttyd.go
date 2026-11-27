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

// startTTYDScript starts ttyd with the credential written to
// config.TTYDCredentialFile, so it never appears in a host command line,
// and with sessionUmask, which the wrapper, tmux, and Claude Code inherit.
const startTTYDScript = sessionUmask + `; exec ttyd -c "$(cat ` + config.TTYDCredentialFile + `)" "$@"`

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

// urlHost returns the host the URLs of a terminal published on host name,
// given its container's or image's labels: host itself, or localhost for
// PublishHost from an image whose ttyd refuses a bracketed IPv6 Host.
// That ttyd's origin check never passes for [::1]:PORT, and localhost
// resolves to [::1].
func urlHost(host string, labels map[string]string) string {
	if host == PublishHost && labels[config.LabelBracketedHostTTYD] == "" {
		return "localhost"
	}
	return host
}

// containerURLHost returns the host a container's terminal URLs name; see
// urlHost.
func containerURLHost(c docker.Container) string {
	return urlHost(publishedHost(c), c.Config.Labels)
}

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

// ensureCredential returns the session's ttyd credential, making a random
// one the first time. It is kept on the host, readable only by the user,
// so it survives ttyd restarts and container recreates.
func (m *Manager) ensureCredential(name string) (Credential, error) {
	c, err := m.Credential(name)
	if err == nil {
		return c, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Credential{}, err
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return Credential{}, err
	}
	c = Credential{User: config.TTYDUser, Password: base64.RawURLEncoding.EncodeToString(b)}
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

// startTTYD starts ttyd requiring the session's credential (-c) and
// refusing WebSocket clients from other origins (-O). The credential goes
// to the container on stdin, not on a command line. The image's ttyd is
// patched to refuse framing on every response (setup/ttyd), which needs no
// flag, so older images' ttyd still starts with these arguments.
func (m *Manager) startTTYD(ctx context.Context, name, container string, native bool) (Credential, error) {
	cred, err := m.ensureCredential(name)
	if err != nil {
		return Credential{}, err
	}
	if _, err := m.Docker.Exec(ctx, container, docker.ExecOptions{Stdin: strings.NewReader(cred.String())}, "sh", "-c", writeCredentialScript); err != nil {
		return Credential{}, err
	}
	args := []string{"sh", "-c", startTTYDScript, "ttyd", "-W", "-O", "-t", "titleFixed=SafeClaw - " + name, "-p", strconv.Itoa(config.TTYDPort)}
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

	// browserHost is the host its URL names; see urlHost.
	browserHost string
}

// URL returns the terminal's URL with its credential in it, on the address
// it is published on; see urlHost.
func (t *Terminal) URL() string {
	return urlOn(t.browserHost, t.Port, &t.Credential)
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
	return &Terminal{
		Addr:        net.JoinHostPort(publishedHost(*c), strconv.Itoa(port)),
		Host:        "localhost:" + strconv.Itoa(port),
		Port:        port,
		Credential:  cred,
		browserHost: containerURLHost(*c),
	}, nil
}
