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
	"time"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/variant"
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

// readsCredentialFile reports whether a container's or image's labels mark
// a ttyd that reads its credential from a file with --credential-file. One
// without it takes the credential only with -c, on its command line, which
// every local user can read on a native Linux docker host.
func readsCredentialFile(labels map[string]string) bool {
	return labels[config.LabelCredentialFileTTYD] != ""
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

// ErrArgvCredential is wrapped by the errors for a session whose image's
// ttyd takes its credential only on its command line; see
// readsCredentialFile.
var ErrArgvCredential = errors.New("its image's ttyd has no --credential-file")

// argvCredentialError returns the error for session name, whose variant's
// image has a ttyd without --credential-file. kept says the session's own
// container is the one refused, so it is recreated once the image is
// updated.
func argvCredentialError(name, variant string, kept bool) error {
	then := "then run it again"
	if kept {
		then = "then run `safeclaw run -s " + name + "` to recreate the session from it"
	}
	return fmt.Errorf("session %q: %w, so its credential would be on ttyd's command line, which other local users can read on a native Linux docker host. Update the image with %s, %s", name, ErrArgvCredential, updateImageCommands(variant), then)
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

// ensureLock takes the session's own lock, which Ensure holds from before
// it reads the container until it returns, so two safeclaw processes (the
// CLI and the dashboard, say) can't interleave restarting one session's
// ttyd: each would rotate the credential, and the host file could end up
// holding one while ttyd took the other. It is a file in a directory of
// the ttyd directory whose dot no session name can start with, so it is
// never taken for a credential. Waiting for it ends with ctx, so a run
// stuck holding it can't keep another past its Ctrl-C.
func (m *Manager) ensureLock(ctx context.Context, name string) (func(), error) {
	release, err := lockFileCtx(ctx, filepath.Join(m.ttydDir(), ".ensure"), name+".lock")
	if err != nil {
		return nil, fmt.Errorf("session %q: wait for other runs of it: %w", name, err)
	}
	return release, nil
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
// line. labels are the container's, which it copied from its image, and
// variant is the session's: a container without
// config.LabelCredentialFileTTYD has a ttyd that takes the credential only
// with -c, on its command line, so it is refused. Ensure recreates or
// refuses such a container before changing anything, so it never gets
// here. The image's ttyd is also patched to refuse framing on every
// response (setup/ttyd), which needs no flag. It returns once the new ttyd
// answers a request carrying the new credential, or an error wrapping
// ErrTTYDRestart if it doesn't.
func (m *Manager) startTTYD(ctx context.Context, name, variant, container string, native bool, labels map[string]string) (Credential, error) {
	if !readsCredentialFile(labels) {
		return Credential{}, argvCredentialError(name, variant, true)
	}
	cred, err := m.rotateCredential(name)
	if err != nil {
		return Credential{}, err
	}
	if _, err := m.Docker.Exec(ctx, container, asSclaw(docker.ExecOptions{Stdin: strings.NewReader(cred.String())}), "sh", "-c", writeCredentialScript); err != nil {
		return Credential{}, err
	}
	args := []string{"sh", "-c", startTTYDScript, "ttyd", "-W", "-O", "-t", "titleFixed=SafeClaw - " + name, "-p", strconv.Itoa(config.TTYDPort)}
	if native {
		args = append(args, "safeclaw", "ttyd-wrapper")
	} else {
		args = append(args, config.LegacyWrapper)
	}
	if _, err := m.Docker.Exec(ctx, container, asSclaw(docker.ExecOptions{Detach: true}), args...); err != nil {
		return Credential{}, err
	}
	if err := m.checkTTYDAnswers(ctx, name, container, cred); err != nil {
		return Credential{}, err
	}
	return cred, nil
}

// The scripts below match ttyd with the pattern [t]tyd, which matches
// "ttyd" but not itself, so pkill -f never matches the shell running it.
// Nor does any other text in them, so a pkill never ends one mid-check.
var (
	// killTTYDScript signals every process with ttyd in its command line,
	// ttyd and the wrapper it runs, with pkill's default SIGTERM or the
	// signal given as its argument. pkill exits 1 when nothing matched,
	// which is not an error here.
	killTTYDScript = `pkill "$@" -f '[t]tyd'; s=$?; [ "$s" -le 1 ] || exit "$s"`
	// ttydGoneScript prints why ttyd is not gone yet: a ttyd process, or
	// anything listening on ttyd's port, read from /proc/net since the
	// image may have no ss or netstat. It prints nothing once both are
	// gone.
	ttydGoneScript = `pgrep -x '[t]tyd' >/dev/null; s=$?; [ "$s" -le 1 ] || exit "$s"
if [ "$s" -eq 0 ]; then echo 'its process is still running'
elif grep -Eqs '^ *[0-9]+: [0-9A-F]+:` + ttydPortHex + ` [0-9A-F]+:[0-9A-F]+ 0A ' /proc/net/tcp /proc/net/tcp6; then echo 'something still listens on port ` + ttydPortStr + `'
fi`
	// ttydAnswersScript requests ttyd's page with the credential curl reads
	// from its config on stdin, so it is on no command line, and prints the
	// HTTP status unless it is 200, or 000 when nothing answered.
	ttydAnswersScript = `c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 2 --config - http://127.0.0.1:` + ttydPortStr + `/); [ "$c" = 200 ] || echo "$c"`

	ttydPortStr = strconv.Itoa(config.TTYDPort)
	ttydPortHex = fmt.Sprintf("%04X", config.TTYDPort)
)

// How often, and for how long, a ttyd is checked while it stops or starts.
const (
	ttydPoll       = 200 * time.Millisecond
	ttydStopPolls  = 25 // 5s for SIGTERM, then as long again for SIGKILL
	ttydStartPolls = 50 // 10s
)

// ErrTTYDRestart is wrapped by the errors for a ttyd that could not be
// stopped, or a new one that did not answer with its new credential.
var ErrTTYDRestart = errors.New("its ttyd could not be restarted")

// stopTTYD stops the ttyd running in a session's container, and waits until
// no ttyd runs and nothing listens on its port, so the one started next
// with a new credential is the only one: an old ttyd left running would
// keep the port and take the old credential while the host file and the
// printed URL carry the new one. One that ignores SIGTERM gets SIGKILL. A
// failed pkill, or a ttyd still there after SIGKILL, is an error, before
// the credential is rotated, so the old credential stays the one the host
// file holds.
func (m *Manager) stopTTYD(ctx context.Context, name, container string) error {
	why := ""
	for _, sig := range [][]string{nil, {"-KILL"}} {
		args := append([]string{"sh", "-c", killTTYDScript, "sh"}, sig...)
		if _, err := m.Docker.Exec(ctx, container, asSclaw(docker.ExecOptions{}), args...); err != nil {
			return fmt.Errorf("session %q: %w: stopping the old ttyd failed: %w", name, ErrTTYDRestart, err)
		}
		var err error
		why, err = m.pollTTYD(ctx, container, ttydGoneScript, nil, ttydStopPolls, nil)
		if err != nil {
			return fmt.Errorf("session %q: %w: checking that the old ttyd stopped failed: %w", name, ErrTTYDRestart, err)
		}
		if why == "" {
			return nil
		}
	}
	return fmt.Errorf("session %q: %w: the old ttyd did not stop (%s), so it would keep taking the old credential. Stop the session with `safeclaw stop %s` and run it again", name, ErrTTYDRestart, why, name)
}

// checkTTYDAnswers waits until the ttyd just started in container answers
// a request carrying cred. A refusal means another ttyd, with another
// credential, holds the port, and is an error right away.
func (m *Manager) checkTTYDAnswers(ctx context.Context, name, container string, cred Credential) error {
	stdin := func() io.Reader { return strings.NewReader(`user = "` + cred.String() + "\"\n") }
	status, err := m.pollTTYD(ctx, container, ttydAnswersScript, stdin, ttydStartPolls, func(out string) bool { return out == "401" })
	switch {
	case err != nil:
		return fmt.Errorf("session %q: %w: checking that the new ttyd answers failed: %w", name, ErrTTYDRestart, err)
	case status == "401":
		return fmt.Errorf("session %q: %w: the ttyd on port %d refused the new credential, so another ttyd still holds it. Stop the session with `safeclaw stop %s` and run it again", name, ErrTTYDRestart, config.TTYDPort, name)
	case status != "":
		return fmt.Errorf("session %q: %w: the new ttyd did not answer on port %d (HTTP status %s)", name, ErrTTYDRestart, config.TTYDPort, status)
	}
	return nil
}

// pollTTYD runs script in container up to polls times, ttydPoll apart,
// until it prints nothing or prints what final accepts, and returns its
// last output. stdin, when set, gives each run its stdin.
func (m *Manager) pollTTYD(ctx context.Context, container, script string, stdin func() io.Reader, polls int, final func(string) bool) (string, error) {
	out := ""
	for i := range polls {
		if i > 0 {
			m.sleep(ttydPoll)
		}
		if err := ctx.Err(); err != nil {
			return "", err
		}
		opts := asSclaw(docker.ExecOptions{})
		if stdin != nil {
			opts.Stdin = stdin()
		}
		b, err := m.Docker.Exec(ctx, container, opts, "sh", "-c", script)
		if err != nil {
			return "", err
		}
		out = strings.TrimSpace(string(b))
		if out == "" || (final != nil && final(out)) {
			break
		}
	}
	return out, nil
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
	// legacyHost says it is published on 127.0.0.1, the dashboard's cookie
	// host, as sessions created before PublishHost were.
	legacyHost bool
	// argvCredential says its ttyd takes its credential on its command
	// line; see readsCredentialFile.
	argvCredential bool
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
// ttyd, and its credential. A session held offline has none, even while
// still attached. A session without one gets an error wrapping
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
	// A held session that is still attached, for example after a failed
	// disconnect, is relayed to no more than an offline one, and neither is
	// one whose saved state can't be read.
	holds, err := m.holdsFor(name, *c)
	if err != nil {
		return nil, fmt.Errorf("session %q %w: %w", name, ErrNoTerminal, err)
	}
	if len(holds) > 0 {
		return nil, noTerminal("it is held offline by " + strings.Join(HoldLabels(holds), ", ") + "; bring it back with `safeclaw net on " + name + "`")
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
		Addr:           net.JoinHostPort(publishedHost(*c), strconv.Itoa(port)),
		Host:           "localhost:" + strconv.Itoa(port),
		Port:           port,
		Credential:     cred,
		browserHost:    browserHost,
		legacyHost:     publishedOnCookieHost(*c),
		argvCredential: !readsCredentialFile(c.Config.Labels),
		name:           name,
		variant:        variantOf(*c),
	}, nil
}

// legacyPublishWarning returns the warning for kept session name, published
// on legacyPublishHost, whose variant's image has a ttyd that refuses [::1]
// URLs, so it can't be recreated on PublishHost yet.
func legacyPublishWarning(name, want string) string {
	return fmt.Sprintf("Warning: session %s publishes its terminal on %s, the dashboard's cookie host, because it was created before terminals moved to [%s], and its image's ttyd refuses [%s] URLs. Update the image with %s, then run `safeclaw run -s %s` again to recreate it on [%s]\n", name, legacyPublishHost, PublishHost, PublishHost, updateImageCommands(want), name, PublishHost)
}

// WarnTerminal prints the warnings `safeclaw run` gives about a session an
// earlier version created, for a terminal whose URL is about to be printed
// without running it: one published on 127.0.0.1, the dashboard's cookie
// host, and one whose ttyd takes its credential on its command line. Each
// says how to recreate the session, updating its image first when the
// image would be refused.
func (m *Manager) WarnTerminal(ctx context.Context, t *Terminal) {
	if !t.legacyHost && !t.argvCredential {
		return
	}
	// The image is only looked at to say whether it needs updating first,
	// so one that can't be inspected is taken to need it.
	updated := false
	if img, err := m.Docker.InspectImage(ctx, variant.Image(t.variant)); err == nil && img != nil {
		updated = acceptsBracketedHost(img.Config.Labels) && readsCredentialFile(img.Config.Labels)
	}
	if t.legacyHost {
		if updated {
			m.printf("Warning: session %s publishes its terminal on %s, the dashboard's cookie host, because it was created before terminals moved to [%s]. Run `safeclaw run -s %s` to recreate it there\n", t.name, legacyPublishHost, PublishHost, t.name)
		} else {
			m.printf("%s", legacyPublishWarning(t.name, t.variant))
		}
	}
	if t.argvCredential {
		then := "Update the image with " + updateImageCommands(t.variant) + ", then run `safeclaw run -s " + t.name + "` to recreate the session from it"
		if updated {
			then = "Run `safeclaw run -s " + t.name + "` to recreate it from the updated image, whose ttyd reads it from a file"
		}
		m.printf("Warning: session %s's ttyd takes its credential on its command line, which other local users can read on a native Linux docker host, because it was created from an older image. %s\n", t.name, then)
	}
}
