package session

import (
	"bytes"
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
)

func TestTTYDRequiresCredentialAndOrigin(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{}, native: true}
	m, r := newTestManager(t, w)
	res, err := m.Ensure(context.Background(), Options{Name: "work", NoOpen: true})
	if err != nil {
		t.Fatal(err)
	}
	cred, err := m.Credential("work")
	if err != nil {
		t.Fatal(err)
	}
	if cred.User != "safeclaw" || len(cred.Password) < 40 {
		t.Errorf("credential = %+v, want user safeclaw and a long random password", cred)
	}
	if res.URL != URLWithCredential(res.Port, cred) || !strings.HasPrefix(res.URL, "http://safeclaw:") {
		t.Errorf("url = %q", res.URL)
	}

	start, ok := r.Find("exec -d safeclaw-work sh -c ")
	if !ok {
		t.Fatalf("ttyd not started: %v", r.Commands())
	}
	argv := start.Args[slices.Index(start.Args, "ttyd")+1:]
	if !slices.Contains(argv, "-O") || !slices.Contains(argv, "-W") || !strings.Contains(strings.Join(start.Args, " "), `ttyd -c "$(cat /home/sclaw/.ttyd-credential)"`) {
		t.Errorf("ttyd argv = %q, want -c from the credential file and -O", start.Args)
	}
	write, ok := r.Find("exec -i safeclaw-work sh -c umask 077 && cat > /home/sclaw/.ttyd-credential")
	if !ok || write.Stdin != cred.String() {
		t.Errorf("credential not written to the container on stdin: %+v", write)
	}
	for _, c := range r.Commands() {
		if strings.Contains(c, cred.Password) {
			t.Errorf("credential leaked into a host command line: %q", c)
		}
	}
}

func TestCredentialFileIsPrivateAndPersists(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{}, native: true}
	m, _ := newTestManager(t, w)
	ctx := context.Background()
	if _, err := m.Ensure(ctx, Options{Name: "work", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	first, err := m.Credential("work")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(m.TTYDDir, "work")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("credential file mode = %v, want 0600", fi.Mode().Perm())
	}
	di, err := os.Stat(m.TTYDDir)
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("credential dir mode = %v, want 0700", di.Mode().Perm())
	}
	// The history directory is mounted into the container.
	if rel, err := filepath.Rel(m.SessionsDir, path); err == nil && !strings.HasPrefix(rel, "..") {
		t.Errorf("credential %s is inside the mounted history dir %s", path, m.SessionsDir)
	}

	// Restarting ttyd in the running container keeps the credential.
	if _, err := m.Ensure(ctx, Options{Name: "work", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	again, err := m.Credential("work")
	if err != nil || again != first {
		t.Errorf("credential changed across restarts: %+v, %+v (%v)", first, again, err)
	}

	if err := m.Delete(ctx, "work", true); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Credential("work"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("credential after delete: %v", err)
	}
}

// lastCredentialWrite returns what was last written to a container's
// credential file.
func lastCredentialWrite(t *testing.T, r *dockertest.Runner, container string) string {
	t.Helper()
	prefix := "exec -i " + container + " sh -c umask 077 && cat > /home/sclaw/.ttyd-credential"
	for _, c := range slices.Backward(r.Calls) {
		if strings.HasPrefix(c.String(), prefix) {
			return c.Stdin
		}
	}
	t.Fatalf("credential not written to %s: %v", container, r.Commands())
	return ""
}

// A new container for a session's name gets a new credential, which its
// ttyd is started with; restarting a container keeps it.
func TestCredentialRotatesWithContainer(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		replace func(t *testing.T, w *world, m *Manager) Options
		rotated bool
	}{
		{"plain run", func(*testing.T, *world, *Manager) Options {
			return Options{Name: "work"}
		}, false},
		{"start", func(_ *testing.T, w *world, _ *Manager) Options {
			w.containers["safeclaw-work"].Running = false
			return Options{Name: "work"}
		}, false},
		{"same secrets", func(*testing.T, *world, *Manager) Options {
			return Options{Name: "work", Secrets: ptr(AllSecrets())}
		}, false},
		{"secrets", func(*testing.T, *world, *Manager) Options {
			return Options{Name: "work", Secrets: ptr(NoSecrets())}
		}, true},
		{"fresh history", func(*testing.T, *world, *Manager) Options {
			return Options{Name: "work", FreshHistory: true}
		}, true},
		{"volume", func(*testing.T, *world, *Manager) Options {
			return Options{Name: "work", Volume: "/host/proj:/home/sclaw/proj"}
		}, true},
		{"build recreate", func(t *testing.T, _ *world, m *Manager) Options {
			c, err := m.Docker.InspectOne(ctx, "safeclaw-work")
			if err != nil || c == nil {
				t.Fatal(c, err)
			}
			if removed, err := m.RemoveStale(ctx, *c); !removed || err != nil {
				t.Fatalf("removed %v, err %v", removed, err)
			}
			return Options{Name: "work"}
		}, true},
		{"removed outside safeclaw", func(_ *testing.T, w *world, _ *Manager) Options {
			delete(w.containers, "safeclaw-work")
			return Options{Name: "work"}
		}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &world{image: "img", containers: map[string]*fakeContainer{}, native: true}
			m, r := newTestManager(t, w)
			if _, err := m.Ensure(ctx, Options{Name: "work", NoOpen: true}); err != nil {
				t.Fatal(err)
			}
			old, err := m.Credential("work")
			if err != nil {
				t.Fatal(err)
			}
			opts := tc.replace(t, w, m)
			opts.NoOpen = true
			r.Calls = nil
			res, err := m.Ensure(ctx, opts)
			if err != nil {
				t.Fatal(err)
			}
			cred, err := m.Credential("work")
			if err != nil {
				t.Fatal(err)
			}
			if rotated := cred != old; rotated != tc.rotated {
				t.Errorf("credential rotated = %v, want %v", rotated, tc.rotated)
			}
			if got := lastCredentialWrite(t, r, "safeclaw-work"); got != cred.String() {
				t.Errorf("ttyd started with %q, host has %q", got, cred.String())
			}
			if res.URL != URLWithCredential(res.Port, cred) {
				t.Errorf("url = %q, want the current credential", res.URL)
			}
		})
	}
}

// A container restored after a failed recreate starts its ttyd with the
// host's credential, which no container that could read the old one has.
func TestCredentialAfterFailedRecreate(t *testing.T) {
	ctx := context.Background()
	runFailed := errors.New("docker run failed")
	for _, leaveCreated := range []bool{false, true} {
		w := &world{image: "img", containers: map[string]*fakeContainer{}, native: true}
		m, r := newTestManager(t, w)
		if _, err := m.Ensure(ctx, Options{Name: "work", NoOpen: true}); err != nil {
			t.Fatal(err)
		}
		old, err := m.Credential("work")
		if err != nil {
			t.Fatal(err)
		}
		w.runErrs = []runErr{{err: runFailed, leaveCreated: leaveCreated}}
		if _, err := m.Ensure(ctx, Options{Name: "work", Secrets: ptr(NoSecrets()), FreshHistory: true, NoOpen: true}); !errors.Is(err, runFailed) {
			t.Fatalf("err = %v", err)
		}
		c, err := m.Docker.InspectOne(ctx, "safeclaw-work")
		if err != nil || c == nil || !c.State.Running || !secretsOf(*c).Equal(AllSecrets()) {
			t.Fatalf("container not restored: %+v", c)
		}
		restored, err := m.Credential("work")
		if err != nil || restored == old {
			t.Errorf("credential after a failed recreate = %+v, %v; want a new one", restored, err)
		}

		r.Calls = nil
		res, err := m.Ensure(ctx, Options{Name: "work", NoOpen: true})
		if err != nil {
			t.Fatal(err)
		}
		if hasCall(r, "run ") {
			t.Errorf("plain run recreated the restored container: %v", r.Commands())
		}
		cred, err := m.Credential("work")
		if err != nil || cred != restored {
			t.Errorf("credential changed on a plain run: %+v, %+v (%v)", restored, cred, err)
		}
		if got := lastCredentialWrite(t, r, "safeclaw-work"); got != cred.String() {
			t.Errorf("ttyd started with %q, host has %q", got, cred.String())
		}
		if res.URL != URLWithCredential(res.Port, cred) {
			t.Errorf("url = %q, want the current credential", res.URL)
		}
	}
}

func TestTerminalsPublishedAwayFromCookieHost(t *testing.T) {
	if PublishHost == "127.0.0.1" || PublishHost == "localhost" {
		t.Fatalf("PublishHost = %q shares the dashboard's cookie host", PublishHost)
	}
	w := &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-old": {Running: true, Port: 7690, Image: "img"},
	}, native: true}
	m, r := newTestManager(t, w)
	var out bytes.Buffer
	m.Out = &out
	ctx := context.Background()
	if _, err := m.Ensure(ctx, Options{Name: "new", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	run, _ := r.Find("run ")
	if !strings.Contains(run.String(), " -p [::1]:7681:7681 ") {
		t.Errorf("run = %q, want the port published on [::1]", run.String())
	}
	if strings.Contains(out.String(), "127.0.0.1") {
		t.Errorf("new session warned about 127.0.0.1: %s", out.String())
	}

	// Sessions created before keep working on the address they are
	// published on, with a warning.
	out.Reset()
	res, err := m.Ensure(ctx, Options{Name: "old", NoOpen: true})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "publishes its terminal on 127.0.0.1") {
		t.Errorf("no warning for a session on 127.0.0.1: %s", out.String())
	}
	oldCred, err := m.Credential("old")
	if err != nil {
		t.Fatal(err)
	}
	if want := "http://safeclaw:" + oldCred.Password + "@127.0.0.1:7690"; res.URL != want {
		t.Errorf("legacy url = %q, want %q", res.URL, want)
	}

	term, err := m.Terminal(ctx, "new")
	if err != nil {
		t.Fatal(err)
	}
	if term.Addr != "[::1]:7681" || term.Host != "localhost:7681" || term.Port != 7681 {
		t.Errorf("terminal = %+v", term)
	}
	if want := "http://safeclaw:" + term.Credential.Password + "@[::1]:7681"; term.URL() != want {
		t.Errorf("terminal url = %q, want %q", term.URL(), want)
	}
	old, err := m.Terminal(ctx, "old")
	if err != nil || old.Addr != "127.0.0.1:7690" || old.Host != "localhost:7690" {
		t.Errorf("legacy terminal = %+v, %v", old, err)
	} else if want := "http://safeclaw:" + oldCred.Password + "@127.0.0.1:7690"; old.URL() != want {
		t.Errorf("legacy terminal url = %q, want %q", old.URL(), want)
	}
}

// Session URLs name the address the terminal is published on, so a browser
// neither sends them the cookies other local apps set for localhost nor
// connects to 127.0.0.1, where nothing holds the port.
func TestSessionURLsNamePublishAddress(t *testing.T) {
	u, err := url.Parse(URLWithCredential(7682, Credential{User: "safeclaw", Password: "pw"}))
	if err != nil {
		t.Fatal(err)
	}
	if u.Host != "[::1]:7682" || u.User.String() != "safeclaw:pw" {
		t.Errorf("URLWithCredential host = %q, user = %q, want [::1]:7682", u.Host, u.User)
	}
	if got := URLFor(7682); got != "http://[::1]:7682" {
		t.Errorf("URLFor = %q", got)
	}
	for ip, want := range map[string]string{
		"::1":       "::1",
		"::":        "::1",
		"127.0.0.1": "127.0.0.1",
		"0.0.0.0":   "127.0.0.1",
		"":          "127.0.0.1",
	} {
		c := docker.Container{}
		c.HostConfig.PortBindings = map[string][]docker.PortBinding{"7681/tcp": {{HostIP: ip, HostPort: "7690"}}}
		if got := publishedHost(c); got != want {
			t.Errorf("publishedHost(%q) = %q, want %q", ip, got, want)
		}
	}
}

// A session made from an image whose ttyd refuses a bracketed Host keeps a
// localhost URL, which that ttyd accepts, and run says how to move it.
func TestSessionURLsOnOldTTYDUseLocalhost(t *testing.T) {
	w := &world{image: "img", oldTTYD: true, containers: map[string]*fakeContainer{
		"safeclaw-work": {Running: true, Port: 7690, HostIP: "::1", Image: "img"},
		"safeclaw-old":  {Running: true, Port: 7691, HostIP: "127.0.0.1", Image: "img"},
	}, native: true}
	m, _ := newTestManager(t, w)
	var out bytes.Buffer
	m.Out = &out
	ctx := context.Background()
	for name, want := range map[string]string{"work": "@localhost:7690", "old": "@127.0.0.1:7691", "new": "@localhost:7681"} {
		out.Reset()
		res, err := m.Ensure(ctx, Options{Name: name, NoOpen: true})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(res.URL, want) {
			t.Errorf("%s: url = %q, want it to end in %q", name, res.URL, want)
		}
		if warned := strings.Contains(out.String(), "URL uses localhost"); warned != (name != "old") {
			t.Errorf("%s: localhost warning = %v: %s", name, warned, out.String())
		}
		term, err := m.Terminal(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasSuffix(term.URL(), want) {
			t.Errorf("%s: terminal url = %q, want it to end in %q", name, term.URL(), want)
		}
	}
	list, err := m.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range list {
		if s.Name == "work" && s.URL != "http://localhost:7690" {
			t.Errorf("listed url = %q", s.URL)
		}
	}
}

func TestTerminalRefusesUnreachableSessions(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-stopped": {Port: 7681, HostIP: "::1", Image: "img"},
		"safeclaw-off":     {Running: true, Port: 7682, HostIP: "::1", Image: "img", Offline: true},
		"safeclaw-box":     {Running: true, Image: "img", Labels: map[string]string{"safeclaw.type": "sandbox"}, NetworkMode: "none", Offline: true},
		"safeclaw-nocred":  {Running: true, Port: 7683, HostIP: "::1", Image: "img"},
	}}
	m, _ := newTestManager(t, w)
	for name, why := range map[string]string{
		"missing": "it does not exist",
		"stopped": "it is stopped; start it with `safeclaw run -s stopped`",
		"off":     "it is offline; bring it back with `safeclaw net on off`",
		"box":     "it is a sandbox",
	} {
		_, err := m.Terminal(context.Background(), name)
		if !errors.Is(err, ErrNoTerminal) {
			t.Errorf("%s: err = %v, want ErrNoTerminal", name, err)
			continue
		}
		if want := `session "` + name + `" has no running web terminal: ` + why; err.Error() != want {
			t.Errorf("%s: err = %q, want %q", name, err, want)
		}
	}
	if _, err := m.Terminal(context.Background(), "nocred"); err == nil || errors.Is(err, ErrNoTerminal) {
		t.Errorf("nocred: err = %v, want a credential error", err)
	}
}

func TestCredentialSymlinkIsReplacedNotFollowed(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{}, native: true}
	m, _ := newTestManager(t, w)
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("evil:planted\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(m.TTYDDir, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(m.TTYDDir, "work")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Credential("work"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("symlinked credential read: %v", err)
	}
	if _, err := m.Ensure(context.Background(), Options{Name: "work", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	cred, err := m.Credential("work")
	if err != nil || cred.Password == "planted" {
		t.Errorf("credential = %+v, %v", cred, err)
	}
	if b, _ := os.ReadFile(target); string(b) != "evil:planted\n" {
		t.Errorf("symlink target was written: %q", b)
	}
	if fi, err := os.Lstat(link); err != nil || !fi.Mode().IsRegular() {
		t.Errorf("credential is not a regular file: %v %v", fi, err)
	}
	if _, err := m.Credential("../work"); err == nil {
		t.Error("credential accepted a path in the name")
	}
}
