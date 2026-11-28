package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/config"
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

	start, ok := r.Find("exec -d --user sclaw safeclaw-work sh -c ")
	if !ok {
		t.Fatalf("ttyd not started: %v", r.Commands())
	}
	argv := start.Args[slices.Index(start.Args, "ttyd")+1:]
	if !slices.Contains(argv, "-O") || !slices.Contains(argv, "-W") || !strings.Contains(strings.Join(start.Args, " "), `exec ttyd --credential-file /home/sclaw/.ttyd-credential "$@"`) {
		t.Errorf("ttyd argv = %q, want --credential-file and -O", start.Args)
	}
	// The credential is in no command line, ttyd's included: the script
	// passes ttyd the file, not its contents.
	if slices.Contains(argv, "-c") || strings.Contains(startTTYDScript, "$(") || strings.Contains(startTTYDScript, " -c ") {
		t.Errorf("ttyd gets the credential on its command line: %q", start.Args)
	}
	write, ok := r.Find("exec -i --user sclaw safeclaw-work sh -c umask 077 && cat > /home/sclaw/.ttyd-credential")
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

	// Restarting ttyd replaces the credential, and the file stays private.
	if _, err := m.Ensure(ctx, Options{Name: "work", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	again, err := m.Credential("work")
	if err != nil || again == first {
		t.Errorf("credential after restarting ttyd = %+v, %v; want a new one", again, err)
	}
	if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("rotated credential file = %v, %v; want mode 0600", fi, err)
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
	prefix := "exec -i --user sclaw " + container + " sh -c umask 077 && cat > /home/sclaw/.ttyd-credential"
	for _, c := range slices.Backward(r.Calls) {
		if strings.HasPrefix(c.String(), prefix) {
			return c.Stdin
		}
	}
	t.Fatalf("credential not written to %s: %v", container, r.Commands())
	return ""
}

// Every ttyd start gets a new credential, which the container's credential
// file, the printed URL, and the dashboard's relay get too: a new
// container, a stopped one started again, and a running one whose ttyd is
// restarted. A stopped container's port is released, so whatever held it
// meanwhile may have been sent the old credential by an open tab.
func TestCredentialRotatesWithContainer(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		replace func(t *testing.T, w *world, m *Manager) Options
	}{
		{"plain run", func(*testing.T, *world, *Manager) Options {
			return Options{Name: "work"}
		}},
		{"start", func(_ *testing.T, w *world, _ *Manager) Options {
			w.containers["safeclaw-work"].Running = false
			return Options{Name: "work"}
		}},
		{"stop then start", func(t *testing.T, _ *world, m *Manager) Options {
			if err := m.Stop(ctx, "work"); err != nil {
				t.Fatal(err)
			}
			return Options{Name: "work"}
		}},
		{"start offline", func(_ *testing.T, w *world, _ *Manager) Options {
			w.containers["safeclaw-work"].Running = false
			w.containers["safeclaw-work"].Offline = true
			return Options{Name: "work"}
		}},
		{"same secrets", func(*testing.T, *world, *Manager) Options {
			return Options{Name: "work", Secrets: ptr(AllSecrets())}
		}},
		{"secrets", func(*testing.T, *world, *Manager) Options {
			return Options{Name: "work", Secrets: ptr(NoSecrets())}
		}},
		{"fresh history", func(*testing.T, *world, *Manager) Options {
			return Options{Name: "work", FreshHistory: true}
		}},
		{"volume", func(*testing.T, *world, *Manager) Options {
			return Options{Name: "work", Volume: "/host/proj:/home/sclaw/proj"}
		}},
		{"build recreate", func(t *testing.T, _ *world, m *Manager) Options {
			c, err := m.Docker.InspectOne(ctx, "safeclaw-work")
			if err != nil || c == nil {
				t.Fatal(c, err)
			}
			if removed, err := m.RemoveStale(ctx, *c); !removed || err != nil {
				t.Fatalf("removed %v, err %v", removed, err)
			}
			return Options{Name: "work"}
		}},
		{"removed outside safeclaw", func(_ *testing.T, w *world, _ *Manager) Options {
			delete(w.containers, "safeclaw-work")
			return Options{Name: "work"}
		}},
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
			if cred == old {
				t.Errorf("credential kept across a ttyd start: %+v", cred)
			}
			if got := lastCredentialWrite(t, r, "safeclaw-work"); got != cred.String() {
				t.Errorf("ttyd started with %q, host has %q", got, cred.String())
			}
			if res.URL != URLWithCredential(res.Port, cred) {
				t.Errorf("url = %q, want the current credential", res.URL)
			}
			if res.Offline {
				return
			}
			term, err := m.Terminal(ctx, "work")
			if err != nil || term.Credential != cred {
				t.Fatalf("terminal = %+v, %v; want the current credential", term, err)
			}
			if u, err := term.URL(); err != nil || u != res.URL {
				t.Errorf("terminal url = %q, %v; want %q", u, err, res.URL)
			}
		})
	}
}

// A container restored after a failed recreate runs no ttyd until the next
// run starts one with a new credential, which no container that could read
// the old one has.
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
		r.Calls = nil
		if _, err := m.Ensure(ctx, Options{Name: "work", Secrets: ptr(NoSecrets()), FreshHistory: true, NoOpen: true}); !errors.Is(err, runFailed) {
			t.Fatalf("err = %v", err)
		}
		c, err := m.Docker.InspectOne(ctx, "safeclaw-work")
		if err != nil || c == nil || !c.State.Running || !secretsOf(*c).Equal(AllSecrets()) {
			t.Fatalf("container not restored: %+v", c)
		}
		if hasCall(r, "exec -d --user sclaw safeclaw-work") {
			t.Errorf("ttyd started after a failed recreate: %v", r.Commands())
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
		if err != nil || cred == old {
			t.Errorf("credential of the restored container's ttyd = %+v, %v; want a new one", cred, err)
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
	w := &world{image: "img", containers: map[string]*fakeContainer{}, native: true}
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

	term, err := m.Terminal(ctx, "new")
	if err != nil {
		t.Fatal(err)
	}
	if term.Addr != "[::1]:7681" || term.Host != "localhost:7681" || term.Port != 7681 {
		t.Errorf("terminal = %+v", term)
	}
	if want := "http://safeclaw:" + term.Credential.Password + "@[::1]:7681"; mustURL(t, term) != want {
		t.Errorf("terminal url = %q, want %q", mustURL(t, term), want)
	}
}

// legacyWorld has sessions published where terminals were before they
// moved to [::1], made from an image whose ttyd refused [::1] URLs. oldTTYD
// says whether the image still refuses them.
func legacyWorld(oldTTYD bool) *world {
	labels := map[string]string{"safeclaw.variant": "sandbox", "safeclaw.secrets": "", "safeclaw.ipc": "host", "safeclaw.memory": "off"}
	return &world{images: map[string]string{"safeclaw": "base-id", "safeclaw:sandbox": "sb-id"}, oldTTYD: oldTTYD, containers: map[string]*fakeContainer{
		"safeclaw-old": {Running: true, Port: 7690, HostIP: "127.0.0.1", Image: "sb-id", OldTTYD: true, IpcMode: "host", Labels: labels,
			Mounts: []string{"/hist:/home/sclaw/.claude/projects", "/proj:/home/sclaw/proj"}},
		"safeclaw-any": {Port: 7691, HostIP: "0.0.0.0", Image: "base-id", OldTTYD: true, Labels: map[string]string{"safeclaw.secrets": ""}},
	}, native: true}
}

// A session still published on 127.0.0.1, the dashboard's cookie host, or
// on every address, is recreated on [::1] once its image's ttyd accepts
// [::1] URLs, keeping its port, variant, secrets, IPC namespace, auto
// memory setting, mounts, and history.
func TestLegacyPublishRecreatedOnPublishHost(t *testing.T) {
	w := legacyWorld(false)
	m, r := newTestManager(t, w)
	var out bytes.Buffer
	m.Out = &out
	ctx := context.Background()
	if err := os.MkdirAll(filepath.Join(m.SessionsDir, "old"), 0o700); err != nil {
		t.Fatal(err)
	}
	res, err := m.Ensure(ctx, Options{Name: "old", NoOpen: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCall(r, "rm -v -f safeclaw-old") || res.Port != 7690 {
		t.Errorf("not recreated on the old port: %d %v", res.Port, r.Commands())
	}
	run, _ := r.Find("run ")
	for _, want := range []string{" -p [::1]:7690:7681 ", "--ipc=host --label safeclaw.ipc=host ", "--label safeclaw.memory=off ", "--label safeclaw.secrets= ", "--label safeclaw.variant=sandbox ", "-v /proj:/home/sclaw/proj ", filepath.Join(m.SessionsDir, "old") + ":/home/sclaw/.claude/projects "} {
		if !strings.Contains(run.String(), want) {
			t.Errorf("run lacks %q: %q", want, run.String())
		}
	}
	if !strings.HasSuffix(run.String(), " --label safeclaw.image=safeclaw:sandbox sha256:sb-id sleep infinity") {
		t.Errorf("run = %q, want the sandbox variant", run.String())
	}
	if _, err := os.Stat(filepath.Join(m.SessionsDir, "old")); err != nil {
		t.Errorf("history moved: %v", err)
	}
	if c := w.containers["safeclaw-old"]; c == nil || c.HostIP != "::1" {
		t.Errorf("container = %+v, want it published on ::1", c)
	}
	if !strings.Contains(out.String(), "Removing existing container to recreate it there") || strings.Contains(out.String(), "Warning: session old publishes") {
		t.Errorf("output = %s", out.String())
	}
	cred, err := m.Credential("old")
	if err != nil {
		t.Fatal(err)
	}
	if want := "http://safeclaw:" + cred.Password + "@[::1]:7690"; res.URL != want {
		t.Errorf("url = %q, want %q", res.URL, want)
	}
	if term, err := m.Terminal(ctx, "old"); err != nil || term.Addr != "[::1]:7690" {
		t.Errorf("terminal = %+v, %v", term, err)
	}
	// The new container runs its image's ttyd, not the old container's.
	if !strings.Contains(strings.Join(r.Commands(), "\n"), "exec ttyd --credential-file ") {
		t.Errorf("ttyd not started with the image's --credential-file: %v", r.Commands())
	}

	// A stopped session published on every address moves too.
	r.Calls = nil
	res, err = m.Ensure(ctx, Options{Name: "any", NoOpen: true})
	if err != nil {
		t.Fatal(err)
	}
	if run, ok := r.Find("run "); !ok || !strings.Contains(run.String(), " -p [::1]:7691:7681 ") || res.Port != 7691 {
		t.Errorf("run = %q, port = %d", run.String(), res.Port)
	}

	// Once moved, a plain run keeps it.
	r.Calls = nil
	if _, err := m.Ensure(ctx, Options{Name: "old", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if hasCall(r, "rm ") || hasCall(r, "run ") {
		t.Errorf("recreated again: %v", r.Commands())
	}
}

// With an image whose ttyd still refuses [::1] URLs, a legacy session
// cannot move there. Its image's ttyd also takes its credential only on
// its command line, so it is refused until the image is updated, and
// nothing is changed, stopped or started. A legacy container whose own
// ttyd reads its credential from a file is kept where it is, and run says
// how to move it.
func TestLegacyPublishOnOldTTYDRefused(t *testing.T) {
	w := legacyWorld(true)
	m, r := newTestManager(t, w)
	var out bytes.Buffer
	m.Out = &out
	ctx := context.Background()
	updates := map[string]string{"old": "`safeclaw pull --variant sandbox` or `safeclaw build --variant sandbox`", "any": "`safeclaw pull` or `safeclaw build`"}
	for name, update := range updates {
		r.Calls = nil
		_, err := m.Ensure(ctx, Options{Name: name, NoOpen: true})
		if !errors.Is(err, ErrArgvCredential) || !strings.Contains(err.Error(), "Update the image with "+update+", then run `safeclaw run -s "+name+"` to recreate the session from it") {
			t.Errorf("%s: err = %v", name, err)
		}
		for _, c := range r.Commands() {
			if !strings.HasPrefix(c, "image inspect") && !strings.HasPrefix(c, "container inspect") && !strings.HasPrefix(c, "ps") {
				t.Errorf("%s: refused run ran %q", name, c)
			}
		}
	}
	if c := w.containers["safeclaw-old"]; c == nil || !c.Running || c.HostIP != "127.0.0.1" {
		t.Errorf("old = %+v, want it kept", c)
	}

	for name, update := range updates {
		w.containers["safeclaw-"+name].Labels[config.LabelCredentialFileTTYD] = "1"
		out.Reset()
		r.Calls = nil
		res, err := m.Ensure(ctx, Options{Name: name, NoOpen: true})
		if err != nil {
			t.Fatal(err)
		}
		if hasCall(r, "rm ") || hasCall(r, "run ") {
			t.Errorf("%s: recreated: %v", name, r.Commands())
		}
		if !strings.Contains(res.URL, "@127.0.0.1:") {
			t.Errorf("%s: url = %q", name, res.URL)
		}
		want := "publishes its terminal on 127.0.0.1, the dashboard's cookie host"
		if s := out.String(); !strings.Contains(s, want) || !strings.Contains(s, "Update the image with "+update+", then run `safeclaw run -s "+name+"` again to recreate it on [::1]") {
			t.Errorf("%s: output = %s", name, s)
		}

		// `safeclaw url` gives the same warning, and nothing else.
		ensured := out.String()
		out.Reset()
		term, err := m.Terminal(ctx, name)
		if err != nil {
			t.Fatal(err)
		}
		m.WarnTerminal(ctx, term)
		if s := out.String(); s != legacyPublishWarning(name, w.containers["safeclaw-"+name].Labels[config.LabelVariant]) || !strings.Contains(ensured, s) {
			t.Errorf("%s: url warning = %q, run printed %q", name, s, ensured)
		}
	}
}

// An offline legacy session is not recreated, which would bring it back
// online; run refuses and says how to let it move.
func TestLegacyPublishOfflineRefused(t *testing.T) {
	w := legacyWorld(false)
	w.containers["safeclaw-old"].Offline = true
	m, r := newTestManager(t, w)
	_, err := m.Ensure(context.Background(), Options{Name: "old", NoOpen: true})
	if !errors.Is(err, ErrOffline) || !strings.Contains(err.Error(), "safeclaw net on old") || hasCall(r, "rm ") || hasCall(r, "run ") {
		t.Errorf("err = %v, commands = %v", err, r.Commands())
	}
	if c := w.containers["safeclaw-old"]; c == nil || c.HostIP != "127.0.0.1" {
		t.Errorf("container = %+v", c)
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

func mustURL(t *testing.T, term *Terminal) string {
	t.Helper()
	u, err := term.URL()
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// oldTTYDWorld has an image whose ttyd refuses a bracketed Host, and
// sessions made from it: work, running on [::1]; stopped, stopped on [::1];
// and old, a legacy one on 127.0.0.1.
func oldTTYDWorld() *world {
	return &world{image: "img", oldTTYD: true, containers: map[string]*fakeContainer{
		"safeclaw-work":    {Running: true, Port: 7690, HostIP: "::1", Image: "img", Mounts: []string{"/proj:/home/sclaw/proj"}},
		"safeclaw-stopped": {Port: 7691, HostIP: "::1", Image: "img"},
		"safeclaw-old":     {Running: true, Port: 7692, HostIP: "127.0.0.1", Image: "img"},
	}, native: true}
}

// No session gets a URL naming localhost while only [::1] is published: a
// browser falls back to 127.0.0.1 for it when [::1] refuses, where nothing
// holds the port and another local user can listen. A new session from an
// image whose ttyd refuses [::1] URLs, and a kept [::1] one made from such
// an image, are refused until the image is updated, and nothing is changed.
// A legacy session from such an image is refused too, but one an earlier
// version started still lists the 127.0.0.1 URL it is published on.
func TestOldTTYDSessionsRefused(t *testing.T) {
	w := oldTTYDWorld()
	m, r := newTestManager(t, w)
	var out bytes.Buffer
	m.Out = &out
	ctx := context.Background()
	for _, name := range []string{"work", "stopped", "old", "new"} {
		if _, err := m.rotateCredential(name); err != nil {
			t.Fatal(err)
		}
	}
	for name, then := range map[string]string{
		"new":     "then run it again",
		"work":    "then run `safeclaw run -s work` to recreate the session from it",
		"stopped": "then run `safeclaw run -s stopped` to recreate the session from it",
	} {
		r.Calls = nil
		out.Reset()
		_, err := m.Ensure(ctx, Options{Name: name, NoOpen: true})
		if !errors.Is(err, ErrOldTTYD) || !strings.Contains(err.Error(), "Update the image with `safeclaw pull` or `safeclaw build`, "+then) {
			t.Errorf("%s: err = %v", name, err)
		}
		for _, c := range r.Commands() {
			if !strings.HasPrefix(c, "image inspect") && !strings.HasPrefix(c, "container inspect") && !strings.HasPrefix(c, "ps") {
				t.Errorf("%s: refused run ran %q", name, c)
			}
		}
		if strings.Contains(out.String(), "localhost") {
			t.Errorf("%s: output = %s", name, out.String())
		}
	}
	if c := w.containers["safeclaw-work"]; c == nil || !c.Running || c.HostIP != "::1" {
		t.Errorf("work = %+v, want it kept", c)
	}
	if _, ok := w.containers["safeclaw-new"]; ok {
		t.Error("new session created")
	}

	// An explicit recreate would make a container from the old image too.
	w.containers["safeclaw-labelled"] = &fakeContainer{Running: true, Port: 7693, HostIP: "::1", Image: "img", Labels: map[string]string{config.LabelBracketedHostTTYD: "1"}}
	r.Calls = nil
	if _, err := m.Ensure(ctx, Options{Name: "labelled", Volume: t.TempDir() + ":/home/sclaw/x", NoOpen: true}); !errors.Is(err, ErrOldTTYD) || hasCall(r, "rm ") {
		t.Errorf("explicit recreate: err = %v, commands = %v", err, r.Commands())
	}

	// A sandbox variant's image is updated with its own commands.
	w.images = map[string]string{"safeclaw": "img", "safeclaw:sandbox": "sb"}
	if _, err := m.Ensure(ctx, Options{Name: "fresh", Variant: "sandbox", NoOpen: true}); !errors.Is(err, ErrOldTTYD) || !strings.Contains(err.Error(), "`safeclaw pull --variant sandbox` or `safeclaw build --variant sandbox`") {
		t.Errorf("variant: err = %v", err)
	}

	// The legacy session's image's ttyd has no --credential-file either, so
	// it is refused too, and left running as it was.
	r.Calls = nil
	if _, err := m.Ensure(ctx, Options{Name: "old", NoOpen: true}); !errors.Is(err, ErrArgvCredential) || hasCall(r, "rm ") || hasCall(r, "exec ") {
		t.Errorf("old: err = %v, commands = %v", err, r.Commands())
	}

	// A running [::1] session from the old image, started by an earlier
	// version, still has a terminal for the dashboard's relay, but no URL.
	term, err := m.Terminal(ctx, "work")
	if err != nil || term.Addr != "[::1]:7690" {
		t.Fatalf("terminal = %+v, %v", term, err)
	}
	if u, err := term.URL(); !errors.Is(err, ErrOldTTYD) || u != "" || !strings.Contains(err.Error(), "`safeclaw run -s work`") {
		t.Errorf("terminal url = %q, %v", u, err)
	}
	if term, err := m.Terminal(ctx, "old"); err != nil || !strings.HasSuffix(mustURL(t, term), "@127.0.0.1:7692") {
		t.Errorf("old terminal = %+v, %v", term, err)
	}
	list, err := m.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range list {
		if strings.Contains(s.URL, "localhost") || (s.Name == "work" && s.URL != "") || (s.Name == "old" && s.URL != "http://127.0.0.1:7692") {
			t.Errorf("%s: listed url = %q", s.Name, s.URL)
		}
	}
}

// Once the image is updated, a kept [::1] session made from an image whose
// ttyd refused [::1] URLs is recreated from it on its port, keeping its
// mounts like any other recreate, and gets a [::1] URL.
func TestOldTTYDSessionsRecreatedFromUpdatedImage(t *testing.T) {
	w := oldTTYDWorld()
	w.oldTTYD = false
	for _, c := range w.containers {
		c.OldTTYD = true
	}
	m, r := newTestManager(t, w)
	var out bytes.Buffer
	m.Out = &out
	ctx := context.Background()
	for name, port := range map[string]int{"work": 7690, "stopped": 7691} {
		r.Calls = nil
		out.Reset()
		res, err := m.Ensure(ctx, Options{Name: name, NoOpen: true})
		if err != nil {
			t.Fatal(err)
		}
		if !hasCall(r, "rm -v -f safeclaw-"+name) || res.Port != port {
			t.Errorf("%s: not recreated on its port: %d %v", name, res.Port, r.Commands())
		}
		if !strings.Contains(out.String(), "Removing existing container to recreate it from the updated one") {
			t.Errorf("%s: output = %s", name, out.String())
		}
		cred, err := m.Credential(name)
		if err != nil {
			t.Fatal(err)
		}
		if want := URLWithCredential(port, cred); res.URL != want {
			t.Errorf("%s: url = %q, want %q", name, res.URL, want)
		}
		term, err := m.Terminal(ctx, name)
		if err != nil || mustURL(t, term) != res.URL {
			t.Errorf("%s: terminal = %+v, %v", name, term, err)
		}
		if run, _ := r.Find("run "); !strings.Contains(run.String(), fmt.Sprintf(" -p [::1]:%d:7681 ", port)) {
			t.Errorf("%s: run = %q", name, run.String())
		}
	}
	if c := w.containers["safeclaw-work"]; c == nil || !slices.Contains(c.Mounts, "/proj:/home/sclaw/proj") {
		t.Errorf("work = %+v, want its mount kept", c)
	}

	// Once recreated, a plain run keeps it.
	r.Calls = nil
	if _, err := m.Ensure(ctx, Options{Name: "work", NoOpen: true}); err != nil || hasCall(r, "rm ") || hasCall(r, "run ") {
		t.Errorf("recreated again: %v %v", err, r.Commands())
	}
}

// An offline [::1] session from an old image is not recreated, which would
// bring it back online; run refuses and says how to let it move.
func TestOldTTYDSessionOfflineRefused(t *testing.T) {
	w := oldTTYDWorld()
	w.oldTTYD = false
	w.containers["safeclaw-work"].OldTTYD = true
	w.containers["safeclaw-work"].Offline = true
	m, r := newTestManager(t, w)
	_, err := m.Ensure(context.Background(), Options{Name: "work", NoOpen: true})
	if !errors.Is(err, ErrOffline) || !strings.Contains(err.Error(), "safeclaw net on work") || hasCall(r, "rm ") || hasCall(r, "run ") {
		t.Errorf("err = %v, commands = %v", err, r.Commands())
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

// No ttyd gets its credential on its command line, which every local user
// can read on a native Linux docker host. A new session from an image whose
// ttyd has no --credential-file is refused. A kept container made from such
// an image is recreated from the current image once that has it, on its
// port and keeping its mounts and history, and refused until then, with
// nothing changed.
func TestTTYDNeverTakesCredentialOnArgv(t *testing.T) {
	current := `exec ttyd --credential-file /home/sclaw/.ttyd-credential "$@" ttyd -W -O`
	argvContainer := func(running bool) *fakeContainer {
		return &fakeContainer{Running: running, Port: 7690, HostIP: "::1", Image: "img", OldTTYD: true, Labels: map[string]string{config.LabelBracketedHostTTYD: "1"}, Mounts: []string{"/proj:/home/sclaw/proj"}}
	}
	for _, tc := range []struct {
		name string
		w    *world
		// then is the end of the refusal, or "" when the session starts.
		then     string
		recreate bool
	}{
		{"new from old image", &world{image: "img", argvCredTTYD: true, containers: map[string]*fakeContainer{}, native: true}, "then run it again", false},
		{"new from current image", &world{image: "img", containers: map[string]*fakeContainer{}, native: true}, "", false},
		{"kept from old image, current image updated", &world{image: "img", containers: map[string]*fakeContainer{"safeclaw-work": argvContainer(true)}, native: true}, "", true},
		{"stopped from old image, current image updated", &world{image: "img", containers: map[string]*fakeContainer{"safeclaw-work": argvContainer(false)}, native: true}, "", true},
		{"kept from old image, current image old", &world{image: "img", argvCredTTYD: true, containers: map[string]*fakeContainer{"safeclaw-work": argvContainer(true)}, native: true}, "then run `safeclaw run -s work` to recreate the session from it", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, r := newTestManager(t, tc.w)
			var out bytes.Buffer
			m.Out = &out
			if err := os.MkdirAll(filepath.Join(m.SessionsDir, "work"), 0o700); err != nil {
				t.Fatal(err)
			}
			res, err := m.Ensure(context.Background(), Options{Name: "work", NoOpen: true})
			if tc.then != "" {
				if !errors.Is(err, ErrArgvCredential) || !strings.Contains(err.Error(), "Update the image with `safeclaw pull` or `safeclaw build`, "+tc.then) {
					t.Errorf("err = %v", err)
				}
				for _, c := range r.Commands() {
					if !strings.HasPrefix(c, "image inspect") && !strings.HasPrefix(c, "container inspect") && !strings.HasPrefix(c, "ps") {
						t.Errorf("refused run ran %q", c)
					}
				}
				if c, ok := tc.w.containers["safeclaw-work"]; ok && !c.Running {
					t.Errorf("container = %+v, want it kept running", c)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if recreated := hasCall(r, "rm -v -f safeclaw-work"); recreated != tc.recreate {
				t.Errorf("recreated = %v, want %v: %v", recreated, tc.recreate, r.Commands())
			}
			if tc.recreate {
				if res.Port != 7690 || !strings.Contains(out.String(), "takes its credential on its command line because it was created from an older image. Removing existing container") {
					t.Errorf("port = %d, output = %s", res.Port, out.String())
				}
				c := tc.w.containers["safeclaw-work"]
				if c == nil || !slices.Contains(c.Mounts, "/proj:/home/sclaw/proj") || !slices.Contains(c.Mounts, filepath.Join(m.SessionsDir, "work")+":/home/sclaw/.claude/projects") {
					t.Errorf("work = %+v, want its mount and history kept", c)
				}
			}
			cred, err := m.Credential("work")
			if err != nil {
				t.Fatal(err)
			}
			if res.URL != URLWithCredential(res.Port, cred) {
				t.Errorf("url = %q", res.URL)
			}
			start, ok := r.Find("exec -d --user sclaw safeclaw-work sh -c ")
			if !ok {
				t.Fatalf("ttyd not started: %v", r.Commands())
			}
			if got := strings.Join(start.Args, " "); !strings.Contains(got, current) {
				t.Errorf("ttyd started with %q, want %q", got, current)
			}
			for _, c := range r.Commands() {
				if strings.Contains(c, cred.Password) || strings.Contains(c, "ttyd -c") {
					t.Errorf("credential on a command line: %q", c)
				}
			}

			// Once recreated, a plain run keeps it.
			r.Calls = nil
			if _, err := m.Ensure(context.Background(), Options{Name: "work", NoOpen: true}); err != nil || hasCall(r, "rm ") || hasCall(r, "run ") {
				t.Errorf("recreated again: %v %v", err, r.Commands())
			}
		})
	}
}

// An offline session whose ttyd takes its credential on its command line is
// not recreated, which would bring it back online; run refuses and says how
// to let it move.
func TestArgvCredentialSessionOfflineRefused(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-work": {Running: true, Port: 7690, HostIP: "::1", Image: "img", OldTTYD: true, Offline: true, Labels: map[string]string{config.LabelBracketedHostTTYD: "1"}},
	}, native: true}
	m, r := newTestManager(t, w)
	_, err := m.Ensure(context.Background(), Options{Name: "work", NoOpen: true})
	if !errors.Is(err, ErrOffline) || !strings.Contains(err.Error(), "takes its credential on its command line") || !strings.Contains(err.Error(), "safeclaw net on work") || hasCall(r, "rm ") || hasCall(r, "run ") || hasCall(r, "exec ") {
		t.Errorf("err = %v, commands = %v", err, r.Commands())
	}
}

// startTTYD refuses a container whose ttyd would take its credential on its
// command line, before writing a credential anywhere.
func TestStartTTYDRefusesArgvCredential(t *testing.T) {
	m, r := newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{}, native: true})
	if _, err := m.startTTYD(context.Background(), "work", "", "safeclaw-work", true, map[string]string{config.LabelBracketedHostTTYD: "1"}); !errors.Is(err, ErrArgvCredential) || len(r.Calls) != 0 {
		t.Errorf("err = %v, commands = %v", err, r.Commands())
	}
	if _, err := m.Credential("work"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("credential written: %v", err)
	}
}
