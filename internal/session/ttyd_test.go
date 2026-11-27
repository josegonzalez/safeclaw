package session

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
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

	// Sessions created before keep working, with a warning.
	out.Reset()
	if _, err := m.Ensure(ctx, Options{Name: "old", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "publishes its terminal on 127.0.0.1") {
		t.Errorf("no warning for a session on 127.0.0.1: %s", out.String())
	}

	term, err := m.Terminal(ctx, "new")
	if err != nil {
		t.Fatal(err)
	}
	if term.Addr != "[::1]:7681" || term.Host != "localhost:7681" || term.Port != 7681 {
		t.Errorf("terminal = %+v", term)
	}
	if want := "http://safeclaw:" + term.Credential.Password + "@localhost:7681"; term.URL() != want {
		t.Errorf("terminal url = %q, want %q", term.URL(), want)
	}
	if old, err := m.Terminal(ctx, "old"); err != nil || old.Addr != "127.0.0.1:7690" || old.Host != "localhost:7690" {
		t.Errorf("legacy terminal = %+v, %v", old, err)
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
