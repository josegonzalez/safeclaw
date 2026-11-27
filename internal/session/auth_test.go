package session

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
	"github.com/josegonzalez/safeclaw/internal/secrets"
)

const fakeToken = "sk-ant-oat01-AbC_d-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_-0123456789abcdefghij-AA"

func TestParseSetupToken(t *testing.T) {
	tests := []struct {
		name, in string
	}{
		{"plain", "Your OAuth token (valid for 1 year):\n\n" + fakeToken + "\n\nStore this token securely.\n"},
		{"colored", "\x1b[32m✓\x1b[39m Done\r\n\x1b[1m" + fakeToken + "\x1b[22m\r\n"},
		{"hyperlink and erase", "\x1b]8;;https://x\x07link\x1b]8;;\x07\r\n\x1b[2K  " + fakeToken + "  \r\n"},
		{"last wins", "sk-ant-oat01-old\n" + fakeToken + "\n"},
		{"next line not joined", fakeToken + "\nStore\n"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseSetupToken([]byte(tc.in))
			if err != nil {
				t.Fatal(err)
			}
			if got != fakeToken {
				t.Errorf("token = %q, want %q", got, fakeToken)
			}
		})
	}
	if _, err := ParseSetupToken([]byte("Login cancelled\n")); err == nil || !strings.Contains(err.Error(), "safeclaw auth set") {
		t.Errorf("missing token err = %v", err)
	}
}

func TestClaudeTokenStatus(t *testing.T) {
	dir := t.TempDir()
	store := secrets.FileStore{Dir: dir}
	m := &Manager{Secrets: store}
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)

	if st, err := m.ClaudeTokenStatus(now); err != nil || st.State != TokenMissing || !st.NeedsAttention() {
		t.Fatalf("missing: %+v, %v", st, err)
	}
	_ = store.Set(secrets.ClaudeToken, "tok")
	tests := []struct {
		age  time.Duration
		want TokenState
		days int
	}{
		{24 * time.Hour, TokenValid, 364},
		{TokenLifetime - TokenWarnWindow - time.Hour, TokenValid, 31},
		{TokenLifetime - 10*24*time.Hour, TokenExpiring, 10},
		{TokenLifetime + 3*24*time.Hour, TokenExpired, -3},
	}
	for _, tc := range tests {
		at := now.Add(-tc.age)
		_ = os.Chtimes(filepath.Join(dir, secrets.ClaudeToken), at, at)
		st, err := m.ClaudeTokenStatus(now)
		if err != nil {
			t.Fatal(err)
		}
		if st.State != tc.want || st.DaysLeft != tc.days || !st.ExpiresAt.Equal(at.Add(TokenLifetime)) {
			t.Errorf("age %v: %+v, want %s with %d days left", tc.age, st, tc.want, tc.days)
		}
		if st.NeedsAttention() != (tc.want != TokenValid) {
			t.Errorf("age %v: NeedsAttention = %v", tc.age, st.NeedsAttention())
		}
	}
}

func TestEnsureWarnsAboutExpiringToken(t *testing.T) {
	w := &world{image: "sha256:new", containers: map[string]*fakeContainer{}}
	m, _ := newTestManager(t, w)
	var out bytes.Buffer
	m.Out = &out
	at := time.Now().Add(-TokenLifetime + 5*24*time.Hour)
	_ = os.Chtimes(filepath.Join(m.Secrets.Location(), secrets.ClaudeToken), at, at)
	if _, err := m.Ensure(context.Background(), Options{NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Warning: the Claude Code token expires on") || !strings.Contains(out.String(), "safeclaw auth login") {
		t.Errorf("output = %q", out.String())
	}

	// A session that doesn't receive the token isn't warned about it.
	out.Reset()
	set := NoSecrets()
	if _, err := m.Ensure(context.Background(), Options{Name: "none", NoOpen: true, Secrets: &set}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "token expires") {
		t.Errorf("output = %q", out.String())
	}
}

func TestErrNoClaudeTokenPointsToAuth(t *testing.T) {
	for _, s := range []string{"safeclaw auth login", "safeclaw auth set"} {
		if !strings.Contains(ErrNoClaudeToken.Error(), s) {
			t.Errorf("ErrNoClaudeToken = %q, want it to mention %s", ErrNoClaudeToken, s)
		}
	}
}

// authWorld answers the docker calls SetupToken makes.
type authWorld struct {
	noImage  bool
	runErr   error
	execErr  error
	catErr   error
	log      string
	leftover string
	// imageLabels is the image's labels as a JSON object, if any.
	imageLabels string
	// duringExec runs while `claude setup-token` would be attached.
	duringExec func()
}

func (w *authWorld) handle(args []string, _ string) ([]byte, error) {
	switch args[0] {
	case "image":
		if w.noImage {
			return nil, dockertest.NotFound(args)
		}
		labels := w.imageLabels
		if labels == "" {
			labels = "null"
		}
		return []byte(`{"Id":"sha256:img","Config":{"Labels":` + labels + "}}\n"), nil
	case "ps":
		return []byte(w.leftover), nil
	case "run":
		if w.runErr != nil {
			return nil, w.runErr
		}
		return []byte("authid\n"), nil
	case "exec":
		if slices.Contains(args, "-it") {
			if w.duringExec != nil {
				w.duringExec()
			}
			return nil, w.execErr
		}
		if slices.Contains(args, "cat") {
			return []byte(w.log), w.catErr
		}
		return nil, nil
	}
	return nil, nil
}

// Owner IDs used by the tests: this login's, a live login's, and logins
// that are gone.
const (
	testOwner = "00000000000000000000000000000000"
	liveOwner = "11111111111111111111111111111111"
	goneOwner = "22222222222222222222222222222222"
	leftOwner = "33333333333333333333333333333333"
)

func newAuthManager(t *testing.T, w *authWorld) (*Manager, *dockertest.Runner) {
	t.Helper()
	r := &dockertest.Runner{Handler: w.handle}
	name, owner := authName, authOwner
	authName = func() string { return "safeclaw.auth.test" }
	authOwner = func() string { return testOwner }
	t.Cleanup(func() { authName, authOwner = name, owner })
	return &Manager{Docker: r.Client(), AuthDir: t.TempDir()}, r
}

// holdLiveOwner makes owner look like a login that is still running.
func holdLiveOwner(t *testing.T, m *Manager, owner string) {
	t.Helper()
	release, err := m.holdAuthOwner(owner)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
}

// leaveOwnerFile leaves owner's file behind, unlocked, the way a login
// killed after it started its container does.
func leaveOwnerFile(t *testing.T, m *Manager, owner string) {
	t.Helper()
	if err := os.MkdirAll(m.authDir(), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.authOwnerPath(owner), nil, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestSetupToken(t *testing.T) {
	w := &authWorld{log: "\x1b[1m" + fakeToken + "\x1b[0m\r\n", leftover: "deadid safeclaw.auth.dead " + goneOwner + "\nliveid safeclaw.auth.live " + liveOwner + "\n"}
	m, r := newAuthManager(t, w)
	holdLiveOwner(t, m, liveOwner)
	tok, err := m.SetupToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != fakeToken {
		t.Errorf("token = %q", tok)
	}
	want := []string{
		"image inspect --format {{json .}} safeclaw",
		`ps -a --filter label=safeclaw.auth --format {{.ID}} {{.Names}} {{.Label "safeclaw.auth"}}`,
		"rm -v -f deadid",
		"run -d --name safeclaw.auth.test --label safeclaw.auth=" + testOwner + " --user sclaw --cap-drop ALL --security-opt no-new-privileges --label safeclaw.image=safeclaw sha256:img sleep infinity",
		"exec -it --user sclaw authid script -qec claude setup-token /tmp/setup-token.log",
		"exec --user sclaw authid cat /tmp/setup-token.log",
		"exec --user sclaw authid rm -f /tmp/setup-token.log",
		"rm -v -f authid",
	}
	if got := r.Commands(); !slices.Equal(got, want) {
		t.Errorf("calls:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// While the sign-in runs, its owner file is locked, so another process
// leaves its container alone. Afterwards the file is gone.
func TestSetupTokenHoldsOwnerWhileRunning(t *testing.T) {
	for name, w := range map[string]*authWorld{
		"token":      {log: fakeToken + "\r\n"},
		"exec fails": {execErr: errors.New("exit status 1")},
		"cancelled":  {execErr: context.Canceled},
		"cat fails":  {catErr: errors.New("exit status 1")},
	} {
		t.Run(name, func(t *testing.T) {
			m, _ := newAuthManager(t, w)
			var heldStale, ran bool
			w.duringExec = func() {
				ran = true
				release, stale := m.claimStaleAuthOwner(testOwner)
				release()
				heldStale = stale
			}
			_, _ = m.SetupToken(context.Background())
			if !ran || heldStale {
				t.Errorf("owner not held during the sign-in (ran %t, stale %t)", ran, heldStale)
			}
			if _, err := os.Stat(m.authOwnerPath(testOwner)); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("owner file left behind: %v", err)
			}
		})
	}
}

func TestSetupTokenRemovesContainerOnFailure(t *testing.T) {
	for name, w := range map[string]*authWorld{
		"exec fails":   {execErr: errors.New("exit status 1")},
		"cancelled":    {execErr: context.Canceled},
		"no token":     {log: "Login cancelled\r\n"},
		"empty output": {},
	} {
		t.Run(name, func(t *testing.T) {
			m, r := newAuthManager(t, w)
			if _, err := m.SetupToken(context.Background()); err == nil {
				t.Fatal("expected an error")
			}
			if !hasCall(r, "rm -v -f authid") {
				t.Errorf("container not removed: %v", r.Commands())
			}
		})
	}
}

// A run that fails, for example because it was cancelled, may have created
// the container without printing its ID, so it is removed by name.
func TestSetupTokenRemovesContainerByNameWhenRunFails(t *testing.T) {
	m, r := newAuthManager(t, &authWorld{runErr: context.Canceled})
	if _, err := m.SetupToken(context.Background()); err == nil {
		t.Fatal("expected an error")
	}
	if !hasCall(r, "rm -v -f safeclaw.auth.test") {
		t.Errorf("container not removed by name: %v", r.Commands())
	}
	if _, err := os.Stat(m.authOwnerPath(testOwner)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("owner file left behind: %v", err)
	}
}

// The recording is removed right after it is read, even when reading it
// fails or it holds no token, so it never waits for the container's removal.
func TestSetupTokenRemovesLogAfterReading(t *testing.T) {
	for name, w := range map[string]*authWorld{
		"token":     {log: fakeToken + "\r\n"},
		"no token":  {log: "Login cancelled\r\n"},
		"cat fails": {catErr: errors.New("exit status 1")},
	} {
		t.Run(name, func(t *testing.T) {
			m, r := newAuthManager(t, w)
			_, _ = m.SetupToken(context.Background())
			got := r.Commands()
			cat := slices.Index(got, "exec --user sclaw authid cat /tmp/setup-token.log")
			rm := slices.Index(got, "exec --user sclaw authid rm -f /tmp/setup-token.log")
			if cat < 0 || rm != cat+1 {
				t.Errorf("log not removed right after reading:\n%s", strings.Join(got, "\n"))
			}
		})
	}
}

// A container is stale once the login that owns it no longer holds its
// owner file, however long ago that was and whatever process now has the
// login's PID. Only containers named like sign-in containers are removed,
// since docker copies an image's safeclaw.auth label onto every container
// made from it.
func TestRemoveStaleAuthContainers(t *testing.T) {
	// A PID label from an earlier version is stale even when that PID is
	// running now, since the PID may have been reused: this test's own PID
	// stands in for an unrelated process that took it over.
	reused := strconv.Itoa(os.Getpid())
	w := &authWorld{leftover: "goneid safeclaw.auth.gone " + goneOwner + "\nleftid safeclaw.auth.left " + leftOwner + "\n" +
		"liveid safeclaw.auth.live " + liveOwner + "\npidid safeclaw.auth.pid " + reused + "\nnolabel safeclaw.auth.empty \n" +
		"badid safeclaw.auth.bad ../../" + liveOwner + "\nsessionid safeclaw-work " + goneOwner + "\nolderid eager_turing " + goneOwner + "\nunnamed\n"}
	m, r := newAuthManager(t, w)
	holdLiveOwner(t, m, liveOwner)
	leaveOwnerFile(t, m, leftOwner)
	m.RemoveStaleAuthContainers(context.Background())
	want := []string{
		`ps -a --filter label=safeclaw.auth --format {{.ID}} {{.Names}} {{.Label "safeclaw.auth"}}`,
		"rm -v -f goneid",
		"rm -v -f leftid",
		"rm -v -f pidid",
		"rm -v -f nolabel",
		"rm -v -f badid",
	}
	if got := r.Commands(); !slices.Equal(got, want) {
		t.Errorf("calls:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if _, err := os.Stat(m.authOwnerPath(leftOwner)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("stale owner file kept: %v", err)
	}
	if _, err := os.Stat(m.authOwnerPath(liveOwner)); err != nil {
		t.Errorf("live owner file removed: %v", err)
	}
}

// A live login's owner is still held after another process has checked
// it, so a second check keeps its container too.
func TestRemoveStaleAuthContainersKeepsLiveOwner(t *testing.T) {
	w := &authWorld{leftover: "liveid safeclaw.auth.live " + liveOwner + "\n"}
	m, r := newAuthManager(t, w)
	holdLiveOwner(t, m, liveOwner)
	m.RemoveStaleAuthContainers(context.Background())
	m.RemoveStaleAuthContainers(context.Background())
	if hasCall(r, "rm") {
		t.Errorf("removed a live login's container: %v", r.Commands())
	}
}

func TestSetupTokenRefusesLabeledImage(t *testing.T) {
	m, r := newAuthManager(t, &authWorld{imageLabels: `{"safeclaw.type":"sandbox"}`})
	if _, err := m.SetupToken(context.Background()); !errors.Is(err, ErrImageLabel) {
		t.Errorf("err = %v, want ErrImageLabel", err)
	}
	if hasCall(r, "run") {
		t.Error("started a container from a labeled image")
	}
}

func TestSetupTokenNeedsImage(t *testing.T) {
	m, r := newAuthManager(t, &authWorld{noImage: true})
	if _, err := m.SetupToken(context.Background()); !errors.Is(err, ErrNoImage) {
		t.Errorf("err = %v, want ErrNoImage", err)
	}
	if hasCall(r, "run") {
		t.Error("started a container without an image")
	}
}
