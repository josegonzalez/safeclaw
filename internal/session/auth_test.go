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
	execErr  error
	log      string
	leftover string
}

func (w *authWorld) handle(args []string, _ string) ([]byte, error) {
	switch args[0] {
	case "image":
		if w.noImage {
			return nil, dockertest.NotFound(args)
		}
		return []byte("sha256:img\n"), nil
	case "ps":
		return []byte(w.leftover), nil
	case "run":
		return []byte("authid\n"), nil
	case "exec":
		if slices.Contains(args, "-it") {
			return nil, w.execErr
		}
		return []byte(w.log), nil
	}
	return nil, nil
}

func newAuthManager(w *authWorld) (*Manager, *dockertest.Runner) {
	r := &dockertest.Runner{Handler: w.handle}
	return &Manager{Docker: r.Client(), ProcessAlive: func(pid string) bool { return pid == "4242" }}, r
}

func TestSetupToken(t *testing.T) {
	w := &authWorld{log: "\x1b[1m" + fakeToken + "\x1b[0m\r\n", leftover: "deadid 999999\nliveid 4242\n"}
	m, r := newAuthManager(w)
	tok, err := m.SetupToken(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok != fakeToken {
		t.Errorf("token = %q", tok)
	}
	want := []string{
		"image inspect --format {{.Id}} safeclaw",
		`ps -a --filter label=safeclaw.auth --format {{.ID}} {{.Label "safeclaw.auth"}}`,
		"rm -v -f deadid",
		"run -d --label safeclaw.auth=" + strconv.Itoa(os.Getpid()) + " safeclaw sleep infinity",
		"exec -it authid script -qec claude setup-token /tmp/setup-token.log",
		"exec authid cat /tmp/setup-token.log",
		"rm -v -f authid",
	}
	if got := r.Commands(); !slices.Equal(got, want) {
		t.Errorf("calls:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestSetupTokenRemovesContainerOnFailure(t *testing.T) {
	for name, w := range map[string]*authWorld{
		"exec fails":   {execErr: errors.New("exit status 1")},
		"no token":     {log: "Login cancelled\r\n"},
		"empty output": {},
	} {
		t.Run(name, func(t *testing.T) {
			m, r := newAuthManager(w)
			if _, err := m.SetupToken(context.Background()); err == nil {
				t.Fatal("expected an error")
			}
			if !hasCall(r, "rm -v -f authid") {
				t.Errorf("container not removed: %v", r.Commands())
			}
		})
	}
}

func TestSetupTokenNeedsImage(t *testing.T) {
	m, r := newAuthManager(&authWorld{noImage: true})
	if _, err := m.SetupToken(context.Background()); !errors.Is(err, ErrNoImage) {
		t.Errorf("err = %v, want ErrNoImage", err)
	}
	if hasCall(r, "run") {
		t.Error("started a container without an image")
	}
}
