package cli

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/zalando/go-keyring"

	"github.com/josegonzalez/safeclaw/internal/hangup"
	"github.com/josegonzalez/safeclaw/internal/secrets"
	"github.com/josegonzalez/safeclaw/internal/session"
)

// staleAuthCleanups counts calls to removeStaleAuthContainers.
var staleAuthCleanups int

// TestMain keeps every test in this package off the real keychain and
// docker.
func TestMain(m *testing.M) {
	keyring.MockInit()
	removeStaleAuthContainers = func(context.Context) { staleAuthCleanups++ }
	os.Exit(m.Run())
}

func TestAuthCommandsRemoveStaleSignIns(t *testing.T) {
	freshSecrets(t)
	for _, args := range [][]string{{"auth", "status"}, {"auth", "logout"}} {
		before := staleAuthCleanups
		_, _ = runCLI(t, "", args...)
		if staleAuthCleanups != before+1 {
			t.Errorf("%v: stale sign-in cleanups = %d, want 1", args, staleAuthCleanups-before)
		}
	}
	// login cleans up in SetupToken, right before it starts its container.
	before := staleAuthCleanups
	_, _ = runCLI(t, "", "auth", "login")
	if staleAuthCleanups != before {
		t.Error("login cleaned up twice")
	}
}

// runCLI runs safeclaw with args and stdin in a fresh config directory's
// keychain, returning stdout.
func runCLI(t *testing.T, stdin string, args ...string) (string, error) {
	t.Helper()
	root := NewRootCommand()
	var out, errOut bytes.Buffer
	root.SetArgs(args)
	root.SetIn(strings.NewReader(stdin))
	root.SetOut(&out)
	root.SetErr(&errOut)
	err := root.ExecuteContext(context.Background())
	return out.String(), err
}

// freshSecrets gives a test an empty config directory and keychain.
func freshSecrets(t *testing.T) secrets.Store {
	t.Helper()
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	keyring.MockInit()
	return secrets.KeyringStore{}
}

func TestAuthCommands(t *testing.T) {
	root := NewRootCommand()
	for _, sub := range []string{"login", "set", "status", "logout"} {
		c, _, err := root.Find([]string{"auth", sub})
		if err != nil || c.Name() != sub {
			t.Errorf("auth %s: %v", sub, err)
		}
	}
}

func TestAuthSetFromStdin(t *testing.T) {
	store := freshSecrets(t)
	out, err := runCLI(t, "  sk-ant-oat01-abc\n", "auth", "set")
	if err != nil {
		t.Fatal(err)
	}
	if v, _ := store.Get(secrets.ClaudeToken); v != "sk-ant-oat01-abc" {
		t.Errorf("stored %q", v)
	}
	if !strings.Contains(out, "Saved CLAUDE_CODE_OAUTH_TOKEN to the system keychain") {
		t.Errorf("output = %q", out)
	}
	if strings.Contains(out, "sk-ant") {
		t.Error("output shows the token")
	}
}

func TestAuthSetRejectsBadInput(t *testing.T) {
	store := freshSecrets(t)
	for _, in := range []string{"", "\n", "two words", "line1\nline2"} {
		if _, err := runCLI(t, in, "auth", "set"); err == nil {
			t.Errorf("accepted %q", in)
		}
	}
	if store.Has(secrets.ClaudeToken) {
		t.Error("stored a rejected token")
	}
}

func TestAuthLoginNeedsTerminal(t *testing.T) {
	freshSecrets(t)
	_, err := runCLI(t, "", "auth", "login")
	if err == nil || !strings.Contains(err.Error(), "safeclaw auth set") {
		t.Errorf("err = %v", err)
	}
}

func TestAuthStatusAndLogout(t *testing.T) {
	store := freshSecrets(t)
	out, err := runCLI(t, "", "auth", "status")
	if !errors.Is(err, errTokenUnusable) || !strings.Contains(out, "No Claude Code token stored") {
		t.Errorf("missing: %q, %v", out, err)
	}

	_ = store.Set(secrets.ClaudeToken, "tok")
	out, err = runCLI(t, "", "auth", "status")
	if err != nil || !strings.Contains(out, "Valid for 365 more days") {
		t.Errorf("valid: %q, %v", out, err)
	}

	out, err = runCLI(t, "", "auth", "logout")
	if err != nil || !strings.Contains(out, "Deleted CLAUDE_CODE_OAUTH_TOKEN") || store.Has(secrets.ClaudeToken) {
		t.Errorf("logout: %q, %v", out, err)
	}
	out, err = runCLI(t, "", "auth", "logout")
	if err != nil || !strings.Contains(out, "No Claude Code token stored") {
		t.Errorf("second logout: %q, %v", out, err)
	}
}

func TestWriteTokenStatus(t *testing.T) {
	set := time.Date(2026, 1, 2, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		st      session.TokenStatus
		want    string
		wantErr bool
	}{
		{session.TokenStatus{State: session.TokenValid, SetAt: set, ExpiresAt: set.Add(session.TokenLifetime), DaysLeft: 100}, "Valid for 100 more days", false},
		{session.TokenStatus{State: session.TokenExpiring, SetAt: set, ExpiresAt: set.Add(session.TokenLifetime), DaysLeft: 12}, "Warning: expires in 12 days. Run `safeclaw auth login`", false},
		{session.TokenStatus{State: session.TokenExpired, SetAt: set, ExpiresAt: set.Add(session.TokenLifetime), DaysLeft: -4}, "Expired 4 days ago", true},
		{session.TokenStatus{State: session.TokenMissing}, "No Claude Code token stored", true},
	}
	for _, tc := range tests {
		var out bytes.Buffer
		err := writeTokenStatus(&out, tc.st, "somewhere")
		if (err != nil) != tc.wantErr || !strings.Contains(out.String(), tc.want) {
			t.Errorf("%s: %q, %v", tc.st.State, out.String(), err)
		}
		if tc.st.State != session.TokenMissing && !strings.Contains(out.String(), "Expires: 2027-01-02") {
			t.Errorf("%s: no expiry date in %q", tc.st.State, out.String())
		}
	}
}

func TestEnvCommands(t *testing.T) {
	store := freshSecrets(t)
	if _, err := runCLI(t, "value with spaces\n", "env", "set", "OPENAI_API_KEY"); err != nil {
		t.Fatal(err)
	}
	if v, _ := store.Get("OPENAI_API_KEY"); v != "value with spaces" {
		t.Errorf("stored %q", v)
	}
	if _, err := runCLI(t, "x", "env", "set", "bad-name"); err == nil {
		t.Error("accepted an invalid name")
	}
	if _, err := runCLI(t, "", "env", "set", "EMPTY"); err == nil {
		t.Error("accepted an empty value")
	}
	_ = store.Set("A", "1")
	out, err := runCLI(t, "", "env", "ls")
	if err != nil || out != "A\nOPENAI_API_KEY\n" {
		t.Errorf("ls = %q, %v", out, err)
	}
	if _, err := runCLI(t, "", "env", "rm", "A"); err != nil || store.Has("A") {
		t.Errorf("rm: %v", err)
	}
	if _, err := runCLI(t, "", "env", "rm", "A"); err == nil || !strings.Contains(err.Error(), "not set") {
		t.Errorf("rm of a missing secret: %v", err)
	}
}

func TestStdinIsTerminal(t *testing.T) {
	freshSecrets(t)
	root := NewRootCommand()
	run, _, _ := root.Find([]string{"run"})
	run.SetIn(strings.NewReader(""))
	if stdinIsTerminal(run) {
		t.Fatal("a reader stdin counts as a terminal")
	}
}

// Closing the terminal during a login cancels it, so it removes its sign-in
// container instead of dying with it still there.
func TestCancelOnHangup(t *testing.T) {
	if len(hangup.Signals(syscall.SIGHUP)) == 0 {
		t.Skip("SIGHUP is ignored, as under nohup")
	}
	ctx, stop := cancelOnHangup(context.Background())
	defer stop()
	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ctx.Done():
	case <-time.After(5 * time.Second):
		t.Fatal("SIGHUP did not cancel the login")
	}
}
