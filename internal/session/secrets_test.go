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

	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
	"github.com/josegonzalez/safeclaw/internal/secrets"
)

func only(t *testing.T, names ...string) *SecretSet {
	t.Helper()
	s, err := OnlySecrets(names...)
	if err != nil {
		t.Fatal(err)
	}
	return &s
}

func ptr(s SecretSet) *SecretSet { return &s }

func TestSecretSet(t *testing.T) {
	s, err := OnlySecrets(" GH_TOKEN", "A", "GH_TOKEN")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s.Names, []string{"A", "GH_TOKEN"}) || s.String() != "A,GH_TOKEN" {
		t.Errorf("OnlySecrets = %+v", s)
	}
	if !s.Includes("A") || s.Includes("B") || !AllSecrets().Includes("B") || NoSecrets().Includes("A") {
		t.Error("Includes is wrong")
	}
	if _, err := OnlySecrets("A", "bad-name"); err == nil {
		t.Error("invalid name accepted")
	}
	if _, err := OnlySecrets(""); err == nil {
		t.Error("empty name accepted")
	}

	var zero SecretSet
	if !zero.All() || zero.String() != "all" || NoSecrets().String() != "none" {
		t.Errorf("zero = %v, none = %v", zero, NoSecrets())
	}
	none, _ := OnlySecrets()
	for _, tc := range []struct {
		a, b SecretSet
		want bool
	}{
		{AllSecrets(), AllSecrets(), true},
		{NoSecrets(), none, true},
		{s, *only(t, "GH_TOKEN", "A"), true},
		{AllSecrets(), NoSecrets(), false},
		{s, NoSecrets(), false},
		{s, *only(t, "A"), false},
	} {
		if got := tc.a.Equal(tc.b); got != tc.want {
			t.Errorf("%v.Equal(%v) = %v", tc.a, tc.b, got)
		}
	}
}

func TestSecretsLabel(t *testing.T) {
	label := func(s SecretSet) map[string]string {
		args := secretArgs(s)
		if len(args) == 0 {
			return nil
		}
		k, v, _ := strings.Cut(args[1], "=")
		return map[string]string{k: v}
	}
	for _, s := range []SecretSet{AllSecrets(), NoSecrets(), *only(t, "A", "B")} {
		var c docker.Container
		c.Config.Labels = label(s)
		if got := secretsOf(c); !got.Equal(s) {
			t.Errorf("round trip of %v = %v", s, got)
		}
	}
	if args := secretArgs(NoSecrets()); !slices.Equal(args, []string{"--label", "safeclaw.secrets="}) {
		t.Errorf("none args = %v", args)
	}
	var sandbox docker.Container
	sandbox.Config.Labels = map[string]string{"safeclaw.type": "sandbox"}
	if got := sessionSecrets(sandbox); !got.Equal(NoSecrets()) {
		t.Errorf("sandbox secrets = %v", got)
	}
}

func envCall(t *testing.T, r *dockertest.Runner, container string) string {
	t.Helper()
	c, ok := r.Find("exec -i --user sclaw " + container + " sh -c umask 077")
	if !ok {
		t.Fatalf("env not written: %v", r.Commands())
	}
	return c.Stdin
}

func TestEnsureLimitedSecrets(t *testing.T) {
	ctx := context.Background()
	w := &world{image: "img", containers: map[string]*fakeContainer{}, native: true}
	m, r := newTestManager(t, w)
	_ = m.Secrets.Set(secrets.GitHubToken, "gh")
	_ = m.Secrets.Set("OTHER", "x")

	if _, err := m.Ensure(ctx, Options{Name: "chat", Secrets: only(t, secrets.ClaudeToken), NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if got := w.containers["safeclaw-chat"].Labels["safeclaw.secrets"]; got != secrets.ClaudeToken {
		t.Errorf("label = %q", got)
	}
	if env := envCall(t, r, "safeclaw-chat"); env != "export CLAUDE_CODE_OAUTH_TOKEN='tok'\n" {
		t.Errorf("env = %q", env)
	}
	if hasCall(r, "exec --user sclaw safeclaw-chat bash -c") {
		t.Error("git config should be skipped without GH_TOKEN in the set")
	}

	// Every secret leaves the label off and configures git.
	if _, err := m.Ensure(ctx, Options{Name: "all", Secrets: ptr(AllSecrets()), NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.containers["safeclaw-all"].Labels["safeclaw.secrets"]; ok {
		t.Errorf("all secrets labelled: %v", w.containers["safeclaw-all"].Labels)
	}
	if env := envCall(t, r, "safeclaw-all"); !strings.Contains(env, "GH_TOKEN") || !strings.Contains(env, "OTHER") {
		t.Errorf("env = %q", env)
	}
	if !hasCall(r, "exec --user sclaw safeclaw-all bash -c") {
		t.Error("git config skipped")
	}
}

func TestEnsureNoSecrets(t *testing.T) {
	ctx := context.Background()
	w := &world{image: "img", containers: map[string]*fakeContainer{}, native: true}
	m, r := newTestManager(t, w)
	var out bytes.Buffer
	m.Out = &out
	_ = m.Secrets.Delete(secrets.ClaudeToken)
	_ = m.Secrets.Set(secrets.GitHubToken, "gh")
	// Neither token is asked for, since the session gets neither.
	m.Prompter = failPrompter{t}

	if _, err := m.Ensure(ctx, Options{Name: "bare", Secrets: ptr(NoSecrets()), Interactive: true, NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if v, ok := w.containers["safeclaw-bare"].Labels["safeclaw.secrets"]; !ok || v != "" {
		t.Errorf("label = %q, %v", v, ok)
	}
	if env := envCall(t, r, "safeclaw-bare"); env != "" {
		t.Errorf("env = %q", env)
	}
	if hasCall(r, "exec --user sclaw safeclaw-bare bash -c") {
		t.Error("git config should be skipped")
	}
	if !strings.Contains(out.String(), "does not receive CLAUDE_CODE_OAUTH_TOKEN, so Claude Code will not be logged in") {
		t.Errorf("no warning: %s", out.String())
	}

	// Non-interactive runs only need the Claude token when the set has it.
	if _, err := m.Ensure(ctx, Options{Name: "gh", Secrets: only(t, secrets.GitHubToken), NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Ensure(ctx, Options{Name: "full", NoOpen: true}); !errors.Is(err, ErrNoClaudeToken) {
		t.Errorf("err = %v", err)
	}
}

type failPrompter struct{ t *testing.T }

func (p failPrompter) ClaudeToken() (string, error) {
	p.t.Error("prompted for the Claude token")
	return "", errors.New("no")
}

func (p failPrompter) GitHubToken() (string, error) {
	p.t.Error("prompted for the GitHub token")
	return "", nil
}

func TestEnsureSecretsPrompts(t *testing.T) {
	ctx := context.Background()
	m, _ := newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{}, native: true})
	_ = m.Secrets.Delete(secrets.ClaudeToken)

	// A listed token is prompted for.
	m.Prompter = fakePrompter{claude: "new-tok", gh: "new-gh"}
	if _, err := m.Ensure(ctx, Options{Name: "a", Secrets: only(t, secrets.GitHubToken), Interactive: true, NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if m.Secrets.Has(secrets.ClaudeToken) {
		t.Error("prompted for the Claude token the set leaves out")
	}
	if v, _ := m.Secrets.Get(secrets.GitHubToken); v != "new-gh" {
		t.Errorf("GH_TOKEN = %q", v)
	}

	// Skipping the prompt for a listed token fails the run.
	_ = m.Secrets.Delete(secrets.GitHubToken)
	m.Prompter = fakePrompter{claude: "new-tok"}
	if _, err := m.Ensure(ctx, Options{Name: "b", Secrets: only(t, secrets.ClaudeToken, secrets.GitHubToken), Interactive: true, NoOpen: true}); !errors.Is(err, ErrNoSecret) {
		t.Errorf("err = %v", err)
	}
}

func TestEnsureMissingSecret(t *testing.T) {
	ctx := context.Background()
	w := &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-p": {Running: true, Port: 7705, Image: "img"},
	}, native: true}
	m, r := newTestManager(t, w)
	_, err := m.Ensure(ctx, Options{Name: "p", Secrets: only(t, secrets.ClaudeToken, "NOPE"), NoOpen: true})
	if !errors.Is(err, ErrNoSecret) || !strings.Contains(err.Error(), "NOPE") || !strings.Contains(err.Error(), "safeclaw env") {
		t.Errorf("err = %v", err)
	}
	if hasCall(r, "rm ") || hasCall(r, "run ") || hasCall(r, "exec ") {
		t.Errorf("acted on a missing secret: %v", r.Commands())
	}
}

// A symlinked entry in the secrets directory is not a secret, so naming it
// fails the check instead of passing it and being skipped when .env is
// written.
func TestEnsureSymlinkedSecret(t *testing.T) {
	ctx := context.Background()
	w := &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-p": {Running: true, Port: 7705, Image: "img"},
	}, native: true}
	m, r := newTestManager(t, w)
	target := filepath.Join(t.TempDir(), "target")
	if err := os.WriteFile(target, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(m.Secrets.Location(), "LINKED")); err != nil {
		t.Fatal(err)
	}
	_, err := m.Ensure(ctx, Options{Name: "p", Secrets: only(t, secrets.ClaudeToken, "LINKED"), NoOpen: true})
	if !errors.Is(err, ErrNoSecret) || !strings.Contains(err.Error(), "LINKED") {
		t.Errorf("err = %v", err)
	}
	if hasCall(r, "rm ") || hasCall(r, "run ") || hasCall(r, "exec ") {
		t.Errorf("acted on a symlinked secret: %v", r.Commands())
	}
}

func TestEnsureSecretsReuseAndRecreate(t *testing.T) {
	ctx := context.Background()
	existing := func(labels map[string]string) *world {
		return &world{image: "img", images: map[string]string{"safeclaw": "img", "safeclaw:sandbox": "sb"}, containers: map[string]*fakeContainer{
			"safeclaw-p": {Running: true, Port: 7705, Image: "img", Labels: labels,
				Mounts: []string{"/hist:/home/sclaw/.claude/projects", "/proj:/home/sclaw/proj"}},
		}, native: true}
	}
	limited := func() map[string]string {
		return map[string]string{"safeclaw.secrets": "CLAUDE_CODE_OAUTH_TOKEN,GONE", "safeclaw.variant": "sandbox"}
	}

	// Without a set, or with the same one, the container and its set are
	// kept, and a remembered secret that is gone is skipped.
	for _, set := range []*SecretSet{nil, only(t, "CLAUDE_CODE_OAUTH_TOKEN", "GONE")} {
		w := existing(limited())
		m, r := newTestManager(t, w)
		_ = m.Secrets.Set(secrets.GitHubToken, "gh")
		var out bytes.Buffer
		m.Out = &out
		_, err := m.Ensure(ctx, Options{Name: "p", Secrets: set, NoOpen: true})
		if set != nil {
			// The same set given again must exist.
			if !errors.Is(err, ErrNoSecret) {
				t.Errorf("err = %v", err)
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		if hasCall(r, "rm ") || hasCall(r, "run ") {
			t.Errorf("recreated: %v", r.Commands())
		}
		if env := envCall(t, r, "safeclaw-p"); env != "export CLAUDE_CODE_OAUTH_TOKEN='tok'\n" {
			t.Errorf("env = %q", env)
		}
		if !strings.Contains(out.String(), "secret GONE is no longer set, skipping it") {
			t.Errorf("no warning: %s", out.String())
		}
	}

	// The same set, when every name exists, keeps the container.
	w := existing(map[string]string{"safeclaw.secrets": "CLAUDE_CODE_OAUTH_TOKEN"})
	m, r := newTestManager(t, w)
	if _, err := m.Ensure(ctx, Options{Name: "p", Secrets: only(t, secrets.ClaudeToken), NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if hasCall(r, "rm ") || hasCall(r, "run ") {
		t.Errorf("same set recreated: %v", r.Commands())
	}

	// An unlabelled container already gets every secret.
	w = existing(nil)
	m, r = newTestManager(t, w)
	if _, err := m.Ensure(ctx, Options{Name: "p", Secrets: ptr(AllSecrets()), NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if hasCall(r, "rm ") || hasCall(r, "run ") {
		t.Errorf("all on unlabelled recreated: %v", r.Commands())
	}

	// A different set recreates it on the same port, keeping its mounts and
	// variant.
	for _, tc := range []struct {
		set   *SecretSet
		label string
		has   bool
	}{
		{ptr(NoSecrets()), "", true},
		{ptr(AllSecrets()), "", false},
	} {
		w = existing(limited())
		m, r = newTestManager(t, w)
		res, err := m.Ensure(ctx, Options{Name: "p", Secrets: tc.set, NoOpen: true})
		if err != nil {
			t.Fatal(err)
		}
		if !hasCall(r, "rm -v -f safeclaw-p") || res.Port != 7705 {
			t.Errorf("%v: not recreated on the old port: %d %v", tc.set, res.Port, r.Commands())
		}
		c := w.containers["safeclaw-p"]
		if v, ok := c.Labels["safeclaw.secrets"]; ok != tc.has || v != tc.label {
			t.Errorf("%v: label = %q, %v", tc.set, v, ok)
		}
		if c.Labels["safeclaw.variant"] != "sandbox" || !slices.Contains(c.Mounts, "/proj:/home/sclaw/proj") {
			t.Errorf("%v: recreate lost the variant or mount: %+v", tc.set, c)
		}
	}
}

func TestListSecrets(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-all":  {Running: true},
		"safeclaw-none": {Labels: map[string]string{"safeclaw.secrets": ""}},
		"safeclaw-some": {Labels: map[string]string{"safeclaw.secrets": "A,B"}},
		"safeclaw-box":  {Labels: map[string]string{"safeclaw.type": "sandbox"}},
	}}
	m, _ := newTestManager(t, w)
	list, err := m.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"all": "all", "none": "none", "some": "A,B", "box": "none"}
	for _, s := range list {
		if s.Secrets.String() != want[s.Name] {
			t.Errorf("%s secrets = %v, want %s", s.Name, s.Secrets, want[s.Name])
		}
	}
	got, err := m.Get(context.Background(), "some")
	if err != nil || got.Secrets.String() != "A,B" {
		t.Errorf("Get = %+v, %v", got, err)
	}
}

func TestSecretNames(t *testing.T) {
	m, _ := newTestManager(t, &world{})
	_ = m.Secrets.Set("A", "1")
	names, err := m.SecretNames()
	if err != nil || !slices.Equal(names, []string{"A", secrets.ClaudeToken}) {
		t.Errorf("SecretNames = %v, %v", names, err)
	}
}

// A recreate that can't complete keeps the session's container, so its
// remembered secret set is never lost.
func TestEnsureFailedRecreateKeepsSecrets(t *testing.T) {
	ctx := context.Background()
	runFailed := errors.New("docker run failed")
	restoreFailed := errors.New("restore failed")
	existing := func() *world {
		return &world{image: "img", images: map[string]string{"safeclaw": "img", "safeclaw:sandbox": "sb"}, containers: map[string]*fakeContainer{
			"safeclaw-work": {Running: true, Port: 7690, Image: "sb",
				Labels: map[string]string{"safeclaw.secrets": secrets.ClaudeToken, "safeclaw.variant": "sandbox"},
				Mounts: []string{"/hist:/home/sclaw/.claude/projects", "/host/old:/home/sclaw/old:ro"}},
		}, native: true}
	}
	// kept checks the container is the old session's, or a copy of it,
	// and that a plain rerun still writes only the remembered secrets.
	kept := func(t *testing.T, w *world, m *Manager, r *dockertest.Runner) {
		t.Helper()
		c := w.containers["safeclaw-work"]
		if c == nil {
			t.Fatalf("container gone: %v", r.Commands())
		}
		if c.Labels["safeclaw.secrets"] != secrets.ClaudeToken || c.Labels["safeclaw.variant"] != "sandbox" || c.Port != 7690 ||
			!slices.Contains(c.Mounts, "/host/old:/home/sclaw/old:ro") || !c.Running {
			t.Errorf("container not kept: %+v", c)
		}
		r.Calls = nil
		if _, err := m.Ensure(ctx, Options{Name: "work", NoOpen: true}); err != nil {
			t.Fatal(err)
		}
		if hasCall(r, "run ") {
			t.Errorf("plain rerun recreated: %v", r.Commands())
		}
		if env := envCall(t, r, "safeclaw-work"); env != "export CLAUDE_CODE_OAUTH_TOKEN='tok'\n" {
			t.Errorf("env = %q", env)
		}
	}
	rms := func(r *dockertest.Runner) int {
		n := 0
		for _, c := range r.Commands() {
			if strings.HasPrefix(c, "rm ") {
				n++
			}
		}
		return n
	}

	for _, tc := range []struct {
		name string
		opts Options
	}{
		{"volume", Options{Name: "work", Volume: "/host/proj"}},
		{"volume and secrets", Options{Name: "work", Volume: ":/x", Secrets: ptr(NoSecrets())}},
	} {
		t.Run("rejected "+tc.name, func(t *testing.T) {
			w := existing()
			m, r := newTestManager(t, w)
			_ = m.Secrets.Set("EXCLUDED_SECRET", "dummy-excluded-value")
			tc.opts.NoOpen = true
			if _, err := m.Ensure(ctx, tc.opts); err == nil || !strings.Contains(err.Error(), "invalid volume") {
				t.Fatalf("err = %v", err)
			}
			if hasCall(r, "rm ") || hasCall(r, "run ") {
				t.Errorf("acted on a rejected volume: %v", r.Commands())
			}
			kept(t, w, m, r)
		})
	}

	// Kept mounts are checked too, when no -v is given.
	t.Run("rejected kept mount", func(t *testing.T) {
		w := existing()
		c := w.containers["safeclaw-work"]
		c.Mounts = append(c.Mounts, ":/broken")
		m, r := newTestManager(t, w)
		if _, err := m.Ensure(ctx, Options{Name: "work", Secrets: ptr(NoSecrets()), NoOpen: true}); err == nil {
			t.Fatal("recreated with a broken mount")
		}
		if hasCall(r, "rm ") || hasCall(r, "run ") {
			t.Errorf("acted on a rejected volume: %v", r.Commands())
		}
	})

	for _, tc := range []struct {
		name         string
		leaveCreated bool
		rms          int
	}{
		{"create", false, 1},
		{"start", true, 2},
	} {
		t.Run("failed "+tc.name, func(t *testing.T) {
			w := existing()
			w.runErrs = []runErr{{err: runFailed, leaveCreated: tc.leaveCreated}}
			m, r := newTestManager(t, w)
			_ = m.Secrets.Set("EXCLUDED_SECRET", "dummy-excluded-value")
			_, err := m.Ensure(ctx, Options{Name: "work", Volume: "/host/proj:/home/sclaw/proj", NoOpen: true})
			if !errors.Is(err, runFailed) {
				t.Fatalf("err = %v", err)
			}
			if n := rms(r); n != tc.rms {
				t.Errorf("%d removes, want %d: %v", n, tc.rms, r.Commands())
			}
			kept(t, w, m, r)
		})
	}

	t.Run("failed restore", func(t *testing.T) {
		w := existing()
		w.runErrs = []runErr{{err: runFailed}, {err: restoreFailed}}
		m, _ := newTestManager(t, w)
		_, err := m.Ensure(ctx, Options{Name: "work", Volume: "/host/proj:/home/sclaw/proj", NoOpen: true})
		if !errors.Is(err, runFailed) || !errors.Is(err, restoreFailed) {
			t.Fatalf("err = %v", err)
		}
	})
}

// A session created again over an earlier one's history is warned that it
// receives every secret.
func TestEnsureWarnsUnrememberedSecrets(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		history bool
		set     *SecretSet
		warn    bool
	}{
		{"new", false, nil, false},
		{"history", true, nil, true},
		{"history with all", true, ptr(AllSecrets()), false},
		{"history with none", true, ptr(NoSecrets()), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &world{image: "img", containers: map[string]*fakeContainer{}, native: true}
			m, _ := newTestManager(t, w)
			if tc.history {
				if err := os.MkdirAll(filepath.Join(m.SessionsDir, "work"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			var out bytes.Buffer
			m.Out = &out
			if _, err := m.Ensure(ctx, Options{Name: "work", Secrets: tc.set, NoOpen: true}); err != nil {
				t.Fatal(err)
			}
			if got := strings.Contains(out.String(), "no secret selection is remembered"); got != tc.warn {
				t.Errorf("warned = %v: %s", got, out.String())
			}
		})
	}
}
