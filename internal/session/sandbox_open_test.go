package session

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
	"github.com/josegonzalez/safeclaw/internal/secrets"
)

func TestOpenArgv(t *testing.T) {
	prefix := func(flags ...string) []string {
		return slices.Concat([]string{"docker", "exec"}, flags, []string{"--user", "sandbox", "--workdir", "/sandbox", "safeclaw-box",
			"/bin/sh", "-c", `umask 022; exec "$@"`, "sh", "timeout", "--kill-after=5s", "--", "1800s"})
	}
	cases := []struct {
		name           string
		o              OpenOptions
		expand, totext []string
	}{
		{
			name:   "open",
			o:      OpenOptions{Timeout: 30 * time.Minute},
			expand: slices.Concat(prefix(), []string{"safeclaw-expand", "--", "/sandbox/in", "/sandbox/tree"}),
		},
		{
			// A path that looks like a flag stays the value of its own.
			name: "skips, password, and policy",
			o: OpenOptions{Timeout: 30 * time.Minute, Skip: []string{"--plan", "1-a.zip"}, Unskip: []string{"2-b.zip"},
				EnvFile: "/dev/fd/3", ExpandArgs: []string{"--depth=5", "--no-mail=true"}},
			expand: slices.Concat(prefix("--env-file", "/dev/fd/3"), []string{"safeclaw-expand", "--depth=5", "--no-mail=true",
				"--skip=--plan", "--skip=1-a.zip", "--unskip=2-b.zip", "--", "/sandbox/in", "/sandbox/tree"}),
		},
		{
			name:   "plan",
			o:      OpenOptions{Timeout: 30 * time.Minute, Plan: true, EnvFile: "/dev/fd/3"},
			expand: slices.Concat(prefix("--env-file", "/dev/fd/3"), []string{"safeclaw-expand", "--plan", "--", "/sandbox/tree"}),
		},
		{
			// safeclaw-totext never gets the password.
			name:   "text",
			o:      OpenOptions{Timeout: 30 * time.Minute, Text: true, EnvFile: "/dev/fd/3", TotextArgs: []string{"--max-pages=300", "--ocr-lang=eng+deu"}},
			expand: slices.Concat(prefix("--env-file", "/dev/fd/3"), []string{"safeclaw-expand", "--", "/sandbox/in", "/sandbox/tree"}),
			totext: slices.Concat(prefix(), []string{"safeclaw-totext", "--recursive", "--replace", "--max-pages=300", "--ocr-lang=eng+deu", "--", "/sandbox/tree", "/sandbox/out"}),
		},
	}
	for _, tc := range cases {
		run := OpenArgv("box", tc.o)
		if run.Name != "box" || !slices.Equal(run.Expand, tc.expand) || !slices.Equal(run.Totext, tc.totext) {
			t.Errorf("%s:\nexpand = %q\nwant     %q\ntotext = %q\nwant     %q", tc.name, run.Expand, tc.expand, run.Totext, tc.totext)
		}
	}
}

// newOpenManager is a sandbox world whose helper probe prints missing.
func newOpenManager(t *testing.T, missing string) (*Manager, *dockertest.Runner) {
	t.Helper()
	w := &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-box":  {Running: true, Image: "img", Labels: sandboxLabels, NetworkMode: "none", Offline: true},
		"safeclaw-off":  {Image: "img", Labels: sandboxLabels, NetworkMode: "none", Offline: true},
		"safeclaw-chat": {Running: true, Image: "img"},
	}}
	m, r := newTestManager(t, w)
	r.Handler = func(args []string, stdin string) ([]byte, error) {
		if args[0] == "exec" && slices.Contains(args, openProbeScript) {
			return []byte(missing), nil
		}
		return w.handle(args, stdin)
	}
	return m, r
}

func TestPrepareOpen(t *testing.T) {
	ctx := context.Background()
	o := OpenOptions{Timeout: time.Minute, Text: true}
	m, r := newOpenManager(t, "")
	run, err := m.PrepareOpen(ctx, "box", o)
	if err != nil {
		t.Fatal(err)
	}
	if want := OpenArgv("box", o); !slices.Equal(run.Expand, want.Expand) || !slices.Equal(run.Totext, want.Totext) {
		t.Errorf("run = %+v", run)
	}
	probe, ok := r.Find("exec --user sandbox --workdir /sandbox safeclaw-box /bin/sh -c")
	if !ok || !slices.Equal(probe.Args[len(probe.Args)-3:], []string{"sh", "safeclaw-expand", "safeclaw-totext"}) {
		t.Errorf("probe = %q in %v", probe.Args, r.Commands())
	}

	// Without --text only safeclaw-expand is needed.
	m, r = newOpenManager(t, "")
	if _, err := m.PrepareOpen(ctx, "box", OpenOptions{Timeout: time.Minute}); err != nil {
		t.Fatal(err)
	}
	if probe, _ := r.Find("exec "); probe.Args[len(probe.Args)-1] != "safeclaw-expand" {
		t.Errorf("probe = %q", probe.Args)
	}

	for missing, want := range map[string]string{
		"safeclaw-totext\n":                  "its image has no safeclaw-totext. Recreate it with the sandbox image variant: `safeclaw sandbox run -s box --variant sandbox`",
		"safeclaw-expand\nsafeclaw-totext\n": "its image has no safeclaw-expand or safeclaw-totext.",
	} {
		m, _ := newOpenManager(t, missing)
		_, err := m.PrepareOpen(ctx, "box", o)
		if !errors.Is(err, ErrNoHelpers) || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v", missing, err)
		}
	}
	// Output the probe can't print is not taken for a missing helper.
	m, _ = newOpenManager(t, "\x1b[2Jsafeclaw-expand\n")
	if _, err := m.PrepareOpen(ctx, "box", o); err == nil || errors.Is(err, ErrNoHelpers) || !strings.Contains(err.Error(), `unexpected output "\x1b[2J`) {
		t.Errorf("err = %v", err)
	}
}

func TestPrepareOpenRefuses(t *testing.T) {
	ctx := context.Background()
	for name, want := range map[string]error{
		"chat":    ErrNotSandbox,
		"off":     ErrNotRunning,
		"missing": ErrNotFound,
	} {
		m, r := newOpenManager(t, "")
		if _, err := m.PrepareOpen(ctx, name, OpenOptions{Timeout: time.Minute}); !errors.Is(err, want) {
			t.Errorf("%s: err = %v, want %v", name, err, want)
		}
		if hasExec(r) {
			t.Errorf("%s ran %v", name, r.Commands())
		}
	}
	for _, tc := range []struct {
		o    OpenOptions
		want string
	}{
		{OpenOptions{Timeout: time.Minute, Plan: true, Skip: []string{"a"}}, "--plan can't be given with --skip or --unskip"},
		{OpenOptions{Timeout: time.Minute, Plan: true, Unskip: []string{"a"}}, "--plan can't be given with --skip or --unskip"},
		{OpenOptions{Timeout: time.Minute, Plan: true, Text: true}, "--plan can't be given with --text"},
		{OpenOptions{}, "invalid timeout 0s"},
		{OpenOptions{Timeout: time.Minute, TotextArgs: []string{"--max-pages=3"}}, "--max-pages needs --text"},
		{OpenOptions{Timeout: time.Minute, ExpandArgs: []string{"depth=3"}}, `invalid helper flag "depth=3"`},
	} {
		m, r := newOpenManager(t, "")
		if _, err := m.PrepareOpen(ctx, "box", tc.o); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%+v: err = %v, want %q", tc.o, err, tc.want)
		}
		if len(r.Commands()) != 0 {
			t.Errorf("%+v ran %v", tc.o, r.Commands())
		}
	}
}

func TestOpenPasswordEnv(t *testing.T) {
	m := &Manager{Secrets: secrets.FileStore{Dir: t.TempDir()}}
	if err := m.Secrets.Set("MY_API_KEY", "k"); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"PW": "p w=x", "EMPTY": "", "NL": "a\nb", "MY_API_KEY": "k", "GH_TOKEN": "g"}
	lookup := func(n string) (string, bool) { v, ok := env[n]; return v, ok }
	for _, tc := range []struct{ from, want, err string }{
		{"", "", ""},
		{"PW", "SAFECLAW_UNPACK_PASSWORD=p w=x\n", ""},
		{"UNSET", "", ""},
		{"EMPTY", "", ""},
		{"NL", "", "--password-env NL: the value must be UTF-8 text"},
		{"MY_API_KEY", "", "--password-env MY_API_KEY is the name of a safeclaw secret"},
		{"GH_TOKEN", "", "is the name of a safeclaw secret"},
		{"CLAUDE_CODE_OAUTH_TOKEN", "", "is the name of a safeclaw secret"},
		{"1X", "", `invalid --password-env "1X"`},
		// What follows = may be a value, so it is never echoed.
		{"PW=hunter2", "", `invalid --password-env "PW": it takes a NAME only`},
	} {
		got, err := m.OpenPasswordEnv(tc.from, "SAFECLAW_UNPACK_PASSWORD", lookup)
		if got != tc.want || (tc.err == "") != (err == nil) || err != nil && !strings.Contains(err.Error(), tc.err) {
			t.Errorf("%q: got %q, %v; want %q, %q", tc.from, got, err, tc.want, tc.err)
		}
		if err != nil && strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%q: error echoes the value: %v", tc.from, err)
		}
	}
	env["BIG"] = strings.Repeat("a", MaxExecEnvBytes)
	if _, err := m.OpenPasswordEnv("BIG", "SAFECLAW_UNPACK_PASSWORD", lookup); err == nil {
		t.Error("want an error for a password past MaxExecEnvBytes")
	}
}
