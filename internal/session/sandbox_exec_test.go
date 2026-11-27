package session

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/josegonzalez/safeclaw/internal/secrets"
)

func TestSandboxExecArgv(t *testing.T) {
	wrap := []string{"/bin/sh", "-c", `umask 022; exec "$@"`, "sh"}
	prefix := func(flags ...string) []string {
		return append(append([]string{"docker", "exec"}, flags...), "--user", "sandbox", "--workdir", "/sandbox", "safeclaw-box")
	}
	cmd := []string{"pdftotext", "-", "-"}
	cases := []struct {
		o    ExecOptions
		want []string
	}{
		{ExecOptions{}, slices.Concat(prefix(), wrap, cmd)},
		{ExecOptions{Interactive: true}, slices.Concat(prefix("-i"), wrap, cmd)},
		{ExecOptions{Interactive: true, TTY: true}, slices.Concat(prefix("-i", "-t"), wrap, cmd)},
		{ExecOptions{EnvFile: "/dev/fd/3"}, slices.Concat(prefix("--env-file", "/dev/fd/3"), wrap, cmd)},
		// The timeout goes inside the umask wrapper, so the command keeps
		// the umask, and before the command, so its arguments stay its own.
		{ExecOptions{Timeout: 90 * time.Second}, slices.Concat(prefix(), wrap, []string{"timeout", "--kill-after=5s", "--", "90s"}, cmd)},
		{ExecOptions{Timeout: 1500 * time.Millisecond, TTY: true}, slices.Concat(prefix("-t"), wrap, []string{"timeout", "--kill-after=5s", "--foreground", "--", "1.5s"}, cmd)},
	}
	for _, tc := range cases {
		if got := SandboxExecArgv("box", tc.o, cmd); !slices.Equal(got, tc.want) {
			t.Errorf("%+v: argv =\n%q\nwant\n%q", tc.o, got, tc.want)
		}
	}
}

func TestEphemeralRunArgsExecOptions(t *testing.T) {
	got, err := EphemeralRunArgs("safeclaw-box", SandboxOptions{Variant: "sandbox"}, ExecOptions{Interactive: true, EnvFile: "/dev/fd/3", Timeout: time.Minute}, []string{"7z", "x", "-p", "/in/a.7z"})
	if err != nil {
		t.Fatal(err)
	}
	s := strings.Join(got, " ")
	if !strings.HasPrefix(s, "--rm --init -i --env-file /dev/fd/3 --name safeclaw-box ") {
		t.Errorf("args = %q", s)
	}
	if !strings.HasSuffix(s, ` safeclaw:sandbox /bin/sh -c umask 022; exec "$@" sh timeout --kill-after=5s -- 60s 7z x -p /in/a.7z`) {
		t.Errorf("args = %q", s)
	}
}

func TestPrepareEphemeralRefusesNegativeTimeout(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{}}
	m, r := newTestManager(t, w)
	if _, _, err := m.PrepareEphemeral(context.Background(), SandboxOptions{}, ExecOptions{Timeout: -time.Second}, []string{"ls"}); err == nil {
		t.Error("want an error for a negative timeout")
	}
	if len(r.Commands()) != 0 {
		t.Errorf("ran docker: %v", r.Commands())
	}
}

func TestSandboxVolumes(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{}}
	m, r := newTestManager(t, w)
	if _, err := m.EnsureSandbox(context.Background(), SandboxOptions{Name: "box", Volumes: []string{"/in:/in", "/tools:/opt/tools:rw"}}); err != nil {
		t.Fatal(err)
	}
	run, _ := r.Find("run ")
	if !strings.Contains(run.String(), " -v /in:/in:ro -v /tools:/opt/tools:ro safeclaw:sandbox ") {
		t.Errorf("run = %q", run.String())
	}

	for _, vols := range [][]string{
		{"/a:/in", "/b:/in"},
		{"/a:/in", "/b:/in/:ro"},
		{"/a:/sandbox"},
		{"/a:/tmp/"},
	} {
		if _, err := EphemeralRunArgs("safeclaw-box", SandboxOptions{Volumes: vols}, ExecOptions{}, []string{"ls"}); err == nil || !strings.Contains(err.Error(), "already used") {
			t.Errorf("%q: err = %v, want a duplicate mount point", vols, err)
		}
	}
}

func TestEnsureSandboxRecreateVolumes(t *testing.T) {
	existing := func() *world {
		return &world{images: map[string]string{"safeclaw": "base-id", "safeclaw:sandbox": "sb-id"}, containers: map[string]*fakeContainer{
			"safeclaw-box": {Running: true, Image: "sb-id", Labels: map[string]string{"safeclaw.type": "sandbox", "safeclaw.variant": "sandbox"},
				Mounts: []string{"/in:/in:ro", "/tools:/tools:ro"}},
		}}
	}
	cases := []struct {
		name      string
		opts      SandboxOptions
		want, not string
	}{
		{"kept", SandboxOptions{Name: "box", Memory: "4g", Recreate: true}, " -v /in:/in:ro -v /tools:/tools:ro safeclaw:sandbox ", ""},
		{"replaced", SandboxOptions{Name: "box", Volumes: []string{"/new:/new", "/in:/in"}}, " -v /new:/new:ro -v /in:/in:ro safeclaw:sandbox ", "/tools"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, r := newTestManager(t, existing())
			if _, err := m.EnsureSandbox(context.Background(), tc.opts); err != nil {
				t.Fatal(err)
			}
			run, _ := r.Find("run ")
			if !strings.Contains(run.String(), tc.want) || tc.not != "" && strings.Contains(run.String(), tc.not) {
				t.Errorf("run = %q\nwant %q without %q", run.String(), tc.want, tc.not)
			}
		})
	}
}

func TestExecEnv(t *testing.T) {
	m, _ := newTestManager(t, &world{})
	if err := m.Secrets.Set("OPENAI_API_KEY", "sk"); err != nil {
		t.Fatal(err)
	}
	env := map[string]string{"FROM_CALLER": "caller value", "EMPTY": ""}
	lookup := func(name string) (string, bool) {
		v, ok := env[name]
		return v, ok
	}

	got, err := m.ExecEnv([]string{"PASSWORD=p a=s s ", "FROM_CALLER", "EMPTY", "BLANK=", "_x1=été"}, lookup)
	if err != nil {
		t.Fatal(err)
	}
	if want := "PASSWORD=p a=s s \nFROM_CALLER=caller value\nEMPTY=\nBLANK=\n_x1=été\n"; got != want {
		t.Errorf("env = %q, want %q", got, want)
	}
	if got, err := m.ExecEnv(nil, lookup); got != "" || err != nil {
		t.Errorf("no specs = %q, %v", got, err)
	}

	for _, tc := range []struct {
		spec, want string
	}{
		{"UNSET", "not set"},
		{"1X=a", "invalid -e"},
		{"BAD NAME=hunter2", "invalid -e"},
		{"=hunter2", "invalid -e"},
		{"X=hunter2\nY=z", "newlines"},
		{"X=hunter2\r", "newlines"},
		{"X=hunter2\x00", "newlines"},
		{"X=\xffhunter2", "UTF-8"},
		{"X=" + strings.Repeat("a", MaxExecEnvBytes), "allowed"},
		{"OPENAI_API_KEY=x", "secret"},
		{"GH_TOKEN", "secret"},
		{"CLAUDE_CODE_OAUTH_TOKEN=x", "secret"},
	} {
		_, err := m.ExecEnv([]string{tc.spec}, lookup)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: err = %v, want %q", tc.spec, err, tc.want)
			continue
		}
		// Errors name the variable but never echo its value.
		if strings.Contains(err.Error(), "hunter2") {
			t.Errorf("%q: error leaks the value: %v", tc.spec, err)
		}
	}
	if _, err := m.ExecEnv([]string{"A=1", "A=2"}, lookup); err == nil {
		t.Error("want an error for a name given twice")
	}
	if _, err := m.ExecEnv([]string{"GH_TOKEN=x"}, lookup); !errors.Is(err, ErrSecretEnv) {
		t.Errorf("err = %v, want ErrSecretEnv", err)
	}

	m.Secrets = keysFailStore{m.Secrets}
	if _, err := m.ExecEnv([]string{"A=1"}, lookup); err == nil || !strings.Contains(err.Error(), "could not list") {
		t.Errorf("err = %v, want the secret listing error", err)
	}
}

// keysFailStore is a secrets store that can't list its keys.
type keysFailStore struct{ secrets.Store }

func (keysFailStore) Keys() ([]string, error) { return nil, errors.New("locked") }
