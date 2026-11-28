package cli

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
	"github.com/josegonzalez/safeclaw/internal/session"
)

// fakeContainers makes newManager see the containers in cs, keyed by
// container name and holding docker's inspect JSON for each. Inspecting
// any name fails with inspectErr when it is set.
func fakeContainers(t *testing.T, cs map[string]string, inspectErr error) {
	t.Helper()
	r := &dockertest.Runner{Handler: func(args []string, _ string) ([]byte, error) {
		if len(args) > 0 && args[0] == "ps" {
			var names []string
			for n := range cs {
				names = append(names, n)
			}
			return []byte(strings.Join(names, "\n")), nil
		}
		if len(args) > 2 && args[0] == "container" && args[1] == "inspect" {
			if inspectErr != nil {
				return nil, inspectErr
			}
			if c, ok := cs[args[2]]; ok {
				return []byte("[" + c + "]"), nil
			}
		}
		return nil, dockertest.NotFound(args)
	}}
	orig := newManager
	t.Cleanup(func() { newManager = orig })
	newManager = func() *session.Manager {
		return &session.Manager{Docker: r.Client(), NetworkDir: t.TempDir(), ChoicesDir: t.TempDir()}
	}
}

func fakeContainer(name, typ string, running bool) string {
	status, run := "exited", "false"
	if running {
		status, run = "running", "true"
	}
	return `{"Id":"id","Name":"/` + name + `","State":{"Status":"` + status + `","Running":` + run + `},` +
		`"Config":{"Image":"safeclaw","User":"sandbox","Labels":{"safeclaw.type":"` + typ + `"}},` +
		`"HostConfig":{"NetworkMode":"none","Memory":1048576}}`
}

// runStderr runs the root command with args, returning its stdout, stderr,
// and error.
func runStderr(args ...string) (string, string, error) {
	var out, errOut bytes.Buffer
	root := NewRootCommand()
	root.SetArgs(args)
	root.SetOut(&out)
	root.SetErr(&errOut)
	err := root.Execute()
	return out.String(), errOut.String(), err
}

func TestSandboxStatus(t *testing.T) {
	fakeContainers(t, map[string]string{
		"safeclaw-up":     fakeContainer("safeclaw-up", "sandbox", true),
		"safeclaw-down":   fakeContainer("safeclaw-down", "sandbox", false),
		"safeclaw-chat":   fakeContainer("safeclaw-chat", "session", true),
		"safeclaw-odd":    fakeContainer("safeclaw-odd", "other", true),
		"safeclaw-legacy": fakeContainer("safeclaw-legacy", "", true),
	}, nil)
	for _, tc := range []struct {
		name, out, stderr string
		code              int
	}{
		{"up", "running\n", "", 0},
		{"UP", "running\n", "", 0},
		{"safeclaw-down", "stopped\n", "", 3},
		{"gone", "missing\n", "", 4},
		{"chat", "", `Error: session "chat" is an interactive session, not a sandbox` + "\n", 5},
		{"legacy", "", `Error: session "legacy" is an interactive session, not a sandbox` + "\n", 5},
	} {
		out, stderr, err := runStderr("sandbox", "status", tc.name)
		code := 0
		if err != nil {
			var exit exitCodeError
			if !errors.As(err, &exit) {
				t.Errorf("%s: err = %v, want exit code %d", tc.name, err, tc.code)
				continue
			}
			code = exit.code
		}
		if code != tc.code || out != tc.out || stderr != tc.stderr {
			t.Errorf("%s: exit %d, out %q, stderr %q; want exit %d, out %q, stderr %q", tc.name, code, out, stderr, tc.code, tc.out, tc.stderr)
		}
	}

	// Other errors exit 1 through Execute's error path, printed once.
	for _, args := range [][]string{{"odd"}, {"a b"}, {}, {"up", "down"}} {
		out, stderr, err := runStderr(append([]string{"sandbox", "status"}, args...)...)
		var exit exitCodeError
		if err == nil || errors.As(err, &exit) || out != "" || stderr != "" {
			t.Errorf("%v: out %q, stderr %q, err %v; want a plain error", args, out, stderr, err)
		}
	}
	if _, _, err := runStderr("sandbox", "status", "odd"); !errors.Is(err, session.ErrNotManaged) {
		t.Errorf("odd: err = %v, want ErrNotManaged", err)
	}
}

func TestSandboxStatusDockerError(t *testing.T) {
	boom := errors.New("docker exploded")
	fakeContainers(t, map[string]string{"safeclaw-up": fakeContainer("safeclaw-up", "sandbox", true)}, boom)
	out, _, err := runStderr("sandbox", "status", "up")
	var exit exitCodeError
	if out != "" || errors.As(err, &exit) || err == nil || !strings.Contains(err.Error(), "docker exploded") {
		t.Errorf("out %q, err %v; want the docker error", out, err)
	}
}

func TestSandboxStatusCodes(t *testing.T) {
	for _, tc := range []struct {
		info  *session.SandboxInfo
		err   error
		state string
		code  int
	}{
		{&session.SandboxInfo{Running: true}, nil, "running", 0},
		{&session.SandboxInfo{}, nil, "stopped", 3},
		{nil, session.ErrNotFound, "missing", 4},
		{nil, session.ErrNotSandbox, "", 5},
		{nil, session.ErrNotManaged, "", 1},
		{nil, errors.New("boom"), "", 1},
	} {
		state, code, err := sandboxStatus(tc.info, tc.err)
		if state != tc.state || code != tc.code || (err == nil) != (tc.state != "") {
			t.Errorf("%v: %q, %d, %v; want %q, %d", tc.err, state, code, err, tc.state, tc.code)
		}
	}
}
