package cli

import (
	"errors"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
	"github.com/josegonzalez/safeclaw/internal/session"
)

// fakeStopWorld makes newManager see a running sandbox "up", a stopped
// sandbox "down", a one-off sandbox "job" that docker removes between the
// lookup and the stop or rm, and an interactive session "chat". It
// returns the docker stop and rm calls made.
func fakeStopWorld(t *testing.T) *[]string {
	t.Helper()
	cs := map[string]string{
		"safeclaw-up":   fakeContainer("safeclaw-up", "sandbox", true),
		"safeclaw-down": fakeContainer("safeclaw-down", "sandbox", false),
		"safeclaw-job":  fakeContainer("safeclaw-job", "sandbox", true),
		"safeclaw-chat": fakeContainer("safeclaw-chat", "session", true),
	}
	var calls []string
	r := &dockertest.Runner{Handler: func(args []string, _ string) ([]byte, error) {
		switch {
		case args[0] == "ps":
			var names []string
			for n := range cs {
				names = append(names, n)
			}
			return []byte(strings.Join(names, "\n")), nil
		case len(args) > 2 && args[0] == "container" && args[1] == "inspect":
			if c, ok := cs[args[2]]; ok {
				return []byte("[" + c + "]"), nil
			}
		case args[0] == "stop" || args[0] == "rm":
			name := args[len(args)-1]
			calls = append(calls, args[0]+" "+name)
			if name == "safeclaw-job" {
				return nil, &docker.Error{Args: args, Stderr: "Error response from daemon: No such container: " + name, Err: errors.New("exit status 1")}
			}
			if _, ok := cs[name]; ok {
				return nil, nil
			}
		}
		return nil, dockertest.NotFound(args)
	}}
	orig := newManager
	t.Cleanup(func() { newManager = orig })
	newManager = func() *session.Manager {
		return &session.Manager{Docker: r.Client(), NetworkDir: t.TempDir(), ChoicesDir: t.TempDir(), TTYDDir: t.TempDir()}
	}
	return &calls
}

func TestSandboxStopRemoveMissingOK(t *testing.T) {
	for _, tc := range []struct {
		args   []string
		stderr string
		calls  string
		err    error
	}{
		{[]string{"stop", "up"}, "", "stop safeclaw-up", nil},
		{[]string{"stop", "--missing-ok", "up"}, "", "stop safeclaw-up", nil},
		{[]string{"stop", "down"}, "", "stop safeclaw-down", nil},
		{[]string{"stop", "--missing-ok", "down"}, `Sandbox "down" is already stopped, nothing to stop` + "\n", "", nil},
		{[]string{"stop", "gone"}, "", "", session.ErrNotFound},
		{[]string{"stop", "--missing-ok", "GONE"}, `Sandbox "gone" is missing, nothing to stop` + "\n", "", nil},
		{[]string{"stop", "--missing-ok", "job"}, `Sandbox "job" is missing, nothing to stop` + "\n", "stop safeclaw-job", nil},
		{[]string{"stop", "--missing-ok", "chat"}, "", "", session.ErrNotSandbox},
		{[]string{"rm", "-f", "up"}, "", "rm safeclaw-up", nil},
		{[]string{"rm", "--missing-ok", "down"}, "", "rm safeclaw-down", nil},
		{[]string{"rm", "gone"}, "", "", session.ErrNotFound},
		{[]string{"rm", "--missing-ok", "gone"}, `Sandbox "gone" is missing, nothing to remove` + "\n", "", nil},
		{[]string{"rm", "-f", "--missing-ok", "gone"}, `Sandbox "gone" is missing, nothing to remove` + "\n", "", nil},
		{[]string{"rm", "-f", "--missing-ok", "job"}, `Sandbox "job" is missing, nothing to remove` + "\n", "rm safeclaw-job", nil},
		{[]string{"rm", "-f", "--missing-ok", "chat"}, "", "", session.ErrNotSandbox},
		{[]string{"delete", "-f", "--missing-ok", "chat"}, "", "", session.ErrNotSandbox},
	} {
		calls := fakeStopWorld(t)
		out, stderr, err := runStderr(append([]string{"sandbox"}, tc.args...)...)
		if out != "" || stderr != tc.stderr || !errors.Is(err, tc.err) || (tc.err == nil) != (err == nil) {
			t.Errorf("%v: out %q, stderr %q, err %v; want stderr %q, err %v", tc.args, out, stderr, err, tc.stderr, tc.err)
		}
		if got := strings.Join(*calls, ", "); got != tc.calls {
			t.Errorf("%v: docker calls %q, want %q", tc.args, got, tc.calls)
		}
	}

	// Without --missing-ok, a sandbox removed meanwhile still fails.
	for _, args := range [][]string{{"stop", "job"}, {"rm", "-f", "job"}} {
		fakeStopWorld(t)
		if _, _, err := runStderr(append([]string{"sandbox"}, args...)...); !docker.IsNotFound(err) {
			t.Errorf("%v: err %v, want docker's not found", args, err)
		}
	}

	// Each takes exactly one name.
	for _, args := range [][]string{{"stop", "--missing-ok"}, {"stop", "--missing-ok", "up", "down"}, {"rm", "--missing-ok", "up", "down"}} {
		calls := fakeStopWorld(t)
		if _, _, err := runStderr(append([]string{"sandbox"}, args...)...); err == nil || len(*calls) != 0 {
			t.Errorf("%v: err %v, calls %v; want refused", args, err, *calls)
		}
	}
}
