package session

import (
	"context"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
)

// stuckOn makes the execs whose command contains script hang until their
// context is done, like a docker exec that never sees its stdin close, and
// answers the rest from w.
func stuckOn(r *dockertest.Runner, w *world, script string) {
	r.ExecHandler = func(ctx context.Context, args []string, stdin io.Reader) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), script) {
			<-ctx.Done()
			return nil, ctx.Err()
		}
		in := ""
		if stdin != nil {
			b, _ := io.ReadAll(stdin)
			in = string(b)
		}
		return w.handle(args, in)
	}
}

// Every exec fed input is bounded, and the error names the step that hung,
// so a stuck docker exec can't hang a run.
func TestEnsureInputExecTimeout(t *testing.T) {
	for _, c := range []struct{ name, script, want string }{
		{"env", "cat > " + config.EnvFile, "writing the env file in safeclaw-p: timed out after 50ms"},
		{"legacy env", "cat > " + config.LegacyEnvFile, "writing the env file in safeclaw-p: timed out after 50ms"},
		{"memory", "cat > " + config.SessionSettingsFile, "writing the auto memory setting in safeclaw-p: timed out after 50ms"},
		{"credential", "cat > " + config.TTYDCredentialFile, "writing the ttyd credential in safeclaw-p: timed out after 50ms"},
		{"ttyd check", "--config -", "sending ttyd the credential in safeclaw-p: timed out after 50ms"},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := &world{image: "img", containers: map[string]*fakeContainer{}, native: true, rootEnv: c.name != "legacy env"}
			m, r := newTestManager(t, w)
			m.InputTimeout = 50 * time.Millisecond
			stuckOn(r, w, c.script)
			start := time.Now()
			_, err := m.Ensure(context.Background(), Options{Name: "p", NoMemory: boolPtr(true), NoOpen: true})
			if !errors.Is(err, ErrInputTimeout) || !strings.Contains(err.Error(), c.want) {
				t.Errorf("err = %v, want %q", err, c.want)
			}
			if d := time.Since(start); d > 5*time.Second {
				t.Errorf("Ensure took %s", d)
			}
		})
	}
}

// A run cancelled by its caller says so, rather than blaming the step.
func TestExecInputCancelled(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{}, native: true}
	m, r := newTestManager(t, w)
	ctx, cancel := context.WithCancel(context.Background())
	r.ExecHandler = func(ctx context.Context, args []string, stdin io.Reader) ([]byte, error) {
		cancel()
		<-ctx.Done()
		return nil, ctx.Err()
	}
	_, err := m.execInput(ctx, "writing the env file", "safeclaw-p", asSclaw(docker.ExecOptions{Input: "x"}), "sh", "-c", "cat > "+config.EnvFile)
	if errors.Is(err, ErrInputTimeout) || !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want the cancellation", err)
	}
	if !slices.ContainsFunc(r.Calls, func(c dockertest.Call) bool { return c.Input }) {
		t.Errorf("exec not given Input: %v", r.Commands())
	}
}
