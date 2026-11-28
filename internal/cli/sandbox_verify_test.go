package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
	"github.com/josegonzalez/safeclaw/internal/secrets"
	"github.com/josegonzalez/safeclaw/internal/session"
)

// An existing sandbox that fails --verify is reported on stderr and left
// as it was.
func TestSandboxRunVerifyKeepsExisting(t *testing.T) {
	r := &dockertest.Runner{Handler: func(args []string, _ string) ([]byte, error) {
		switch {
		case args[0] == "image" && args[1] == "inspect":
			return json.Marshal(map[string]any{"Id": "sha256:img", "Config": map[string]any{"Labels": map[string]string{
				config.LabelBracketedHostTTYD: "1", config.LabelCredentialFileTTYD: "1"}}})
		case args[0] == "container" && args[1] == "inspect":
			// A running sandbox with none of its isolation.
			return json.Marshal([]any{map[string]any{
				"Id": "abc", "Name": "/safeclaw-box", "Image": "sha256:img",
				"Config":     map[string]any{"Labels": map[string]string{config.LabelType: config.TypeSandbox, config.LabelVariant: "sandbox"}},
				"State":      map[string]any{"Status": "running", "Running": true},
				"HostConfig": map[string]any{"NetworkMode": "bridge"},
			}})
		case args[0] == "exec":
			return nil, errors.New("exit 1")
		}
		return nil, nil
	}}
	orig := newManager
	t.Cleanup(func() { newManager = orig })
	dir := t.TempDir()
	newManager = func() *session.Manager {
		return &session.Manager{Docker: r.Client(), Secrets: secrets.FileStore{Dir: filepath.Join(dir, ".secrets")},
			NetworkDir: filepath.Join(dir, "network"), ChoicesDir: filepath.Join(dir, "choices")}
	}
	var out, errOut strings.Builder
	cmd := NewRootCommand()
	cmd.SetArgs([]string{"sandbox", "run", "-s", "box", "--verify"})
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	err := cmd.Execute()
	var ve *session.SandboxVerifyError
	if !errors.As(err, &ve) || !ve.Kept || !strings.Contains(err.Error(), "network") {
		t.Fatalf("err = %v", err)
	}
	if !strings.Contains(errOut.String(), "FAIL  network") {
		t.Errorf("stderr lacks the report: %q", errOut.String())
	}
	if !strings.Contains(out.String(), "Verifying sandbox: safeclaw-box") || strings.Contains(out.String(), "FAIL") {
		t.Errorf("stdout = %q", out.String())
	}
	if _, ok := r.Find("rm "); ok {
		t.Errorf("existing sandbox removed: %v", r.Commands())
	}
}

func TestSandboxVerifyFlags(t *testing.T) {
	for _, cmd := range []*cobra.Command{newSandboxRunCommand(), newSandboxExecCommand()} {
		if f := cmd.Flags().Lookup("verify"); f == nil || f.DefValue != "false" {
			t.Errorf("%s: --verify = %+v", cmd.Name(), f)
		}
	}
	cmd := newSandboxRunCommand()
	if err := cmd.ParseFlags([]string{"--rm", "--verify"}); err != nil {
		t.Fatal(err)
	}
	var f sandboxFlags
	f.verify = true
	none := func(string) bool { return false }
	if !f.options(none, none).Verify {
		t.Error("options lost Verify")
	}
}

// gated returns a command that waits for flag to exist, as the sandbox's
// gate does, then prints "ran" and exits with code.
func gated(flag, code string) []string {
	return []string{"sh", "-c", `while [ ! -e "$0" ]; do sleep 0.01; done; echo ran; exit "$1"`, flag, code}
}

func TestRunSandboxExecVerify(t *testing.T) {
	failed := &session.SandboxVerifyError{Name: "job", Report: &session.SandboxReport{Name: "job",
		Checks: []session.SandboxCheck{{Name: "network", Detail: "bridge"}, {Name: "user", OK: true}}}}

	t.Run("passes", func(t *testing.T) {
		flag := filepath.Join(t.TempDir(), "go")
		var out, errOut strings.Builder
		var ranBefore bool
		verify := func(_ context.Context, _ <-chan struct{}) error {
			time.Sleep(50 * time.Millisecond)
			ranBefore = strings.Contains(out.String(), "ran")
			return os.WriteFile(flag, nil, 0o600)
		}
		err := runSandboxExec(execCmd(&out, &errOut), nil, gated(flag, "3"), execRun{ephemeral: true, name: "job", verify: verify})
		if !errors.Is(err, exitCodeError{3}) || out.String() != "ran\n" || errOut.String() != "" || ranBefore {
			t.Errorf("err = %v, out = %q, stderr = %q, ran before the checks = %v", err, out.String(), errOut.String(), ranBefore)
		}
	})
	t.Run("fails", func(t *testing.T) {
		flag := filepath.Join(t.TempDir(), "go")
		var out, errOut strings.Builder
		// The command never starts: removing the sandbox ends docker.
		verify := func(_ context.Context, _ <-chan struct{}) error { return failed }
		err := runSandboxExec(execCmd(&out, &errOut), nil, gated(flag, "0"), execRun{ephemeral: true, name: "job", verify: verify})
		var ve *session.SandboxVerifyError
		if !errors.As(err, &ve) || out.String() != "" {
			t.Errorf("err = %v, out = %q", err, out.String())
		}
		if !strings.Contains(errOut.String(), "FAIL  network  bridge") || !strings.Contains(errOut.String(), "ok    user") {
			t.Errorf("stderr = %q", errOut.String())
		}
	})
	t.Run("docker exits first", func(t *testing.T) {
		var out, errOut strings.Builder
		verify := func(_ context.Context, exited <-chan struct{}) error {
			<-exited
			return session.ErrExited
		}
		err := runSandboxExec(execCmd(&out, &errOut), nil, []string{"sh", "-c", "exit 7"}, execRun{ephemeral: true, name: "job", verify: verify})
		if !errors.Is(err, exitCodeError{7}) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("timeout counts from the checks", func(t *testing.T) {
		flag := filepath.Join(t.TempDir(), "go")
		var out, errOut strings.Builder
		verify := func(_ context.Context, _ <-chan struct{}) error {
			time.Sleep(300 * time.Millisecond)
			return os.WriteFile(flag, nil, 0o600)
		}
		// Exiting 124 before the timeout has passed since the checks is
		// the command's own exit code, not a timeout.
		err := runSandboxExec(execCmd(&out, &errOut), nil, gated(flag, "124"), execRun{ephemeral: true, name: "job", timeout: 250 * time.Millisecond, verify: verify})
		if !errors.Is(err, exitCodeError{124}) || errOut.String() != "" {
			t.Errorf("err = %v, stderr = %q", err, errOut.String())
		}
	})
}
