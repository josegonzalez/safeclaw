package cli

import (
	"errors"
	"io"
	"os"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/spf13/cobra"

	"github.com/josegonzalez/safeclaw/internal/session"
)

func TestSandboxExecEnvFlag(t *testing.T) {
	cmd := newSandboxExecCommand()
	if err := cmd.ParseFlags([]string{"-e", "A=1,2", "--env", "B", "--env-if-set", "C", "--env-if-set", "D,E"}); err != nil {
		t.Fatal(err)
	}
	// StringArray, not StringSlice, so a comma in a value is kept.
	if got, _ := cmd.Flags().GetStringArray("env"); !slices.Equal(got, []string{"A=1,2", "B"}) {
		t.Errorf("env = %q", got)
	}
	// A comma isn't a separator either, so "D,E" is refused as a name
	// rather than read as two.
	if got, _ := cmd.Flags().GetStringArray("env-if-set"); !slices.Equal(got, []string{"C", "D,E"}) {
		t.Errorf("env-if-set = %q", got)
	}
}

func TestEnvPipe(t *testing.T) {
	r, err := envPipe("A=1\nB=two words\n")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	b, err := io.ReadAll(r)
	if err != nil || string(b) != "A=1\nB=two words\n" {
		t.Errorf("read %q, %v", b, err)
	}
	// The largest env ExecEnv allows fits in the pipe before anything reads it.
	r2, err := envPipe(strings.Repeat("a", session.MaxExecEnvBytes))
	if err != nil {
		t.Fatal(err)
	}
	_ = r2.Close()
}

func TestTimedOut(t *testing.T) {
	const to = time.Second
	cases := []struct {
		timeout, elapsed time.Duration
		code             int
		forced, want     bool
	}{
		{0, time.Hour, 124, false, false},
		{to, 2 * to, 124, false, true},
		{to, 2 * to, 137, false, true},
		{to, to, 124, false, true},
		// A command that exits 124 by itself before the timeout.
		{to, to / 2, 124, false, false},
		{to, 2 * to, 1, false, false},
		{to, 2 * to, 0, false, false},
		{to, 12 * to, -1, true, true},
	}
	for _, tc := range cases {
		if got := timedOut(tc.timeout, tc.elapsed, tc.code, tc.forced); got != tc.want {
			t.Errorf("timedOut(%s, %s, %d, %v) = %v", tc.timeout, tc.elapsed, tc.code, tc.forced, got)
		}
	}
}

func TestRunChildDeadline(t *testing.T) {
	var called atomic.Bool
	start := time.Now()
	code, err := runChild([]string{"sleep", "30"}, childOptions{
		stdout: io.Discard, stderr: io.Discard,
		deadline:   100 * time.Millisecond,
		onDeadline: func(p *os.Process) { called.Store(true); _ = p.Kill() },
	})
	if err != nil {
		t.Fatal(err)
	}
	if !called.Load() || code != 137 {
		t.Errorf("code = %d, onDeadline called = %v", code, called.Load())
	}
	if time.Since(start) > 10*time.Second {
		t.Error("deadline did not stop the command")
	}

	called.Store(false)
	code, err = runChild([]string{"true"}, childOptions{stdout: io.Discard, stderr: io.Discard, deadline: time.Minute, onDeadline: func(*os.Process) { called.Store(true) }})
	if err != nil || code != 0 || called.Load() {
		t.Errorf("code = %d, err = %v, onDeadline called = %v", code, err, called.Load())
	}
}

// execCmd returns a command whose output runSandboxExec writes to out and
// errOut.
func execCmd(out, errOut io.Writer) *cobra.Command {
	cmd := &cobra.Command{}
	cmd.SetOut(out)
	cmd.SetErr(errOut)
	cmd.SetIn(strings.NewReader(""))
	return cmd
}

func TestRunSandboxExec(t *testing.T) {
	t.Run("exit code and raw output", func(t *testing.T) {
		var out, errOut strings.Builder
		err := runSandboxExec(execCmd(&out, &errOut), nil, []string{"sh", "-c", `printf 'a\033b'; exit 3`}, execRun{timeout: time.Minute})
		if !errors.Is(err, exitCodeError{3}) || out.String() != "a\x1bb" || errOut.String() != "" {
			t.Errorf("err = %v, out = %q, stderr = %q", err, out.String(), errOut.String())
		}
	})
	t.Run("escaped", func(t *testing.T) {
		var out, errOut strings.Builder
		err := runSandboxExec(execCmd(&out, &errOut), nil, []string{"sh", "-c", `printf 'a\033b'`}, execRun{escape: true})
		if err != nil || out.String() != `a\x1bb` {
			t.Errorf("err = %v, out = %q", err, out.String())
		}
	})
	t.Run("timed out", func(t *testing.T) {
		var out, errOut strings.Builder
		err := runSandboxExec(execCmd(&out, &errOut), nil, []string{"sh", "-c", "sleep 0.3; exit 124"}, execRun{timeout: 100 * time.Millisecond, name: "box"})
		if !errors.Is(err, exitCodeError{timeoutExitCode}) {
			t.Errorf("err = %v", err)
		}
		if want := "Error: the command timed out after 100ms\n"; errOut.String() != want {
			t.Errorf("stderr = %q, want %q", errOut.String(), want)
		}
	})
	t.Run("124 before the timeout", func(t *testing.T) {
		var out, errOut strings.Builder
		err := runSandboxExec(execCmd(&out, &errOut), nil, []string{"sh", "-c", "exit 124"}, execRun{timeout: time.Minute})
		if !errors.Is(err, exitCodeError{124}) || errOut.String() != "" {
			t.Errorf("err = %v, stderr = %q", err, errOut.String())
		}
	})
	t.Run("backstop", func(t *testing.T) {
		old := timeoutGrace
		timeoutGrace = -session.TimeoutKillAfter
		t.Cleanup(func() { timeoutGrace = old })
		var out, errOut strings.Builder
		err := runSandboxExec(execCmd(&out, &errOut), nil, []string{"sleep", "30"}, execRun{timeout: 100 * time.Millisecond, name: "box"})
		if !errors.Is(err, exitCodeError{timeoutExitCode}) {
			t.Errorf("err = %v", err)
		}
		if !strings.Contains(errOut.String(), "may still be running in sandbox \"box\"") {
			t.Errorf("stderr = %q", errOut.String())
		}
	})
	t.Run("env file on fd 3", func(t *testing.T) {
		r, err := envPipe("PASSWORD=p w\n")
		if err != nil {
			t.Fatal(err)
		}
		defer r.Close()
		var out, errOut strings.Builder
		err = runSandboxExec(execCmd(&out, &errOut), nil, []string{"cat", "/dev/fd/3"}, execRun{escape: true, envFile: r})
		if err != nil || out.String() != "PASSWORD=p w\n" {
			t.Errorf("err = %v, out = %q, stderr = %q", err, out.String(), errOut.String())
		}
	})
}
