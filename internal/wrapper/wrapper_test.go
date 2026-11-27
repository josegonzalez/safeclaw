package wrapper

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
)

type fakeCommander struct {
	hasSession bool
	runs       []string
	exec       string
	// calls records umask and run calls in order.
	calls []string
}

func (f *fakeCommander) Umask(mask int) {
	f.calls = append(f.calls, fmt.Sprintf("umask %04o", mask))
}

func (f *fakeCommander) Run(name string, args ...string) error {
	cmd := name + " " + strings.Join(args, " ")
	f.runs = append(f.runs, cmd)
	f.calls = append(f.calls, cmd)
	if strings.Contains(cmd, "has-session") && !f.hasSession {
		return errors.New("no session")
	}
	return nil
}

func (f *fakeCommander) Exec(name string, args ...string) error {
	f.exec = name + " " + strings.Join(args, " ")
	return nil
}

func TestRunCreatesSessionAndAttaches(t *testing.T) {
	f := &fakeCommander{}
	if err := Run(f, true); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"tmux has-session -t main",
		"tmux -f /dev/null new -d -s main",
		"tmux set -t main status off",
		"tmux set -t main mouse on",
		"tmux set -s set-clipboard off",
		"tmux set -g allow-passthrough off",
		"tmux send-keys -t main claude --dangerously-skip-permissions Enter",
	}
	if !slices.Equal(f.runs, want) {
		t.Errorf("runs = %q", f.runs)
	}
	if f.exec != "tmux attach -t main" {
		t.Errorf("exec = %q", f.exec)
	}
}

func TestRunExistingSessionNoAttach(t *testing.T) {
	f := &fakeCommander{hasSession: true}
	if err := Run(f, false); err != nil {
		t.Fatal(err)
	}
	if len(f.runs) != 1 || f.exec != "" {
		t.Errorf("runs = %q exec = %q", f.runs, f.exec)
	}
}

func TestRunSetsUmaskBeforeTmux(t *testing.T) {
	for _, attach := range []bool{true, false} {
		f := &fakeCommander{}
		if err := Run(f, attach); err != nil {
			t.Fatal(err)
		}
		if len(f.calls) < 2 || f.calls[0] != "umask 0022" {
			t.Errorf("attach=%v: calls = %q, want umask 0022 before any tmux command", attach, f.calls)
		}
	}
}
