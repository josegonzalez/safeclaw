package wrapper

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

type fakeCommander struct {
	hasSession bool
	runs       []string
	exec       string
}

func (f *fakeCommander) Run(name string, args ...string) error {
	cmd := name + " " + strings.Join(args, " ")
	f.runs = append(f.runs, cmd)
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
