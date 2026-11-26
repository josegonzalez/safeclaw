// Package wrapper runs inside the container. It starts the tmux session that
// Claude Code lives in and attaches to it, replacing ttyd-wrapper.sh.
package wrapper

import (
	"os"
	"os/exec"
	"syscall"

	"github.com/josegonzalez/safeclaw/internal/config"
)

// ClaudeCommand is typed into the new tmux session.
const ClaudeCommand = "claude --dangerously-skip-permissions"

// Commander runs and execs processes.
type Commander interface {
	// Run runs a command and returns its error.
	Run(name string, args ...string) error
	// Exec replaces the current process.
	Exec(name string, args ...string) error
}

// OSCommander uses os/exec and syscall.Exec.
type OSCommander struct{}

// Run implements Commander. Output is discarded, like the `2>/dev/null` in
// the original script.
func (OSCommander) Run(name string, args ...string) error {
	return exec.Command(name, args...).Run()
}

// Exec implements Commander.
func (OSCommander) Exec(name string, args ...string) error {
	path, err := exec.LookPath(name)
	if err != nil {
		return err
	}
	return syscall.Exec(path, append([]string{name}, args...), os.Environ())
}

// EnsureSession creates the tmux session and starts Claude Code in it, unless
// the session already exists.
func EnsureSession(c Commander) error {
	s := config.TmuxSession
	if c.Run("tmux", "has-session", "-t", s) == nil {
		return nil
	}
	steps := [][]string{
		{"-f", "/dev/null", "new", "-d", "-s", s},
		{"set", "-t", s, "status", "off"},
		{"set", "-t", s, "mouse", "on"},
		// Env vars are loaded via BASH_ENV -> .env.
		{"send-keys", "-t", s, ClaudeCommand, "Enter"},
	}
	for _, args := range steps {
		if err := c.Run("tmux", args...); err != nil {
			return err
		}
	}
	return nil
}

// Run ensures the session exists and, if attach is true, replaces the
// current process with `tmux attach`.
func Run(c Commander, attach bool) error {
	if err := EnsureSession(c); err != nil {
		return err
	}
	if !attach {
		return nil
	}
	return c.Exec("tmux", "attach", "-t", config.TmuxSession)
}
