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

// Umask is set before tmux runs, so the tmux server, its shells, and
// Claude Code create files that are not world-writable. `docker exec` does
// not inherit the container's umask on every engine, and some run commands
// with 0000.
const Umask = 0o022

// Commander runs and execs processes.
type Commander interface {
	// Run runs a command and returns its error.
	Run(name string, args ...string) error
	// Exec replaces the current process.
	Exec(name string, args ...string) error
	// Umask sets the process's file mode creation mask.
	Umask(mask int)
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

// Umask implements Commander.
func (OSCommander) Umask(mask int) {
	syscall.Umask(mask)
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
		// Don't forward clipboard writes or passthrough sequences to
		// attached clients. This only covers programs that leave these
		// alone: code in the session runs as the server's user and can
		// turn both back on, so `safeclaw attach` filters them on the host.
		{"set", "-s", "set-clipboard", "off"},
		{"set", "-g", "allow-passthrough", "off"},
		// Env vars are loaded via BASH_ENV -> the env file.
		{"send-keys", "-t", s, ClaudeCommand, "Enter"},
	}
	for _, args := range steps {
		if err := c.Run("tmux", args...); err != nil {
			return err
		}
	}
	return nil
}

// Run sets the umask, ensures the session exists and, if attach is true,
// replaces the current process with `tmux attach`.
func Run(c Commander, attach bool) error {
	c.Umask(Umask)
	if err := EnsureSession(c); err != nil {
		return err
	}
	if !attach {
		return nil
	}
	return c.Exec("tmux", "attach", "-t", config.TmuxSession)
}
