// Package config holds the paths and constants shared across safeclaw.
package config

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	// ImageName is the local image every session container runs.
	ImageName = "safeclaw"
	// RemoteImage is the published image `safeclaw pull` fetches.
	RemoteImage = "ghcr.io/josegonzalez/safeclaw"
	// ContainerPrefix prefixes every session container name.
	ContainerPrefix = "safeclaw-"
	// DefaultSession is the session name used when none is given.
	DefaultSession = "default"
	// DashboardPort is the default dashboard port.
	DashboardPort = 7680
	// FirstSessionPort is the first host port handed out to sessions.
	FirstSessionPort = 7681
	// TTYDPort is the port ttyd listens on inside the container.
	TTYDPort = 7681
	// ProjectsMount is where the per-session history directory is mounted.
	ProjectsMount = "/home/sclaw/.claude/projects"
	// EnvFile is the env file sourced by every bash invocation in the container.
	EnvFile = "/home/sclaw/.env"
	// LegacyWrapper is the ttyd wrapper script shipped by upstream images.
	LegacyWrapper = "/home/sclaw/ttyd-wrapper.sh"
	// TmuxSession is the tmux session name Claude Code runs in.
	TmuxSession = "main"
)

// Dir returns the safeclaw config directory, honoring XDG_CONFIG_HOME.
func Dir() string {
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "safeclaw")
}

// SecretsDir returns the directory holding one file per env var.
func SecretsDir() string {
	return filepath.Join(Dir(), ".secrets")
}

// SessionsDir returns the directory holding per-session history.
func SessionsDir() string {
	return filepath.Join(Dir(), "sessions")
}

// ContainerName returns the container name for a session name. Names that
// already carry the prefix are returned unchanged.
func ContainerName(session string) string {
	if strings.HasPrefix(session, ContainerPrefix) {
		return session
	}
	return ContainerPrefix + session
}

// SessionName returns the short session name for a container name.
func SessionName(container string) string {
	return strings.TrimPrefix(container, ContainerPrefix)
}
