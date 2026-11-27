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

	// LabelType is the container label that records a session's type.
	// Containers without it are interactive sessions.
	LabelType = "safeclaw.type"
	// TypeSession is the type of an interactive Claude Code session.
	TypeSession = "session"
	// TypeSandbox is the type of a headless sandbox for untrusted files.
	TypeSandbox = "sandbox"
	// SandboxUser is the unprivileged, non-login user sandboxes run as.
	SandboxUser = "sandbox"
	// SandboxDir is the sandbox user's home and working directory.
	SandboxDir = "/sandbox"

	// LabelVariant is the container and image label that records which
	// image variant a container runs. Containers without it run the base
	// image.
	LabelVariant = "safeclaw.variant"
	// BaseVariant names the base image wherever a variant is expected.
	BaseVariant = "base"

	// LabelSecrets is the container label that records which secrets an
	// interactive session receives, as comma-separated names. Containers
	// without it get every secret, and an empty value means none.
	LabelSecrets = "safeclaw.secrets"
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

// File returns the path of the optional config file.
func File() string {
	return filepath.Join(Dir(), "config.yaml")
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
