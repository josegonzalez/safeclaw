// Package config holds the paths and constants shared across safeclaw.
package config

import (
	"os"
	"path/filepath"
	"strconv"
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
	// TTYDCredentialFile is where the session's ttyd credential is written
	// inside the container, for ttyd to read at start.
	TTYDCredentialFile = "/home/sclaw/.ttyd-credential"
	// TTYDUser is the user name of every session's ttyd credential.
	TTYDUser = "safeclaw"

	// LabelPrefix starts every label safeclaw sets. Images may carry only
	// their own LabelVariant, so every other safeclaw label on a container
	// was written by safeclaw rather than inherited from its image.
	LabelPrefix = "safeclaw."

	// LabelType is the container label that records a session's type.
	// safeclaw sets it on every session and sandbox; containers without it,
	// created by versions that left it off sessions, are interactive
	// sessions.
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

	// LabelIPC is the container label that records an interactive session's
	// IPC namespace. IPCHost means it shares the docker host's, which the
	// user opted into; containers without it get a private one.
	LabelIPC = "safeclaw.ipc"
	// IPCHost is the LabelIPC value, and docker IpcMode, for the host's IPC
	// namespace.
	IPCHost = "host"

	// LabelAuth marks the short-lived container `safeclaw auth login` runs
	// `claude setup-token` in, with the PID of the safeclaw process that
	// started it.
	LabelAuth = "safeclaw.auth"
	// AuthContainerPrefix starts the name of every sign-in container. It is
	// outside ContainerPrefix, so sign-in containers are never listed as
	// sessions, and sessions are never mistaken for sign-in containers.
	AuthContainerPrefix = "safeclaw.auth."
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

// SecretsDir returns the directory holding one file per env var. It is used
// when no system keychain is available, and secrets found there are moved
// into the keychain when one is.
func SecretsDir() string {
	return filepath.Join(Dir(), ".secrets")
}

// SecretsLockPath returns the file locked while the keychain index of
// secrets changes.
func SecretsLockPath() string {
	return filepath.Join(Dir(), "secrets.lock")
}

// SessionsDir returns the directory holding per-session history.
func SessionsDir() string {
	return filepath.Join(Dir(), "sessions")
}

// NetworkDir returns the directory holding the saved networks and holders
// of offline sessions. It is kept apart from SessionsDir, which is mounted
// into the containers.
func NetworkDir() string {
	return filepath.Join(Dir(), "network")
}

// CopyDir returns the directory holding the lock that serializes copies
// into sandboxes across safeclaw processes.
func CopyDir() string {
	return filepath.Join(Dir(), "copy")
}

// TTYDDir returns the directory holding each session's ttyd credential. It
// is kept apart from SessionsDir, which is mounted into the containers.
func TTYDDir() string {
	return filepath.Join(Dir(), "ttyd")
}

// DashboardDir returns the directory holding the dashboard's API tokens.
func DashboardDir() string {
	return filepath.Join(Dir(), "dashboard")
}

// DashboardTokenFile returns the file holding the API token of the
// dashboard listening on port.
func DashboardTokenFile(port int) string {
	return filepath.Join(DashboardDir(), strconv.Itoa(port)+".token")
}

// ContainerName returns the container name for a session name. It always
// adds the prefix, so every session name maps to exactly one container;
// session names may not start with the prefix themselves.
func ContainerName(session string) string {
	return ContainerPrefix + session
}

// SessionName returns the short session name for a container name, removing
// one prefix. Names without the prefix are returned unchanged, so a session
// can be given by either name.
func SessionName(container string) string {
	return strings.TrimPrefix(container, ContainerPrefix)
}
