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
	// EnvFile is the env file sourced by every bash invocation in the
	// container. The image creates it root:sclaw 0640, and safeclaw rewrites
	// its contents as root.
	EnvFile = "/etc/safeclaw/env"
	// ManagedSettingsDir is Claude Code's drop-in folder for managed
	// settings, which take precedence over every other settings file, the
	// --settings flag, and the environment.
	ManagedSettingsDir = "/etc/claude-code/managed-settings.d"
	// SessionSettingsFile holds the managed settings safeclaw sets per
	// session. The image creates it root-owned, and safeclaw rewrites its
	// contents as root.
	SessionSettingsFile = ManagedSettingsDir + "/safeclaw-session.json"
	// LegacyEnvFile is the sclaw-owned env file sourced in containers from
	// images that predate EnvFile.
	LegacyEnvFile = "/home/sclaw/.env"
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
	// SessionUser is the unprivileged user interactive sessions and sign-in
	// containers run as, and the user every exec into them runs as unless
	// it needs root. It is passed explicitly rather than taken from the
	// image's final USER.
	SessionUser = "sclaw"
	// SandboxUser is the unprivileged, non-login user sandboxes run as.
	SandboxUser = "sandbox"
	// SandboxDir is the sandbox user's home and working directory.
	SandboxDir = "/sandbox"

	// LabelVariant is the container and image label that records which
	// image variant a container runs. Containers without it run the base
	// image.
	LabelVariant = "safeclaw.variant"
	// LabelImage is the container label that records the image tag a
	// container was created from. Containers are run from the image ID
	// whose labels were checked, so docker records only that ID as their
	// image.
	LabelImage = "safeclaw.image"
	// BaseVariant names the base image wherever a variant is expected.
	BaseVariant = "base"

	// LabelBracketedHostTTYD is the image label, copied onto its containers,
	// marking an image whose ttyd accepts a bracketed IPv6 Host such as
	// [::1]:PORT in its origin check. It is outside LabelPrefix because the
	// image sets it. Sessions are not created from an image without it, and
	// containers on [::1] without it get no URL until they are recreated.
	LabelBracketedHostTTYD = "io.github.josegonzalez.safeclaw.ttyd-bracketed-host"
	// LabelCredentialFileTTYD is the image label, copied onto its
	// containers, marking an image whose ttyd reads its credential from a
	// file with --credential-file. Sessions are not created from an image
	// without it, and containers without it are recreated from an image
	// with it, or refused, so no ttyd gets the credential on its command
	// line.
	LabelCredentialFileTTYD = "io.github.josegonzalez.safeclaw.ttyd-credential-file"

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

	// LabelMemory is the container label that records an interactive
	// session's Claude Code auto memory. MemoryOff means the user turned it
	// off; containers without it keep it on.
	LabelMemory = "safeclaw.memory"
	// MemoryOff is the LabelMemory value for a session with auto memory off.
	MemoryOff = "off"

	// LabelKeepInputs is the container label that records the absolute
	// host directory a one-off sandbox made with --keep-inputs or
	// --restore-from keeps its input record in, which `sandbox cp-in` and
	// `sandbox open` append to.
	LabelKeepInputs = "safeclaw.keep-inputs"

	// LabelAuth marks the short-lived container `safeclaw auth login` runs
	// `claude setup-token` in, with the random owner ID of the login that
	// started it. That login locks a file named after the ID in AuthDir
	// until the container is gone.
	LabelAuth = "safeclaw.auth"
	// AuthContainerPrefix starts the name of every sign-in container. It is
	// outside ContainerPrefix, so sign-in containers are never listed as
	// sessions, and sessions are never mistaken for sign-in containers.
	AuthContainerPrefix = "safeclaw.auth."

	// SessionNetwork is the docker bridge network every interactive session
	// is created on. safeclaw creates it with inter-container traffic off,
	// so sessions can't reach each other over it.
	SessionNetwork = "safeclaw"
	// LabelNetwork is the network label that marks a network safeclaw
	// created for sessions, with the value NetworkSessions.
	LabelNetwork = "safeclaw.network"
	// NetworkSessions is the LabelNetwork value of the session network.
	NetworkSessions = "sessions"
	// BridgeICCOption is the bridge driver option that turns traffic
	// between containers on the same bridge on or off.
	BridgeICCOption = "com.docker.network.bridge.enable_icc"
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

// CacheDir returns the safeclaw cache directory, honoring XDG_CACHE_HOME.
// It holds data that can be fetched again, such as malware signatures.
func CacheDir() string {
	base := os.Getenv("XDG_CACHE_HOME")
	if base == "" {
		home, _ := os.UserHomeDir()
		base = filepath.Join(home, ".cache")
	}
	return filepath.Join(base, "safeclaw")
}

// SignaturesDir returns the directory holding the ClamAV signatures that
// `sandbox update-signatures` installs and sandboxes mount read-only.
func SignaturesDir() string {
	return filepath.Join(CacheDir(), "clamav")
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

// ChoicesDir returns the directory holding each session's policy choices,
// such as its auto memory choice, so they outlive its container. It is kept
// apart from SessionsDir's history directories, which are mounted into the
// containers.
func ChoicesDir() string {
	return filepath.Join(Dir(), "choices")
}

// CopyDir returns the directory holding the per-sandbox locks that
// serialize copies into each sandbox across safeclaw processes.
func CopyDir() string {
	return filepath.Join(Dir(), "copy")
}

// TTYDDir returns the directory holding each session's ttyd credential. It
// is kept apart from SessionsDir, which is mounted into the containers.
func TTYDDir() string {
	return filepath.Join(Dir(), "ttyd")
}

// AuthDir returns the directory holding the owner file each running
// `safeclaw auth login` locks while its sign-in container exists.
func AuthDir() string {
	return filepath.Join(Dir(), "auth")
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
