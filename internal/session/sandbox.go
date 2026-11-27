package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/variant"
)

// Sandbox resource limit defaults.
const (
	// DefaultSandboxMemory leaves room for a full /sandbox and /tmp, whose
	// tmpfs pages count toward the memory limit.
	DefaultSandboxMemory    = "2g"
	DefaultSandboxPidsLimit = 256
	DefaultSandboxCPUs      = "1"
	// DefaultSandboxDisk is the size of the /sandbox tmpfs.
	DefaultSandboxDisk = "1g"
	// sandboxTmpfs bounds the scratch space under /tmp.
	sandboxTmpfs = "/tmp:rw,nosuid,nodev,size=256m"
	// sandboxUID is the sandbox user's uid in the image, which owns the
	// /sandbox tmpfs.
	sandboxUID = 2000
	// sandboxDirOptions are the /sandbox tmpfs options other than its size.
	// exec keeps what a docker volume allows.
	sandboxDirOptions = "rw,nosuid,nodev,exec"
	// sandboxPath leaves out sclaw's ~/.local/bin, which the sandbox user
	// cannot read anyway.
	sandboxPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	// sandboxUmaskScript sets the umask, then replaces the shell with the
	// command given as its positional parameters, leaving them untouched.
	sandboxUmaskScript = `umask 022; exec "$@"`
)

// SandboxCommand wraps cmd so it runs with a umask of 022 instead of
// whatever docker gives it: `docker exec` does not inherit the container's
// umask on every engine, and some run commands with 0000. The arguments
// reach cmd exactly as given.
func SandboxCommand(cmd []string) []string {
	return append([]string{"/bin/sh", "-c", sandboxUmaskScript, "sh"}, cmd...)
}

// TimeoutKillAfter is how long a timed-out sandbox command has to exit
// after SIGTERM before it gets SIGKILL.
const TimeoutKillAfter = 5 * time.Second

// ExecOptions configures how a sandbox command runs, with or without
// --ephemeral.
type ExecOptions struct {
	// Interactive keeps stdin open (-i), and TTY allocates one (-t).
	Interactive, TTY bool
	// EnvFile is a path docker reads the command's environment from
	// (--env-file), so values never appear in its argv.
	EnvFile string
	// Timeout, when set, runs the command under coreutils timeout inside
	// the container: SIGTERM after Timeout, then SIGKILL TimeoutKillAfter
	// later.
	Timeout time.Duration
}

// flags returns the docker exec or run flags for o.
func (o ExecOptions) flags() []string {
	var args []string
	if o.Interactive {
		args = append(args, "-i")
	}
	if o.TTY {
		args = append(args, "-t")
	}
	if o.EnvFile != "" {
		args = append(args, "--env-file", o.EnvFile)
	}
	return args
}

// command wraps cmd with the timeout, if any, and SandboxCommand. Without
// a TTY, timeout runs the command in its own process group and signals the
// whole group. With one it must leave the command in the terminal's
// foreground group (--foreground), so only the command itself is timed
// out, not its children.
func (o ExecOptions) command(cmd []string) []string {
	if o.Timeout > 0 {
		t := []string{"timeout", "--kill-after=" + seconds(TimeoutKillAfter)}
		if o.TTY {
			t = append(t, "--foreground")
		}
		cmd = append(append(t, "--", seconds(o.Timeout)), cmd...)
	}
	return SandboxCommand(cmd)
}

// seconds formats d as coreutils timeout reads it, such as 1.5s.
func seconds(d time.Duration) string {
	return strconv.FormatFloat(d.Seconds(), 'f', -1, 64) + "s"
}

// Validate refuses a negative timeout.
func (o ExecOptions) Validate() error {
	if o.Timeout < 0 {
		return fmt.Errorf("invalid timeout %s: must be more than 0", o.Timeout)
	}
	return nil
}

// SandboxExecArgv returns the docker argv that runs cmd in the named
// sandbox as the sandbox user, wrapped by ExecOptions.
func SandboxExecArgv(name string, o ExecOptions, cmd []string) []string {
	argv := append([]string{"docker", "exec"}, o.flags()...)
	argv = append(argv, "--user", config.SandboxUser, "--workdir", config.SandboxDir, config.ContainerName(name))
	return append(argv, o.command(cmd)...)
}

// ErrIsSandbox is returned when an interactive-session operation targets a
// sandbox.
var ErrIsSandbox = errors.New("is a sandbox: use the `safeclaw sandbox` commands")

// ErrNotSandbox is returned when a sandbox operation targets an interactive
// session.
var ErrNotSandbox = errors.New("is an interactive session, not a sandbox")

// ErrNotFound is returned when a session container does not exist.
var ErrNotFound = errors.New("not found")

// ErrSandboxName is returned when a sandbox is requested without a name.
var ErrSandboxName = errors.New("a sandbox name is required (-s NAME)")

// ErrExists is returned when a one-off sandbox is requested with the name of
// a container that already exists.
var ErrExists = errors.New("already exists: one-off sandboxes are always new")

// ErrNotRunning is returned when an operation needs a running sandbox.
var ErrNotRunning = errors.New("is not running")

// ErrNoCommand is returned when a one-off sandbox command is empty.
var ErrNoCommand = errors.New("a command is required")

// oneOffPrefix starts the names generated for one-off sandboxes.
const oneOffPrefix = "tmp-"

// randomName returns a name for a one-off sandbox started without one.
var randomName = func() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return oneOffPrefix + hex.EncodeToString(b)
}

// SandboxOptions configures EnsureSandbox and PrepareEphemeral.
type SandboxOptions struct {
	// Name is the sandbox name. It is required unless Remove is set, and
	// optional for PrepareEphemeral.
	Name string
	// Volumes are host:container bind mounts, each always mounted
	// read-only. Setting any recreates an existing sandbox with exactly
	// these mounts.
	Volumes []string
	// Variant is the image variant, config.BaseVariant for the base image.
	// Empty keeps an existing sandbox's variant, or uses the configured
	// default for a new one. A different variant recreates an existing
	// sandbox. SandboxRunArgs and EphemeralRunArgs take it already
	// resolved, so there empty means the base image.
	Variant string
	// Memory is docker's --memory value. Empty keeps a recreated sandbox's
	// limit, or uses DefaultSandboxMemory.
	Memory string
	// PidsLimit is docker's --pids-limit value. Zero keeps a recreated
	// sandbox's limit, or uses DefaultSandboxPidsLimit.
	PidsLimit int
	// CPUs is docker's --cpus value. Empty keeps a recreated sandbox's
	// limit, or uses DefaultSandboxCPUs.
	CPUs string
	// Disk is the size of /sandbox, a tmpfs, with an optional k, m, g, or t
	// suffix. Empty keeps a recreated sandbox's size, or uses
	// DefaultSandboxDisk.
	Disk string
	// Recreate removes an existing sandbox first, e.g. because its limits
	// changed. A recreated sandbox keeps the mount, variant, and limits
	// that are not given again.
	Recreate bool
	// Remove makes a one-off sandbox: docker removes it when it stops. Name
	// is optional, a random one is picked without it, and an existing
	// container with the name is refused.
	Remove bool

	// kept are the bind mounts carried over from a recreated sandbox.
	kept []string
}

// keep fills in what opts leaves unset from the sandbox it recreates.
func (o SandboxOptions) keep(c docker.Container) SandboxOptions {
	if len(o.Volumes) == 0 {
		o.kept = c.BindSpecs()
	}
	if o.Memory == "" && c.HostConfig.Memory > 0 {
		o.Memory = strconv.FormatInt(c.HostConfig.Memory, 10)
	}
	if o.PidsLimit == 0 && c.HostConfig.PidsLimit != nil && *c.HostConfig.PidsLimit > 0 {
		o.PidsLimit = int(*c.HostConfig.PidsLimit)
	}
	if o.CPUs == "" && c.HostConfig.NanoCpus > 0 {
		o.CPUs = strconv.FormatFloat(float64(c.HostConfig.NanoCpus)/1e9, 'f', -1, 64)
	}
	if o.Disk == "" {
		o.Disk = tmpfsSize(c.HostConfig.Tmpfs[config.SandboxDir])
	}
	return o
}

// tmpfsSize returns the size= value of tmpfs mount options, or "".
func tmpfsSize(options string) string {
	for _, o := range strings.Split(options, ",") {
		if v, ok := strings.CutPrefix(o, "size="); ok {
			return v
		}
	}
	return ""
}

// validate checks the limits that docker would not refuse itself.
func (o SandboxOptions) validate() error {
	if o.PidsLimit < 0 {
		return fmt.Errorf("invalid pids limit %d", o.PidsLimit)
	}
	if o.Disk != "" {
		if _, err := diskBytes(o.Disk); err != nil {
			return err
		}
	}
	return nil
}

// diskBytes parses a /sandbox size. Zero is refused: a tmpfs of size 0 has
// no limit at all.
func diskBytes(s string) (int64, error) {
	n, err := ParseSize(s)
	if err != nil {
		return 0, fmt.Errorf("disk: %w", err)
	}
	if n == 0 {
		return 0, fmt.Errorf("invalid disk size %q: must be more than 0", s)
	}
	return n, nil
}

// volumes returns the bind mounts to give the sandbox.
func (o SandboxOptions) volumes() []string {
	if len(o.Volumes) > 0 {
		return o.Volumes
	}
	return o.kept
}

func (o SandboxOptions) withDefaults() SandboxOptions {
	if o.Memory == "" {
		o.Memory = DefaultSandboxMemory
	}
	if o.PidsLimit == 0 {
		o.PidsLimit = DefaultSandboxPidsLimit
	}
	if o.CPUs == "" {
		o.CPUs = DefaultSandboxCPUs
	}
	if o.Disk == "" {
		o.Disk = DefaultSandboxDisk
	}
	return o
}

func wrongType(name string, err error) error {
	return fmt.Errorf("session %q %w", name, err)
}

// EnsureSandbox creates or starts a headless sandbox container. Unlike
// Ensure it writes no secrets or git config, starts no ttyd, tmux or Claude
// Code, publishes no port, and runs the container without a network as the
// unprivileged sandbox user. With opts.Remove it always creates a new
// one-off sandbox that docker removes when it stops.
func (m *Manager) EnsureSandbox(ctx context.Context, opts SandboxOptions) (*Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if opts.Name == "" && !opts.Remove {
		return nil, ErrSandboxName
	}
	if err := opts.validate(); err != nil {
		return nil, err
	}
	if opts.Remove {
		want, _, err := m.pickVariant(opts.Variant, config.TypeSandbox, nil)
		if err != nil {
			return nil, err
		}
		if err := m.checkImage(ctx, want); err != nil {
			return nil, err
		}
		opts.Variant = want
		name, err := m.pickName(ctx, opts.Name)
		if err != nil {
			return nil, err
		}
		container := config.ContainerName(name)
		m.printf("Creating one-off sandbox: %s\n", container)
		if err := m.createSandbox(ctx, container, opts); err != nil {
			return nil, err
		}
		m.printf("\nSandbox is ready: %s\n", container)
		m.printf("Run commands with: safeclaw sandbox exec %s -- <command>\n", name)
		m.printf("It is removed when stopped: safeclaw sandbox stop %s\n", name)
		return &Result{Name: name, Container: container}, nil
	}

	name := config.SessionName(opts.Name)
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	container := config.ContainerName(name)

	existing, err := m.Docker.InspectOne(ctx, container)
	if err != nil {
		return nil, err
	}
	if existing != nil && TypeOf(*existing) != config.TypeSandbox {
		return nil, wrongType(name, ErrNotSandbox)
	}

	want, changed, err := m.pickVariant(opts.Variant, config.TypeSandbox, existing)
	if err != nil {
		return nil, err
	}
	if err := m.checkImage(ctx, want); err != nil {
		return nil, err
	}
	opts.Variant = want

	if existing != nil && (len(opts.Volumes) > 0 || opts.Recreate || changed) {
		m.printf("Recreating sandbox: %s\n", container)
		opts = opts.keep(*existing)
		if err := m.Docker.Remove(ctx, container, true); err != nil {
			return nil, err
		}
		existing = nil
	}

	switch {
	case existing != nil && existing.State.Running:
		m.printf("Sandbox already running: %s\n", container)
	case existing != nil:
		m.printf("Starting existing sandbox: %s\n", container)
		if err := m.Docker.Start(ctx, container); err != nil {
			return nil, err
		}
	default:
		m.printf("Creating sandbox: %s\n", container)
		if err := m.createSandbox(ctx, container, opts); err != nil {
			return nil, err
		}
	}

	m.printf("\nSandbox is ready: %s\n", container)
	m.printf("Run commands with: safeclaw sandbox exec %s -- <command>\n", name)
	m.printf("To remove: safeclaw sandbox rm -f %s\n", name)
	return &Result{Name: name, Container: container}, nil
}

// pickName returns the session name for a new one-off sandbox. A given name
// must be valid and not taken by any container. Without one, a random name
// is picked.
func (m *Manager) pickName(ctx context.Context, name string) (string, error) {
	if name != "" {
		name = config.SessionName(name)
		if err := ValidateName(name); err != nil {
			return "", err
		}
		c, err := m.Docker.InspectOne(ctx, config.ContainerName(name))
		if err != nil {
			return "", err
		}
		if c != nil {
			return "", fmt.Errorf("session %q %w", name, ErrExists)
		}
		return name, nil
	}
	for range 5 {
		name := randomName()
		c, err := m.Docker.InspectOne(ctx, config.ContainerName(name))
		if err != nil {
			return "", err
		}
		if c == nil {
			return name, nil
		}
	}
	return "", errors.New("could not pick an unused sandbox name")
}

// PrepareEphemeral checks that a one-off sandbox can run cmd and returns the
// `docker run --rm` argv that runs it in the foreground, along with the
// sandbox name. The caller runs the argv, so docker removes the container
// when cmd exits even if the caller is killed. It prints nothing: stdout
// belongs to cmd. If the name is taken between this check and `docker run`,
// docker refuses the name itself.
func (m *Manager) PrepareEphemeral(ctx context.Context, opts SandboxOptions, exec ExecOptions, cmd []string) ([]string, string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if len(cmd) == 0 {
		return nil, "", ErrNoCommand
	}
	if err := opts.validate(); err != nil {
		return nil, "", err
	}
	if err := exec.Validate(); err != nil {
		return nil, "", err
	}
	want, _, err := m.pickVariant(opts.Variant, config.TypeSandbox, nil)
	if err != nil {
		return nil, "", err
	}
	if err := m.checkImage(ctx, want); err != nil {
		return nil, "", err
	}
	opts.Variant = want
	name, err := m.pickName(ctx, opts.Name)
	if err != nil {
		return nil, "", err
	}
	args, err := EphemeralRunArgs(config.ContainerName(name), opts, exec, cmd)
	if err != nil {
		return nil, "", err
	}
	return append([]string{"docker", "run"}, args...), name, nil
}

// SandboxRunArgs returns the `docker run` arguments for a detached sandbox
// container.
func SandboxRunArgs(container string, opts SandboxOptions) ([]string, error) {
	args := []string{"-d"}
	if opts.Remove {
		args = append(args, "--rm")
	}
	shared, err := sandboxArgs(container, opts)
	if err != nil {
		return nil, err
	}
	args = append(args, shared...)
	return append(args, variant.Image(opts.Variant), "sleep", "infinity"), nil
}

// EphemeralRunArgs returns the `docker run` arguments that run cmd in a
// one-off sandbox in the foreground. --init forwards signals to cmd, which
// would otherwise run as PID 1 and ignore them. cmd is wrapped with
// ExecOptions.command so it gets the same umask and timeout as
// `sandbox exec NAME`.
func EphemeralRunArgs(container string, opts SandboxOptions, exec ExecOptions, cmd []string) ([]string, error) {
	args := append([]string{"--rm", "--init"}, exec.flags()...)
	shared, err := sandboxArgs(container, opts)
	if err != nil {
		return nil, err
	}
	args = append(args, shared...)
	args = append(args, variant.Image(opts.Variant))
	return append(args, exec.command(cmd)...), nil
}

// sandboxArgs returns the `docker run` flags every sandbox gets: its name,
// label, isolation, limits, and optional read-only volume. /sandbox is a
// tmpfs of opts.Disk bytes owned by the sandbox user, since docker volumes
// can't be size-limited on most storage drivers. The container keeps no
// log, whatever the daemon's default driver: any sandbox process can write
// to PID 1's stdout through /proc/1/fd/1, and a log would keep those bytes
// on the docker host's disk outside every limit. Nothing reads a sandbox's
// log, since a one-off sandbox's output reaches the caller attached.
func sandboxArgs(container string, opts SandboxOptions) ([]string, error) {
	opts = opts.withDefaults()
	disk, err := diskBytes(opts.Disk)
	if err != nil {
		return nil, err
	}
	args := []string{
		"--name", container,
		"--label", config.LabelType + "=" + config.TypeSandbox,
	}
	args = append(args, variantArgs(opts.Variant)...)
	args = append(args,
		"--network", "none",
		"--user", config.SandboxUser,
		"--workdir", config.SandboxDir,
		"--env", "HOME="+config.SandboxDir,
		"--env", "BASH_ENV=",
		"--env", "PATH="+sandboxPath,
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--log-driver", sandboxLogDriver,
		"--read-only",
		"--tmpfs", sandboxTmpfs,
		"--tmpfs", fmt.Sprintf("%s:%s,size=%d,uid=%d,gid=%d,mode=0700", config.SandboxDir, sandboxDirOptions, disk, sandboxUID, sandboxUID),
		"--memory", opts.Memory,
		"--pids-limit", strconv.Itoa(opts.PidsLimit),
		"--cpus", opts.CPUs,
	)
	// Docker refuses two mounts at one path itself, but with a less
	// helpful error, after the image checks.
	seen := map[string]string{"/tmp": "the /tmp tmpfs", config.SandboxDir: "the " + config.SandboxDir + " tmpfs"}
	for _, volume := range opts.volumes() {
		v, err := ReadOnlyVolume(volume)
		if err != nil {
			return nil, err
		}
		dst := path.Clean(volumeDestination(v))
		if other, ok := seen[dst]; ok {
			return nil, fmt.Errorf("volume %q: %s is already used by %s", volume, dst, other)
		}
		seen[dst] = fmt.Sprintf("volume %q", volume)
		args = append(args, "-v", v)
	}
	return args, nil
}

// volumeDestination returns the container path of a host:container[:options]
// spec.
func volumeDestination(v string) string {
	_, rest, _ := strings.Cut(v, ":")
	dst, _, _ := strings.Cut(rest, ":")
	return dst
}

func (m *Manager) createSandbox(ctx context.Context, container string, opts SandboxOptions) error {
	args, err := SandboxRunArgs(container, opts)
	if err != nil {
		return err
	}
	for _, volume := range opts.volumes() {
		v, _ := ReadOnlyVolume(volume)
		m.printf("Mounting volume read-only: %s\n", v)
	}
	_, err = m.Docker.Run(ctx, args...)
	return err
}

// ReadOnlyVolume expands a host:container[:options] volume spec like
// ExpandVolume and forces it read-only.
func ReadOnlyVolume(v string) (string, error) {
	v, err := ExpandVolume(v)
	if err != nil {
		return "", err
	}
	host, rest, _ := strings.Cut(v, ":")
	dst, optStr, _ := strings.Cut(rest, ":")
	if dst == "" {
		return "", fmt.Errorf("invalid volume %q: expected /host/path:/container/path", v)
	}
	opts := []string{"ro"}
	if optStr != "" {
		for _, o := range strings.Split(optStr, ",") {
			if o != "" && o != "ro" && o != "rw" {
				opts = append(opts, o)
			}
		}
	}
	return host + ":" + dst + ":" + strings.Join(opts, ","), nil
}

// Get returns one session, or an error wrapping ErrNotFound.
func (m *Manager) Get(ctx context.Context, name string) (*Session, error) {
	name = config.SessionName(name)
	c, err := m.Docker.InspectOne(ctx, config.ContainerName(name))
	if err != nil {
		return nil, err
	}
	if c == nil {
		return nil, fmt.Errorf("session %q %w", name, ErrNotFound)
	}
	return &Session{
		Container:  c.ShortName(),
		Name:       name,
		Active:     c.State.Running,
		Status:     c.State.Status,
		Type:       TypeOf(*c),
		Variant:    variantOf(*c),
		AutoRemove: c.HostConfig.AutoRemove,
		Secrets:    sessionSecrets(*c),
		Network:    NetworkStatus(*c),
		Holds:      m.holdsFor(name, *c),
	}, nil
}

// RequireType returns an error unless the named session exists and has the
// wanted type (config.TypeSession or config.TypeSandbox).
func (m *Manager) RequireType(ctx context.Context, name, want string) error {
	s, err := m.Get(ctx, name)
	if err != nil {
		return err
	}
	switch {
	case s.Type == want:
		return nil
	case s.IsSandbox():
		return wrongType(s.Name, ErrIsSandbox)
	default:
		return wrongType(s.Name, ErrNotSandbox)
	}
}
