package session

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/josegonzalez/safeclaw/internal/config"
)

// Sandbox resource limit defaults.
const (
	DefaultSandboxMemory    = "1g"
	DefaultSandboxPidsLimit = 256
	DefaultSandboxCPUs      = "1"
	// sandboxTmpfs bounds the scratch space under /tmp.
	sandboxTmpfs = "/tmp:rw,nosuid,nodev,size=256m"
	// sandboxPath leaves out sclaw's ~/.local/bin, which the sandbox user
	// cannot read anyway.
	sandboxPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

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

// SandboxOptions configures EnsureSandbox.
type SandboxOptions struct {
	// Name is the sandbox name. It is required.
	Name string
	// Volume is an optional host:container bind mount, always mounted
	// read-only. Setting it recreates an existing sandbox.
	Volume string
	// Memory is docker's --memory value.
	Memory string
	// PidsLimit is docker's --pids-limit value.
	PidsLimit int
	// CPUs is docker's --cpus value.
	CPUs string
	// Recreate removes an existing sandbox first, e.g. because its limits
	// changed.
	Recreate bool
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
	return o
}

func wrongType(name string, err error) error {
	return fmt.Errorf("session %q %w", name, err)
}

// EnsureSandbox creates or starts a headless sandbox container. Unlike
// Ensure it writes no secrets or git config, starts no ttyd, tmux or Claude
// Code, publishes no port, and runs the container without a network as the
// unprivileged sandbox user.
func (m *Manager) EnsureSandbox(ctx context.Context, opts SandboxOptions) (*Result, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if opts.Name == "" {
		return nil, ErrSandboxName
	}
	name := config.SessionName(opts.Name)
	if err := ValidateName(name); err != nil {
		return nil, err
	}
	if opts.PidsLimit < 0 {
		return nil, fmt.Errorf("invalid pids limit %d", opts.PidsLimit)
	}
	opts = opts.withDefaults()
	container := config.ContainerName(name)

	imageID, err := m.Docker.ImageID(ctx, config.ImageName)
	if err != nil {
		return nil, err
	}
	if imageID == "" {
		return nil, ErrNoImage
	}

	existing, err := m.Docker.InspectOne(ctx, container)
	if err != nil {
		return nil, err
	}
	if existing != nil && TypeOf(*existing) != config.TypeSandbox {
		return nil, wrongType(name, ErrNotSandbox)
	}

	if existing != nil && (opts.Volume != "" || opts.Recreate) {
		m.printf("Recreating sandbox: %s\n", container)
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

// SandboxRunArgs returns the `docker run` arguments for a sandbox container.
func SandboxRunArgs(container string, opts SandboxOptions) ([]string, error) {
	opts = opts.withDefaults()
	args := []string{
		"-d",
		"--name", container,
		"--label", config.LabelType + "=" + config.TypeSandbox,
		"--network", "none",
		"--user", config.SandboxUser,
		"--workdir", config.SandboxDir,
		"--env", "HOME=" + config.SandboxDir,
		"--env", "BASH_ENV=",
		"--env", "PATH=" + sandboxPath,
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--read-only",
		"--tmpfs", sandboxTmpfs,
		"-v", config.SandboxDir,
		"--memory", opts.Memory,
		"--pids-limit", strconv.Itoa(opts.PidsLimit),
		"--cpus", opts.CPUs,
	}
	if opts.Volume != "" {
		v, err := ReadOnlyVolume(opts.Volume)
		if err != nil {
			return nil, err
		}
		args = append(args, "-v", v)
	}
	return append(args, config.ImageName, "sleep", "infinity"), nil
}

func (m *Manager) createSandbox(ctx context.Context, container string, opts SandboxOptions) error {
	args, err := SandboxRunArgs(container, opts)
	if err != nil {
		return err
	}
	if opts.Volume != "" {
		v, _ := ReadOnlyVolume(opts.Volume)
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
		Container: c.ShortName(),
		Name:      name,
		Active:    c.State.Running,
		Status:    c.State.Status,
		Type:      TypeOf(*c),
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
