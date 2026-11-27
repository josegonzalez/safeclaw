package session

import (
	"context"
	"fmt"
	"path"
	"slices"
	"sort"
	"strconv"
	"strings"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/secrets"
)

// SandboxSchema is the version of the SandboxInfo and SandboxReport JSON.
// Fields are only ever added within a version; renaming or removing one, or
// changing its meaning, bumps it.
const SandboxSchema = 1

// sandboxTmpDir is the sandbox's scratch tmpfs.
const sandboxTmpDir = "/tmp"

// sandboxLogDriver is every sandbox's logging driver, so nothing a sandbox
// writes to its main stdout or stderr is kept on the docker host.
const sandboxLogDriver = "none"

// SandboxInfo is what `safeclaw sandbox inspect` prints: a sandbox's
// isolation settings as docker reports them. Lists are never null.
type SandboxInfo struct {
	Schema    int    `json:"schema"`
	Name      string `json:"name"`
	Container string `json:"container"`
	ID        string `json:"id"`
	// Status is docker's container status, e.g. "running" or "exited".
	Status  string `json:"status"`
	Running bool   `json:"running"`
	// OneOff is set for sandboxes that docker removes when they stop.
	OneOff bool `json:"one_off"`
	// Variant is the image variant, config.BaseVariant for the base image.
	Variant string `json:"variant"`
	// Image is the image name the sandbox was created from, ImageID its ID.
	Image   string `json:"image"`
	ImageID string `json:"image_id"`
	// NetworkMode is docker's network mode, "none" for every sandbox, and
	// Networks are the networks it is attached to.
	NetworkMode string   `json:"network_mode"`
	Networks    []string `json:"networks"`
	// User is the user the container runs as.
	User            string   `json:"user"`
	ReadOnlyRoot    bool     `json:"read_only_root"`
	Privileged      bool     `json:"privileged"`
	CapDrop         []string `json:"cap_drop"`
	CapAdd          []string `json:"cap_add"`
	NoNewPrivileges bool     `json:"no_new_privileges"`
	// IPCMode and PIDMode are docker's IPC and PID namespace modes.
	IPCMode string `json:"ipc_mode"`
	PIDMode string `json:"pid_mode"`
	// LogDriver is docker's logging driver, "none" for every sandbox.
	LogDriver string        `json:"log_driver"`
	Limits    SandboxLimits `json:"limits"`
	// Tmpfs are the tmpfs mounts, sorted by path.
	Tmpfs []SandboxTmpfs `json:"tmpfs"`
	// Mounts are the bind mounts and volumes, in docker's order.
	Mounts []SandboxMount `json:"mounts"`
	// Labels are the container's safeclaw.* labels.
	Labels map[string]string `json:"labels"`
}

// SandboxLimits are a sandbox's resource limits, 0 for none.
type SandboxLimits struct {
	MemoryBytes int64   `json:"memory_bytes"`
	CPUs        float64 `json:"cpus"`
	Pids        int64   `json:"pids"`
	// DiskBytes is the size of the /sandbox tmpfs.
	DiskBytes int64 `json:"disk_bytes"`
}

// SandboxTmpfs is one tmpfs mount.
type SandboxTmpfs struct {
	Path    string `json:"path"`
	Options string `json:"options"`
	// SizeBytes is its size= option, 0 when it has none.
	SizeBytes int64 `json:"size_bytes"`
}

// SandboxMount is one bind mount or volume.
type SandboxMount struct {
	Type        string `json:"type"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	ReadOnly    bool   `json:"read_only"`
	// RecursiveReadOnly is set for a read-only bind made with
	// bind-recursive=readonly, whose submounts docker makes read-only too
	// or refuses to create.
	RecursiveReadOnly bool `json:"recursive_read_only"`
}

// getSandbox returns the named sandbox's inspect data, or an error wrapping
// ErrNotFound or ErrNotSandbox.
func (m *Manager) getSandbox(ctx context.Context, name string) (string, *docker.Container, error) {
	name = config.SessionName(name)
	c, err := m.Docker.InspectOne(ctx, config.ContainerName(name))
	if err != nil {
		return "", nil, err
	}
	if c == nil {
		return "", nil, fmt.Errorf("session %q %w", name, ErrNotFound)
	}
	if TypeOf(*c) != config.TypeSandbox {
		return "", nil, wrongType(name, ErrNotSandbox)
	}
	return name, c, nil
}

// InspectSandbox returns the named sandbox's isolation settings. It changes
// nothing and runs nothing in the sandbox.
func (m *Manager) InspectSandbox(ctx context.Context, name string) (*SandboxInfo, error) {
	name, c, err := m.getSandbox(ctx, name)
	if err != nil {
		return nil, err
	}
	info := sandboxInfo(name, *c)
	return &info, nil
}

func sandboxInfo(name string, c docker.Container) SandboxInfo {
	h := c.HostConfig
	info := SandboxInfo{
		Schema:          SandboxSchema,
		Name:            name,
		Container:       c.ShortName(),
		ID:              c.ID,
		Status:          c.State.Status,
		Running:         c.State.Running,
		OneOff:          h.AutoRemove,
		Variant:         variantOf(c),
		Image:           c.Config.Image,
		ImageID:         c.Image,
		NetworkMode:     h.NetworkMode,
		Networks:        []string{},
		User:            c.Config.User,
		ReadOnlyRoot:    h.ReadonlyRootfs,
		Privileged:      h.Privileged,
		CapDrop:         nonNil(h.CapDrop),
		CapAdd:          nonNil(h.CapAdd),
		NoNewPrivileges: noNewPrivileges(h.SecurityOpt),
		IPCMode:         h.IpcMode,
		PIDMode:         h.PidMode,
		LogDriver:       h.LogConfig.Type,
		Limits: SandboxLimits{
			MemoryBytes: h.Memory,
			CPUs:        float64(h.NanoCpus) / 1e9,
		},
		Tmpfs:  []SandboxTmpfs{},
		Mounts: []SandboxMount{},
		Labels: map[string]string{},
	}
	if info.Variant == "" {
		info.Variant = config.BaseVariant
	}
	if h.PidsLimit != nil && *h.PidsLimit > 0 {
		info.Limits.Pids = *h.PidsLimit
	}
	for n := range c.NetworkSettings.Networks {
		info.Networks = append(info.Networks, n)
	}
	sort.Strings(info.Networks)
	for path, opts := range h.Tmpfs {
		size, _ := ParseSize(tmpfsSize(opts))
		info.Tmpfs = append(info.Tmpfs, SandboxTmpfs{Path: path, Options: opts, SizeBytes: size})
		if path == config.SandboxDir {
			info.Limits.DiskBytes = size
		}
	}
	sort.Slice(info.Tmpfs, func(i, j int) bool { return info.Tmpfs[i].Path < info.Tmpfs[j].Path })
	for _, mt := range c.Mounts {
		info.Mounts = append(info.Mounts, SandboxMount{Type: mt.Type, Source: mt.Source, Destination: mt.Destination, ReadOnly: !mt.RW,
			RecursiveReadOnly: !mt.RW && forcedRecursive(h.Mounts, mt.Destination)})
	}
	for k, v := range c.Config.Labels {
		if strings.HasPrefix(k, config.LabelPrefix) {
			info.Labels[k] = v
		}
	}
	return info
}

// forcedRecursive reports whether the --mount bind at dst was made with
// bind-recursive=readonly.
func forcedRecursive(mounts []docker.HostMount, dst string) bool {
	for _, hm := range mounts {
		if hm.Type == "bind" && path.Clean(hm.Target) == dst {
			return hm.ReadOnly && hm.BindOptions != nil && hm.BindOptions.ReadOnlyForceRecursive
		}
	}
	return false
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// noNewPrivileges reports whether docker's security options turn on
// no-new-privileges.
func noNewPrivileges(opts []string) bool {
	for _, o := range opts {
		switch o {
		case "no-new-privileges", "no-new-privileges:true", "no-new-privileges=true":
			return true
		}
	}
	return false
}

// SandboxCheck is the result of one `safeclaw sandbox verify` check.
type SandboxCheck struct {
	// Name is the check's stable name, e.g. "network" or "live-user".
	Name string `json:"name"`
	OK   bool   `json:"ok"`
	// Skipped is set for live checks of a sandbox that is not running.
	// They are not OK.
	Skipped bool `json:"skipped,omitempty"`
	// Detail says what was found.
	Detail string `json:"detail"`
}

// SandboxReport is what `safeclaw sandbox verify --json` prints.
type SandboxReport struct {
	Schema    int    `json:"schema"`
	Name      string `json:"name"`
	Container string `json:"container"`
	// OK is set when every check passed.
	OK     bool           `json:"ok"`
	Checks []SandboxCheck `json:"checks"`
}

// Failed returns the names of the checks that ran and did not pass.
func (r SandboxReport) Failed() []string {
	var out []string
	for _, c := range r.Checks {
		if !c.OK && !c.Skipped {
			out = append(out, c.Name)
		}
	}
	return out
}

// Skipped returns the names of the checks that could not run.
func (r SandboxReport) Skipped() []string {
	var out []string
	for _, c := range r.Checks {
		if c.Skipped {
			out = append(out, c.Name)
		}
	}
	return out
}

// sandboxProbe prints what the live checks need, from inside the sandbox as
// the sandbox user: its uid, whether /home/sclaw can be read or entered, the
// network interfaces, and the kernel's view of its own process and mounts.
// It only reads.
const sandboxProbe = `echo "uid=$(id -u)"
if [ -r /home/sclaw ] || [ -x /home/sclaw ]; then echo home=readable; else echo home=denied; fi
for i in /sys/class/net/*; do echo "net=${i##*/}"; done
echo ---status
cat /proc/self/status
echo ---mounts
cat /proc/self/mounts`

// VerifySandbox checks the named sandbox against the isolation sandboxes
// promise, first from its docker configuration and then, when it is
// running, from inside it as the sandbox user. It changes nothing: the live
// checks only read. A failed check is reported in the result, not as an
// error.
func (m *Manager) VerifySandbox(ctx context.Context, name string) (*SandboxReport, error) {
	name, c, err := m.getSandbox(ctx, name)
	if err != nil {
		return nil, err
	}
	info := sandboxInfo(name, *c)
	checks := staticChecks(info, *c, m.secretNames())
	live := liveCheckNames
	if !c.State.Running {
		checks = append(checks, SandboxCheck{Name: "running", Detail: fmt.Sprintf("status %q", c.State.Status)})
		for _, n := range live {
			checks = append(checks, SandboxCheck{Name: n, Skipped: true, Detail: "sandbox is not running"})
		}
	} else {
		checks = append(checks, SandboxCheck{Name: "running", OK: true, Detail: "status \"running\""})
		out, err := m.Docker.Exec(ctx, c.ShortName(), docker.ExecOptions{User: config.SandboxUser}, "/bin/sh", "-c", sandboxProbe)
		if err != nil {
			for _, n := range live {
				checks = append(checks, SandboxCheck{Name: n, Detail: "probe failed: " + err.Error()})
			}
		} else {
			checks = append(checks, liveChecks(info, parseProbe(string(out)))...)
		}
	}
	r := &SandboxReport{Schema: SandboxSchema, Name: name, Container: info.Container, Checks: checks}
	r.OK = len(r.Failed()) == 0 && len(r.Skipped()) == 0
	return r, nil
}

// secretNames returns the names a secret could be passed to a container
// under: the stored secrets and the tokens sessions get. A store that can't
// be listed gives nil, which fails the no-secrets check.
func (m *Manager) secretNames() map[string]bool {
	names, _ := m.secretNameSet()
	return names
}

// secretNameSet returns the names a secret could be passed to a container
// under, or the error listing the stored secrets gave.
func (m *Manager) secretNameSet() (map[string]bool, error) {
	keys, err := m.Secrets.Keys()
	if err != nil {
		return nil, err
	}
	names := map[string]bool{secrets.ClaudeToken: true, secrets.GitHubToken: true}
	for _, k := range keys {
		names[k] = true
	}
	return names, nil
}

func check(name string, ok bool, format string, args ...any) SandboxCheck {
	return SandboxCheck{Name: name, OK: ok, Detail: fmt.Sprintf(format, args...)}
}

// staticChecks checks a sandbox's docker configuration.
func staticChecks(info SandboxInfo, c docker.Container, secretNames map[string]bool) []SandboxCheck {
	var checks []SandboxCheck

	attached := slices.DeleteFunc(slices.Clone(info.Networks), func(n string) bool { return n == "none" })
	checks = append(checks, check("network", info.NetworkMode == "none" && len(attached) == 0,
		"network mode %q, attached to %q", info.NetworkMode, attached))

	checks = append(checks, check("user", info.User == config.SandboxUser, "user %q", info.User))

	dropAll := slices.ContainsFunc(info.CapDrop, func(c string) bool { return strings.EqualFold(c, "ALL") })
	checks = append(checks, check("capabilities", dropAll && len(info.CapAdd) == 0 && !info.Privileged,
		"cap-drop %q, cap-add %q, privileged %t", info.CapDrop, info.CapAdd, info.Privileged))

	checks = append(checks, check("no-new-privileges", info.NoNewPrivileges, "security options %q", nonNil(c.HostConfig.SecurityOpt)))

	checks = append(checks, check("read-only-root", info.ReadOnlyRoot, "read-only root %t", info.ReadOnlyRoot))

	// A bind must also be forced recursively read-only: a plain :ro bind
	// leaves submounts writable where docker can't make them read-only.
	var writable, notRecursive []string
	for _, mt := range info.Mounts {
		switch {
		case !mt.ReadOnly:
			writable = append(writable, mt.Destination)
		case mt.Type == "bind" && !mt.RecursiveReadOnly:
			notRecursive = append(notRecursive, mt.Destination)
		}
	}
	checks = append(checks, check("mounts-read-only", len(writable) == 0 && len(notRecursive) == 0,
		"%d mounts, writable: %q, not recursively read-only: %q", len(info.Mounts), nonNil(writable), nonNil(notRecursive)))

	if secretNames == nil {
		checks = append(checks, check("no-secrets", false, "could not list the stored secrets"))
	} else {
		var found []string
		for _, e := range c.Config.Env {
			n, _, _ := strings.Cut(e, "=")
			if secretNames[n] {
				found = append(found, n)
			}
		}
		checks = append(checks, check("no-secrets", len(found) == 0, "secret env vars: %q", nonNil(found)))
	}

	checks = append(checks, check("namespaces", info.IPCMode != "host" && info.PIDMode != "host",
		"ipc mode %q, pid mode %q", info.IPCMode, info.PIDMode))

	checks = append(checks, check("limits", info.Limits.MemoryBytes > 0 && info.Limits.CPUs > 0 && info.Limits.Pids > 0,
		"memory %d bytes, %g cpus, %d pids", info.Limits.MemoryBytes, info.Limits.CPUs, info.Limits.Pids))

	checks = append(checks, check("logs", info.LogDriver == sandboxLogDriver, "log driver %q", info.LogDriver))

	disk := c.HostConfig.Tmpfs[config.SandboxDir]
	owned := hasOption(disk, "uid="+strconv.Itoa(sandboxUID)) && hasOption(disk, "mode=0700")
	checks = append(checks, check("disk", info.Limits.DiskBytes > 0 && owned,
		"%s tmpfs %q", config.SandboxDir, disk))

	tmp, ok := c.HostConfig.Tmpfs[sandboxTmpDir]
	tmpSize, _ := ParseSize(tmpfsSize(tmp))
	checks = append(checks, check("tmp", ok && tmpSize > 0, "%s tmpfs %q", sandboxTmpDir, tmp))
	return checks
}

func hasOption(options, want string) bool {
	return slices.Contains(strings.Split(options, ","), want)
}

// liveCheckNames are the checks run inside a running sandbox, in order.
var liveCheckNames = []string{"live-user", "live-home", "live-network", "live-capabilities", "live-read-only-root", "live-mounts", "live-disk"}

// probe is the parsed output of sandboxProbe.
type probe struct {
	values map[string][]string
	status map[string]string
	// mounts maps each mount point to the options of its topmost mount.
	mounts map[string]mountEntry
}

type mountEntry struct {
	fstype  string
	options string
}

func parseProbe(out string) probe {
	p := probe{values: map[string][]string{}, status: map[string]string{}, mounts: map[string]mountEntry{}}
	section := ""
	for _, line := range strings.Split(out, "\n") {
		switch line {
		case "---status", "---mounts":
			section = line
			continue
		}
		switch section {
		case "":
			if k, v, ok := strings.Cut(line, "="); ok {
				p.values[k] = append(p.values[k], v)
			}
		case "---status":
			if k, v, ok := strings.Cut(line, ":"); ok {
				p.status[k] = strings.TrimSpace(v)
			}
		case "---mounts":
			f := strings.Fields(line)
			if len(f) >= 4 {
				p.mounts[unescapeMount(f[1])] = mountEntry{fstype: f[2], options: f[3]}
			}
		}
	}
	return p
}

// below returns the mount points strictly below dir, sorted.
func (p probe) below(dir string) []string {
	prefix := strings.TrimSuffix(dir, "/") + "/"
	var out []string
	for point := range p.mounts {
		if strings.HasPrefix(point, prefix) {
			out = append(out, point)
		}
	}
	sort.Strings(out)
	return out
}

// unescapeMount undoes the octal escapes /proc/self/mounts uses for spaces,
// tabs, newlines, and backslashes in paths.
func unescapeMount(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+3 < len(s) {
			if n, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

// liveChecks checks what the sandbox user sees inside a running sandbox.
func liveChecks(info SandboxInfo, p probe) []SandboxCheck {
	var checks []SandboxCheck

	uid := p.values["uid"]
	checks = append(checks, check("live-user", len(uid) == 1 && uid[0] == strconv.Itoa(sandboxUID), "uid %q", uid))

	home := p.values["home"]
	checks = append(checks, check("live-home", len(home) == 1 && home[0] == "denied", "/home/sclaw %q", home))

	nets := p.values["net"]
	checks = append(checks, check("live-network", len(nets) == 1 && nets[0] == "lo", "interfaces %q", nets))

	var caps []string
	capsOK := p.status["NoNewPrivs"] == "1"
	for _, k := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		v, ok := p.status[k]
		n, err := strconv.ParseUint(v, 16, 64)
		capsOK = capsOK && ok && err == nil && n == 0
		caps = append(caps, k+"="+v)
	}
	checks = append(checks, check("live-capabilities", capsOK, "%s NoNewPrivs=%s", strings.Join(caps, " "), p.status["NoNewPrivs"]))

	root, ok := p.mounts["/"]
	// Only the first option, ro or rw, is shown: an overlay root's options
	// list every layer.
	rootMode, _, _ := strings.Cut(root.options, ",")
	checks = append(checks, check("live-read-only-root", ok && hasOption(root.options, "ro"), "/ mounted %q", rootMode))

	// Every filesystem mounted below a mount must be read-only too: a
	// writable submount is as writable as the mount itself would be.
	var bad []string
	submounts := 0
	for _, mt := range info.Mounts {
		e, ok := p.mounts[mt.Destination]
		if !ok || !hasOption(e.options, "ro") {
			bad = append(bad, mt.Destination)
		}
		for _, point := range p.below(mt.Destination) {
			submounts++
			if !hasOption(p.mounts[point].options, "ro") {
				bad = append(bad, point)
			}
		}
	}
	checks = append(checks, check("live-mounts", len(bad) == 0, "%d mounts, %d submounts, missing or writable: %q",
		len(info.Mounts), submounts, nonNil(bad)))

	disk, ok := p.mounts[config.SandboxDir]
	size, _ := ParseSize(tmpfsSize(disk.options))
	// The kernel rounds a tmpfs size up to whole pages, at most 64 KiB.
	limit := (info.Limits.DiskBytes + 64<<10 - 1) &^ (64<<10 - 1)
	checks = append(checks, check("live-disk", ok && disk.fstype == "tmpfs" && size > 0 && size <= limit,
		"%s %s %q", config.SandboxDir, disk.fstype, disk.options))
	return checks
}
