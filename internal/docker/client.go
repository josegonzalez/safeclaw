package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"slices"
	"strconv"
	"strings"
)

// Client offers the docker operations safeclaw needs on top of a Runner.
type Client struct {
	R Runner
	// Warnf reports a problem that does not fail the operation, such as a
	// container List leaves out. Nil logs it with the log package.
	Warnf func(format string, args ...any)
}

func (c *Client) warnf(format string, args ...any) {
	if c.Warnf != nil {
		c.Warnf(format, args...)
		return
	}
	log.Printf(format, args...)
}

// New returns a Client backed by the real docker CLI.
func New() *Client {
	return &Client{R: ExecRunner{}}
}

// Mount is a container mount.
type Mount struct {
	Type        string `json:"Type"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	RW          bool   `json:"RW"`
}

// HostMount is a mount as it was requested with `docker run --mount`,
// from the container's HostConfig. Mounts given with -v are not listed.
type HostMount struct {
	Type     string `json:"Type"`
	Source   string `json:"Source"`
	Target   string `json:"Target"`
	ReadOnly bool   `json:"ReadOnly"`
	// BindOptions is set for bind mounts given bind options.
	BindOptions *BindOptions `json:"BindOptions"`
}

// BindOptions are a --mount bind's options.
type BindOptions struct {
	Propagation string `json:"Propagation"`
	// ReadOnlyForceRecursive is set by bind-recursive=readonly: docker
	// fails to create the container rather than leave a submount
	// writable.
	ReadOnlyForceRecursive bool `json:"ReadOnlyForceRecursive"`
}

// PortBinding is a host binding for a container port.
type PortBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

// IPAMConfig holds the static addresses an endpoint was given.
type IPAMConfig struct {
	IPv4Address string `json:"IPv4Address"`
	IPv6Address string `json:"IPv6Address"`
}

// Endpoint is a container's connection to one network.
type Endpoint struct {
	Aliases    []string    `json:"Aliases"`
	Links      []string    `json:"Links"`
	IPAMConfig *IPAMConfig `json:"IPAMConfig"`
	// NetworkID is the ID of the network, which a stopped container keeps
	// even after the network is removed.
	NetworkID string `json:"NetworkID"`
}

// Container is the subset of `docker inspect` output safeclaw uses.
type Container struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Image  string `json:"Image"`
	Config struct {
		Labels map[string]string `json:"Labels"`
		// Image is the image name the container was created from.
		Image string `json:"Image"`
		// User is the --user the container runs as, "" for the image's.
		User string `json:"User"`
		// Env are the container's NAME=value environment variables,
		// including the image's.
		Env []string `json:"Env"`
	} `json:"Config"`
	State struct {
		Status  string `json:"Status"`
		Running bool   `json:"Running"`
	} `json:"State"`
	HostConfig struct {
		PortBindings map[string][]PortBinding `json:"PortBindings"`
		// AutoRemove is set for containers created with `docker run --rm`.
		AutoRemove bool `json:"AutoRemove"`
		// Memory is the memory limit in bytes, 0 for none.
		Memory int64 `json:"Memory"`
		// NanoCpus is the CPU limit in billionths of a CPU, 0 for none.
		NanoCpus int64 `json:"NanoCpus"`
		// PidsLimit is the process limit, nil or 0 for none.
		PidsLimit *int64 `json:"PidsLimit"`
		// NetworkMode is the network the container was created with, e.g.
		// "bridge", "default", "host", "none", or "container:ID".
		NetworkMode string `json:"NetworkMode"`
		// IpcMode is the IPC namespace the container was created with, e.g.
		// "private", "shareable", or "host".
		IpcMode string `json:"IpcMode"`
		// Tmpfs maps each --tmpfs mount point to its options, e.g.
		// "rw,size=1073741824".
		Tmpfs map[string]string `json:"Tmpfs"`
		// CapDrop are the capabilities dropped with --cap-drop.
		CapDrop []string `json:"CapDrop"`
		// SecurityOpt are the --security-opt options, e.g.
		// "no-new-privileges".
		SecurityOpt []string `json:"SecurityOpt"`
		// CapAdd are the capabilities added with --cap-add.
		CapAdd []string `json:"CapAdd"`
		// Privileged is set for containers run with --privileged.
		Privileged bool `json:"Privileged"`
		// ReadonlyRootfs is set for containers run with --read-only.
		ReadonlyRootfs bool `json:"ReadonlyRootfs"`
		// Mounts are the mounts given with --mount.
		Mounts []HostMount `json:"Mounts"`
		// PidMode is the PID namespace, "" for the container's own or
		// "host".
		PidMode string `json:"PidMode"`
		// LogConfig is the logging driver, e.g. "json-file" or "none",
		// and its --log-opt options.
		LogConfig struct {
			Type   string            `json:"Type"`
			Config map[string]string `json:"Config"`
		} `json:"LogConfig"`
	} `json:"HostConfig"`
	NetworkSettings struct {
		// Networks are the networks the container is connected to, by name.
		Networks map[string]Endpoint `json:"Networks"`
	} `json:"NetworkSettings"`
	Mounts []Mount `json:"Mounts"`
}

// ShortName returns the container name without docker's leading slash.
func (c Container) ShortName() string {
	return strings.TrimPrefix(c.Name, "/")
}

// Label returns the value of a container label, or "".
func (c Container) Label(key string) string {
	return c.Config.Labels[key]
}

// LookupLabel returns the value of a container label and whether it is set,
// which tells an empty label apart from a missing one.
func (c Container) LookupLabel(key string) (string, bool) {
	v, ok := c.Config.Labels[key]
	return v, ok
}

// HostPort returns the host port bound to the given container port, or 0.
// It reads the configured bindings, so it works for stopped containers too.
func (c Container) HostPort(containerPort int) int {
	for _, b := range c.HostConfig.PortBindings[fmt.Sprintf("%d/tcp", containerPort)] {
		if p, err := strconv.Atoi(b.HostPort); err == nil && p > 0 {
			return p
		}
	}
	return 0
}

// HostIP returns the host address the given container port is published
// on, "" when it is not published or docker reports none.
func (c Container) HostIP(containerPort int) string {
	for _, b := range c.HostConfig.PortBindings[fmt.Sprintf("%d/tcp", containerPort)] {
		if p, err := strconv.Atoi(b.HostPort); err == nil && p > 0 {
			return b.HostIP
		}
	}
	return ""
}

// BindMounts returns "source:destination" for each bind mount, skipping any
// whose destination is in skip.
func (c Container) BindMounts(skip ...string) []string {
	var out []string
outer:
	for _, m := range c.Mounts {
		if m.Type != "bind" {
			continue
		}
		for _, s := range skip {
			if m.Destination == s {
				continue outer
			}
		}
		out = append(out, m.Source+":"+m.Destination)
	}
	return out
}

// BindSpecs returns each bind mount as a `docker run -v` spec,
// "source:destination", with ":ro" appended for read-only mounts, skipping
// any whose destination is in skip.
func (c Container) BindSpecs(skip ...string) []string {
	var out []string
outer:
	for _, m := range c.Mounts {
		if m.Type != "bind" {
			continue
		}
		for _, s := range skip {
			if m.Destination == s {
				continue outer
			}
		}
		spec := m.Source + ":" + m.Destination
		if !m.RW {
			spec += ":ro"
		}
		out = append(out, spec)
	}
	return out
}

// ImageID returns the ID of a local image, or "" if it does not exist.
func (c *Client) ImageID(ctx context.Context, image string) (string, error) {
	out, err := c.R.Output(ctx, nil, "image", "inspect", "--format", "{{.Id}}", image)
	if err != nil {
		if IsNotFound(err) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

// ContainerNames lists all container names (running or not) starting with prefix.
func (c *Client) ContainerNames(ctx context.Context, prefix string) ([]string, error) {
	out, err := c.R.Output(ctx, nil, "ps", "-a", "--filter", "name="+prefix, "--format", "{{.Names}}")
	if err != nil {
		return nil, err
	}
	var names []string
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && strings.HasPrefix(line, prefix) {
			names = append(names, line)
		}
	}
	return names, nil
}

// Inspect returns inspect data for the named containers.
func (c *Client) Inspect(ctx context.Context, names ...string) ([]Container, error) {
	if len(names) == 0 {
		return nil, nil
	}
	out, err := c.R.Output(ctx, nil, append([]string{"container", "inspect"}, names...)...)
	if err != nil {
		return nil, err
	}
	return ParseInspect(out)
}

// ParseInspect parses `docker inspect` JSON output.
func ParseInspect(out []byte) ([]Container, error) {
	var cs []Container
	if err := json.Unmarshal(out, &cs); err != nil {
		return nil, fmt.Errorf("parse docker inspect: %w", err)
	}
	return cs, nil
}

// InspectOne returns inspect data for one container, or nil if it does not exist.
func (c *Client) InspectOne(ctx context.Context, name string) (*Container, error) {
	cs, err := c.Inspect(ctx, name)
	if err != nil {
		if IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	if len(cs) == 0 {
		return nil, nil
	}
	return &cs[0], nil
}

// List returns inspect data for every container whose name starts with prefix.
// A container removed between listing and inspecting is left out, and so
// is one whose inspect output alone is over MaxOutput, with a warning.
func (c *Client) List(ctx context.Context, prefix string) ([]Container, error) {
	names, err := c.ContainerNames(ctx, prefix)
	if err != nil {
		return nil, err
	}
	cs, err := c.Inspect(ctx, names...)
	if err == nil || !retryEach(err) {
		return cs, err
	}
	// One of them is gone, or the containers' labels, which include their
	// images', add up to too much output, either of which fails the whole
	// inspect. So inspect each on its own and skip the missing ones.
	cs = nil
	for _, name := range names {
		ct, err := c.InspectOne(ctx, name)
		if errors.Is(err, ErrOutputTooLarge) {
			c.warnf("Warning: leaving out container %s: %v", name, err)
			continue
		}
		if err != nil {
			return nil, err
		}
		if ct != nil {
			cs = append(cs, *ct)
		}
	}
	return cs, nil
}

// retryEach reports whether a failed inspect of several containers should
// be retried one container at a time.
func retryEach(err error) bool {
	return IsNotFound(err) || errors.Is(err, ErrOutputTooLarge)
}

// Run runs `docker run` with the given args and returns the container ID.
func (c *Client) Run(ctx context.Context, args ...string) (string, error) {
	out, err := c.R.Output(ctx, nil, append([]string{"run"}, args...)...)
	return strings.TrimSpace(string(out)), err
}

// Start starts a stopped container.
func (c *Client) Start(ctx context.Context, name string) error {
	_, err := c.R.Output(ctx, nil, "start", name)
	return err
}

// Stop stops a container with the given grace period in seconds.
func (c *Client) Stop(ctx context.Context, name string, timeout int) error {
	_, err := c.R.Output(ctx, nil, "stop", "-t", strconv.Itoa(timeout), name)
	return err
}

// Remove removes a container along with its anonymous volumes. Bind mounts
// and named volumes are left alone.
func (c *Client) Remove(ctx context.Context, name string, force bool) error {
	args := []string{"rm", "-v"}
	if force {
		args = append(args, "-f")
	}
	_, err := c.R.Output(ctx, nil, append(args, name)...)
	return err
}

// ConnectOptions configures NetworkConnect.
type ConnectOptions struct {
	Aliases []string
	Links   []string
	IPv4    string
	IPv6    string
}

// NetworkConnect connects a container to a network.
func (c *Client) NetworkConnect(ctx context.Context, network, container string, opts ConnectOptions) error {
	args := []string{"network", "connect"}
	for _, a := range opts.Aliases {
		args = append(args, "--alias", a)
	}
	for _, l := range opts.Links {
		args = append(args, "--link", l)
	}
	if opts.IPv4 != "" {
		args = append(args, "--ip", opts.IPv4)
	}
	if opts.IPv6 != "" {
		args = append(args, "--ip6", opts.IPv6)
	}
	_, err := c.R.Output(ctx, nil, append(args, network, container)...)
	return err
}

// Network is the part of `docker network inspect` safeclaw reads.
type Network struct {
	Name     string            `json:"Name"`
	ID       string            `json:"Id"`
	Driver   string            `json:"Driver"`
	Internal bool              `json:"Internal"`
	Options  map[string]string `json:"Options"`
	Labels   map[string]string `json:"Labels"`
}

// NetworkInspect returns a network, or nil if it does not exist.
func (c *Client) NetworkInspect(ctx context.Context, name string) (*Network, error) {
	out, err := c.R.Output(ctx, nil, "network", "inspect", name)
	if err != nil {
		if IsNotFound(err) {
			return nil, nil
		}
		return nil, err
	}
	var ns []Network
	if err := json.Unmarshal(out, &ns); err != nil {
		return nil, fmt.Errorf("parse docker network inspect: %w", err)
	}
	if len(ns) == 0 {
		return nil, nil
	}
	return &ns[0], nil
}

// NetworkCreateOptions configures NetworkCreate.
type NetworkCreateOptions struct {
	Driver  string
	Options map[string]string
	Labels  map[string]string
}

// NetworkCreate creates a network. Options and labels are passed in key
// order.
func (c *Client) NetworkCreate(ctx context.Context, name string, opts NetworkCreateOptions) error {
	args := []string{"network", "create"}
	if opts.Driver != "" {
		args = append(args, "--driver", opts.Driver)
	}
	for _, k := range slices.Sorted(maps.Keys(opts.Options)) {
		args = append(args, "--opt", k+"="+opts.Options[k])
	}
	for _, k := range slices.Sorted(maps.Keys(opts.Labels)) {
		args = append(args, "--label", k+"="+opts.Labels[k])
	}
	_, err := c.R.Output(ctx, nil, append(args, name)...)
	return err
}

// NetworkDisconnect disconnects a container from a network.
func (c *Client) NetworkDisconnect(ctx context.Context, network, container string) error {
	_, err := c.R.Output(ctx, nil, "network", "disconnect", network, container)
	return err
}

// ExecOptions configures Exec and ExecStream.
type ExecOptions struct {
	Detach bool
	Stdin  io.Reader
	// User runs the command as this user instead of the container's.
	User string
	// Workdir runs the command in this directory instead of the container's.
	Workdir string
	// MaxOutput, when above zero, is the most stdout Exec buffers, in place
	// of the runner's MaxOutput: a command that writes more is stopped and
	// Exec returns an *OutputLimitError. It can't be used with Stdin or
	// Detach.
	MaxOutput int
}

// OutputLimitError is returned by Exec when a command writes more than its
// ExecOptions.MaxOutput. It matches ErrOutputTooLarge with errors.Is.
type OutputLimitError struct {
	Args []string
	Max  int
}

func (e *OutputLimitError) Error() string {
	return fmt.Sprintf("docker %s: output exceeds %d bytes", firstArg(e.Args), e.Max)
}

// Is reports whether target is ErrOutputTooLarge.
func (e *OutputLimitError) Is(target error) bool { return target == ErrOutputTooLarge }

func (o ExecOptions) args(name string, cmd []string) []string {
	args := []string{"exec"}
	if o.Detach {
		args = append(args, "-d")
	}
	if o.Stdin != nil {
		args = append(args, "-i")
	}
	if o.User != "" {
		args = append(args, "--user", o.User)
	}
	if o.Workdir != "" {
		args = append(args, "--workdir", o.Workdir)
	}
	args = append(args, name)
	return append(args, cmd...)
}

// Exec runs a command in a container and returns its stdout, at most
// opts.MaxOutput bytes of it when that is set.
func (c *Client) Exec(ctx context.Context, name string, opts ExecOptions, cmd ...string) ([]byte, error) {
	if opts.MaxOutput > 0 {
		return c.execLimited(ctx, name, opts, cmd)
	}
	return c.R.Output(ctx, opts.Stdin, opts.args(name, cmd)...)
}

// execLimited runs a command with Stream, reading at most opts.MaxOutput
// bytes of its stdout. Past that, docker is killed and an
// *OutputLimitError returned, so a command flooding its stdout costs the
// host no more than the limit.
func (c *Client) execLimited(ctx context.Context, name string, opts ExecOptions, cmd []string) ([]byte, error) {
	if opts.Stdin != nil || opts.Detach {
		return nil, errors.New("docker exec: MaxOutput can't be used with Stdin or Detach")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	args := opts.args(name, cmd)
	out, wait, err := c.R.Stream(ctx, args...)
	if err != nil {
		return nil, err
	}
	b, rerr := io.ReadAll(io.LimitReader(out, int64(opts.MaxOutput)+1))
	over := len(b) > opts.MaxOutput
	if over || rerr != nil {
		// Docker may still be writing, so wait would block until it exits
		// on its own.
		cancel()
	}
	_ = out.Close()
	werr := wait()
	switch {
	case over:
		return nil, &OutputLimitError{Args: args, Max: opts.MaxOutput}
	case rerr != nil:
		return nil, fmt.Errorf("read docker %s output: %w", firstArg(args), rerr)
	}
	return b, werr
}

// ExecStream runs a command in a container and returns its stdout as it is
// written. Calling the returned function waits for the command to exit and
// returns an *Error carrying stderr if it failed. opts.Stdin and
// opts.Detach are ignored.
func (c *Client) ExecStream(ctx context.Context, name string, opts ExecOptions, cmd ...string) (io.ReadCloser, func() error, error) {
	opts.Stdin, opts.Detach = nil, false
	return c.R.Stream(ctx, opts.args(name, cmd)...)
}

// Tag tags an image.
func (c *Client) Tag(ctx context.Context, src, dst string) error {
	_, err := c.R.Output(ctx, nil, "tag", src, dst)
	return err
}

// Event is a docker container or network event.
type Event struct {
	// Type is "container" or "network".
	Type   string
	Action string
	// Name is the container's name for container events and the network's
	// name for network events.
	Name string
	// Container is the container ID the event is about: the actor of a
	// container event, or the container attribute of a network event.
	Container string
	// Err is set, and the other fields are empty, for a line that could not
	// be read as an event, such as one longer than MaxEventLine. The event
	// it held is lost.
	Err error
}

// MaxEventLine is the longest `docker events` line Events reads. Longer
// lines are skipped.
const MaxEventLine = 1 << 20

// ErrEventTooLarge is the Err of an Event for a line longer than
// MaxEventLine.
var ErrEventTooLarge = fmt.Errorf("event exceeds %d bytes", MaxEventLine)

type rawEvent struct {
	Type   string `json:"Type"`
	Action string `json:"Action"`
	Actor  struct {
		ID         string            `json:"ID"`
		Attributes map[string]string `json:"Attributes"`
	} `json:"Actor"`
}

// ParseEvent parses one line of `docker events --format '{{json .}}'`.
func ParseEvent(line []byte) (Event, bool) {
	ev, ok, _ := parseEvent(line)
	return ev, ok
}

// parseEvent is ParseEvent, with an error for a line that is not JSON.
func parseEvent(line []byte) (Event, bool, error) {
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return Event{}, false, nil
	}
	var r rawEvent
	if err := json.Unmarshal(line, &r); err != nil {
		return Event{}, false, fmt.Errorf("parse docker event: %w", err)
	}
	typ := r.Type
	if typ == "" {
		typ = "container"
	}
	if typ != "container" && typ != "network" {
		return Event{}, false, nil
	}
	ev := Event{Type: typ, Action: r.Action, Name: r.Actor.Attributes["name"], Container: r.Actor.ID}
	if typ == "network" {
		ev.Container = r.Actor.Attributes["container"]
	}
	return ev, true, nil
}

// Events streams container and network events until ctx is done or docker
// exits. A line too long or garbled to parse is passed to fn as an Event
// with Err set, and the stream goes on. If reading the stream fails,
// docker is killed and the read error returned.
func (c *Client) Events(ctx context.Context, fn func(Event)) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	out, wait, err := c.R.Stream(ctx, "events", "--filter", "type=container", "--filter", "type=network", "--format", "{{json .}}")
	if err != nil {
		return err
	}
	rerr := readEvents(out, fn)
	if rerr != nil {
		// Docker may still be writing, so wait would block until it
		// exits on its own.
		cancel()
	}
	werr := wait()
	if rerr != nil {
		return fmt.Errorf("read docker events: %w", rerr)
	}
	return werr
}

// readEvents passes each event line in r to fn until r ends, keeping at
// most MaxEventLine bytes of any one line. It returns nil at EOF.
func readEvents(r io.Reader, fn func(Event)) error {
	br := bufio.NewReaderSize(r, 64<<10)
	var line []byte
	tooLong := false
	for {
		chunk, err := br.ReadSlice('\n')
		if !tooLong && len(line)+len(chunk) > MaxEventLine {
			tooLong, line = true, line[:0]
		}
		if !tooLong {
			line = append(line, chunk...)
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		switch ev, ok, perr := parseEvent(line); {
		case tooLong:
			fn(Event{Err: ErrEventTooLarge})
		case perr != nil:
			fn(Event{Err: perr})
		case ok:
			fn(ev)
		}
		line, tooLong = line[:0], false
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
