package docker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// Client offers the docker operations safeclaw needs on top of a Runner.
type Client struct {
	R Runner
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
}

// Container is the subset of `docker inspect` output safeclaw uses.
type Container struct {
	ID     string `json:"Id"`
	Name   string `json:"Name"`
	Image  string `json:"Image"`
	Config struct {
		Labels map[string]string `json:"Labels"`
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
// A container removed between listing and inspecting is left out.
func (c *Client) List(ctx context.Context, prefix string) ([]Container, error) {
	names, err := c.ContainerNames(ctx, prefix)
	if err != nil {
		return nil, err
	}
	cs, err := c.Inspect(ctx, names...)
	if err == nil || !IsNotFound(err) {
		return cs, err
	}
	// One of them is gone, which fails the whole inspect, so inspect each
	// on its own and skip the missing ones.
	cs = nil
	for _, name := range names {
		ct, err := c.InspectOne(ctx, name)
		if err != nil {
			return nil, err
		}
		if ct != nil {
			cs = append(cs, *ct)
		}
	}
	return cs, nil
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
}

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

// Exec runs a command in a container and returns its stdout.
func (c *Client) Exec(ctx context.Context, name string, opts ExecOptions, cmd ...string) ([]byte, error) {
	return c.R.Output(ctx, opts.Stdin, opts.args(name, cmd)...)
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
}

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
	line = bytes.TrimSpace(line)
	if len(line) == 0 {
		return Event{}, false
	}
	var r rawEvent
	if err := json.Unmarshal(line, &r); err != nil {
		return Event{}, false
	}
	typ := r.Type
	if typ == "" {
		typ = "container"
	}
	if typ != "container" && typ != "network" {
		return Event{}, false
	}
	ev := Event{Type: typ, Action: r.Action, Name: r.Actor.Attributes["name"], Container: r.Actor.ID}
	if typ == "network" {
		ev.Container = r.Actor.Attributes["container"]
	}
	return ev, true
}

// Events streams container and network events until ctx is done or docker
// exits. It returns when the stream ends.
func (c *Client) Events(ctx context.Context, fn func(Event)) error {
	out, wait, err := c.R.Stream(ctx, "events", "--filter", "type=container", "--filter", "type=network", "--format", "{{json .}}")
	if err != nil {
		return err
	}
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		if ev, ok := ParseEvent(sc.Bytes()); ok {
			fn(ev)
		}
	}
	return wait()
}
