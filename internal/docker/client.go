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
}

// PortBinding is a host binding for a container port.
type PortBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

// Container is the subset of `docker inspect` output safeclaw uses.
type Container struct {
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
	} `json:"HostConfig"`
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
func (c *Client) List(ctx context.Context, prefix string) ([]Container, error) {
	names, err := c.ContainerNames(ctx, prefix)
	if err != nil {
		return nil, err
	}
	return c.Inspect(ctx, names...)
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

// ExecOptions configures Exec.
type ExecOptions struct {
	Detach bool
	Stdin  io.Reader
}

// Exec runs a command in a container and returns its stdout.
func (c *Client) Exec(ctx context.Context, name string, opts ExecOptions, cmd ...string) ([]byte, error) {
	args := []string{"exec"}
	if opts.Detach {
		args = append(args, "-d")
	}
	if opts.Stdin != nil {
		args = append(args, "-i")
	}
	args = append(args, name)
	args = append(args, cmd...)
	return c.R.Output(ctx, opts.Stdin, args...)
}

// Tag tags an image.
func (c *Client) Tag(ctx context.Context, src, dst string) error {
	_, err := c.R.Output(ctx, nil, "tag", src, dst)
	return err
}

// Event is a docker container event.
type Event struct {
	Action string
	Name   string
}

type rawEvent struct {
	Type   string `json:"Type"`
	Action string `json:"Action"`
	Actor  struct {
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
	if r.Type != "" && r.Type != "container" {
		return Event{}, false
	}
	return Event{Action: r.Action, Name: r.Actor.Attributes["name"]}, true
}

// Events streams container events until ctx is done or docker exits. It
// returns when the stream ends.
func (c *Client) Events(ctx context.Context, fn func(Event)) error {
	out, wait, err := c.R.Stream(ctx, "events", "--filter", "type=container", "--format", "{{json .}}")
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
