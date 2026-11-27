package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
)

// Network statuses, as shown by `safeclaw ls` and the dashboard.
const (
	// NetOnline is a session connected to at least one network.
	NetOnline = "online"
	// NetOffline is a session disconnected from every network.
	NetOffline = "offline"
	// NetNone is a container created without a network, such as a sandbox.
	NetNone = "none"
	// NetHost is a container using the host's network.
	NetHost = "host"
	// NetShared is a container using another container's network.
	NetShared = "shared"
)

// ErrHostNetwork is returned when a session using host networking is taken
// offline.
var ErrHostNetwork = errors.New("uses host networking, which cannot be disconnected")

// ErrSharedNetwork is returned when a session sharing another container's
// network is taken offline.
var ErrSharedNetwork = errors.New("shares another container's network, which cannot be disconnected")

// ErrNoNetwork is returned when a session created without a network is
// taken offline.
var ErrNoNetwork = errors.New("has no network to disconnect")

// ErrHeld is wrapped by the error returned when `net on` is refused because
// other owners still hold the session offline.
var ErrHeld = errors.New("is held offline")

// ErrOffline is wrapped by the error returned when an offline session would
// have to be recreated.
var ErrOffline = errors.New("is offline")

// Hold records one owner keeping a session offline.
type Hold struct {
	// Owner names who holds the session offline. "" is the unnamed hold
	// shared by every caller that gives no owner.
	Owner  string    `json:"owner"`
	Reason string    `json:"reason,omitempty"`
	Since  time.Time `json:"since"`
}

// Label returns the owner, or "unnamed" for the unnamed hold.
func (h Hold) Label() string {
	if h.Owner == "" {
		return "unnamed"
	}
	return h.Owner
}

// HoldLabels returns each hold's label.
func HoldLabels(holds []Hold) []string {
	out := make([]string, len(holds))
	for i, h := range holds {
		out[i] = h.Label()
	}
	return out
}

// savedNetwork is a network an offline session is restored to.
type savedNetwork struct {
	Name    string   `json:"name"`
	Aliases []string `json:"aliases,omitempty"`
	Links   []string `json:"links,omitempty"`
	IPv4    string   `json:"ipv4,omitempty"`
	IPv6    string   `json:"ipv6,omitempty"`
}

// netState is the saved state of an offline session. It belongs to one
// container: a session recreated under the same name has a new ID, so the
// state is ignored.
type netState struct {
	ContainerID string         `json:"containerId"`
	Networks    []savedNetwork `json:"networks"`
	Holds       []Hold         `json:"holds"`
}

func (s *netState) hold(owner string) int {
	return slices.IndexFunc(s.Holds, func(h Hold) bool { return h.Owner == owner })
}

// NetOffOptions configures NetOff.
type NetOffOptions struct {
	// Owner names the hold. Empty is the unnamed hold.
	Owner string
	// Reason is shown next to the hold.
	Reason string
}

// NetOnOptions configures NetOn.
type NetOnOptions struct {
	// Owner names the hold to release. Empty is the unnamed hold.
	Owner string
	// Force releases every hold.
	Force bool
}

// NetResult describes a session's network after NetOff or NetOn.
type NetResult struct {
	Name    string
	Offline bool
	// Holds are the holds keeping the session offline.
	Holds []Hold
	// Networks are the networks disconnected or reconnected.
	Networks []string
}

// NetworkStatus returns a container's network status: NetOnline,
// NetOffline, NetNone, NetHost, or NetShared.
func NetworkStatus(c docker.Container) string {
	if TypeOf(c) == config.TypeSandbox {
		return NetNone
	}
	mode := c.HostConfig.NetworkMode
	switch {
	case mode == "host":
		return NetHost
	case mode == "none":
		return NetNone
	case strings.HasPrefix(mode, "container:"):
		return NetShared
	case len(c.NetworkSettings.Networks) == 0:
		return NetOffline
	}
	return NetOnline
}

// Offline reports whether an interactive session is disconnected from every
// network.
func Offline(c docker.Container) bool {
	return NetworkStatus(c) == NetOffline
}

func (m *Manager) netDir() string {
	if m.NetworkDir != "" {
		return m.NetworkDir
	}
	return config.NetworkDir()
}

// netLock takes the lock that serializes network changes and offline state
// across safeclaw processes. One lock file is shared by every session and
// never removed, since removing it while another process waits on it would
// let two holders in. The returned function releases it and is safe to call
// more than once.
func (m *Manager) netLock() (func(), error) {
	dir := m.netDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, ".lock"), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		_ = f.Close()
		return nil, fmt.Errorf("lock %s: %w", f.Name(), err)
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			_ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
			_ = f.Close()
		})
	}, nil
}

func (m *Manager) statePath(name string) string {
	return filepath.Join(m.netDir(), name+".json")
}

// readState returns a session's saved state, nil if there is none.
func (m *Manager) readState(name string) (*netState, error) {
	b, err := os.ReadFile(m.statePath(name))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var st netState
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("read offline state for %q: %w", name, err)
	}
	return &st, nil
}

// writeState replaces a session's saved state atomically.
func (m *Manager) writeState(name string, st *netState) error {
	dir := m.netDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+name+".*.tmp")
	if err != nil {
		return err
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		_ = f.Close()
		_ = os.Remove(f.Name())
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(f.Name())
		return err
	}
	if err := os.Rename(f.Name(), m.statePath(name)); err != nil {
		_ = os.Remove(f.Name())
		return err
	}
	return nil
}

// removeState deletes a session's saved state, if any.
func (m *Manager) removeState(name string) error {
	if err := os.Remove(m.statePath(name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}

// currentState returns the saved state for a container, deleting state left
// by an earlier container with the same name. It never returns nil.
func (m *Manager) currentState(name string, c docker.Container) (*netState, error) {
	st, err := m.readState(name)
	if err != nil {
		return nil, err
	}
	if st != nil && st.ContainerID != c.ID {
		m.printf("Ignoring saved network state for %s: it belongs to an earlier container\n", name)
		if err := m.removeState(name); err != nil {
			return nil, err
		}
		st = nil
	}
	if st == nil {
		st = &netState{ContainerID: c.ID}
	}
	return st, nil
}

// holdsFor returns the holds on a container, ignoring state that belongs to
// another container or cannot be read. Writes are atomic renames, so it
// needs no lock.
func (m *Manager) holdsFor(name string, c docker.Container) []Hold {
	if TypeOf(c) == config.TypeSandbox {
		return nil
	}
	st, err := m.readState(name)
	if err != nil || st == nil || st.ContainerID != c.ID {
		return nil
	}
	return st.Holds
}

// netTarget returns the interactive session a network change applies to,
// refusing sandboxes and networks that cannot be disconnected.
func (m *Manager) netTarget(ctx context.Context, name string) (string, *docker.Container, error) {
	name = config.SessionName(name)
	if err := ValidateName(name); err != nil {
		return "", nil, err
	}
	c, err := m.Docker.InspectOne(ctx, config.ContainerName(name))
	if err != nil {
		return "", nil, err
	}
	if c == nil {
		return "", nil, fmt.Errorf("session %q %w", name, ErrNotFound)
	}
	if TypeOf(*c) == config.TypeSandbox {
		return "", nil, wrongType(name, ErrIsSandbox)
	}
	switch NetworkStatus(*c) {
	case NetHost:
		return "", nil, wrongType(name, ErrHostNetwork)
	case NetShared:
		return "", nil, wrongType(name, ErrSharedNetwork)
	case NetNone:
		return "", nil, wrongType(name, ErrNoNetwork)
	}
	return name, c, nil
}

// attached returns the names of the networks a container is connected to,
// sorted.
func attached(c docker.Container) []string {
	names := make([]string, 0, len(c.NetworkSettings.Networks))
	for n := range c.NetworkSettings.Networks {
		names = append(names, n)
	}
	slices.Sort(names)
	return names
}

// saveNetwork records how a container is connected to a network, leaving out
// the aliases docker adds by itself (the container's name and short ID).
func saveNetwork(c docker.Container, name string) savedNetwork {
	ep := c.NetworkSettings.Networks[name]
	s := savedNetwork{Name: name, Links: ep.Links}
	short := c.ID
	if len(short) > 12 {
		short = short[:12]
	}
	for _, a := range ep.Aliases {
		if a == c.ShortName() || a == config.SessionName(c.ShortName()) || (short != "" && a == short) {
			continue
		}
		s.Aliases = append(s.Aliases, a)
	}
	if ep.IPAMConfig != nil {
		s.IPv4 = ep.IPAMConfig.IPv4Address
		s.IPv6 = ep.IPAMConfig.IPv6Address
	}
	return s
}

// connectOptions returns how to reconnect a saved network. The default
// bridge network rejects aliases.
func (s savedNetwork) connectOptions() docker.ConnectOptions {
	opts := docker.ConnectOptions{Links: s.Links, IPv4: s.IPv4, IPv6: s.IPv6}
	if s.Name != "bridge" {
		opts.Aliases = s.Aliases
	}
	return opts
}

// NetOff disconnects an interactive session from every network and records
// a hold for opts.Owner. The networks are saved first, tied to the
// container's ID, so NetOn restores exactly those. Taking an offline
// session offline again adds or updates the hold and keeps the saved
// networks. It works on stopped sessions too.
func (m *Manager) NetOff(ctx context.Context, name string, opts NetOffOptions) (*NetResult, error) {
	unlock, err := m.netLock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	name, c, err := m.netTarget(ctx, name)
	if err != nil {
		return nil, err
	}
	st, err := m.currentState(name, *c)
	if err != nil {
		return nil, err
	}
	nets := attached(*c)
	for _, n := range nets {
		if !slices.ContainsFunc(st.Networks, func(s savedNetwork) bool { return s.Name == n }) {
			st.Networks = append(st.Networks, saveNetwork(*c, n))
		}
	}
	owner := strings.TrimSpace(opts.Owner)
	h := Hold{Owner: owner, Reason: strings.TrimSpace(opts.Reason), Since: time.Now().UTC()}
	if i := st.hold(owner); i >= 0 {
		h.Since = st.Holds[i].Since
		st.Holds[i] = h
	} else {
		st.Holds = append(st.Holds, h)
	}
	// Save before disconnecting, so a failure part way still knows every
	// network to restore.
	if err := m.writeState(name, st); err != nil {
		return nil, err
	}
	container := c.ShortName()
	for _, n := range nets {
		m.printf("Disconnecting %s from %s\n", container, n)
		if err := m.Docker.NetworkDisconnect(ctx, n, container); err != nil {
			return nil, err
		}
	}
	m.printf("Session %s is offline, held by %s\n", name, strings.Join(HoldLabels(st.Holds), ", "))
	m.printf("Its web terminal is unreachable until: safeclaw net on %s\n", name)
	return &NetResult{Name: name, Offline: true, Holds: st.Holds, Networks: nets}, nil
}

// NetOn releases opts.Owner's hold on a session and, once no holds remain,
// reconnects it to the networks saved by NetOff. Without saved networks it
// reconnects to the container's network mode. If opts.Owner holds nothing
// while others do, it returns an error wrapping ErrHeld along with the
// result naming them. If other holds remain after the release, the session
// stays offline and the result says so. opts.Force releases every hold.
func (m *Manager) NetOn(ctx context.Context, name string, opts NetOnOptions) (*NetResult, error) {
	unlock, err := m.netLock()
	if err != nil {
		return nil, err
	}
	defer unlock()

	name, c, err := m.netTarget(ctx, name)
	if err != nil {
		return nil, err
	}
	st, err := m.currentState(name, *c)
	if err != nil {
		return nil, err
	}
	res := &NetResult{Name: name, Offline: Offline(*c)}
	owner := strings.TrimSpace(opts.Owner)
	switch {
	case opts.Force:
		st.Holds = nil
	case len(st.Holds) > 0:
		i := st.hold(owner)
		if i < 0 {
			res.Holds = st.Holds
			return res, fmt.Errorf("session %q %w by %s: release it with --owner, or use --force", name, ErrHeld, strings.Join(HoldLabels(st.Holds), ", "))
		}
		st.Holds = slices.Delete(st.Holds, i, i+1)
	}
	if len(st.Holds) > 0 {
		if err := m.writeState(name, st); err != nil {
			return nil, err
		}
		res.Holds = st.Holds
		m.printf("Session %s is still held offline by %s\n", name, strings.Join(HoldLabels(st.Holds), ", "))
		return res, nil
	}

	targets := st.Networks
	if len(targets) == 0 && len(c.NetworkSettings.Networks) == 0 {
		mode := c.HostConfig.NetworkMode
		if mode == "" || mode == "default" {
			mode = "bridge"
		}
		m.printf("No saved networks for %s, reconnecting it to %s, its network mode\n", name, mode)
		targets = []savedNetwork{{Name: mode}}
	}
	container := c.ShortName()
	for _, n := range targets {
		if _, ok := c.NetworkSettings.Networks[n.Name]; ok {
			continue
		}
		m.printf("Connecting %s to %s\n", container, n.Name)
		if err := m.Docker.NetworkConnect(ctx, n.Name, container, n.connectOptions()); err != nil {
			return nil, err
		}
		res.Networks = append(res.Networks, n.Name)
	}
	if err := m.removeState(name); err != nil {
		return nil, err
	}
	res.Offline = false
	if len(res.Networks) == 0 {
		m.printf("Session %s is online\n", name)
	} else {
		m.printf("Session %s is online again\n", name)
	}
	return res, nil
}

// keepOffline disconnects a container that should be offline from any
// network docker attached, for example when it was started.
func (m *Manager) keepOffline(ctx context.Context, container string) error {
	c, err := m.Docker.InspectOne(ctx, container)
	if err != nil || c == nil {
		return err
	}
	for _, n := range attached(*c) {
		m.printf("Disconnecting %s from %s to keep it offline\n", container, n)
		if err := m.Docker.NetworkDisconnect(ctx, n, container); err != nil {
			return err
		}
	}
	return nil
}
