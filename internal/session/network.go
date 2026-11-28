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

// ErrUnreadableState is wrapped by the error returned when a session's
// saved offline state can't be read. The session may be held offline, so
// whatever could bring it online or remove it is refused.
var ErrUnreadableState = errors.New("may be held offline")

// ErrOffline is wrapped by the error returned when an offline session would
// have to be recreated.
var ErrOffline = errors.New("is offline")

// ErrStillOnline is wrapped by the error returned when `net off` records its
// hold but a session could not be disconnected from every network.
var ErrStillOnline = errors.New("is held offline but still attached")

// ErrForeignNetwork is wrapped by the error returned when the session
// network exists but safeclaw did not create it with traffic between its
// containers off.
var ErrForeignNetwork = errors.New("is not safeclaw's session network")

// sessionNetwork returns the docker network sessions are created on.
func (m *Manager) sessionNetwork() string {
	if m.Network != "" {
		return m.Network
	}
	return config.SessionNetwork
}

// sessionNetworkOptions are how safeclaw creates the session network: a
// bridge whose containers can't reach each other, labeled as safeclaw's.
var sessionNetworkOptions = docker.NetworkCreateOptions{
	Driver:  "bridge",
	Options: map[string]string{config.BridgeICCOption: "false"},
	Labels:  map[string]string{config.LabelNetwork: config.NetworkSessions},
}

// ensureNetwork returns the session network, creating it if it does not
// exist. One that exists is used only if safeclaw created it: a bridge
// labeled as the session network with traffic between its containers off.
// Anything else is refused with an error wrapping ErrForeignNetwork, rather
// than putting sessions on a network where they could reach each other.
func (m *Manager) ensureNetwork(ctx context.Context) (*docker.Network, error) {
	name := m.sessionNetwork()
	n, err := m.Docker.NetworkInspect(ctx, name)
	if err != nil {
		return nil, err
	}
	if n == nil {
		m.printf("Creating network %s, with traffic between sessions off\n", name)
		// Something else may have created it meanwhile, so it is inspected
		// either way and checked like any network found.
		cerr := m.Docker.NetworkCreate(ctx, name, sessionNetworkOptions)
		if n, err = m.Docker.NetworkInspect(ctx, name); err != nil || n == nil {
			if cerr != nil {
				return nil, cerr
			}
			return nil, fmt.Errorf("docker network %q is missing right after it was created: %w", name, err)
		}
	}
	if err := checkSessionNetwork(n); err != nil {
		return nil, err
	}
	return n, nil
}

// reattachSessionNetwork reconnects a stopped session to the session
// network when the network it was attached to has been removed and created
// again, such as after `docker network prune` while every session was
// stopped. Docker keeps the old network's ID on a stopped container, and
// refuses to start it once that network is gone.
func (m *Manager) reattachSessionNetwork(ctx context.Context, c docker.Container) error {
	if c.HostConfig.NetworkMode != m.sessionNetwork() {
		return nil
	}
	n, err := m.ensureNetwork(ctx)
	if err != nil {
		return err
	}
	ep, ok := c.NetworkSettings.Networks[n.Name]
	if !ok || ep.NetworkID == "" || ep.NetworkID == n.ID {
		return nil
	}
	container := c.ShortName()
	m.printf("Reattaching %s to %s, which was removed and created again\n", container, n.Name)
	if err := m.Docker.NetworkDisconnect(ctx, n.Name, container); err != nil {
		return err
	}
	return m.Docker.NetworkConnect(ctx, n.Name, container, saveNetwork(c, n.Name).connectOptions())
}

// checkSessionNetwork refuses a network safeclaw did not create for
// sessions.
func checkSessionNetwork(n *docker.Network) error {
	var why string
	switch {
	case n.Labels[config.LabelNetwork] != config.NetworkSessions:
		why = fmt.Sprintf("it lacks the label %s=%s that safeclaw creates it with", config.LabelNetwork, config.NetworkSessions)
	case n.Driver != "bridge":
		why = fmt.Sprintf("it uses the %s driver rather than bridge", n.Driver)
	case n.Options[config.BridgeICCOption] != "false":
		why = fmt.Sprintf("it lets its containers reach each other, without %s=false", config.BridgeICCOption)
	case n.Internal:
		why = "it is internal, so sessions on it couldn't reach the internet"
	default:
		return nil
	}
	return fmt.Errorf("docker network %q %w: %s. Remove it with `docker network rm %s`, disconnecting its containers first, and safeclaw creates it again", n.Name, ErrForeignNetwork, why, n.Name)
}

// onDefaultBridge reports whether an interactive session was created on
// docker's default bridge, as ones created before sessions moved to the
// session network were.
func onDefaultBridge(c docker.Container) bool {
	if TypeOf(c) == config.TypeSandbox {
		return false
	}
	switch c.HostConfig.NetworkMode {
	case "", "default", "bridge":
		return true
	}
	return false
}

// Hold records one owner keeping a session offline.
type Hold struct {
	// Owner names who holds the session offline. "" is the unnamed hold
	// shared by every caller that gives no owner.
	Owner  string    `json:"owner"`
	Reason string    `json:"reason,omitempty"`
	Since  time.Time `json:"since"`

	// unknown marks the hold listings show for a session whose saved
	// state can't be read, which counts as held.
	unknown bool
}

// Label returns the owner, "unnamed" for the unnamed hold, or "unknown"
// for a session whose saved state can't be read.
func (h Hold) Label() string {
	switch {
	case h.unknown:
		return "unknown"
	case h.Owner == "":
		return "unnamed"
	}
	return h.Owner
}

// unknownHold is the hold listed for a session whose saved state can't be
// read.
var unknownHold = Hold{Reason: "its offline state can't be read", unknown: true}

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
// across safeclaw processes.
func (m *Manager) netLock() (func(), error) {
	return lockFile(m.netDir())
}

// lockFile takes an exclusive lock on dir/.lock, creating dir if needed.
// One lock file is shared by every session and never removed, since
// removing it while another process waits on it would let two holders in.
// The returned function releases it and is safe to call more than once.
func lockFile(dir string) (func(), error) {
	return lockPath(dir, ".lock", func(fd int) error {
		return syscall.Flock(fd, syscall.LOCK_EX)
	})
}

// lockRetry is how often lockFileCtx tries again for a held lock.
const lockRetry = 25 * time.Millisecond

// lockFileCtx takes an exclusive lock on dir/name, creating dir if needed,
// like lockFile, but gives up with ctx's error once ctx is done, so a
// holder that never lets go can't hold the caller past its deadline or
// Ctrl-C. Like lockFile's, the lock file is never removed.
func lockFileCtx(ctx context.Context, dir, name string) (func(), error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return lockPath(dir, name, func(fd int) error {
		t := time.NewTicker(lockRetry)
		defer t.Stop()
		for {
			err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB)
			if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
				return err
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-t.C:
			}
		}
	})
}

// lockPath opens dir/name, creating both if needed, and locks it with
// lock. The returned function releases it and is safe to call more than
// once.
func lockPath(dir, name string, lock func(fd int) error) (func(), error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(dir, name), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lock(int(f.Fd())); err != nil {
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
		return nil, m.unreadableState(name, err)
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
// another container. State that can't be read fails closed: it returns an
// error wrapping ErrUnreadableState, since the session may be held. Writes
// are atomic renames, so it needs no lock.
func (m *Manager) holdsFor(name string, c docker.Container) ([]Hold, error) {
	if TypeOf(c) == config.TypeSandbox {
		return nil, nil
	}
	st, err := m.readState(name)
	if err != nil {
		return nil, m.unreadableState(name, err)
	}
	if st == nil || st.ContainerID != c.ID {
		return nil, nil
	}
	return st.Holds, nil
}

// unreadableState returns the error for a session whose saved state can't
// be read, wrapping ErrUnreadableState.
func (m *Manager) unreadableState(name string, err error) error {
	return fmt.Errorf("session %q %w: its offline state in %s can't be read (%w). Fix or remove that file, or remove the session with `safeclaw rm --release-holds %s`", name, ErrUnreadableState, m.statePath(name), err, name)
}

// listedHolds returns the holds a listing shows for a container, with the
// unknown hold for one whose saved state can't be read.
func (m *Manager) listedHolds(name string, c docker.Container) []Hold {
	holds, err := m.holdsFor(name, c)
	if err != nil {
		return []Hold{unknownHold}
	}
	return holds
}

// OfflineOrHeld reports whether a session is offline or held offline. A
// held session counts as offline even while something keeps it attached,
// such as a failed disconnect or a network docker restored. Sandboxes never
// are. A session whose saved state can't be read counts as held, and the
// error says why.
func (m *Manager) OfflineOrHeld(c docker.Container) (bool, error) {
	holds, err := m.holdsFor(config.SessionName(c.ShortName()), c)
	if err != nil {
		return true, err
	}
	return Offline(c) || len(holds) > 0, nil
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
	}
	// The hold stays even if a disconnect fails: rolling back would put the
	// session back online while its owner expects it offline, and the hold
	// keeps run, start, and build --recreate treating it as offline.
	if left, err := m.disconnectAll(ctx, container, nets); err != nil {
		res := &NetResult{Name: name, Holds: st.Holds}
		m.printf("Session %s is held offline by %s, but is still attached to %s\n", name, strings.Join(HoldLabels(st.Holds), ", "), strings.Join(left, ", "))
		return res, fmt.Errorf("session %q %w to %s: %w; run `safeclaw net off %s` again to retry", name, ErrStillOnline, strings.Join(left, ", "), err, name)
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
		// The session network may have been removed while this session was
		// off it, and one created in its place outside safeclaw is refused.
		if n.Name == m.sessionNetwork() {
			if _, err := m.ensureNetwork(ctx); err != nil {
				return nil, err
			}
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

// disconnectAll disconnects a container from nets, trying every network
// even when one fails. Failed networks are retried once against a fresh
// inspect, since one may have been disconnected meanwhile. It returns the
// networks still attached along with the first error.
func (m *Manager) disconnectAll(ctx context.Context, container string, nets []string) ([]string, error) {
	var firstErr error
	try := func(nets []string) []string {
		var failed []string
		for _, n := range nets {
			if err := m.Docker.NetworkDisconnect(ctx, n, container); err != nil {
				if firstErr == nil {
					firstErr = err
				}
				failed = append(failed, n)
			}
		}
		return failed
	}
	failed := try(nets)
	if len(failed) == 0 {
		return nil, nil
	}
	c, err := m.Docker.InspectOne(ctx, container)
	if err != nil {
		return failed, err
	}
	if c == nil {
		return failed, firstErr
	}
	still := slices.DeleteFunc(failed, func(n string) bool {
		_, ok := c.NetworkSettings.Networks[n]
		return !ok
	})
	if len(still) == 0 {
		return nil, nil
	}
	m.printf("Retrying the disconnect of %s from %s\n", container, strings.Join(still, ", "))
	firstErr = nil
	if left := try(still); len(left) > 0 {
		return left, firstErr
	}
	return nil, nil
}

// keepOffline disconnects a container that should be offline from any
// network attached to it, for example by docker when it was started, or
// left by a `net off` whose disconnect failed.
func (m *Manager) keepOffline(ctx context.Context, container string) error {
	c, err := m.Docker.InspectOne(ctx, container)
	if err != nil || c == nil {
		return err
	}
	nets := attached(*c)
	for _, n := range nets {
		m.printf("Disconnecting %s from %s to keep it offline\n", container, n)
	}
	if left, err := m.disconnectAll(ctx, container, nets); err != nil {
		return fmt.Errorf("keep %s offline: still attached to %s: %w", container, strings.Join(left, ", "), err)
	}
	return nil
}

// RemoveStale removes a session container that `build --recreate` found
// running an older image, under the network lock. It refuses, with an error
// wrapping ErrOffline, a session that is offline or held offline, since a
// recreated container would come back online. A container that was removed
// or replaced since c was listed is left alone, and removed reports false.
// A session's secrets and auto memory choices are kept on the host, so the
// container created next with its name gets them back.
func (m *Manager) RemoveStale(ctx context.Context, c docker.Container) (removed bool, err error) {
	unlock, err := m.netLock()
	if err != nil {
		return false, err
	}
	defer unlock()

	container := c.ShortName()
	name := config.SessionName(container)
	cur, err := m.Docker.InspectOne(ctx, container)
	if err != nil || cur == nil || cur.ID != c.ID {
		return false, err
	}
	holds, err := m.holdsFor(name, *cur)
	if err != nil {
		return false, err
	}
	if Offline(*cur) || len(holds) > 0 {
		by := ""
		if len(holds) > 0 {
			by = " by " + strings.Join(HoldLabels(holds), ", ")
		}
		return false, fmt.Errorf("session %q %w%s", name, ErrOffline, by)
	}
	// The session's next container gets its choices back.
	if err := m.keepChoices(name, *cur); err != nil {
		return false, err
	}
	if err := m.Docker.Remove(ctx, container, true); err != nil {
		return false, err
	}
	if err := m.removeRemovedState(ctx, name, false); err != nil {
		return true, err
	}
	return true, nil
}

// removeRemovedState deletes a session's saved state once its container
// has been removed, unless the state belongs to a container that now has
// the session's name, such as one created outside safeclaw. State that
// can't be read is an error, unless anyway is set, which removes it. The
// caller holds the network lock, so no safeclaw process creates a container
// or takes one offline meanwhile.
func (m *Manager) removeRemovedState(ctx context.Context, name string, anyway bool) error {
	st, err := m.readState(name)
	switch {
	case err != nil && anyway:
		return m.removeState(name)
	case err != nil:
		return m.unreadableState(name, err)
	case st == nil:
		return nil
	}
	cur, err := m.Docker.InspectOne(ctx, config.ContainerName(name))
	if err != nil {
		return err
	}
	if cur != nil && cur.ID == st.ContainerID {
		return nil
	}
	return m.removeState(name)
}
