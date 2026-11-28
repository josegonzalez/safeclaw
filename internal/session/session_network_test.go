package session

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
)

const createSessionNetwork = "network create --driver bridge --opt com.docker.network.bridge.enable_icc=false --label safeclaw.network=sessions safeclaw"

// sessionNet returns the session network as safeclaw creates it.
func sessionNet() *docker.Network {
	return &docker.Network{Name: "safeclaw", ID: "net-1", Driver: "bridge",
		Options: map[string]string{config.BridgeICCOption: "false"},
		Labels:  map[string]string{config.LabelNetwork: config.NetworkSessions}}
}

func calls(r interface{ Commands() []string }, prefix string) int {
	n := 0
	for _, c := range r.Commands() {
		if strings.HasPrefix(c, prefix) {
			n++
		}
	}
	return n
}

func TestEnsureCreatesSessionOnSessionNetwork(t *testing.T) {
	w := &world{image: "img", native: true, containers: map[string]*fakeContainer{}}
	m, r := newTestManager(t, w)
	ctx := context.Background()

	if _, err := m.Ensure(ctx, Options{Name: "a", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Ensure(ctx, Options{Name: "b", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	// The network is created once and reused.
	if n := calls(r, "network create"); n != 1 || !hasCall(r, createSessionNetwork) {
		t.Errorf("network creates = %d: %v", n, r.Commands())
	}
	for _, name := range []string{"safeclaw-a", "safeclaw-b"} {
		c := w.containers[name]
		if c.NetworkMode != "safeclaw" || !slices.Equal(attachedNames(c), []string{"safeclaw"}) {
			t.Errorf("%s: mode %q, nets %v", name, c.NetworkMode, c.Nets)
		}
	}
	// The run names the network before the image.
	run, _ := r.Find("run -d --name safeclaw-a")
	if !strings.Contains(run.String(), " --network safeclaw -p ") {
		t.Errorf("run = %q", run.String())
	}
}

func attachedNames(c *fakeContainer) []string {
	var out []string
	for n := range c.networks() {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}

func TestEnsureUsesConfiguredNetwork(t *testing.T) {
	w := &world{image: "img", native: true, containers: map[string]*fakeContainer{}}
	m, r := newTestManager(t, w)
	m.Network = "itest-net"
	if _, err := m.Ensure(context.Background(), Options{Name: "a", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	run, _ := r.Find("run ")
	if !hasCall(r, "network create --driver bridge --opt com.docker.network.bridge.enable_icc=false --label safeclaw.network=sessions itest-net") || !strings.Contains(run.String(), "--network itest-net") {
		t.Errorf("calls = %v", r.Commands())
	}
}

func TestEnsureRefusesForeignNetwork(t *testing.T) {
	cases := map[string]func(n *docker.Network){
		"unlabeled": func(n *docker.Network) { delete(n.Labels, config.LabelNetwork) },
		"icc on":    func(n *docker.Network) { delete(n.Options, config.BridgeICCOption) },
		"icc true":  func(n *docker.Network) { n.Options[config.BridgeICCOption] = "true" },
		"overlay":   func(n *docker.Network) { n.Driver = "overlay" },
		"internal":  func(n *docker.Network) { n.Internal = true },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			n := sessionNet()
			change(n)
			w := &world{image: "img", native: true, containers: map[string]*fakeContainer{}, networks: map[string]*docker.Network{"safeclaw": n}}
			m, r := newTestManager(t, w)
			_, err := m.Ensure(context.Background(), Options{Name: "a", NoOpen: true})
			if !errors.Is(err, ErrForeignNetwork) || !strings.Contains(err.Error(), "docker network rm safeclaw") {
				t.Errorf("err = %v, want ErrForeignNetwork with the fix", err)
			}
			if hasCall(r, "run ") || hasCall(r, "network create") {
				t.Errorf("calls = %v", r.Commands())
			}
		})
	}
}

// A recreate checks the network before removing the old container.
func TestEnsureRecreateRefusesForeignNetworkFirst(t *testing.T) {
	foreign := sessionNet()
	foreign.Labels = nil
	w := &world{image: "img", native: true, containers: map[string]*fakeContainer{
		"safeclaw-old": {Running: true, Port: 7705, Image: "img"},
	}, networks: map[string]*docker.Network{"safeclaw": foreign}}
	m, r := newTestManager(t, w)
	if _, err := m.Ensure(context.Background(), Options{Name: "old", Volume: "/new:/home/sclaw/new", NoOpen: true}); !errors.Is(err, ErrForeignNetwork) {
		t.Errorf("err = %v, want ErrForeignNetwork", err)
	}
	if hasCall(r, "rm ") || w.containers["safeclaw-old"] == nil {
		t.Errorf("old container removed: %v", r.Commands())
	}
}

// A network created by another process between the inspect and the create
// is used if it is safeclaw's, and refused if not.
func TestEnsureNetworkCreateRace(t *testing.T) {
	w := &world{image: "img", native: true, containers: map[string]*fakeContainer{}, failNetworkCreate: sessionNet()}
	m, r := newTestManager(t, w)
	if _, err := m.Ensure(context.Background(), Options{Name: "a", NoOpen: true}); err != nil {
		t.Fatalf("raced with safeclaw's network: %v", err)
	}
	if !hasCall(r, "run ") {
		t.Error("no run")
	}

	foreign := sessionNet()
	foreign.Labels = nil
	w = &world{image: "img", native: true, containers: map[string]*fakeContainer{}, failNetworkCreate: foreign}
	m, r = newTestManager(t, w)
	if _, err := m.Ensure(context.Background(), Options{Name: "a", NoOpen: true}); !errors.Is(err, ErrForeignNetwork) {
		t.Errorf("raced with a foreign network: err = %v", err)
	}
	if hasCall(r, "run ") {
		t.Error("ran on a foreign network")
	}
}

// A session on docker's default bridge is warned about and moved to the
// session network when it is recreated.
func TestEnsureLegacyBridgeSession(t *testing.T) {
	w := &world{image: "img", native: true, containers: map[string]*fakeContainer{
		"safeclaw-old": {Running: true, Port: 7705, Image: "img"},
	}}
	m, r := newTestManager(t, w)
	var out bytes.Buffer
	m.Out = &out
	ctx := context.Background()
	if _, err := m.Ensure(ctx, Options{Name: "old", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Warning: session old is on docker's default bridge") {
		t.Errorf("no warning:\n%s", out.String())
	}
	if hasCall(r, "rm ") || hasCall(r, "network ") {
		t.Errorf("kept session was changed: %v", r.Commands())
	}

	out.Reset()
	if _, err := m.Ensure(ctx, Options{Name: "old", Volume: "/new:/home/sclaw/new", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	c := w.containers["safeclaw-old"]
	if c.NetworkMode != "safeclaw" || strings.Contains(out.String(), "default bridge") {
		t.Errorf("recreated on %q:\n%s", c.NetworkMode, out.String())
	}
}

// A stopped session whose network was removed, such as by `docker network
// prune`, gets it back before it starts, and is reattached to it, since
// docker keeps the removed network's ID on the container.
func TestEnsureStartRecreatesMissingNetwork(t *testing.T) {
	w := &world{image: "img", native: true, containers: map[string]*fakeContainer{
		"safeclaw-a": {Port: 7705, Image: "img", NetworkMode: "safeclaw", Nets: map[string]docker.Endpoint{"safeclaw": {NetworkID: "gone"}}},
	}}
	m, r := newTestManager(t, w)
	if _, err := m.Ensure(context.Background(), Options{Name: "a", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	cmds := r.Commands()
	order := []int{
		slices.Index(cmds, createSessionNetwork),
		slices.Index(cmds, "network disconnect safeclaw safeclaw-a"),
		slices.Index(cmds, "network connect safeclaw safeclaw-a"),
		slices.Index(cmds, "start safeclaw-a"),
	}
	if slices.Contains(order, -1) || !slices.IsSorted(order) {
		t.Errorf("calls = %v, want the network created and reattached before the start", cmds)
	}
}

// A stopped session still attached to the current session network is
// started as is.
func TestEnsureStartKeepsCurrentNetwork(t *testing.T) {
	w := &world{image: "img", native: true, containers: map[string]*fakeContainer{
		"safeclaw-a": {Port: 7705, Image: "img", NetworkMode: "safeclaw", Nets: map[string]docker.Endpoint{"safeclaw": {NetworkID: "net-1"}}},
	}, networks: map[string]*docker.Network{"safeclaw": sessionNet()}}
	m, r := newTestManager(t, w)
	if _, err := m.Ensure(context.Background(), Options{Name: "a", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if hasCall(r, "network create") || hasCall(r, "network disconnect") || hasCall(r, "network connect") || !hasCall(r, "start safeclaw-a") {
		t.Errorf("calls = %v", r.Commands())
	}
}

func TestEnsureStartRefusesForeignNetwork(t *testing.T) {
	foreign := sessionNet()
	foreign.Options = nil
	w := &world{image: "img", native: true, containers: map[string]*fakeContainer{
		"safeclaw-a": {Port: 7705, Image: "img", NetworkMode: "safeclaw"},
	}, networks: map[string]*docker.Network{"safeclaw": foreign}}
	m, r := newTestManager(t, w)
	if _, err := m.Ensure(context.Background(), Options{Name: "a", NoOpen: true}); !errors.Is(err, ErrForeignNetwork) {
		t.Errorf("err = %v, want ErrForeignNetwork", err)
	}
	if hasCall(r, "start ") {
		t.Errorf("started on a foreign network: %v", r.Commands())
	}
}

func TestNetOffOnSessionNetwork(t *testing.T) {
	c := &fakeContainer{Running: true, Port: 7681, Image: "img", NetworkMode: "safeclaw", ID: "c1"}
	w := netWorld(c)
	w.networks = map[string]*docker.Network{"safeclaw": sessionNet()}
	m, r := newTestManager(t, w)
	ctx := context.Background()

	if _, err := m.NetOff(ctx, "n", NetOffOptions{Owner: "job"}); err != nil {
		t.Fatal(err)
	}
	if !hasCall(r, "network disconnect safeclaw safeclaw-n") || len(c.Nets) != 0 {
		t.Errorf("calls = %v, nets %v", r.Commands(), c.Nets)
	}
	// Nothing is attached to it meanwhile, so it can be removed.
	delete(w.networks, "safeclaw")

	res, err := m.NetOn(ctx, "n", NetOnOptions{Owner: "job"})
	if err != nil || res.Offline || !slices.Equal(res.Networks, []string{"safeclaw"}) {
		t.Fatalf("net on = %+v, %v", res, err)
	}
	cmds := r.Commands()
	create, connect := slices.Index(cmds, createSessionNetwork), slices.Index(cmds, "network connect safeclaw safeclaw-n")
	if create < 0 || connect < 0 || create > connect {
		t.Errorf("calls = %v, want the network created before the connect", cmds)
	}
}

func TestNetOnRefusesForeignSessionNetwork(t *testing.T) {
	c := &fakeContainer{Running: true, Port: 7681, Image: "img", NetworkMode: "safeclaw", ID: "c1"}
	w := netWorld(c)
	w.networks = map[string]*docker.Network{"safeclaw": sessionNet()}
	m, r := newTestManager(t, w)
	ctx := context.Background()
	if _, err := m.NetOff(ctx, "n", NetOffOptions{}); err != nil {
		t.Fatal(err)
	}
	foreign := sessionNet()
	foreign.Options[config.BridgeICCOption] = "true"
	w.networks["safeclaw"] = foreign

	if _, err := m.NetOn(ctx, "n", NetOnOptions{}); !errors.Is(err, ErrForeignNetwork) {
		t.Errorf("err = %v, want ErrForeignNetwork", err)
	}
	if hasCall(r, "network connect") || len(c.Nets) != 0 {
		t.Errorf("reconnected to a foreign network: %v", r.Commands())
	}
	// The hold is kept, so the session still counts as held.
	if st, err := m.readState("n"); err != nil || st == nil || len(st.Holds) != 1 {
		t.Errorf("state = %+v, %v", st, err)
	}
}

// Without saved state, net on reconnects a session to the network it was
// created on, the session network.
func TestNetOnWithoutStateUsesSessionNetwork(t *testing.T) {
	c := &fakeContainer{Image: "img", Offline: true, NetworkMode: "safeclaw"}
	m, r := newTestManager(t, netWorld(c))
	res, err := m.NetOn(context.Background(), "n", NetOnOptions{})
	if err != nil || res.Offline || !slices.Equal(res.Networks, []string{"safeclaw"}) {
		t.Fatalf("net on = %+v, %v", res, err)
	}
	if !hasCall(r, createSessionNetwork) || !hasCall(r, "network connect safeclaw safeclaw-n") {
		t.Errorf("calls = %v", r.Commands())
	}
}

// The session network is shared, so removing a session leaves it.
func TestDeleteKeepsSessionNetwork(t *testing.T) {
	c := &fakeContainer{Running: true, Port: 7681, Image: "img", NetworkMode: "safeclaw"}
	w := netWorld(c)
	w.networks = map[string]*docker.Network{"safeclaw": sessionNet()}
	m, r := newTestManager(t, w)
	if err := m.Delete(context.Background(), "n", true); err != nil {
		t.Fatal(err)
	}
	if hasCall(r, "network ") || w.networks["safeclaw"] == nil {
		t.Errorf("calls = %v", r.Commands())
	}
}

func TestOnDefaultBridge(t *testing.T) {
	for mode, want := range map[string]bool{"": true, "default": true, "bridge": true, "safeclaw": false, "host": false, "none": false, "work": false} {
		var c docker.Container
		c.HostConfig.NetworkMode = mode
		if got := onDefaultBridge(c); got != want {
			t.Errorf("%q = %v, want %v", mode, got, want)
		}
	}
	var box docker.Container
	box.Config.Labels = sandboxLabels
	box.HostConfig.NetworkMode = "bridge"
	if onDefaultBridge(box) {
		t.Error("sandbox counted as a legacy session")
	}
}
