package session

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/docker"
)

func netWorld(c *fakeContainer) *world {
	return &world{image: "img", native: true, containers: map[string]*fakeContainer{"safeclaw-n": c}}
}

func TestNetOffSavesThenDisconnects(t *testing.T) {
	c := &fakeContainer{Running: true, Port: 7681, Image: "img", Nets: map[string]docker.Endpoint{
		"bridge": {},
		"work":   {Aliases: []string{"safeclaw-n", "0123456789ab", "api"}, IPAMConfig: &docker.IPAMConfig{IPv4Address: "10.1.0.5"}},
	}, ID: "0123456789abcdef"}
	w := netWorld(c)
	m, r := newTestManager(t, w)
	ctx := context.Background()

	res, err := m.NetOff(ctx, "n", NetOffOptions{Owner: "triage", Reason: "opening a pdf"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Offline || !slices.Equal(res.Networks, []string{"bridge", "work"}) || len(res.Holds) != 1 || res.Holds[0].Owner != "triage" {
		t.Errorf("result = %+v", res)
	}
	if len(c.Nets) != 0 {
		t.Errorf("still attached to %v", c.Nets)
	}
	for _, want := range []string{"network disconnect bridge safeclaw-n", "network disconnect work safeclaw-n"} {
		if !hasCall(r, want) {
			t.Errorf("missing %q in %v", want, r.Commands())
		}
	}
	st, err := m.readState("n")
	if err != nil || st == nil {
		t.Fatalf("state = %+v, %v", st, err)
	}
	if st.ContainerID != c.ID || len(st.Networks) != 2 || st.Holds[0].Reason != "opening a pdf" || st.Holds[0].Since.IsZero() {
		t.Errorf("state = %+v", st)
	}
	work := st.Networks[1]
	if work.Name != "work" || !slices.Equal(work.Aliases, []string{"api"}) || work.IPv4 != "10.1.0.5" {
		t.Errorf("saved work network = %+v, want only the alias docker did not add", work)
	}
	if info, err := os.Stat(m.statePath("n")); err != nil || info.Mode().Perm() != 0o600 {
		t.Errorf("state file mode = %v, %v", info, err)
	}

	s, err := m.Get(ctx, "n")
	if err != nil || s.Network != NetOffline || !s.IsOffline() || len(s.Holds) != 1 {
		t.Errorf("Get = %+v, %v", s, err)
	}

	// A second net off keeps the saved networks.
	if _, err := m.NetOff(ctx, "n", NetOffOptions{Owner: "other"}); err != nil {
		t.Fatal(err)
	}
	st, _ = m.readState("n")
	if len(st.Networks) != 2 || len(st.Holds) != 2 {
		t.Errorf("state after second off = %+v", st)
	}

	// Releasing one hold keeps it offline.
	res, err = m.NetOn(ctx, "n", NetOnOptions{Owner: "triage"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Offline || len(res.Holds) != 1 || res.Holds[0].Owner != "other" || len(c.Nets) != 0 {
		t.Errorf("partial release = %+v, nets %v", res, c.Nets)
	}

	// The last hold reconnects exactly the saved networks.
	res, err = m.NetOn(ctx, "n", NetOnOptions{Owner: "other"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Offline || !slices.Equal(res.Networks, []string{"bridge", "work"}) {
		t.Errorf("final release = %+v", res)
	}
	if !hasCall(r, "network connect bridge safeclaw-n") || !hasCall(r, "network connect --alias api --ip 10.1.0.5 work safeclaw-n") {
		t.Errorf("reconnect calls = %v", r.Commands())
	}
	if _, err := os.Stat(m.statePath("n")); !os.IsNotExist(err) {
		t.Errorf("state not removed: %v", err)
	}
}

func TestNetOnHeld(t *testing.T) {
	c := &fakeContainer{Running: true, Image: "img"}
	m, r := newTestManager(t, netWorld(c))
	ctx := context.Background()
	if _, err := m.NetOff(ctx, "n", NetOffOptions{Owner: "a"}); err != nil {
		t.Fatal(err)
	}
	for _, owner := range []string{"", "b"} {
		res, err := m.NetOn(ctx, "n", NetOnOptions{Owner: owner})
		if !errors.Is(err, ErrHeld) || !strings.Contains(err.Error(), "by a") {
			t.Errorf("owner %q: err = %v, want ErrHeld naming a", owner, err)
		}
		if res == nil || len(res.Holds) != 1 || !res.Offline {
			t.Errorf("owner %q: result = %+v", owner, res)
		}
	}
	if hasCall(r, "network connect") {
		t.Error("reconnected despite the hold")
	}
	res, err := m.NetOn(ctx, "n", NetOnOptions{Force: true})
	if err != nil || res.Offline || len(c.Nets) != 1 {
		t.Errorf("force = %+v, %v, nets %v", res, err, c.Nets)
	}
}

func TestNetUnnamedHoldIsShared(t *testing.T) {
	c := &fakeContainer{Running: true, Image: "img"}
	m, _ := newTestManager(t, netWorld(c))
	ctx := context.Background()
	for range 2 {
		if _, err := m.NetOff(ctx, "n", NetOffOptions{}); err != nil {
			t.Fatal(err)
		}
	}
	res, err := m.NetOn(ctx, "n", NetOnOptions{})
	if err != nil || res.Offline {
		t.Errorf("unnamed on = %+v, %v", res, err)
	}
}

func TestNetStaleStateIgnored(t *testing.T) {
	c := &fakeContainer{Running: true, Image: "img", ID: "old"}
	w := netWorld(c)
	m, r := newTestManager(t, w)
	ctx := context.Background()
	if _, err := m.NetOff(ctx, "n", NetOffOptions{Owner: "a"}); err != nil {
		t.Fatal(err)
	}
	// The session is removed and recreated under the same name.
	w.containers["safeclaw-n"] = &fakeContainer{Running: true, Image: "img", ID: "new"}
	s, _ := m.Get(ctx, "n")
	if s.Network != NetOnline || len(s.Holds) != 0 {
		t.Errorf("recreated session = %+v, want online without holds", s)
	}
	res, err := m.NetOn(ctx, "n", NetOnOptions{Owner: "b"})
	if err != nil || res.Offline || hasCall(r, "network connect") {
		t.Errorf("net on of recreated session = %+v, %v, %v", res, err, r.Commands())
	}
	if _, err := os.Stat(m.statePath("n")); !os.IsNotExist(err) {
		t.Errorf("stale state not removed: %v", err)
	}
}

func TestNetOnWithoutStateUsesNetworkMode(t *testing.T) {
	c := &fakeContainer{Image: "img", Offline: true, NetworkMode: "default"}
	m, r := newTestManager(t, netWorld(c))
	res, err := m.NetOn(context.Background(), "n", NetOnOptions{})
	if err != nil || res.Offline || !slices.Equal(res.Networks, []string{"bridge"}) {
		t.Errorf("result = %+v, %v", res, err)
	}
	if !hasCall(r, "network connect bridge safeclaw-n") {
		t.Errorf("calls = %v", r.Commands())
	}
}

func TestNetOnBridgeDropsAliases(t *testing.T) {
	s := savedNetwork{Name: "bridge", Aliases: []string{"x"}, IPv4: "172.17.0.9"}
	if opts := s.connectOptions(); len(opts.Aliases) != 0 || opts.IPv4 != "172.17.0.9" {
		t.Errorf("bridge options = %+v", opts)
	}
	s.Name = "work"
	if opts := s.connectOptions(); !slices.Equal(opts.Aliases, []string{"x"}) {
		t.Errorf("work options = %+v", opts)
	}
}

func TestNetRefusals(t *testing.T) {
	ctx := context.Background()
	cases := map[string]struct {
		c    *fakeContainer
		want error
	}{
		"host":    {&fakeContainer{Running: true, NetworkMode: "host", Nets: map[string]docker.Endpoint{"host": {}}}, ErrHostNetwork},
		"shared":  {&fakeContainer{Running: true, NetworkMode: "container:abc", Nets: map[string]docker.Endpoint{}}, ErrSharedNetwork},
		"none":    {&fakeContainer{Running: true, NetworkMode: "none", Offline: true}, ErrNoNetwork},
		"sandbox": {&fakeContainer{Running: true, Labels: sandboxLabels, NetworkMode: "none", Offline: true}, ErrIsSandbox},
	}
	for name, tc := range cases {
		m, r := newTestManager(t, netWorld(tc.c))
		if _, err := m.NetOff(ctx, "n", NetOffOptions{}); !errors.Is(err, tc.want) {
			t.Errorf("%s: off err = %v, want %v", name, err, tc.want)
		}
		if _, err := m.NetOn(ctx, "n", NetOnOptions{}); !errors.Is(err, tc.want) {
			t.Errorf("%s: on err = %v, want %v", name, err, tc.want)
		}
		if hasCall(r, "network ") {
			t.Errorf("%s: changed networks: %v", name, r.Commands())
		}
	}
	m, _ := newTestManager(t, &world{containers: map[string]*fakeContainer{}})
	if _, err := m.NetOff(ctx, "missing", NetOffOptions{}); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing: err = %v", err)
	}
}

func TestNetStoppedSession(t *testing.T) {
	c := &fakeContainer{Port: 7681, Image: "img"}
	w := netWorld(c)
	w.attachOnStart = true
	m, r := newTestManager(t, w)
	ctx := context.Background()
	if _, err := m.NetOff(ctx, "n", NetOffOptions{Owner: "a"}); err != nil {
		t.Fatal(err)
	}
	// Starting it keeps it offline, even if docker attached a network.
	res, err := m.Ensure(ctx, Options{Name: "n", NoOpen: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Offline || len(c.Nets) != 0 {
		t.Errorf("started session = %+v, nets %v", res, c.Nets)
	}
	cmds := r.Commands()
	start := slices.Index(cmds, "start safeclaw-n")
	if start < 0 || !slices.Contains(cmds[start:], "network disconnect bridge safeclaw-n") {
		t.Errorf("not disconnected after start: %v", cmds)
	}
}

func TestEnsureOffline(t *testing.T) {
	ctx := context.Background()
	c := &fakeContainer{Running: true, Port: 7681, Image: "img"}
	w := netWorld(c)
	m, r := newTestManager(t, w)
	if _, err := m.NetOff(ctx, "n", NetOffOptions{}); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	m.Out = &out
	res, err := m.Ensure(ctx, Options{Name: "n", NoOpen: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Offline || !strings.Contains(out.String(), "safeclaw net on n") {
		t.Errorf("result = %+v, output %q", res, out.String())
	}

	for _, opts := range []Options{
		{Name: "n", Volume: "/tmp:/tmp", NoOpen: true},
		{Name: "n", Secrets: &SecretSet{Limited: true}, NoOpen: true},
	} {
		if _, err := m.Ensure(ctx, opts); !errors.Is(err, ErrOffline) {
			t.Errorf("recreate %+v: err = %v, want ErrOffline", opts, err)
		}
	}
	if hasCall(r, "rm ") {
		t.Error("offline session removed")
	}
}

func TestEnsureCreateRemovesStaleState(t *testing.T) {
	ctx := context.Background()
	c := &fakeContainer{Running: true, Image: "img"}
	w := netWorld(c)
	m, _ := newTestManager(t, w)
	if _, err := m.NetOff(ctx, "n", NetOffOptions{Owner: "a"}); err != nil {
		t.Fatal(err)
	}
	delete(w.containers, "safeclaw-n") // removed outside safeclaw
	res, err := m.Ensure(ctx, Options{Name: "n", NoOpen: true})
	if err != nil || res.Offline {
		t.Fatalf("result = %+v, %v", res, err)
	}
	if _, err := os.Stat(m.statePath("n")); !os.IsNotExist(err) {
		t.Errorf("stale state kept: %v", err)
	}
}

func TestDeleteRefusesHeld(t *testing.T) {
	ctx := context.Background()
	w := netWorld(&fakeContainer{Image: "img"})
	m, r := newTestManager(t, w)
	if _, err := m.NetOff(ctx, "n", NetOffOptions{Owner: "triage"}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.NetOff(ctx, "n", NetOffOptions{}); err != nil {
		t.Fatal(err)
	}
	err := m.Delete(ctx, "n", true)
	if !errors.Is(err, ErrHeld) || !strings.Contains(err.Error(), "by triage, unnamed") || !strings.Contains(err.Error(), "--release-holds") {
		t.Fatalf("err = %v, want it held naming the holders", err)
	}
	if hasCall(r, "rm ") || w.containers["safeclaw-n"] == nil {
		t.Error("held session removed")
	}
	if st, err := m.readState("n"); err != nil || st == nil || len(st.Holds) != 2 {
		t.Errorf("state = %+v, %v; want the holds kept", st, err)
	}

	if err := m.DeleteWith(ctx, "n", DeleteOptions{Force: true, ReleaseHolds: true}); err != nil {
		t.Fatal(err)
	}
	if w.containers["safeclaw-n"] != nil {
		t.Error("session not removed")
	}
	if _, err := os.Stat(m.statePath("n")); !os.IsNotExist(err) {
		t.Errorf("state kept: %v", err)
	}
	if _, err := os.Stat(filepath.Join(m.NetworkDir, ".lock")); err != nil {
		t.Errorf("lock file should stay: %v", err)
	}
}

// A session offline without holds, for example after a raw docker network
// disconnect, is removed as before, along with any state an earlier
// container left.
func TestDeleteOfflineWithoutHolds(t *testing.T) {
	ctx := context.Background()
	w := netWorld(&fakeContainer{Image: "img", Offline: true})
	m, _ := newTestManager(t, w)
	if err := m.writeState("n", &netState{ContainerID: "earlier", Holds: []Hold{{Owner: "a"}}}); err != nil {
		t.Fatal(err)
	}
	if err := m.Delete(ctx, "n", true); err != nil {
		t.Fatal(err)
	}
	if w.containers["safeclaw-n"] != nil {
		t.Error("session not removed")
	}
	if _, err := os.Stat(m.statePath("n")); !os.IsNotExist(err) {
		t.Errorf("stale state kept: %v", err)
	}
}

// Delete holds the network lock while it removes the container, so no
// Ensure or net off can create or take offline a container with the name
// in between, and it keeps state that belongs to a container that has the
// name once it is removed.
func TestDeleteKeepsNewContainersState(t *testing.T) {
	ctx := context.Background()
	w := netWorld(&fakeContainer{Image: "img"})
	m, _ := newTestManager(t, w)
	locked := false
	w.onRemove = func(name string) {
		probe, cancel := context.WithTimeout(ctx, 3*lockRetry)
		defer cancel()
		unlock, err := lockFileCtx(probe, m.netDir(), ".lock")
		if err == nil {
			unlock()
		}
		locked = errors.Is(err, context.DeadlineExceeded)
		// Something outside safeclaw creates a container with the name,
		// whose state is then written.
		w.containers[name] = &fakeContainer{Image: "img", ID: "c2"}
		if err := m.writeState("n", &netState{ContainerID: "c2", Holds: []Hold{{Owner: "b"}}}); err != nil {
			t.Error(err)
		}
	}
	if err := m.Delete(ctx, "n", true); err != nil {
		t.Fatal(err)
	}
	if !locked {
		t.Error("removed without the network lock")
	}
	st, err := m.readState("n")
	if err != nil || st == nil || st.ContainerID != "c2" || len(st.Holds) != 1 {
		t.Errorf("state = %+v, %v; want the new container's kept", st, err)
	}
}

// Unreadable state fails closed: the session may be held, so it is not
// removed, recreated, started, relayed, or removed as stale, and listings
// show it held by unknown owners.
func TestUnreadableStateFailsClosed(t *testing.T) {
	ctx := context.Background()
	c := &fakeContainer{Running: true, Port: 7681, Image: "img"}
	w := netWorld(c)
	m, r := newTestManager(t, w)
	if _, err := m.Ensure(ctx, Options{Name: "n", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(m.statePath("n"), []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	isHeld := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, ErrUnreadableState) || !strings.Contains(err.Error(), m.statePath("n")) {
			t.Errorf("%s: err = %v, want it held naming the state file", what, err)
		}
	}

	held, err := m.OfflineOrHeld(*mustInspect(t, m, "safeclaw-n"))
	if !held {
		t.Error("OfflineOrHeld = false")
	}
	isHeld("OfflineOrHeld", err)
	_, err = m.NetOff(ctx, "n", NetOffOptions{})
	isHeld("net off", err)
	_, err = m.NetOn(ctx, "n", NetOnOptions{Force: true})
	isHeld("net on", err)

	r.Calls = nil
	_, err = m.Ensure(ctx, Options{Name: "n", NoOpen: true})
	isHeld("run", err)
	_, err = m.Ensure(ctx, Options{Name: "n", NoOpen: true, Volume: t.TempDir() + ":/home/sclaw/p"})
	isHeld("recreate", err)
	if hasCall(r, "rm ") || hasCall(r, "run ") || hasCall(r, "exec ") {
		t.Errorf("run acted on it: %v", r.Commands())
	}

	_, err = m.Terminal(ctx, "n")
	isHeld("terminal", err)
	if !errors.Is(err, ErrNoTerminal) {
		t.Errorf("terminal err = %v, want ErrNoTerminal", err)
	}

	removed, err := m.RemoveStale(ctx, *mustInspect(t, m, "safeclaw-n"))
	if removed {
		t.Error("removed as stale")
	}
	isHeld("build --recreate", err)

	s, err := m.Get(ctx, "n")
	if err != nil || len(s.Holds) != 1 || s.Holds[0].Label() != "unknown" {
		t.Errorf("Get = %+v, %v; want an unknown hold", s, err)
	}
	list, err := m.List(ctx)
	if err != nil || len(list) != 1 || HoldLabels(list[0].Holds)[0] != "unknown" {
		t.Errorf("List = %+v, %v; want an unknown hold", list, err)
	}

	err = m.Delete(ctx, "n", true)
	isHeld("rm", err)
	if w.containers["safeclaw-n"] == nil {
		t.Fatal("removed")
	}
	if err := m.DeleteWith(ctx, "n", DeleteOptions{Force: true, ReleaseHolds: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(m.statePath("n")); !os.IsNotExist(err) {
		t.Errorf("unreadable state kept: %v", err)
	}
}

// A held session that is still attached, after a failed disconnect, gets
// no terminal, like an offline one.
func TestTerminalRefusesHeld(t *testing.T) {
	ctx := context.Background()
	w := netWorld(twoNetContainer())
	w.failDisconnect = map[string]int{"work": 2}
	m, _ := newTestManager(t, w)
	if _, err := m.Ensure(ctx, Options{Name: "n", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.Terminal(ctx, "n"); err != nil {
		t.Fatalf("online terminal: %v", err)
	}
	if _, err := m.NetOff(ctx, "n", NetOffOptions{Owner: "triage"}); !errors.Is(err, ErrStillOnline) {
		t.Fatalf("net off err = %v, want it still attached", err)
	}
	if _, err := m.Terminal(ctx, "n"); !errors.Is(err, ErrNoTerminal) || !strings.Contains(err.Error(), "held offline by triage") {
		t.Errorf("terminal err = %v, want it refused naming the holder", err)
	}
}

func mustInspect(t *testing.T, m *Manager, name string) *docker.Container {
	t.Helper()
	c, err := m.Docker.InspectOne(context.Background(), name)
	if err != nil || c == nil {
		t.Fatal(c, err)
	}
	return c
}

func TestListNetwork(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-on":   {Running: true},
		"safeclaw-off":  {Running: true},
		"safeclaw-host": {Running: true, NetworkMode: "host", Nets: map[string]docker.Endpoint{"host": {}}},
		"safeclaw-box":  {Running: true, Labels: sandboxLabels, NetworkMode: "none", Offline: true},
	}}
	m, _ := newTestManager(t, w)
	ctx := context.Background()
	if _, err := m.NetOff(ctx, "off", NetOffOptions{Owner: "job"}); err != nil {
		t.Fatal(err)
	}
	list, err := m.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, s := range list {
		got[s.Name] = s.Network + ":" + strings.Join(HoldLabels(s.Holds), ",")
	}
	want := map[string]string{"on": "online:", "off": "offline:job", "host": "host:", "box": "none:"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
}

func twoNetContainer() *fakeContainer {
	return &fakeContainer{Running: true, Port: 7681, Image: "img", ID: "c1", Nets: map[string]docker.Endpoint{"bridge": {}, "work": {}}}
}

func TestNetOffRetriesFailedDisconnect(t *testing.T) {
	c := twoNetContainer()
	w := netWorld(c)
	w.failDisconnect = map[string]int{"work": 1}
	m, _ := newTestManager(t, w)
	res, err := m.NetOff(context.Background(), "n", NetOffOptions{Owner: "a"})
	if err != nil || !res.Offline || len(c.Nets) != 0 {
		t.Errorf("result = %+v, %v, nets %v", res, err, c.Nets)
	}
}

func TestNetOffPartialFailureKeepsHold(t *testing.T) {
	ctx := context.Background()
	c := twoNetContainer()
	w := netWorld(c)
	w.failDisconnect = map[string]int{"work": 2}
	m, r := newTestManager(t, w)
	var out strings.Builder
	m.Out = &out

	res, err := m.NetOff(ctx, "n", NetOffOptions{Owner: "a"})
	if !errors.Is(err, ErrStillOnline) || !strings.Contains(err.Error(), "attached to work") || !strings.Contains(err.Error(), "safeclaw net off n") {
		t.Fatalf("err = %v, want ErrStillOnline naming work", err)
	}
	if res == nil || res.Offline || len(res.Holds) != 1 {
		t.Errorf("result = %+v", res)
	}
	if !strings.Contains(out.String(), "held offline by a, but is still attached to work") {
		t.Errorf("output = %q", out.String())
	}
	if _, ok := c.Nets["bridge"]; ok {
		t.Error("bridge not disconnected after work failed")
	}
	if _, ok := c.Nets["work"]; !ok {
		t.Fatal("work disconnected despite the failures")
	}
	if hasCall(r, "network connect") {
		t.Error("rolled back to online")
	}
	st, _ := m.readState("n")
	if st == nil || len(st.Holds) != 1 || len(st.Networks) != 2 {
		t.Errorf("state = %+v, want the hold and both networks", st)
	}
	s, _ := m.Get(ctx, "n")
	if s.Network != NetOnline || len(s.Holds) != 1 {
		t.Errorf("Get = %+v, want online with the hold", s)
	}

	// A held session can't be recreated while it is still attached.
	if _, err := m.Ensure(ctx, Options{Name: "n", Volume: "/tmp:/tmp", NoOpen: true}); !errors.Is(err, ErrOffline) {
		t.Errorf("recreate err = %v, want ErrOffline", err)
	}

	// Running it again finishes the disconnect.
	ensured, err := m.Ensure(ctx, Options{Name: "n", NoOpen: true})
	if err != nil {
		t.Fatal(err)
	}
	if !ensured.Offline || len(c.Nets) != 0 {
		t.Errorf("Ensure = %+v, nets %v", ensured, c.Nets)
	}
	if hasCall(r, "rm ") {
		t.Error("held session removed")
	}
	// Both networks are restored once the hold is released.
	on, err := m.NetOn(ctx, "n", NetOnOptions{Owner: "a"})
	if err != nil || on.Offline || !slices.Equal(on.Networks, []string{"bridge", "work"}) {
		t.Errorf("NetOn = %+v, %v", on, err)
	}
}

func TestEnsureRunningHeldReconnected(t *testing.T) {
	ctx := context.Background()
	c := &fakeContainer{Running: true, Port: 7681, Image: "img"}
	m, r := newTestManager(t, netWorld(c))
	if _, err := m.NetOff(ctx, "n", NetOffOptions{Owner: "a"}); err != nil {
		t.Fatal(err)
	}
	// Something reconnected it behind safeclaw's back.
	c.networks()["bridge"] = docker.Endpoint{}
	res, err := m.Ensure(ctx, Options{Name: "n", NoOpen: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Offline || len(c.Nets) != 0 {
		t.Errorf("result = %+v, nets %v", res, c.Nets)
	}
	cmds := r.Commands()
	if n := slices.Index(cmds, "network disconnect bridge safeclaw-n"); n < 0 || !slices.Contains(cmds[n+1:], "network disconnect bridge safeclaw-n") {
		t.Errorf("not disconnected again: %v", cmds)
	}
}

func TestRemoveStale(t *testing.T) {
	ctx := context.Background()
	c := twoNetContainer()
	w := netWorld(c)
	w.failDisconnect = map[string]int{"work": 2}
	m, r := newTestManager(t, w)
	_, _ = m.NetOff(ctx, "n", NetOffOptions{Owner: "a"})
	listed, err := m.Docker.InspectOne(ctx, "safeclaw-n")
	if err != nil || listed == nil {
		t.Fatal(listed, err)
	}

	// Held but still attached.
	removed, err := m.RemoveStale(ctx, *listed)
	if removed || !errors.Is(err, ErrOffline) || !strings.Contains(err.Error(), "by a") {
		t.Errorf("held: removed %v, err %v", removed, err)
	}
	if hasCall(r, "rm ") {
		t.Error("held session removed")
	}

	// Replaced since it was listed.
	w.containers["safeclaw-n"] = &fakeContainer{Running: true, Image: "img", ID: "c2"}
	if removed, err := m.RemoveStale(ctx, *listed); removed || err != nil {
		t.Errorf("replaced: removed %v, err %v", removed, err)
	}

	// Online, with state left by the earlier container.
	listed, _ = m.Docker.InspectOne(ctx, "safeclaw-n")
	if removed, err := m.RemoveStale(ctx, *listed); !removed || err != nil {
		t.Errorf("online: removed %v, err %v", removed, err)
	}
	if !hasCall(r, "rm -v -f safeclaw-n") {
		t.Errorf("calls = %v", r.Commands())
	}
	if _, err := os.Stat(m.statePath("n")); !os.IsNotExist(err) {
		t.Errorf("state kept: %v", err)
	}
}
