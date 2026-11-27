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

func TestDeleteRemovesState(t *testing.T) {
	ctx := context.Background()
	m, _ := newTestManager(t, netWorld(&fakeContainer{Image: "img"}))
	if _, err := m.NetOff(ctx, "n", NetOffOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := m.Delete(ctx, "n", true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(m.statePath("n")); !os.IsNotExist(err) {
		t.Errorf("state kept: %v", err)
	}
	if _, err := os.Stat(filepath.Join(m.NetworkDir, ".lock")); err != nil {
		t.Errorf("lock file should stay: %v", err)
	}
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
