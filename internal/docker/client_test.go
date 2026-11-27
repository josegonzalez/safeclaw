package docker_test

import (
	"context"
	"reflect"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
)

const inspectJSON = `[{
  "Id": "abc123def456789",
  "Name": "/safeclaw-work",
  "Image": "sha256:abc",
  "Config": {"Labels": {"safeclaw.type": "sandbox", "safeclaw.secrets": ""}},
  "State": {"Status": "exited", "Running": false},
  "HostConfig": {"PortBindings": {"7681/tcp": [{"HostIp": "127.0.0.1", "HostPort": "7683"}]}, "AutoRemove": true, "NetworkMode": "bridge"},
  "NetworkSettings": {"Networks": {
    "bridge": {"Aliases": null, "IPAMConfig": null},
    "work": {"Aliases": ["safeclaw-work", "api"], "Links": ["db:db"], "IPAMConfig": {"IPv4Address": "10.1.0.5"}}
  }},
  "Mounts": [
    {"Type": "bind", "Source": "/Users/me/.config/safeclaw/sessions/work", "Destination": "/home/sclaw/.claude/projects"},
    {"Type": "bind", "Source": "/Users/me/proj", "Destination": "/home/sclaw/proj"},
    {"Type": "volume", "Source": "/var/lib/docker/volumes/x", "Destination": "/data"}
  ]
}]`

func TestParseInspect(t *testing.T) {
	cs, err := docker.ParseInspect([]byte(inspectJSON))
	if err != nil {
		t.Fatal(err)
	}
	c := cs[0]
	if c.ShortName() != "safeclaw-work" {
		t.Errorf("name = %q", c.ShortName())
	}
	if got := c.HostPort(7681); got != 7683 {
		t.Errorf("HostPort = %d, want 7683 (from bindings, even when stopped)", got)
	}
	if got := c.HostPort(22); got != 0 {
		t.Errorf("HostPort(22) = %d", got)
	}
	if got := c.Label("safeclaw.type"); got != "sandbox" {
		t.Errorf("Label = %q, want sandbox", got)
	}
	if got := c.Label("missing"); got != "" {
		t.Errorf("Label(missing) = %q", got)
	}
	if v, ok := c.LookupLabel("safeclaw.secrets"); !ok || v != "" {
		t.Errorf("LookupLabel(empty) = %q, %v", v, ok)
	}
	if _, ok := c.LookupLabel("missing"); ok {
		t.Error("LookupLabel(missing) found a label")
	}
	if !c.HostConfig.AutoRemove {
		t.Error("AutoRemove = false, want true")
	}
	if c.ID != "abc123def456789" || c.HostConfig.NetworkMode != "bridge" {
		t.Errorf("ID, NetworkMode = %q, %q", c.ID, c.HostConfig.NetworkMode)
	}
	work := c.NetworkSettings.Networks["work"]
	if len(c.NetworkSettings.Networks) != 2 || !reflect.DeepEqual(work.Aliases, []string{"safeclaw-work", "api"}) ||
		work.IPAMConfig == nil || work.IPAMConfig.IPv4Address != "10.1.0.5" || !reflect.DeepEqual(work.Links, []string{"db:db"}) {
		t.Errorf("Networks = %+v", c.NetworkSettings.Networks)
	}
	want := []string{"/Users/me/proj:/home/sclaw/proj"}
	if got := c.BindMounts("/home/sclaw/.claude/projects"); !reflect.DeepEqual(got, want) {
		t.Errorf("BindMounts = %v, want %v", got, want)
	}
}

func TestContainerNamesFiltersPrefix(t *testing.T) {
	r := &dockertest.Runner{Handler: func(args []string, _ string) ([]byte, error) {
		return []byte("safeclaw-a\nmy-safeclaw-b\nsafeclaw-c\n\n"), nil
	}}
	names, err := r.Client().ContainerNames(context.Background(), "safeclaw-")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"safeclaw-a", "safeclaw-c"}; !reflect.DeepEqual(names, want) {
		t.Errorf("names = %v, want %v", names, want)
	}
}

func TestImageIDMissing(t *testing.T) {
	r := &dockertest.Runner{Handler: func(args []string, _ string) ([]byte, error) {
		return nil, dockertest.NotFound(args)
	}}
	id, err := r.Client().ImageID(context.Background(), "safeclaw")
	if err != nil || id != "" {
		t.Errorf("ImageID = %q, %v; want empty, nil", id, err)
	}
}

func TestParseEvent(t *testing.T) {
	ev, ok := docker.ParseEvent([]byte(`{"Type":"container","Action":"die","Actor":{"Attributes":{"name":"safeclaw-x"}}}`))
	if !ok || ev.Action != "die" || ev.Name != "safeclaw-x" {
		t.Errorf("ParseEvent = %+v, %v", ev, ok)
	}
	if ev.Type != "container" || ev.Container != "" {
		t.Errorf("container event = %+v", ev)
	}
	ev, ok = docker.ParseEvent([]byte(`{"Type":"network","Action":"disconnect","Actor":{"Attributes":{"name":"bridge","container":"abc"}}}`))
	if !ok || ev.Type != "network" || ev.Action != "disconnect" || ev.Name != "bridge" || ev.Container != "abc" {
		t.Errorf("network event = %+v, %v", ev, ok)
	}
	if _, ok := docker.ParseEvent([]byte(`{"Type":"image","Action":"pull"}`)); ok {
		t.Error("image events should be ignored")
	}
	if _, ok := docker.ParseEvent([]byte(`not json`)); ok {
		t.Error("bad lines should be ignored")
	}
}

func TestEventsStream(t *testing.T) {
	r := &dockertest.Runner{Events: `{"Type":"container","Action":"start","Actor":{"Attributes":{"name":"safeclaw-a"}}}
{"Type":"container","Action":"stop","Actor":{"Attributes":{"name":"other"}}}
`}
	var got []docker.Event
	if err := r.Client().Events(context.Background(), func(e docker.Event) { got = append(got, e) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Name != "safeclaw-a" {
		t.Errorf("events = %+v", got)
	}
	if want := "events --filter type=container --filter type=network --format {{json .}}"; r.Commands()[0] != want {
		t.Errorf("events = %q, want %q", r.Commands()[0], want)
	}
}

func TestNetworkArgs(t *testing.T) {
	r := &dockertest.Runner{}
	c := r.Client()
	ctx := context.Background()
	_ = c.NetworkDisconnect(ctx, "bridge", "safeclaw-a")
	_ = c.NetworkConnect(ctx, "bridge", "safeclaw-a", docker.ConnectOptions{})
	_ = c.NetworkConnect(ctx, "work", "safeclaw-a", docker.ConnectOptions{Aliases: []string{"api"}, Links: []string{"db:db"}, IPv4: "10.1.0.5", IPv6: "fd00::5"})
	want := []string{
		"network disconnect bridge safeclaw-a",
		"network connect bridge safeclaw-a",
		"network connect --alias api --link db:db --ip 10.1.0.5 --ip6 fd00::5 work safeclaw-a",
	}
	if got := r.Commands(); !reflect.DeepEqual(got, want) {
		t.Errorf("network = %v, want %v", got, want)
	}
}

func TestExecArgs(t *testing.T) {
	r := &dockertest.Runner{}
	c := r.Client()
	_, _ = c.Exec(context.Background(), "safeclaw-a", docker.ExecOptions{Detach: true}, "ttyd", "-p", "7681")
	if got := r.Commands()[0]; got != "exec -d safeclaw-a ttyd -p 7681" {
		t.Errorf("exec = %q", got)
	}
}

func TestRemoveDropsAnonymousVolumes(t *testing.T) {
	r := &dockertest.Runner{}
	c := r.Client()
	_ = c.Remove(context.Background(), "safeclaw-a", false)
	_ = c.Remove(context.Background(), "safeclaw-b", true)
	want := []string{"rm -v safeclaw-a", "rm -v -f safeclaw-b"}
	if got := r.Commands(); !reflect.DeepEqual(got, want) {
		t.Errorf("rm = %v, want %v", got, want)
	}
}
