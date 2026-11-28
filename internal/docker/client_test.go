package docker_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
)

const inspectJSON = `[{
  "Id": "abc123def456789",
  "Name": "/safeclaw-work",
  "Image": "sha256:abc",
  "Config": {"Labels": {"safeclaw.type": "sandbox", "safeclaw.secrets": ""}},
  "State": {"Status": "exited", "Running": false},
  "HostConfig": {"PortBindings": {"7681/tcp": [{"HostIp": "127.0.0.1", "HostPort": "7683"}]}, "AutoRemove": true, "NetworkMode": "bridge", "IpcMode": "host"},
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
	if c.ID != "abc123def456789" || c.HostConfig.NetworkMode != "bridge" || c.HostConfig.IpcMode != "host" {
		t.Errorf("ID, NetworkMode, IpcMode = %q, %q, %q", c.ID, c.HostConfig.NetworkMode, c.HostConfig.IpcMode)
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

func listRunner(missing map[string]bool) *dockertest.Runner {
	return &dockertest.Runner{Handler: func(args []string, _ string) ([]byte, error) {
		if args[0] == "ps" {
			return []byte("safeclaw-a\nsafeclaw-b\nsafeclaw-c\n"), nil
		}
		var objs []string
		for _, name := range args[2:] {
			if missing[name] {
				return nil, dockertest.NotFound(args)
			}
			objs = append(objs, `{"Id":"id-`+name+`","Name":"/`+name+`"}`)
		}
		return []byte("[" + strings.Join(objs, ",") + "]"), nil
	}}
}

func listNames(cs []docker.Container) []string {
	var names []string
	for _, c := range cs {
		names = append(names, c.ShortName())
	}
	return names
}

func TestListInspectsOnce(t *testing.T) {
	r := listRunner(nil)
	cs, err := r.Client().List(context.Background(), "safeclaw-")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"safeclaw-a", "safeclaw-b", "safeclaw-c"}; !reflect.DeepEqual(listNames(cs), want) {
		t.Errorf("List = %v, want %v", listNames(cs), want)
	}
	want := []string{"ps -a --filter name=safeclaw- --format {{.Names}}", "container inspect safeclaw-a safeclaw-b safeclaw-c"}
	if got := r.Commands(); !reflect.DeepEqual(got, want) {
		t.Errorf("commands = %q, want %q", got, want)
	}
}

func TestListSkipsRemovedContainers(t *testing.T) {
	r := listRunner(map[string]bool{"safeclaw-b": true})
	cs, err := r.Client().List(context.Background(), "safeclaw-")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"safeclaw-a", "safeclaw-c"}; !reflect.DeepEqual(listNames(cs), want) {
		t.Errorf("List = %v, want %v", listNames(cs), want)
	}
	if cs[0].ID != "id-safeclaw-a" || cs[1].ID != "id-safeclaw-c" {
		t.Errorf("IDs = %q, %q", cs[0].ID, cs[1].ID)
	}
	for _, name := range []string{"safeclaw-a", "safeclaw-b", "safeclaw-c"} {
		if _, ok := r.Find("container inspect " + name); !ok {
			t.Errorf("%s not inspected on its own: %q", name, r.Commands())
		}
	}
}

func TestListFailsOnOtherErrors(t *testing.T) {
	boom := &docker.Error{Args: []string{"container"}, Stderr: "Cannot connect to the Docker daemon", Err: io.EOF}
	r := &dockertest.Runner{Handler: func(args []string, _ string) ([]byte, error) {
		if args[0] == "ps" {
			return []byte("safeclaw-a\nsafeclaw-b\n"), nil
		}
		if len(args) > 3 {
			return nil, dockertest.NotFound(args)
		}
		return nil, boom
	}}
	if _, err := r.Client().List(context.Background(), "safeclaw-"); !errors.Is(err, boom) {
		t.Errorf("List error = %v, want %v", err, boom)
	}
}

func TestListSkipsOversizedContainers(t *testing.T) {
	tooLarge := func(args []string) error {
		return &docker.Error{Args: args, Err: docker.ErrOutputTooLarge}
	}
	r := &dockertest.Runner{Handler: func(args []string, _ string) ([]byte, error) {
		switch {
		case args[0] == "ps":
			return []byte("safeclaw-a\nsafeclaw-b\n"), nil
		case len(args) > 3, args[2] == "safeclaw-b":
			return nil, tooLarge(args)
		}
		return []byte(`[{"Id":"id-a","Name":"/safeclaw-a"}]`), nil
	}}
	c := r.Client()
	var warnings []string
	c.Warnf = func(format string, args ...any) { warnings = append(warnings, fmt.Sprintf(format, args...)) }
	cs, err := c.List(context.Background(), "safeclaw-")
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"safeclaw-a"}; !reflect.DeepEqual(listNames(cs), want) {
		t.Errorf("List = %v, want %v", listNames(cs), want)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "safeclaw-b") {
		t.Errorf("warnings = %q, want one naming safeclaw-b", warnings)
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
	ev, ok = docker.ParseEvent([]byte(`{"Type":"container","Action":"destroy","Actor":{"ID":"def","Attributes":{"name":"safeclaw-x"}}}`))
	if !ok || ev.Action != "destroy" || ev.Container != "def" {
		t.Errorf("container event with ID = %+v, %v", ev, ok)
	}
	ev, ok = docker.ParseEvent([]byte(`{"Type":"network","Action":"disconnect","Actor":{"ID":"netid","Attributes":{"name":"bridge","container":"abc"}}}`))
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

const startEvent = `{"Type":"container","Action":"start","Actor":{"Attributes":{"name":"safeclaw-a"}}}`

func TestEventsSkipsUnreadableLines(t *testing.T) {
	huge := `{"Type":"container","Action":"start","Actor":{"Attributes":{"name":"` + strings.Repeat("x", docker.MaxEventLine) + `"}}}`
	r := &dockertest.Runner{Events: huge + "\nnot json\n\n" + startEvent + "\n" + huge}
	var got []docker.Event
	if err := r.Client().Events(context.Background(), func(e docker.Event) { got = append(got, e) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 4 {
		t.Fatalf("events = %d, want 4: %+v", len(got), got)
	}
	if !errors.Is(got[0].Err, docker.ErrEventTooLarge) || got[0].Name != "" {
		t.Errorf("oversized line = %+v, want ErrEventTooLarge", got[0])
	}
	if got[1].Err == nil {
		t.Errorf("garbled line = %+v, want an error", got[1])
	}
	if got[2].Err != nil || got[2].Action != "start" || got[2].Name != "safeclaw-a" {
		t.Errorf("event after the bad lines = %+v", got[2])
	}
	if !errors.Is(got[3].Err, docker.ErrEventTooLarge) {
		t.Errorf("oversized last line = %+v, want ErrEventTooLarge", got[3])
	}
}

type failingReader struct{ err error }

func (r failingReader) Read([]byte) (int, error) { return 0, r.err }

func TestEventsKillsDockerOnReadError(t *testing.T) {
	boom := errors.New("read failed")
	r := &dockertest.Runner{StreamHandler: func(ctx context.Context, _ []string) (io.ReadCloser, func() error, error) {
		out := io.MultiReader(strings.NewReader(startEvent+"\n"), failingReader{boom})
		// Like docker, the stream only ends when the process is killed.
		return io.NopCloser(out), func() error { <-ctx.Done(); return ctx.Err() }, nil
	}}
	done := make(chan error, 1)
	var got []docker.Event
	go func() {
		done <- r.Client().Events(context.Background(), func(e docker.Event) { got = append(got, e) })
	}()
	select {
	case err := <-done:
		if !errors.Is(err, boom) {
			t.Errorf("Events = %v, want the read error", err)
		}
		if len(got) != 1 || got[0].Action != "start" {
			t.Errorf("events = %+v, want the one before the error", got)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Events is still waiting for docker after a read error")
	}
}

func TestEventsFromProcess(t *testing.T) {
	script := filepath.Join(t.TempDir(), "docker")
	body := "#!/bin/sh\nhead -c 3000000 /dev/zero | tr '\\0' x\necho\necho '" + startEvent + "'\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	c := &docker.Client{R: docker.ExecRunner{Binary: script}}
	var got []docker.Event
	if err := c.Events(context.Background(), func(e docker.Event) { got = append(got, e) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || !errors.Is(got[0].Err, docker.ErrEventTooLarge) || got[1].Name != "safeclaw-a" {
		t.Errorf("events = %+v, want a skipped line then safeclaw-a", got)
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

func TestNetworkCreateArgs(t *testing.T) {
	r := &dockertest.Runner{}
	c := r.Client()
	err := c.NetworkCreate(context.Background(), "safeclaw", docker.NetworkCreateOptions{
		Driver:  "bridge",
		Options: map[string]string{"z": "1", "com.docker.network.bridge.enable_icc": "false"},
		Labels:  map[string]string{"safeclaw.network": "sessions", "a": "b"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "network create --driver bridge --opt com.docker.network.bridge.enable_icc=false --opt z=1 --label a=b --label safeclaw.network=sessions safeclaw"
	if got := r.Commands(); len(got) != 1 || got[0] != want {
		t.Errorf("network create = %v, want %q", got, want)
	}
}

func TestNetworkInspect(t *testing.T) {
	r := &dockertest.Runner{Handler: func(args []string, _ string) ([]byte, error) {
		if args[len(args)-1] == "missing" {
			return nil, &docker.Error{Args: args, Stderr: "Error response from daemon: network missing not found", Err: errors.New("exit 1")}
		}
		return []byte(`[{"Name": "safeclaw", "Id": "n1", "Driver": "bridge", "Internal": false, "Options": {"com.docker.network.bridge.enable_icc": "false"}, "Labels": {"safeclaw.network": "sessions"}}]`), nil
	}}
	c := r.Client()
	ctx := context.Background()
	n, err := c.NetworkInspect(ctx, "safeclaw")
	if err != nil || n == nil || n.ID != "n1" || n.Driver != "bridge" || n.Options["com.docker.network.bridge.enable_icc"] != "false" || n.Labels["safeclaw.network"] != "sessions" {
		t.Errorf("inspect = %+v, %v", n, err)
	}
	if n, err := c.NetworkInspect(ctx, "missing"); n != nil || err != nil {
		t.Errorf("missing = %+v, %v, want nil, nil", n, err)
	}
	if got := r.Commands()[0]; got != "network inspect safeclaw" {
		t.Errorf("inspect args = %q", got)
	}
}

func TestExecArgs(t *testing.T) {
	r := &dockertest.Runner{}
	c := r.Client()
	_, _ = c.Exec(context.Background(), "safeclaw-a", docker.ExecOptions{Detach: true}, "ttyd", "-p", "7681")
	if got := r.Commands()[0]; got != "exec -d safeclaw-a ttyd -p 7681" {
		t.Errorf("exec = %q", got)
	}
	_, _ = c.Exec(context.Background(), "safeclaw-a", docker.ExecOptions{Stdin: strings.NewReader("x"), User: "sandbox", Workdir: "/sandbox"}, "tar", "-x")
	if got := r.Commands()[1]; got != "exec -i --user sandbox --workdir /sandbox safeclaw-a tar -x" {
		t.Errorf("exec = %q", got)
	}
}

func TestExecStream(t *testing.T) {
	failed := errors.New("exit 2")
	r := &dockertest.Runner{Handler: func(args []string, _ string) ([]byte, error) {
		return []byte("data"), failed
	}}
	out, wait, err := r.Client().ExecStream(context.Background(), "safeclaw-a",
		docker.ExecOptions{Detach: true, Stdin: strings.NewReader("x"), User: "sandbox"}, "tar", "-c")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(out)
	if string(b) != "data" {
		t.Errorf("stdout = %q", b)
	}
	if err := wait(); !errors.Is(err, failed) {
		t.Errorf("wait = %v, want the command's error", err)
	}
	// Streams never detach or take stdin.
	if got := r.Commands()[0]; got != "exec --user sandbox safeclaw-a tar -c" {
		t.Errorf("exec = %q", got)
	}
}

func TestExecMaxOutput(t *testing.T) {
	failed := errors.New("exit 2")
	r := &dockertest.Runner{Handler: func(args []string, _ string) ([]byte, error) {
		if args[len(args)-1] == "fail" {
			return []byte("12"), failed
		}
		return []byte(args[len(args)-1]), nil
	}}
	c := r.Client()
	opts := docker.ExecOptions{User: "sandbox", MaxOutput: 4}
	if out, err := c.Exec(context.Background(), "safeclaw-a", opts, "echo", "1234"); err != nil || string(out) != "1234" {
		t.Errorf("at the limit: %q, %v", out, err)
	}
	_, err := c.Exec(context.Background(), "safeclaw-a", opts, "echo", "12345")
	var le *docker.OutputLimitError
	if !errors.As(err, &le) || le.Max != 4 || !errors.Is(err, docker.ErrOutputTooLarge) {
		t.Errorf("past the limit: err = %v", err)
	}
	if err == nil || err.Error() != "docker exec: output exceeds 4 bytes" {
		t.Errorf("message = %v", err)
	}
	if out, err := c.Exec(context.Background(), "safeclaw-a", opts, "fail"); !errors.Is(err, failed) || string(out) != "12" {
		t.Errorf("failed command: %q, %v", out, err)
	}
	if got := r.Commands()[0]; got != "exec --user sandbox safeclaw-a echo 1234" {
		t.Errorf("exec = %q", got)
	}
	for _, o := range []docker.ExecOptions{{MaxOutput: 1, Detach: true}, {MaxOutput: 1, Stdin: strings.NewReader("x")}} {
		if _, err := c.Exec(context.Background(), "safeclaw-a", o, "true"); err == nil {
			t.Errorf("%+v should be refused", o)
		}
	}
}

// A command that keeps writing past MaxOutput is killed rather than waited
// for.
func TestExecMaxOutputKillsDocker(t *testing.T) {
	script := filepath.Join(t.TempDir(), "docker")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexec yes\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	c := &docker.Client{R: docker.ExecRunner{Binary: script}}
	done := make(chan error, 1)
	go func() {
		_, err := c.Exec(context.Background(), "safeclaw-a", docker.ExecOptions{MaxOutput: 1 << 20}, "yes")
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, docker.ErrOutputTooLarge) {
			t.Errorf("err = %v, want the output limit", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Exec is still reading past MaxOutput")
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
