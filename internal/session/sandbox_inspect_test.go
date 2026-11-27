package session

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
)

// goodSandbox returns `docker inspect` data for a sandbox created by
// sandboxArgs with a read-only /in mount.
func goodSandbox() map[string]any {
	return map[string]any{
		"Id":    "abc",
		"Name":  "/safeclaw-box",
		"Image": "sha256:img",
		"Config": map[string]any{
			"Image":  "safeclaw:sandbox",
			"User":   "sandbox",
			"Env":    []string{"HOME=/sandbox", "BASH_ENV=", "PATH=/usr/bin"},
			"Labels": map[string]string{"safeclaw.type": "sandbox", "safeclaw.variant": "sandbox", "org.example": "x"},
		},
		"State": map[string]any{"Status": "running", "Running": true},
		"HostConfig": map[string]any{
			"NetworkMode":    "none",
			"IpcMode":        "private",
			"PidMode":        "",
			"Memory":         2 << 30,
			"NanoCpus":       1e9,
			"PidsLimit":      256,
			"ReadonlyRootfs": true,
			"CapDrop":        []string{"ALL"},
			"SecurityOpt":    []string{"no-new-privileges"},
			"Tmpfs": map[string]string{
				"/tmp":     "rw,nosuid,nodev,size=256m",
				"/sandbox": "rw,nosuid,nodev,exec,size=1073741824,uid=2000,gid=2000,mode=0700",
			},
		},
		"NetworkSettings": map[string]any{"Networks": map[string]any{"none": map[string]any{}}},
		"Mounts":          []map[string]any{{"Type": "bind", "Source": "/host/in", "Destination": "/in", "RW": false}},
	}
}

const goodProbe = `uid=2000
home=denied
net=lo
---status
Name:	cat
CapInh:	0000000000000000
CapPrm:	0000000000000000
CapEff:	0000000000000000
CapBnd:	0000000000000000
CapAmb:	0000000000000000
NoNewPrivs:	1
---mounts
overlay / overlay ro,relatime,lowerdir=/a:/b 0 0
proc /proc proc rw,nosuid,nodev,noexec,relatime 0 0
tmpfs /tmp tmpfs rw,nosuid,nodev,relatime,size=262144k 0 0
tmpfs /sandbox tmpfs rw,nosuid,nodev,relatime,size=1048576k,mode=700,uid=2000,gid=2000 0 0
/dev/vda1 /in ext4 ro,relatime 0 0
`

// inspectWorld answers inspect with c and the probe exec with probe.
type inspectWorld struct {
	c        map[string]any
	probe    string
	probeErr error
}

func (w *inspectWorld) handle(args []string, _ string) ([]byte, error) {
	switch {
	case args[0] == "container" && args[1] == "inspect":
		if w.c == nil {
			return nil, dockertest.NotFound(args)
		}
		return json.Marshal([]any{w.c})
	case args[0] == "exec":
		return []byte(w.probe), w.probeErr
	}
	return nil, errors.New("unexpected docker call")
}

func newInspectManager(t *testing.T, w *inspectWorld) (*Manager, *dockertest.Runner) {
	t.Helper()
	m, r := newTestManager(t, &world{})
	r.Handler = w.handle
	return m, r
}

func TestInspectSandbox(t *testing.T) {
	m, r := newInspectManager(t, &inspectWorld{c: goodSandbox()})
	info, err := m.InspectSandbox(context.Background(), "box")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(info)
	want := `{"schema":1,"name":"box","container":"safeclaw-box","id":"abc","status":"running","running":true,"one_off":false,` +
		`"variant":"sandbox","image":"safeclaw:sandbox","image_id":"sha256:img","network_mode":"none","networks":["none"],` +
		`"user":"sandbox","read_only_root":true,"privileged":false,"cap_drop":["ALL"],"cap_add":[],"no_new_privileges":true,` +
		`"ipc_mode":"private","pid_mode":"","limits":{"memory_bytes":2147483648,"cpus":1,"pids":256,"disk_bytes":1073741824},` +
		`"tmpfs":[{"path":"/sandbox","options":"rw,nosuid,nodev,exec,size=1073741824,uid=2000,gid=2000,mode=0700","size_bytes":1073741824},` +
		`{"path":"/tmp","options":"rw,nosuid,nodev,size=256m","size_bytes":268435456}],` +
		`"mounts":[{"type":"bind","source":"/host/in","destination":"/in","read_only":true}],` +
		`"labels":{"safeclaw.type":"sandbox","safeclaw.variant":"sandbox"}}`
	if string(b) != want {
		t.Errorf("info =\n%s\nwant\n%s", b, want)
	}
	if got := r.Commands(); len(got) != 1 {
		t.Errorf("inspect should only inspect: %q", got)
	}
}

func TestInspectSandboxEmptyLists(t *testing.T) {
	c := goodSandbox()
	c["Mounts"] = nil
	c["NetworkSettings"] = map[string]any{}
	hc := c["HostConfig"].(map[string]any)
	hc["CapDrop"], hc["Tmpfs"] = nil, nil
	cfg := c["Config"].(map[string]any)
	cfg["Labels"] = map[string]string{"safeclaw.type": "sandbox"}
	m, _ := newInspectManager(t, &inspectWorld{c: c})
	info, err := m.InspectSandbox(context.Background(), "box")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(info)
	for _, s := range []string{`"networks":[]`, `"cap_drop":[]`, `"tmpfs":[]`, `"mounts":[]`, `"variant":"base"`} {
		if !strings.Contains(string(b), s) {
			t.Errorf("info lacks %s: %s", s, b)
		}
	}
}

func TestInspectSandboxErrors(t *testing.T) {
	m, _ := newInspectManager(t, &inspectWorld{})
	if _, err := m.InspectSandbox(context.Background(), "box"); !errors.Is(err, ErrNotFound) {
		t.Errorf("missing: err = %v", err)
	}
	if _, err := m.VerifySandbox(context.Background(), "box"); !errors.Is(err, ErrNotFound) {
		t.Errorf("verify missing: err = %v", err)
	}
	c := goodSandbox()
	c["Config"].(map[string]any)["Labels"] = map[string]string{"safeclaw.type": "session"}
	m, _ = newInspectManager(t, &inspectWorld{c: c})
	if _, err := m.InspectSandbox(context.Background(), "box"); !errors.Is(err, ErrNotSandbox) {
		t.Errorf("session: err = %v", err)
	}
	if _, err := m.VerifySandbox(context.Background(), "box"); !errors.Is(err, ErrNotSandbox) {
		t.Errorf("verify session: err = %v", err)
	}
}

func TestVerifySandboxPasses(t *testing.T) {
	m, r := newInspectManager(t, &inspectWorld{c: goodSandbox(), probe: goodProbe})
	rep, err := m.VerifySandbox(context.Background(), "box")
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK || len(rep.Failed()) != 0 {
		t.Errorf("report = %+v", rep)
	}
	var names []string
	for _, c := range rep.Checks {
		names = append(names, c.Name)
	}
	want := []string{"network", "user", "capabilities", "no-new-privileges", "read-only-root", "mounts-read-only", "no-secrets",
		"namespaces", "limits", "disk", "tmp", "running", "live-user", "live-home", "live-network", "live-capabilities",
		"live-read-only-root", "live-mounts", "live-disk"}
	if !slices.Equal(names, want) {
		t.Errorf("checks = %q\nwant     %q", names, want)
	}
	cmds := r.Commands()
	if len(cmds) != 2 || !strings.HasPrefix(cmds[1], "exec --user sandbox safeclaw-box /bin/sh -c ") {
		t.Errorf("verify should only inspect and run the probe: %q", cmds)
	}
}

// failedChecks verifies and returns the failed check names.
func failedChecks(t *testing.T, w *inspectWorld) []string {
	t.Helper()
	m, _ := newInspectManager(t, w)
	_ = m.Secrets.Set("MY_API_KEY", "v")
	rep, err := m.VerifySandbox(context.Background(), "box")
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK != (len(rep.Failed()) == 0) {
		t.Errorf("ok = %t with failed %q", rep.OK, rep.Failed())
	}
	return rep.Failed()
}

func TestVerifySandboxStaticFailures(t *testing.T) {
	tests := []struct {
		name   string
		change func(c, cfg, hc map[string]any)
		want   []string
	}{
		{"bridge", func(c, _, hc map[string]any) {
			hc["NetworkMode"] = "bridge"
			c["NetworkSettings"] = map[string]any{"Networks": map[string]any{"bridge": map[string]any{}}}
		}, []string{"network"}},
		{"attached", func(c, _, _ map[string]any) {
			c["NetworkSettings"] = map[string]any{"Networks": map[string]any{"none": map[string]any{}, "evil": map[string]any{}}}
		}, []string{"network"}},
		{"root user", func(_, cfg, _ map[string]any) { cfg["User"] = "" }, []string{"user"}},
		{"caps kept", func(_, _, hc map[string]any) { hc["CapDrop"] = nil }, []string{"capabilities"}},
		{"cap added", func(_, _, hc map[string]any) { hc["CapAdd"] = []string{"NET_RAW"} }, []string{"capabilities"}},
		{"privileged", func(_, _, hc map[string]any) { hc["Privileged"] = true }, []string{"capabilities"}},
		{"new privileges", func(_, _, hc map[string]any) { hc["SecurityOpt"] = []string{"seccomp=unconfined"} }, []string{"no-new-privileges"}},
		{"writable root", func(_, _, hc map[string]any) { hc["ReadonlyRootfs"] = false }, []string{"read-only-root"}},
		{"writable mount", func(c, _, _ map[string]any) {
			c["Mounts"] = []map[string]any{{"Type": "bind", "Source": "/host/in", "Destination": "/in", "RW": true}}
		}, []string{"mounts-read-only"}},
		{"token env", func(_, cfg, _ map[string]any) { cfg["Env"] = []string{"GH_TOKEN=x", "PATH=/bin"} }, []string{"no-secrets"}},
		{"stored secret env", func(_, cfg, _ map[string]any) { cfg["Env"] = []string{"MY_API_KEY=x"} }, []string{"no-secrets"}},
		{"host ipc", func(_, _, hc map[string]any) { hc["IpcMode"] = "host" }, []string{"namespaces"}},
		{"host pid", func(_, _, hc map[string]any) { hc["PidMode"] = "host" }, []string{"namespaces"}},
		{"no memory", func(_, _, hc map[string]any) { hc["Memory"] = 0 }, []string{"limits"}},
		{"no pids", func(_, _, hc map[string]any) { hc["PidsLimit"] = nil }, []string{"limits"}},
		{"no disk tmpfs", func(_, _, hc map[string]any) {
			hc["Tmpfs"] = map[string]string{"/tmp": "rw,size=256m"}
		}, []string{"disk", "live-disk"}},
		{"unbounded disk", func(_, _, hc map[string]any) {
			hc["Tmpfs"] = map[string]string{"/tmp": "rw,size=256m", "/sandbox": "rw,uid=2000,mode=0700"}
		}, []string{"disk", "live-disk"}},
		{"disk not owned", func(_, _, hc map[string]any) {
			hc["Tmpfs"] = map[string]string{"/tmp": "rw,size=256m", "/sandbox": "rw,size=1g,mode=0777"}
		}, []string{"disk"}},
		{"unbounded tmp", func(_, _, hc map[string]any) {
			hc["Tmpfs"] = map[string]string{"/tmp": "rw", "/sandbox": "rw,size=1073741824,uid=2000,gid=2000,mode=0700"}
		}, []string{"tmp"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := goodSandbox()
			tt.change(c, c["Config"].(map[string]any), c["HostConfig"].(map[string]any))
			if got := failedChecks(t, &inspectWorld{c: c, probe: goodProbe}); !slices.Equal(got, tt.want) {
				t.Errorf("failed = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVerifySandboxLiveFailures(t *testing.T) {
	tests := []struct {
		name     string
		old, new string
		want     []string
	}{
		{"root uid", "uid=2000", "uid=0", []string{"live-user"}},
		{"no uid", "uid=2000\n", "", []string{"live-user"}},
		{"home readable", "home=denied", "home=readable", []string{"live-home"}},
		{"eth0", "net=lo", "net=eth0\nnet=lo", []string{"live-network"}},
		{"no interfaces", "net=lo", "net=*", []string{"live-network"}},
		{"effective caps", "CapEff:\t0000000000000000", "CapEff:\t00000000a80425fb", []string{"live-capabilities"}},
		{"bounding caps", "CapBnd:\t0000000000000000", "CapBnd:\t00000000a80425fb", []string{"live-capabilities"}},
		{"new privs", "NoNewPrivs:\t1", "NoNewPrivs:\t0", []string{"live-capabilities"}},
		{"rw root", "overlay / overlay ro,", "overlay / overlay rw,", []string{"live-read-only-root"}},
		{"rw mount", "/in ext4 ro,", "/in ext4 rw,", []string{"live-mounts"}},
		{"missing mount", "/dev/vda1 /in ext4 ro,relatime 0 0\n", "", []string{"live-mounts"}},
		{"disk not tmpfs", "tmpfs /sandbox tmpfs", "/dev/vda1 /sandbox ext4", []string{"live-disk"}},
		{"disk too big", "size=1048576k,mode=700", "size=2097152k,mode=700", []string{"live-disk"}},
		{"disk unbounded", "size=1048576k,mode=700", "mode=700", []string{"live-disk"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !strings.Contains(goodProbe, tt.old) {
				t.Fatalf("probe lacks %q", tt.old)
			}
			probe := strings.Replace(goodProbe, tt.old, tt.new, 1)
			if got := failedChecks(t, &inspectWorld{c: goodSandbox(), probe: probe}); !slices.Equal(got, tt.want) {
				t.Errorf("failed = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVerifySandboxLaterMountWins(t *testing.T) {
	probe := goodProbe + "tmpfs /in tmpfs rw 0 0\n"
	if got := failedChecks(t, &inspectWorld{c: goodSandbox(), probe: probe}); !slices.Equal(got, []string{"live-mounts"}) {
		t.Errorf("failed = %q", got)
	}
}

// Every mount of a sandbox made with several -v is checked, not just the
// first.
func TestVerifySandboxSeveralMounts(t *testing.T) {
	two := func(rw bool) map[string]any {
		c := goodSandbox()
		c["Mounts"] = []map[string]any{
			{"Type": "bind", "Source": "/host/in", "Destination": "/in", "RW": false},
			{"Type": "bind", "Source": "/host/tools", "Destination": "/opt/tools", "RW": rw},
		}
		return c
	}
	probe := goodProbe + "/dev/vda1 /opt/tools ext4 ro,relatime 0 0\n"
	if got := failedChecks(t, &inspectWorld{c: two(false), probe: probe}); len(got) != 0 {
		t.Errorf("failed = %q", got)
	}
	if got := failedChecks(t, &inspectWorld{c: two(true), probe: probe}); !slices.Equal(got, []string{"mounts-read-only"}) {
		t.Errorf("writable second mount: failed = %q", got)
	}
	if got := failedChecks(t, &inspectWorld{c: two(false), probe: goodProbe}); !slices.Equal(got, []string{"live-mounts"}) {
		t.Errorf("missing second mount: failed = %q", got)
	}
	rw := strings.Replace(probe, "/opt/tools ext4 ro,", "/opt/tools ext4 rw,", 1)
	if got := failedChecks(t, &inspectWorld{c: two(false), probe: rw}); !slices.Equal(got, []string{"live-mounts"}) {
		t.Errorf("second mount rw live: failed = %q", got)
	}

	m, _ := newInspectManager(t, &inspectWorld{c: two(false)})
	info, err := m.InspectSandbox(context.Background(), "box")
	if err != nil {
		t.Fatal(err)
	}
	if len(info.Mounts) != 2 || info.Mounts[1].Destination != "/opt/tools" || !info.Mounts[1].ReadOnly {
		t.Errorf("mounts = %+v", info.Mounts)
	}
}

func TestVerifySandboxEscapedMount(t *testing.T) {
	c := goodSandbox()
	c["Mounts"] = []map[string]any{{"Type": "bind", "Source": "/host/my in", "Destination": "/my in", "RW": false}}
	probe := strings.Replace(goodProbe, " /in ext4", ` /my\040in ext4`, 1)
	if got := failedChecks(t, &inspectWorld{c: c, probe: probe}); len(got) != 0 {
		t.Errorf("failed = %q", got)
	}
}

func TestVerifySandboxStopped(t *testing.T) {
	c := goodSandbox()
	c["State"] = map[string]any{"Status": "exited", "Running": false}
	m, r := newInspectManager(t, &inspectWorld{c: c})
	rep, err := m.VerifySandbox(context.Background(), "box")
	if err != nil {
		t.Fatal(err)
	}
	if rep.OK || !slices.Equal(rep.Failed(), []string{"running"}) || len(rep.Skipped()) != len(liveCheckNames) {
		t.Errorf("failed = %q, skipped = %q", rep.Failed(), rep.Skipped())
	}
	if hasCall(r, "exec") {
		t.Error("a stopped sandbox should not be exec'd into")
	}
}

func TestVerifySandboxProbeFails(t *testing.T) {
	got := failedChecks(t, &inspectWorld{c: goodSandbox(), probeErr: errors.New("boom")})
	if !slices.Equal(got, liveCheckNames) {
		t.Errorf("failed = %q", got)
	}
}

func TestUnescapeMount(t *testing.T) {
	for in, want := range map[string]string{
		`/a`:          "/a",
		`/a\040b`:     "/a b",
		`/a\011\012`:  "/a\t\n",
		`/a\134b`:     `/a\b`,
		`/a\04`:       `/a\04`,
		`/a\999`:      `/a\999`,
		`/trailing\\`: `/trailing\\`,
	} {
		if got := unescapeMount(in); got != want {
			t.Errorf("unescapeMount(%q) = %q, want %q", in, got, want)
		}
	}
}
