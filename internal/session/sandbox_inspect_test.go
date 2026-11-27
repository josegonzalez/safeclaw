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
	c := map[string]any{
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
			"LogConfig":      map[string]any{"Type": "none", "Config": map[string]string{}},
			"Tmpfs": map[string]string{
				"/tmp":     "rw,nosuid,nodev,size=256m",
				"/sandbox": "rw,nosuid,nodev,exec,size=1073741824,uid=2000,gid=2000,mode=0700",
			},
		},
		"NetworkSettings": map[string]any{"Networks": map[string]any{"none": map[string]any{}}},
	}
	setBinds(c, "/host/in:/in")
	return c
}

// setBinds gives c the binds sandboxArgs makes for each source:destination,
// read-only with bind-recursive=readonly. They are listed in both
// .Mounts and .HostConfig.Mounts, like docker does for --mount.
func setBinds(c map[string]any, specs ...string) {
	var mounts, hostMounts []map[string]any
	for _, s := range specs {
		src, dst, _ := strings.Cut(s, ":")
		mounts = append(mounts, map[string]any{"Type": "bind", "Source": src, "Destination": dst, "RW": false, "Propagation": "rprivate"})
		hostMounts = append(hostMounts, map[string]any{"Type": "bind", "Source": src, "Target": dst, "ReadOnly": true,
			"BindOptions": map[string]any{"Propagation": "rprivate", "ReadOnlyForceRecursive": true}})
	}
	c["Mounts"] = mounts
	c["HostConfig"].(map[string]any)["Mounts"] = hostMounts
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
---end
`

// withMounts returns goodProbe with lines added to its mounts.
func withMounts(lines string) string {
	return strings.Replace(goodProbe, "---end\n", lines+"---end\n", 1)
}

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
		`"ipc_mode":"private","pid_mode":"","log_driver":"none","limits":{"memory_bytes":2147483648,"cpus":1,"pids":256,"disk_bytes":1073741824},` +
		`"tmpfs":[{"path":"/sandbox","options":"rw,nosuid,nodev,exec,size=1073741824,uid=2000,gid=2000,mode=0700","size_bytes":1073741824},` +
		`{"path":"/tmp","options":"rw,nosuid,nodev,size=256m","size_bytes":268435456}],` +
		`"mounts":[{"type":"bind","source":"/host/in","destination":"/in","read_only":true,"recursive_read_only":true}],` +
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
		"namespaces", "limits", "logs", "disk", "tmp", "running", "live-user", "live-home", "live-network", "live-capabilities",
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
		// A -v :ro bind is read-only, but docker leaves its submounts
		// writable where it can't make them read-only.
		{"short syntax bind", func(_, _, hc map[string]any) { delete(hc, "Mounts") }, []string{"mounts-read-only"}},
		{"recursive not forced", func(_, _, hc map[string]any) {
			hc["Mounts"].([]map[string]any)[0]["BindOptions"] = map[string]any{"Propagation": "rprivate"}
		}, []string{"mounts-read-only"}},
		{"token env", func(_, cfg, _ map[string]any) { cfg["Env"] = []string{"GH_TOKEN=x", "PATH=/bin"} }, []string{"no-secrets"}},
		{"stored secret env", func(_, cfg, _ map[string]any) { cfg["Env"] = []string{"MY_API_KEY=x"} }, []string{"no-secrets"}},
		{"host ipc", func(_, _, hc map[string]any) { hc["IpcMode"] = "host" }, []string{"namespaces"}},
		{"host pid", func(_, _, hc map[string]any) { hc["PidMode"] = "host" }, []string{"namespaces"}},
		{"no memory", func(_, _, hc map[string]any) { hc["Memory"] = 0 }, []string{"limits"}},
		{"no pids", func(_, _, hc map[string]any) { hc["PidsLimit"] = nil }, []string{"limits"}},
		{"default log driver", func(_, _, hc map[string]any) {
			hc["LogConfig"] = map[string]any{"Type": "json-file", "Config": map[string]string{}}
		}, []string{"logs"}},
		{"no log config", func(_, _, hc map[string]any) { delete(hc, "LogConfig") }, []string{"logs"}},
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
		{"rw submount", "/dev/vda1 /in ext4 ro,relatime 0 0\n", "/dev/vda1 /in ext4 ro,relatime 0 0\ntmpfs /in/sub tmpfs rw,relatime 0 0\n", []string{"live-mounts"}},
		{"rw nested submount", "/dev/vda1 /in ext4 ro,relatime 0 0\n",
			"/dev/vda1 /in ext4 ro,relatime 0 0\ntmpfs /in/a tmpfs ro 0 0\ncgroup2 /in/a/b\\040c cgroup2 rw,nosuid 0 0\n", []string{"live-mounts"}},
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

// A point mounted more than once is read-only only when every mount on it
// is, so neither a writable mount over it nor a read-only line added after
// a writable one passes.
func TestVerifySandboxRepeatedMountPoint(t *testing.T) {
	for _, tt := range []struct {
		name, probe string
		want        []string
	}{
		{"writable over", withMounts("tmpfs /in tmpfs rw 0 0\n"), []string{"live-mounts"}},
		{"read-only after writable", withMounts("tmpfs /in/sub tmpfs rw 0 0\ntmpfs /in/sub tmpfs ro 0 0\n"), []string{"live-mounts"}},
		{"read-only twice", withMounts("tmpfs /in/sub tmpfs ro 0 0\ntmpfs /in/sub tmpfs ro 0 0\n"), nil},
		{"root again", withMounts("overlay / overlay ro 0 0\n"), nil},
		{"root rw then ro", strings.Replace(withMounts("overlay / overlay ro 0 0\n"), "overlay / overlay ro,", "overlay / overlay rw,", 1),
			[]string{"live-read-only-root"}},
		{"second disk", withMounts("tmpfs /sandbox tmpfs rw,size=4k 0 0\n"), []string{"live-disk"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := failedChecks(t, &inspectWorld{c: goodSandbox(), probe: tt.probe}); !slices.Equal(got, tt.want) {
				t.Errorf("failed = %q, want %q", got, tt.want)
			}
		})
	}
}

// Probe output not shaped like the probe's, as when other processes of the
// sandbox user write to its stdout, fails every live check rather than
// letting a later line win.
func TestVerifySandboxTamperedProbe(t *testing.T) {
	tests := []struct {
		name, probe, reason string
	}{
		{"second uid", strings.Replace(goodProbe, "home=denied", "uid=2000\nhome=denied", 1), "line 2: uid repeated"},
		{"second home", strings.Replace(goodProbe, "net=lo", "home=denied\nnet=lo", 1), "line 3: home repeated"},
		{"repeated interface", strings.Replace(goodProbe, "net=lo", "net=lo\nnet=lo", 1), `line 4: net "lo" repeated`},
		{"unknown key", strings.Replace(goodProbe, "net=lo", "net=lo\nroot=no", 1), "line 4: unexpected line"},
		{"stray line", strings.Replace(goodProbe, "net=lo", "net=lo\nhello", 1), "line 4: unexpected line"},
		{"repeated status", strings.Replace(goodProbe, "NoNewPrivs:\t1", "NoNewPrivs:\t0\nNoNewPrivs:\t1", 1), `line 12: status field "NoNewPrivs" repeated`},
		{"status not a field", strings.Replace(goodProbe, "NoNewPrivs:\t1", "NoNewPrivs:\t1\nnope", 1), "line 12: not a status field"},
		{"second mounts", withMounts("---mounts\noverlay / overlay ro 0 0\n"), "line 18: unexpected section marker"},
		{"second status", withMounts("---status\nCapEff:\t0\n"), "line 18: unexpected section marker"},
		{"sections swapped", strings.NewReplacer("---status", "---mounts", "---mounts", "---status").Replace(goodProbe), "line 4: unexpected section marker"},
		{"short mount", withMounts("tmpfs /x tmpfs\n"), "line 18: not a mount"},
		{"after end", goodProbe + "---mounts\noverlay / overlay ro 0 0\n", "line 19: output after ---end"},
		{"after end, blank", goodProbe + "\n", "line 19: output after ---end"},
		{"no end", strings.Replace(goodProbe, "---end\n", "", 1), "output ends before ---end"},
		{"empty", "", "output ends before ---status"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.probe == goodProbe {
				t.Fatal("the probe is unchanged")
			}
			m, _ := newInspectManager(t, &inspectWorld{c: goodSandbox(), probe: tt.probe})
			rep, err := m.VerifySandbox(context.Background(), "box")
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(rep.Failed(), liveCheckNames) {
				t.Errorf("failed = %q", rep.Failed())
			}
			want := "probe failed: output looks tampered with: " + tt.reason
			for _, c := range rep.Checks {
				if strings.HasPrefix(c.Name, "live-") && c.Detail != want {
					t.Errorf("%s detail = %q, want %q", c.Name, c.Detail, want)
				}
			}
		})
	}
}

// The probe's own output parses, and so does a /proc/self/status with
// fields the live checks don't read.
func TestParseProbe(t *testing.T) {
	p, err := parseProbe(goodProbe)
	if err != nil {
		t.Fatal(err)
	}
	if p.status["NoNewPrivs"] != "1" || !slices.Equal(p.values["net"], []string{"lo"}) || len(p.mounts) != 5 {
		t.Errorf("probe = %+v", p)
	}
	if _, err := parseProbe(strings.TrimSuffix(goodProbe, "\n")); err != nil {
		t.Errorf("no trailing newline: %v", err)
	}
	if !strings.Contains(sandboxProbe, "echo ---end") {
		t.Error("the probe does not print its end marker")
	}
}

// Probe output past probeMaxOutput fails the live checks without being
// parsed.
func TestVerifySandboxProbeTooLarge(t *testing.T) {
	probe := withMounts(strings.Repeat("tmpfs /in/x tmpfs ro 0 0\n", probeMaxOutput/25+1))
	m, _ := newInspectManager(t, &inspectWorld{c: goodSandbox(), probe: probe})
	rep, err := m.VerifySandbox(context.Background(), "box")
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(rep.Failed(), liveCheckNames) {
		t.Errorf("failed = %q", rep.Failed())
	}
	for _, c := range rep.Checks {
		if c.Name == "live-user" && !strings.Contains(c.Detail, "output exceeds 1048576 bytes") {
			t.Errorf("detail = %q", c.Detail)
		}
	}
}

// Every submount below a bind must be read-only too, and only mounts below
// it count.
func TestVerifySandboxSubmounts(t *testing.T) {
	probe := withMounts("sysfs /in/fs/cgroup cgroup2 ro,nosuid 0 0\ntmpfs /in/sub tmpfs ro 0 0\ntmpfs /inbox tmpfs rw 0 0\n")
	m, _ := newInspectManager(t, &inspectWorld{c: goodSandbox(), probe: probe})
	rep, err := m.VerifySandbox(context.Background(), "box")
	if err != nil {
		t.Fatal(err)
	}
	if !rep.OK {
		t.Errorf("read-only submounts: failed = %q", rep.Failed())
	}
	for _, c := range rep.Checks {
		if c.Name == "live-mounts" && c.Detail != `1 mounts, 2 submounts, missing or writable: []` {
			t.Errorf("detail = %q", c.Detail)
		}
	}

	rw := strings.Replace(probe, "/in/sub tmpfs ro", "/in/sub tmpfs rw", 1)
	m, _ = newInspectManager(t, &inspectWorld{c: goodSandbox(), probe: rw})
	rep, err = m.VerifySandbox(context.Background(), "box")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range rep.Checks {
		if c.Name == "live-mounts" && (c.OK || c.Detail != `1 mounts, 2 submounts, missing or writable: ["/in/sub"]`) {
			t.Errorf("writable submount: %+v", c)
		}
	}
}

// Every mount of a sandbox made with several -v is checked, not just the
// first.
func TestVerifySandboxSeveralMounts(t *testing.T) {
	two := func(rw bool) map[string]any {
		c := goodSandbox()
		setBinds(c, "/host/in:/in", "/host/tools:/opt/tools")
		if rw {
			c["Mounts"].([]map[string]any)[1]["RW"] = true
		}
		return c
	}
	probe := withMounts("/dev/vda1 /opt/tools ext4 ro,relatime 0 0\n")
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
	setBinds(c, "/host/my in:/my in")
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
