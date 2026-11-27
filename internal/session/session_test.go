package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
	"github.com/josegonzalez/safeclaw/internal/secrets"
)

type fakeContainer struct {
	Running bool
	Port    int
	// HostIP is the address Port is published on. Defaults to 127.0.0.1,
	// as for containers created before terminals moved to [::1].
	HostIP string
	Mounts []string // source:destination bind mounts, or a bare anonymous volume path
	Image  string
	Labels map[string]string
	// RunImage is the image name the container was run from.
	RunImage string
	// Memory, NanoCPUs, and PidsLimit are the limits docker reports.
	Memory, NanoCPUs, PidsLimit int64
	// Tmpfs maps each tmpfs mount point to its options.
	Tmpfs map[string]string
	// AutoRemove is set for containers run with --rm.
	AutoRemove bool
	// ID is the container ID. Defaults to "id-" plus the name.
	ID string
	// NetworkMode defaults to "bridge".
	NetworkMode string
	// IpcMode defaults to "private".
	IpcMode string
	// Nets are the attached networks. Nil means only "bridge", unless
	// Offline is set.
	Nets map[string]docker.Endpoint
	// Offline means no attached networks.
	Offline bool
	// Unhardened containers keep docker's default capabilities and
	// security options, like ones created before sessions dropped them.
	Unhardened bool
}

// networks returns the attached networks, materializing the default.
func (c *fakeContainer) networks() map[string]docker.Endpoint {
	if c.Nets == nil {
		c.Nets = map[string]docker.Endpoint{}
		if !c.Offline {
			c.Nets["bridge"] = docker.Endpoint{}
		}
	}
	return c.Nets
}

// world is a tiny fake docker daemon.
type world struct {
	// image is the ID every image name resolves to, unless images is set.
	image string
	// images maps image names to IDs. Names it lacks do not exist.
	images map[string]string
	// imageLabels maps image names to their labels.
	imageLabels map[string]map[string]string
	// oldTTYD leaves off the labels images whose ttyd accepts a bracketed
	// IPv6 Host and reads its credential from a file carry.
	oldTTYD bool
	// argvCredTTYD leaves off only the label images whose ttyd reads its
	// credential from a file carry.
	argvCredTTYD bool
	containers   map[string]*fakeContainer
	native       bool
	prompt       bool
	// rootEnv makes containers report the root-owned env file of current
	// images, instead of only sclaw's ~/.env.
	rootEnv bool
	// attachOnStart makes start reconnect a container to bridge, as if
	// docker restored its network.
	attachOnStart bool
	// runs counts docker run calls, to give each container a new ID.
	runs int
	// runErrs fail the next docker run calls, one each, in order. A run
	// failing with leaveCreated leaves a stopped container behind, like a
	// failed start.
	runErrs []runErr
	// failDisconnect fails that many disconnects from each named network.
	failDisconnect map[string]int
	// failMemory fails writing the session's auto memory setting.
	failMemory bool
}

type runErr struct {
	err          error
	leaveCreated bool
}

func (w *world) inspectJSON(names []string) []byte {
	var out []map[string]any
	for _, n := range names {
		c, ok := w.containers[n]
		if !ok {
			continue
		}
		var mounts []map[string]any
		for _, m := range c.Mounts {
			src, dst, ok := strings.Cut(m, ":")
			if !ok {
				mounts = append(mounts, map[string]any{"Type": "volume", "Source": "/var/lib/docker/volumes/anon", "Destination": m, "RW": true})
				continue
			}
			dst, opt, _ := strings.Cut(dst, ":")
			mounts = append(mounts, map[string]any{"Type": "bind", "Source": src, "Destination": dst, "RW": !strings.Contains(opt, "ro")})
		}
		bindings := map[string]any{}
		if c.Port > 0 {
			ip := c.HostIP
			if ip == "" {
				ip = "127.0.0.1"
			}
			bindings["7681/tcp"] = []map[string]string{{"HostIp": ip, "HostPort": fmt.Sprint(c.Port)}}
		}
		status := "exited"
		if c.Running {
			status = "running"
		}
		id := c.ID
		if id == "" {
			id = "id-" + n
		}
		mode := c.NetworkMode
		if mode == "" {
			mode = "bridge"
		}
		ipc := c.IpcMode
		if ipc == "" {
			ipc = "private"
		}
		capDrop, secOpt := []string{"ALL"}, []string{"no-new-privileges"}
		if c.Unhardened {
			capDrop, secOpt = nil, nil
		}
		nets := c.networks()
		// Containers carry their image's labels, as made by run.
		labels := maps.Clone(c.Labels)
		if !w.oldTTYD {
			if labels == nil {
				labels = map[string]string{}
			}
			labels[config.LabelBracketedHostTTYD] = "1"
			if !w.argvCredTTYD {
				labels[config.LabelCredentialFileTTYD] = "1"
			}
		}
		out = append(out, map[string]any{
			"Id":              id,
			"Name":            "/" + n,
			"Image":           c.Image,
			"Config":          map[string]any{"Labels": labels},
			"State":           map[string]any{"Status": status, "Running": c.Running},
			"HostConfig":      map[string]any{"PortBindings": bindings, "AutoRemove": c.AutoRemove, "Memory": c.Memory, "NanoCpus": c.NanoCPUs, "PidsLimit": c.PidsLimit, "NetworkMode": mode, "IpcMode": ipc, "Tmpfs": c.Tmpfs, "CapDrop": capDrop, "SecurityOpt": secOpt},
			"NetworkSettings": map[string]any{"Networks": nets},
			"Mounts":          mounts,
		})
	}
	b, _ := json.Marshal(out)
	return b
}

// labelsOf returns an image's labels.
func (w *world) labelsOf(image string) map[string]string {
	labels := maps.Clone(w.imageLabels[image])
	if labels == nil {
		labels = map[string]string{}
	}
	if !w.oldTTYD {
		labels[config.LabelBracketedHostTTYD] = "1"
		if !w.argvCredTTYD {
			labels[config.LabelCredentialFileTTYD] = "1"
		}
	}
	return labels
}

func (w *world) handle(args []string, _ string) ([]byte, error) {
	switch {
	case args[0] == "image" && args[1] == "inspect":
		id := w.image
		if w.images != nil {
			id = w.images[args[len(args)-1]]
		}
		if id == "" {
			return nil, dockertest.NotFound(args)
		}
		b, _ := json.Marshal(map[string]any{"Id": id, "Config": map[string]any{"Labels": w.labelsOf(args[len(args)-1])}})
		return append(b, '\n'), nil
	case args[0] == "ps":
		var names []string
		for n := range w.containers {
			names = append(names, n)
		}
		slices.Sort(names)
		return []byte(strings.Join(names, "\n")), nil
	case args[0] == "container" && args[1] == "inspect":
		b := w.inspectJSON(args[2:])
		if string(b) == "null" {
			return nil, dockertest.NotFound(args)
		}
		return b, nil
	case args[0] == "run":
		var name string
		var port int
		hostIP := ""
		var mounts []string
		var autoRemove bool
		var memory, cpus, pids int64
		tmpfs := map[string]string{}
		ipc := ""
		mode := ""
		image := ""
		capDropAll, noNewPrivs := false, false
		if i := slices.Index(args, "sleep"); i > 0 {
			image = args[i-1]
		}
		// Like docker, containers start with their image's labels, which
		// --label overrides.
		labels := w.labelsOf(image)
		for i := 0; i < len(args); i++ {
			switch args[i] {
			case "--rm":
				autoRemove = true
			case "--name":
				name = args[i+1]
			case "--label":
				k, v, _ := strings.Cut(args[i+1], "=")
				labels[k] = v
			case "-p":
				if _, err := fmt.Sscanf(args[i+1], "[::1]:%d:7681", &port); err == nil {
					hostIP = "::1"
				}
			case "-v":
				mounts = append(mounts, args[i+1])
			case "--memory":
				memory, _ = strconv.ParseInt(strings.TrimSuffix(args[i+1], "g"), 10, 64)
				if strings.HasSuffix(args[i+1], "g") {
					memory <<= 30
				}
			case "--cpus":
				f, _ := strconv.ParseFloat(args[i+1], 64)
				cpus = int64(f * 1e9)
			case "--pids-limit":
				pids, _ = strconv.ParseInt(args[i+1], 10, 64)
			case "--tmpfs":
				dst, opts, _ := strings.Cut(args[i+1], ":")
				tmpfs[dst] = opts
			case "--network":
				mode = args[i+1]
			case "--ipc=host":
				ipc = "host"
			case "--cap-drop":
				capDropAll = capDropAll || args[i+1] == "ALL"
			case "--security-opt":
				noNewPrivs = noNewPrivs || args[i+1] == "no-new-privileges"
			}
		}
		id := w.image
		if w.images != nil {
			id = w.images[image]
		}
		var fail runErr
		if len(w.runErrs) > 0 {
			fail, w.runErrs = w.runErrs[0], w.runErrs[1:]
			if fail.err != nil && !fail.leaveCreated {
				return nil, fail.err
			}
		}
		w.runs++
		w.containers[name] = &fakeContainer{Running: fail.err == nil, Port: port, HostIP: hostIP, Mounts: mounts, Image: id, RunImage: image, Labels: labels, AutoRemove: autoRemove,
			Memory: memory, NanoCPUs: cpus, PidsLimit: pids, Tmpfs: tmpfs, ID: fmt.Sprintf("id-%s-%d", name, w.runs), NetworkMode: mode, IpcMode: ipc, Offline: mode == "none", Unhardened: !capDropAll || !noNewPrivs}
		return []byte("id\n"), fail.err
	case args[0] == "rm":
		delete(w.containers, args[len(args)-1])
	case args[0] == "start":
		c := w.containers[args[1]]
		c.Running = true
		if w.attachOnStart {
			c.networks()["bridge"] = docker.Endpoint{}
		}
	case args[0] == "network" && args[1] == "disconnect":
		c := w.containers[args[3]]
		nets := c.networks()
		if _, ok := nets[args[2]]; !ok {
			return nil, errors.New("not connected")
		}
		if w.failDisconnect[args[2]] > 0 {
			w.failDisconnect[args[2]]--
			return nil, errors.New("disconnect failed")
		}
		delete(nets, args[2])
	case args[0] == "network" && args[1] == "connect":
		c := w.containers[args[len(args)-1]]
		network := args[len(args)-2]
		nets := c.networks()
		if _, ok := nets[network]; ok {
			return nil, errors.New("already connected")
		}
		var ep docker.Endpoint
		for i := 2; i < len(args)-2; i++ {
			switch args[i] {
			case "--alias":
				if network == "bridge" {
					return nil, errors.New("network-scoped alias is supported only for containers in user defined networks")
				}
				ep.Aliases = append(ep.Aliases, args[i+1])
			case "--ip":
				ep.IPAMConfig = &docker.IPAMConfig{IPv4Address: args[i+1]}
			}
		}
		nets[network] = ep
	case args[0] == "stop":
		name := args[len(args)-1]
		if w.containers[name].AutoRemove {
			delete(w.containers, name)
		} else {
			w.containers[name].Running = false
		}
	case args[0] == "exec":
		cmd := strings.Join(args, " ")
		if strings.Contains(cmd, "command -v safeclaw") && !w.native {
			return nil, errors.New("exit 1")
		}
		if strings.Contains(cmd, "if [ -f /etc/safeclaw/env ]") {
			if w.rootEnv {
				return []byte("root\n"), nil
			}
			return []byte("user\n"), nil
		}
		if strings.Contains(cmd, "managed-settings.d") && w.failMemory {
			return nil, errors.New("read-only file system")
		}
		if strings.Contains(cmd, "capture-pane") && w.prompt {
			return []byte("────\n❯ \n"), nil
		}
	}
	return nil, nil
}

func newTestManager(t *testing.T, w *world) (*Manager, *dockertest.Runner) {
	t.Helper()
	r := &dockertest.Runner{Handler: w.handle}
	dir := t.TempDir()
	store := secrets.FileStore{Dir: filepath.Join(dir, ".secrets")}
	if err := store.Set(secrets.ClaudeToken, "tok"); err != nil {
		t.Fatal(err)
	}
	m := &Manager{
		Docker:        r.Client(),
		Secrets:       store,
		SessionsDir:   filepath.Join(dir, "sessions"),
		TTYDDir:       filepath.Join(dir, "ttyd"),
		DashboardDir:  filepath.Join(dir, "dashboard"),
		NetworkDir:    filepath.Join(dir, "network"),
		CopyDir:       filepath.Join(dir, "copy"),
		PortFree:      func(int) bool { return true },
		Sleep:         func(time.Duration) {},
		OpenBrowser:   func(string) error { return nil },
		PromptTimeout: time.Second,
	}
	return m, r
}

func hasCall(r *dockertest.Runner, prefix string) bool {
	_, ok := r.Find(prefix)
	return ok
}

func TestEnsureCreatesContainer(t *testing.T) {
	w := &world{image: "sha256:new", containers: map[string]*fakeContainer{
		"safeclaw-a": {Port: 7681, Image: "sha256:new"},
		"safeclaw-b": {Running: true, Port: 7682, Image: "sha256:new"},
	}, native: true}
	m, r := newTestManager(t, w)
	_ = m.Secrets.Set("WEIRD", "it's")

	res, err := m.Ensure(context.Background(), Options{Name: "work", NoOpen: true})
	if err != nil {
		t.Fatal(err)
	}
	// 7681 is reserved by a stopped container, 7682 by a running one.
	cred, err := m.Credential("work")
	if err != nil {
		t.Fatal(err)
	}
	if res.Port != 7683 || res.URL != "http://safeclaw:"+cred.Password+"@[::1]:7683" || res.Container != "safeclaw-work" {
		t.Errorf("result = %+v", res)
	}
	run, ok := r.Find("run ")
	if !ok {
		t.Fatal("no docker run")
	}
	want := "run -d --name safeclaw-work --label safeclaw.type=session --cap-drop ALL --security-opt no-new-privileges -p [::1]:7683:7681 -v " + filepath.Join(m.SessionsDir, "work") + ":/home/sclaw/.claude/projects safeclaw sleep infinity"
	if run.String() != want {
		t.Errorf("run = %q\nwant  %q", run.String(), want)
	}
	if _, err := os.Stat(filepath.Join(m.SessionsDir, "work")); err != nil {
		t.Errorf("session dir not created: %v", err)
	}

	env, ok := r.Find("exec -i safeclaw-work sh -c umask 077")
	if !ok {
		t.Fatal("env not written")
	}
	if !strings.Contains(env.Stdin, "export CLAUDE_CODE_OAUTH_TOKEN='tok'\n") || !strings.Contains(env.Stdin, `export WEIRD='it'\''s'`) {
		t.Errorf("env stdin = %q", env.Stdin)
	}
	for _, c := range r.Commands() {
		if strings.Contains(c, "tok") {
			t.Errorf("secret leaked into argv: %q", c)
		}
	}
	if !hasCall(r, `exec -d safeclaw-work sh -c umask 022; exec ttyd --credential-file /home/sclaw/.ttyd-credential "$@" ttyd -W -O -t titleFixed=SafeClaw - work -p 7681 safeclaw ttyd-wrapper`) {
		t.Errorf("ttyd not started natively: %v", r.Commands())
	}
	if hasCall(r, "exec safeclaw-work bash -c") {
		t.Error("git config should be skipped without GH_TOKEN")
	}
}

func TestEnsureReusesRunningContainer(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-default": {Running: true, Port: 7690, Image: "img"},
	}}
	m, r := newTestManager(t, w)
	_ = m.Secrets.Set(secrets.GitHubToken, "gh")
	res, err := m.Ensure(context.Background(), Options{NoOpen: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Port != 7690 {
		t.Errorf("port = %d, want reused 7690", res.Port)
	}
	for _, p := range []string{"exec safeclaw-default pkill -f ttyd", "exec safeclaw-default tmux kill-server", "exec safeclaw-default bash -c umask 022\n"} {
		if !hasCall(r, p) {
			t.Errorf("missing %q in %v", p, r.Commands())
		}
	}
	if hasCall(r, "run ") || hasCall(r, "start ") {
		t.Error("should not create or start")
	}
	// Upstream image: falls back to the legacy wrapper script.
	if !hasCall(r, `exec -d safeclaw-default sh -c umask 022; exec ttyd --credential-file /home/sclaw/.ttyd-credential "$@" ttyd -W -O -t titleFixed=SafeClaw - default -p 7681 /home/sclaw/ttyd-wrapper.sh`) {
		t.Errorf("legacy wrapper not used: %v", r.Commands())
	}
}

// TestEnsureWritesRootOwnedConfig checks that in current images the env file
// and git identity are written as root, to the files sclaw can't change, and
// that nothing is written to sclaw's ~/.env or ~/.gitconfig.
func TestEnsureWritesRootOwnedConfig(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{}, native: true, rootEnv: true}
	m, r := newTestManager(t, w)
	_ = m.Secrets.Set(secrets.GitHubToken, "gh")
	if _, err := m.Ensure(context.Background(), Options{Name: "work", NoOpen: true}); err != nil {
		t.Fatal(err)
	}

	env, ok := r.Find("exec -i --user root safeclaw-work /bin/sh -c " + rootPath + "\numask 077 && cat > /etc/safeclaw/env")
	if !ok {
		t.Fatalf("env not written as root: %v", r.Commands())
	}
	if !strings.Contains(env.Stdin, "export GH_TOKEN='gh'\n") {
		t.Errorf("env stdin = %q", env.Stdin)
	}
	git, ok := r.Find("exec --user root safeclaw-work /bin/sh -c umask 022\n" + rootPath + "\n. /etc/safeclaw/env\n")
	if !ok {
		t.Fatalf("git config not written as root: %v", r.Commands())
	}
	if !strings.Contains(git.String(), "git config --system user.name") || strings.Contains(git.String(), "--global") ||
		!strings.Contains(git.String(), "git config --system credential.https://github.com.helper '!/usr/bin/gh auth git-credential'\n") {
		t.Errorf("git config script = %q", git.String())
	}
	for _, c := range r.Commands() {
		if strings.Contains(c, "/home/sclaw/.env") || strings.Contains(c, "bash -c") {
			t.Errorf("wrote sclaw's config: %q", c)
		}
		if strings.Contains(c, "/bin/sh -c") && !strings.Contains(c, "--user root") {
			t.Errorf("root script run as sclaw: %q", c)
		}
	}
	// The layout is checked before anything is written.
	cmds := r.Commands()
	probe := slices.IndexFunc(cmds, func(c string) bool { return strings.Contains(c, "if [ -f /etc/safeclaw/env ]") })
	write := slices.IndexFunc(cmds, func(c string) bool { return strings.Contains(c, "cat > /etc/safeclaw/env") })
	if probe < 0 || probe > write || !strings.HasPrefix(cmds[probe], "exec --user root safeclaw-work /bin/sh -c ") {
		t.Errorf("layout probe = %d, write = %d: %v", probe, write, cmds)
	}
}

// TestEnsureWritesLegacyConfig checks that containers from older images,
// which only source sclaw's ~/.env, keep getting it and ~/.gitconfig.
func TestEnsureWritesLegacyConfig(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-old": {Running: true, Port: 7690, Image: "img"},
	}, native: true}
	m, r := newTestManager(t, w)
	_ = m.Secrets.Set(secrets.GitHubToken, "gh")
	if _, err := m.Ensure(context.Background(), Options{Name: "old", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	env, ok := r.Find("exec -i safeclaw-old sh -c umask 077 && cat > /home/sclaw/.env && chmod 600 /home/sclaw/.env")
	if !ok || !strings.Contains(env.Stdin, "export GH_TOKEN='gh'\n") {
		t.Errorf("legacy env not written: %v", r.Commands())
	}
	git, ok := r.Find("exec safeclaw-old bash -c umask 022\n")
	if !ok || !strings.Contains(git.String(), "git config --global user.name") || strings.Contains(git.String(), "credential") {
		t.Errorf("legacy git config not written: %v", r.Commands())
	}
	// Only the auto memory setting, which is not sclaw's, is written as root.
	if slices.ContainsFunc(r.Commands(), func(c string) bool {
		return (strings.HasPrefix(c, "exec -i --user root") || strings.HasPrefix(c, "exec --user root safeclaw-old /bin/sh -c umask 022")) &&
			!strings.Contains(c, "/etc/claude-code/managed-settings.d/")
	}) {
		t.Errorf("wrote as root in a legacy container: %v", r.Commands())
	}
}

// TestEnsureFailsOnEnvLayoutError checks that a failed layout check fails
// the run instead of writing secrets to a file the container doesn't source.
func TestEnsureFailsOnEnvLayoutError(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-x": {Running: true, Port: 7690, Image: "img"},
	}, native: true}
	m, r := newTestManager(t, w)
	r.Handler = func(args []string, stdin string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), "if [ -f /etc/safeclaw/env ]") {
			return []byte("garbage\n"), nil
		}
		return w.handle(args, stdin)
	}
	if _, err := m.Ensure(context.Background(), Options{Name: "x", NoOpen: true}); err == nil || !strings.Contains(err.Error(), "unexpected output") {
		t.Errorf("err = %v", err)
	}
	if hasCall(r, "exec -i") {
		t.Errorf("env written after a failed check: %v", r.Commands())
	}
}

func TestEnsureStartsStoppedContainer(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-x": {Port: 7700, Image: "img"},
	}, native: true}
	m, r := newTestManager(t, w)
	res, err := m.Ensure(context.Background(), Options{Name: "x", NoOpen: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Port != 7700 || !hasCall(r, "start safeclaw-x") {
		t.Errorf("port=%d calls=%v", res.Port, r.Commands())
	}
}

func TestEnsureVolumeRecreates(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-p": {Running: true, Port: 7705, Image: "img"},
	}, native: true}
	m, r := newTestManager(t, w)
	home, _ := os.UserHomeDir()
	res, err := m.Ensure(context.Background(), Options{Name: "p", Volume: "~/proj:/home/sclaw/proj", NoOpen: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCall(r, "rm -v -f safeclaw-p") {
		t.Error("container not removed")
	}
	if res.Port != 7705 {
		t.Errorf("port = %d, want the old port 7705 reused", res.Port)
	}
	run, _ := r.Find("run ")
	if !strings.Contains(run.String(), "-v "+filepath.Join(home, "proj")+":/home/sclaw/proj") {
		t.Errorf("volume not expanded: %q", run.String())
	}
}

func TestEnsureQuery(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{}, native: true, prompt: true}
	m, r := newTestManager(t, w)
	if _, err := m.Ensure(context.Background(), Options{Name: "q", Query: "Enter the dragon", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	cmds := r.Commands()
	i := slices.Index(cmds, "exec safeclaw-q safeclaw ttyd-wrapper --no-attach")
	j := slices.Index(cmds, "exec safeclaw-q tmux send-keys -t main -l -- Enter the dragon")
	if i < 0 || j < i {
		t.Fatalf("query flow wrong: %v", cmds)
	}
	if cmds[j+1] != "exec safeclaw-q tmux send-keys -t main Enter" || cmds[j+2] != "exec safeclaw-q tmux send-keys -t main Enter" {
		t.Errorf("expected two Enters after query: %v", cmds[j:])
	}
}

func TestEnsureQueryLegacyUmask(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{}, prompt: true}
	m, r := newTestManager(t, w)
	if _, err := m.Ensure(context.Background(), Options{Name: "q", Query: "hi", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	// The tmux server started here is the one Claude Code runs in.
	if !hasCall(r, "exec safeclaw-q bash -c umask 022\nif ! tmux has-session") {
		t.Errorf("legacy tmux session not started with umask 022: %v", r.Commands())
	}
}

func TestEnsureErrors(t *testing.T) {
	m, _ := newTestManager(t, &world{containers: map[string]*fakeContainer{}})
	if _, err := m.Ensure(context.Background(), Options{NoOpen: true}); !errors.Is(err, ErrNoImage) {
		t.Errorf("err = %v, want ErrNoImage", err)
	}

	m, r := newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{}})
	_ = m.Secrets.Delete(secrets.ClaudeToken)
	if _, err := m.Ensure(context.Background(), Options{NoOpen: true}); !errors.Is(err, ErrNoClaudeToken) {
		t.Errorf("err = %v, want ErrNoClaudeToken", err)
	}
	if hasCall(r, "run ") {
		t.Error("container created before token check")
	}

	if _, err := m.Ensure(context.Background(), Options{Name: "bad name", NoOpen: true}); err == nil {
		t.Error("invalid name accepted")
	}
}

type fakePrompter struct{ claude, gh string }

func (p fakePrompter) ClaudeToken() (string, error) { return p.claude, nil }
func (p fakePrompter) GitHubToken() (string, error) { return p.gh, nil }

func TestEnsurePromptsWhenInteractive(t *testing.T) {
	m, _ := newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{}, native: true})
	_ = m.Secrets.Delete(secrets.ClaudeToken)
	m.Prompter = fakePrompter{claude: "new-tok", gh: ""}
	if _, err := m.Ensure(context.Background(), Options{NoOpen: true, Interactive: true}); err != nil {
		t.Fatal(err)
	}
	if v, _ := m.Secrets.Get(secrets.ClaudeToken); v != "new-tok" {
		t.Errorf("token = %q", v)
	}
	if m.Secrets.Has(secrets.GitHubToken) {
		t.Error("empty GH token should be skipped")
	}
}

func TestList(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-zeta":  {Running: true, Port: 7682, Mounts: []string{"/s:/home/sclaw/.claude/projects", "/p:/home/sclaw/p"}},
		"safeclaw-alpha": {Port: 7681, Mounts: []string{"/s:/home/sclaw/.claude/projects"}},
		"safeclaw-beta":  {Running: true, Port: 7683, HostIP: "::1"},
		"safeclaw-box":   {Running: true, Mounts: []string{"/sandbox", "/in:/in:ro"}, Labels: sandboxLabels, AutoRemove: true},
	}}
	m, _ := newTestManager(t, w)
	list, err := m.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, s := range list {
		names = append(names, s.Name)
	}
	if !slices.Equal(names, []string{"beta", "box", "zeta", "alpha"}) {
		t.Errorf("order = %v, want active first then by name", names)
	}
	if list[2].Volume != "/p:/home/sclaw/p" || list[3].Volume != "-" {
		t.Errorf("volumes = %q, %q", list[2].Volume, list[3].Volume)
	}
	// zeta predates [::1] publishing, so its URL names 127.0.0.1.
	if list[3].URL != "" || list[0].URL != "http://[::1]:7683" || list[2].URL != "http://127.0.0.1:7682" {
		t.Errorf("urls = %q, %q, %q", list[0].URL, list[2].URL, list[3].URL)
	}
	box := list[1]
	if !box.IsSandbox() || box.Type != "sandbox" || box.URL != "" || box.Port != 0 || box.Volume != "/in:/in" {
		t.Errorf("sandbox = %+v", box)
	}
	if list[0].Type != "session" || list[0].IsSandbox() {
		t.Errorf("unlabelled container type = %q, want session", list[0].Type)
	}
	if !box.AutoRemove || !box.IsOneOff() || list[0].AutoRemove || list[0].IsOneOff() {
		t.Errorf("auto remove = %v, %v", box.AutoRemove, list[0].AutoRemove)
	}
	// IsOneOff only applies to sandboxes.
	if (Session{Type: "session", AutoRemove: true}).IsOneOff() {
		t.Error("an interactive session is never one-off")
	}
}

func TestNormalizeAndValidate(t *testing.T) {
	cases := map[string]string{"": "default", "  ": "default", "My Project": "my-project", "work": "work"}
	for in, want := range cases {
		if got := NormalizeName(in); got != want {
			t.Errorf("NormalizeName(%q) = %q, want %q", in, got, want)
		}
	}
	for _, bad := range []string{"-x", "a b", "a/b", "a;rm"} {
		if ValidateName(bad) == nil {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestExpandVolume(t *testing.T) {
	home, _ := os.UserHomeDir()
	wd, _ := os.Getwd()
	cases := map[string]string{
		"~/p:/home/sclaw/p":    filepath.Join(home, "p") + ":/home/sclaw/p",
		"./p:/home/sclaw/p:ro": filepath.Join(wd, "p") + ":/home/sclaw/p:ro",
		"/abs:/home/sclaw/abs": "/abs:/home/sclaw/abs",
	}
	for in, want := range cases {
		if got, err := ExpandVolume(in); err != nil || got != want {
			t.Errorf("ExpandVolume(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	if _, err := ExpandVolume("nocolon"); err == nil {
		t.Error("expected error")
	}
}

func TestPromptReady(t *testing.T) {
	if !PromptReady("header\n────\n❯ \n────\n") {
		t.Error("empty input line not detected")
	}
	if PromptReady("  ❯ No, exit\n    Yes, I accept\n") {
		t.Error("selection menu mistaken for the input prompt")
	}
}

func TestPromptReadyPlaceholder(t *testing.T) {
	if !PromptReady("────\n❯ Try \"fix lint errors\"\n────\n") {
		t.Error("input line with placeholder not detected")
	}
	if PromptReady(" ❯ No, exit\n   Yes, I trust this folder\n") {
		t.Error("indented menu matched")
	}
}
