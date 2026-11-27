package session

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/secrets"
)

var sandboxLabels = map[string]string{"safeclaw.type": "sandbox"}

// sandboxRunPrefix is the run command of a sandbox on the default sandbox
// variant.
const sandboxRunPrefix = "run -d --name safeclaw-box --label safeclaw.type=sandbox --label safeclaw.variant=sandbox --network none --user sandbox --workdir /sandbox" +
	" --env HOME=/sandbox --env BASH_ENV= --env PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" +
	" --cap-drop ALL --security-opt no-new-privileges --read-only --tmpfs /tmp:rw,nosuid,nodev,size=256m" +
	" --tmpfs " + sandboxDirTmpfs

// sandboxDirTmpfs is the default /sandbox tmpfs: 1g, owned by the sandbox
// user.
const sandboxDirTmpfs = "/sandbox:rw,nosuid,nodev,exec,size=1073741824,uid=2000,gid=2000,mode=0700"

func TestEnsureSandboxCreates(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{}}
	m, r := newTestManager(t, w)
	// A sandbox must not need, or receive, any secret.
	_ = m.Secrets.Delete(secrets.ClaudeToken)
	_ = m.Secrets.Set(secrets.GitHubToken, "gh-secret")

	res, err := m.EnsureSandbox(context.Background(), SandboxOptions{Name: "box"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Container != "safeclaw-box" || res.Port != 0 || res.URL != "" {
		t.Errorf("result = %+v", res)
	}
	run, ok := r.Find("run ")
	if !ok {
		t.Fatal("no docker run")
	}
	want := sandboxRunPrefix + " --memory 2g --pids-limit 256 --cpus 1 safeclaw:sandbox sleep infinity"
	if run.String() != want {
		t.Errorf("run = %q\nwant  %q", run.String(), want)
	}
	for _, c := range r.Commands() {
		if strings.HasPrefix(c, "exec ") {
			t.Errorf("sandbox should run nothing in the container: %q", c)
		}
		if strings.Contains(c, "gh-secret") || strings.Contains(c, "--ipc") || strings.Contains(c, " -p ") {
			t.Errorf("unexpected docker call: %q", c)
		}
	}
	if _, err := os.Stat(filepath.Join(m.SessionsDir, "box")); !os.IsNotExist(err) {
		t.Errorf("sandbox should not get a history dir: %v", err)
	}
}

func TestEnsureSandboxLimitsAndVolume(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{}}
	m, r := newTestManager(t, w)
	_, err := m.EnsureSandbox(context.Background(), SandboxOptions{
		Name: "box", Volumes: []string{"/in:/in:rw,z"}, Memory: "512m", PidsLimit: 64, CPUs: "0.5", Disk: "256m",
	})
	if err != nil {
		t.Fatal(err)
	}
	run, _ := r.Find("run ")
	want := strings.Replace(sandboxRunPrefix, "size=1073741824,", "size=268435456,", 1) + " --memory 512m --pids-limit 64 --cpus 0.5 -v /in:/in:ro,z safeclaw:sandbox sleep infinity"
	if run.String() != want {
		t.Errorf("run = %q\nwant  %q", run.String(), want)
	}
}

func TestEnsureSandboxReuse(t *testing.T) {
	cases := []struct {
		name    string
		running bool
		opts    SandboxOptions
		want    string // call that must be made
		wantNot []string
	}{
		{"running", true, SandboxOptions{Name: "box"}, "", []string{"run ", "start ", "rm "}},
		{"stopped", false, SandboxOptions{Name: "box"}, "start safeclaw-box", []string{"run ", "rm "}},
		{"volume", true, SandboxOptions{Name: "box", Volumes: []string{"/in:/in"}}, "rm -v -f safeclaw-box", nil},
		{"limits", false, SandboxOptions{Name: "box", Memory: "2g", Recreate: true}, "rm -v -f safeclaw-box", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			w := &world{image: "img", containers: map[string]*fakeContainer{
				"safeclaw-box": {Running: tc.running, Image: "img", Labels: sandboxLabels},
			}}
			m, r := newTestManager(t, w)
			if _, err := m.EnsureSandbox(context.Background(), tc.opts); err != nil {
				t.Fatal(err)
			}
			if tc.want != "" && !hasCall(r, tc.want) {
				t.Errorf("missing %q in %v", tc.want, r.Commands())
			}
			for _, p := range tc.wantNot {
				if hasCall(r, p) {
					t.Errorf("unexpected %q in %v", p, r.Commands())
				}
			}
			if len(tc.opts.Volumes) > 0 || tc.opts.Recreate {
				run, ok := r.Find("run ")
				if !ok || !strings.Contains(run.String(), "--label safeclaw.type=sandbox") {
					t.Errorf("not recreated as a sandbox: %v", r.Commands())
				}
				// A sandbox without a /sandbox tmpfs, such as one made with
				// a volume before there was --disk, gets the default size.
				if !strings.Contains(run.String(), " --tmpfs "+sandboxDirTmpfs+" ") {
					t.Errorf("recreated without the default /sandbox tmpfs: %q", run.String())
				}
			}
		})
	}
}

func TestEnsureSandboxErrors(t *testing.T) {
	ctx := context.Background()
	m, r := newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-work": {Running: true, Port: 7681, Image: "img"},
		"safeclaw-box":  {Running: true, Image: "img", Labels: sandboxLabels},
	}})
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{}); !errors.Is(err, ErrSandboxName) {
		t.Errorf("err = %v, want ErrSandboxName", err)
	}
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: "bad name"}); err == nil {
		t.Error("invalid name accepted")
	}
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: "work", Volumes: []string{"/in:/in"}}); !errors.Is(err, ErrNotSandbox) {
		t.Errorf("err = %v, want ErrNotSandbox", err)
	}
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: "box", PidsLimit: -1}); err == nil {
		t.Error("negative pids limit accepted")
	}
	// A tmpfs of size 0 has no limit, so 0 is refused like a bad size, and
	// before an existing sandbox is removed to recreate it.
	for _, disk := range []string{"0", "0g", "1.5g", "-1g", "big"} {
		for _, opts := range []SandboxOptions{{Name: "box", Disk: disk, Recreate: true}, {Remove: true, Disk: disk}} {
			if _, err := m.EnsureSandbox(ctx, opts); err == nil {
				t.Errorf("disk %q accepted", disk)
			}
		}
	}
	if hasCall(r, "rm ") || hasCall(r, "run ") {
		t.Errorf("should not touch containers: %v", r.Commands())
	}

	m, _ = newTestManager(t, &world{containers: map[string]*fakeContainer{}})
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: "box"}); !errors.Is(err, ErrNoImage) {
		t.Errorf("err = %v, want ErrNoImage", err)
	}
}

func TestEnsureRefusesSandbox(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-box": {Running: true, Image: "img", Labels: sandboxLabels},
	}}
	m, r := newTestManager(t, w)
	// The sandbox error wins over a missing token.
	_ = m.Secrets.Delete(secrets.ClaudeToken)
	_, err := m.Ensure(context.Background(), Options{Name: "box", Volume: "/in:/in", NoOpen: true})
	if !errors.Is(err, ErrIsSandbox) {
		t.Fatalf("err = %v, want ErrIsSandbox", err)
	}
	if !strings.Contains(err.Error(), `"box"`) {
		t.Errorf("error should name the session: %v", err)
	}
	for _, c := range r.Commands() {
		if !strings.HasPrefix(c, "image inspect") && !strings.HasPrefix(c, "container inspect") {
			t.Errorf("unexpected docker call: %q", c)
		}
	}
}

func TestRequireType(t *testing.T) {
	ctx := context.Background()
	m, _ := newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-box":  {Labels: sandboxLabels},
		"safeclaw-work": {Port: 7681},
	}})
	cases := []struct {
		name, want string
		err        error
	}{
		{"box", config.TypeSandbox, nil},
		{"work", config.TypeSession, nil},
		{"box", config.TypeSession, ErrIsSandbox},
		{"work", config.TypeSandbox, ErrNotSandbox},
		{"safeclaw-box", config.TypeSandbox, nil},
		{"missing", config.TypeSession, ErrNotFound},
	}
	for _, tc := range cases {
		err := m.RequireType(ctx, tc.name, tc.want)
		if (tc.err == nil && err != nil) || (tc.err != nil && !errors.Is(err, tc.err)) {
			t.Errorf("RequireType(%q, %q) = %v, want %v", tc.name, tc.want, err, tc.err)
		}
	}
}

func TestReadOnlyVolume(t *testing.T) {
	home, _ := os.UserHomeDir()
	cases := map[string]string{
		"/in:/in":          "/in:/in:ro",
		"/in:/in:ro":       "/in:/in:ro",
		"/in:/in:rw":       "/in:/in:ro",
		"/in:/in:rw,z":     "/in:/in:ro,z",
		"/in:/in:z,ro":     "/in:/in:ro,z",
		"~/inbox:/in":      filepath.Join(home, "inbox") + ":/in:ro",
		"/in:/in:cached,Z": "/in:/in:ro,cached,Z",
	}
	for in, want := range cases {
		if got, err := ReadOnlyVolume(in); err != nil || got != want {
			t.Errorf("ReadOnlyVolume(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"/in", ":/in", "/in:", "/in::ro"} {
		if _, err := ReadOnlyVolume(bad); err == nil {
			t.Errorf("ReadOnlyVolume(%q) should fail", bad)
		}
	}
}

// stubNames makes randomName return names in order, then the last one.
func stubNames(t *testing.T, names ...string) {
	t.Helper()
	orig := randomName
	t.Cleanup(func() { randomName = orig })
	i := 0
	randomName = func() string {
		n := names[min(i, len(names)-1)]
		i++
		return n
	}
}

func TestRandomName(t *testing.T) {
	a, b := randomName(), randomName()
	if !strings.HasPrefix(a, "tmp-") || len(a) != len("tmp-")+8 || ValidateName(a) != nil {
		t.Errorf("random name = %q", a)
	}
	if a == b {
		t.Errorf("random names repeat: %q", a)
	}
}

func TestEnsureSandboxRemove(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{}}
	m, r := newTestManager(t, w)
	res, err := m.EnsureSandbox(context.Background(), SandboxOptions{Name: "job", Remove: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Name != "job" || res.Container != "safeclaw-job" {
		t.Errorf("result = %+v", res)
	}
	run, _ := r.Find("run ")
	want := strings.Replace(sandboxRunPrefix, "run -d --name safeclaw-box", "run -d --rm --name safeclaw-job", 1) +
		" --memory 2g --pids-limit 256 --cpus 1 safeclaw:sandbox sleep infinity"
	if run.String() != want {
		t.Errorf("run = %q\nwant  %q", run.String(), want)
	}
	for _, c := range r.Commands() {
		if strings.HasPrefix(c, "exec ") {
			t.Errorf("sandbox should run nothing in the container: %q", c)
		}
	}
	// Stopping it removes it.
	if err := m.Stop(context.Background(), "job"); err != nil {
		t.Fatal(err)
	}
	if _, ok := w.containers["safeclaw-job"]; ok {
		t.Error("one-off sandbox survived stop")
	}
}

func TestEnsureSandboxRemoveRandomName(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-tmp-taken": {Running: true, Image: "img", Labels: sandboxLabels},
	}}
	m, r := newTestManager(t, w)
	stubNames(t, "tmp-taken", "tmp-free")
	res, err := m.EnsureSandbox(context.Background(), SandboxOptions{Remove: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Name != "tmp-free" {
		t.Errorf("name = %q, want tmp-free", res.Name)
	}
	if !hasCall(r, "run -d --rm --name safeclaw-tmp-free ") || hasCall(r, "rm ") {
		t.Errorf("calls = %v", r.Commands())
	}

	stubNames(t, "tmp-taken")
	if _, err := m.EnsureSandbox(context.Background(), SandboxOptions{Remove: true}); err == nil {
		t.Error("expected an error when every random name is taken")
	}
}

func TestEnsureSandboxRemoveRefusesExisting(t *testing.T) {
	for _, existing := range []*fakeContainer{
		{Running: true, Image: "img", Labels: sandboxLabels},
		{Running: false, Image: "img", Labels: sandboxLabels},
		{Running: true, Port: 7681, Image: "img"},
	} {
		w := &world{image: "img", containers: map[string]*fakeContainer{"safeclaw-job": existing}}
		m, r := newTestManager(t, w)
		_, err := m.EnsureSandbox(context.Background(), SandboxOptions{Name: "job", Remove: true, Volumes: []string{"/in:/in"}, Recreate: true})
		if !errors.Is(err, ErrExists) || !strings.Contains(err.Error(), `"job"`) {
			t.Errorf("err = %v, want ErrExists naming the sandbox", err)
		}
		for _, p := range []string{"rm ", "run ", "start ", "stop "} {
			if hasCall(r, p) {
				t.Errorf("unexpected %q in %v", p, r.Commands())
			}
		}
	}
}

func TestEnsureSandboxRemoveErrors(t *testing.T) {
	ctx := context.Background()
	m, _ := newTestManager(t, &world{containers: map[string]*fakeContainer{}})
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Remove: true}); !errors.Is(err, ErrNoImage) {
		t.Errorf("err = %v, want ErrNoImage", err)
	}
	m, _ = newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{}})
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: "bad name", Remove: true}); err == nil {
		t.Error("invalid name accepted")
	}
}

func TestSandboxCommand(t *testing.T) {
	prefix := []string{"/bin/sh", "-c", `umask 022; exec "$@"`, "sh"}
	for _, cmd := range [][]string{
		{"ls"},
		{"pdftotext", "-", "-"},
		// Leading dashes, empty args, spaces, quotes, and shell syntax are
		// positional parameters, never parsed by the wrapper.
		{"-x", "--", "", "a b", `"$HOME"`, "; rm -rf /", "$(id)"},
	} {
		if got := SandboxCommand(cmd); !slices.Equal(got, append(slices.Clone(prefix), cmd...)) {
			t.Errorf("SandboxCommand(%q) = %q", cmd, got)
		}
	}
}

func TestEphemeralRunArgs(t *testing.T) {
	isolation := strings.TrimPrefix(sandboxRunPrefix, "run -d ")
	base := strings.Replace(isolation, " --label safeclaw.variant=sandbox", "", 1)
	limits := " --memory 2g --pids-limit 256 --cpus 1"
	wrapped := `/bin/sh -c umask 022; exec "$@" sh pdftotext - -`
	sb := SandboxOptions{Variant: "sandbox"}
	cases := []struct {
		i, t bool
		opts SandboxOptions
		want string
	}{
		{false, false, sb, "--rm --init " + isolation + limits + " safeclaw:sandbox " + wrapped},
		{true, false, sb, "--rm --init -i " + isolation + limits + " safeclaw:sandbox " + wrapped},
		{true, true, sb, "--rm --init -i -t " + isolation + limits + " safeclaw:sandbox " + wrapped},
		{false, false, SandboxOptions{Variant: "sandbox", Volumes: []string{"/in:/in:rw"}, Memory: "4g", PidsLimit: 8, CPUs: "2", Disk: "2g"},
			"--rm --init " + strings.Replace(isolation, "size=1073741824,", "size=2147483648,", 1) + " --memory 4g --pids-limit 8 --cpus 2 -v /in:/in:ro safeclaw:sandbox " + wrapped},
		// Already resolved: empty is the base image.
		{false, false, SandboxOptions{}, "--rm --init " + base + limits + " safeclaw " + wrapped},
		{false, false, SandboxOptions{Variant: "base"}, "--rm --init " + base + limits + " safeclaw " + wrapped},
	}
	for _, tc := range cases {
		got, err := EphemeralRunArgs("safeclaw-box", tc.opts, ExecOptions{Interactive: tc.i, TTY: tc.t}, []string{"pdftotext", "-", "-"})
		if err != nil {
			t.Fatal(err)
		}
		if s := strings.Join(got, " "); s != tc.want {
			t.Errorf("args = %q\nwant   %q", s, tc.want)
		}
	}
	if _, err := EphemeralRunArgs("safeclaw-box", SandboxOptions{Volumes: []string{"/in"}}, ExecOptions{}, []string{"ls"}); err == nil {
		t.Error("invalid volume accepted")
	}
	if _, err := EphemeralRunArgs("safeclaw-box", SandboxOptions{Disk: "0"}, ExecOptions{}, []string{"ls"}); err == nil {
		t.Error("zero disk accepted")
	}
}

func TestPrepareEphemeral(t *testing.T) {
	ctx := context.Background()
	w := &world{image: "img", containers: map[string]*fakeContainer{}}
	m, r := newTestManager(t, w)
	out := &strings.Builder{}
	m.Out = out
	stubNames(t, "tmp-abcd1234")
	argv, name, err := m.PrepareEphemeral(ctx, SandboxOptions{}, ExecOptions{Interactive: true}, []string{"cat"})
	if err != nil {
		t.Fatal(err)
	}
	if name != "tmp-abcd1234" {
		t.Errorf("name = %q", name)
	}
	want, _ := EphemeralRunArgs("safeclaw-tmp-abcd1234", SandboxOptions{Variant: "sandbox"}, ExecOptions{Interactive: true}, []string{"cat"})
	if !slices.Equal(argv, append([]string{"docker", "run"}, want...)) {
		t.Errorf("argv = %v", argv)
	}
	// The caller runs the container; preparing only inspects.
	for _, c := range r.Commands() {
		if !strings.HasPrefix(c, "image inspect") && !strings.HasPrefix(c, "container inspect") {
			t.Errorf("unexpected docker call: %q", c)
		}
	}
	if out.Len() != 0 {
		t.Errorf("PrepareEphemeral printed %q", out)
	}

	argv, name, err = m.PrepareEphemeral(ctx, SandboxOptions{Name: "job"}, ExecOptions{}, []string{"ls"})
	if err != nil || name != "job" || !slices.Contains(argv, "safeclaw-job") {
		t.Errorf("named: %v %q %v", argv, name, err)
	}
}

func TestPrepareEphemeralErrors(t *testing.T) {
	ctx := context.Background()
	m, _ := newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-job": {Running: true, Image: "img", Labels: sandboxLabels},
	}})
	if _, _, err := m.PrepareEphemeral(ctx, SandboxOptions{Name: "job"}, ExecOptions{}, []string{"ls"}); !errors.Is(err, ErrExists) {
		t.Errorf("err = %v, want ErrExists", err)
	}
	if _, _, err := m.PrepareEphemeral(ctx, SandboxOptions{}, ExecOptions{}, nil); !errors.Is(err, ErrNoCommand) {
		t.Errorf("err = %v, want ErrNoCommand", err)
	}
	if _, _, err := m.PrepareEphemeral(ctx, SandboxOptions{PidsLimit: -1}, ExecOptions{}, []string{"ls"}); err == nil {
		t.Error("negative pids limit accepted")
	}
	if _, _, err := m.PrepareEphemeral(ctx, SandboxOptions{Disk: "0"}, ExecOptions{}, []string{"ls"}); err == nil {
		t.Error("zero disk accepted")
	}
	m, _ = newTestManager(t, &world{containers: map[string]*fakeContainer{}})
	if _, _, err := m.PrepareEphemeral(ctx, SandboxOptions{}, ExecOptions{}, []string{"ls"}); !errors.Is(err, ErrNoImage) {
		t.Errorf("err = %v, want ErrNoImage", err)
	}
}
