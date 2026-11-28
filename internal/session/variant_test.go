package session

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/variant"
)

func variantsFrom(t *testing.T, yaml string) func() (*variant.Set, error) {
	t.Helper()
	s, err := variant.Parse([]byte(yaml))
	if err != nil {
		t.Fatal(err)
	}
	return func() (*variant.Set, error) { return s, nil }
}

func TestEnsureVariant(t *testing.T) {
	ctx := context.Background()
	w := &world{images: map[string]string{"safeclaw": "base-id", "safeclaw:sandbox": "sb-id"}, containers: map[string]*fakeContainer{}, native: true}
	m, r := newTestManager(t, w)

	// Sessions default to the base image, with no variant label.
	if _, err := m.Ensure(ctx, Options{Name: "plain", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if c := w.containers["safeclaw-plain"]; c.RunImage != "safeclaw" || c.Labels["safeclaw.variant"] != "" {
		t.Errorf("default session = %+v", c)
	}

	if _, err := m.Ensure(ctx, Options{Name: "docs", Variant: "sandbox", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	run, _ := r.Find("run -d --name safeclaw-docs")
	if !strings.Contains(run.String(), " --label safeclaw.variant=sandbox ") || !strings.HasSuffix(run.String(), " --label safeclaw.image=safeclaw:sandbox sha256:sb-id sleep infinity") {
		t.Errorf("run = %q", run.String())
	}

	list, err := m.List(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range list {
		want := map[string]string{"docs": "sandbox", "plain": ""}[s.Name]
		if s.Variant != want {
			t.Errorf("%s variant = %q, want %q", s.Name, s.Variant, want)
		}
	}
}

func TestEnsureVariantReuseAndRecreate(t *testing.T) {
	ctx := context.Background()
	existing := func() *world {
		return &world{images: map[string]string{"safeclaw": "base-id", "safeclaw:sandbox": "sb-id"}, containers: map[string]*fakeContainer{
			"safeclaw-p": {Running: true, Port: 7705, Image: "sb-id", Labels: map[string]string{"safeclaw.variant": "sandbox"},
				Mounts: []string{"/hist:/home/sclaw/.claude/projects", "/proj:/home/sclaw/proj", "/ref:/home/sclaw/ref:ro"}},
		}, native: true}
	}

	// Unspecified, or the same variant, keeps the container.
	for _, v := range []string{"", "sandbox"} {
		w := existing()
		m, r := newTestManager(t, w)
		if _, err := m.Ensure(ctx, Options{Name: "p", Variant: v, NoOpen: true}); err != nil {
			t.Fatal(err)
		}
		if hasCall(r, "rm ") || hasCall(r, "run ") {
			t.Errorf("variant %q: recreated: %v", v, r.Commands())
		}
	}

	// A different variant recreates it with the same port and mounts.
	w := existing()
	m, r := newTestManager(t, w)
	res, err := m.Ensure(ctx, Options{Name: "p", Variant: "base", NoOpen: true})
	if err != nil {
		t.Fatal(err)
	}
	if !hasCall(r, "rm -v -f safeclaw-p") || res.Port != 7705 {
		t.Errorf("not recreated on the old port: %d %v", res.Port, r.Commands())
	}
	run, _ := r.Find("run ")
	for _, want := range []string{"-v /proj:/home/sclaw/proj ", "-v /ref:/home/sclaw/ref:ro ", ":/home/sclaw/.claude/projects "} {
		if !strings.Contains(run.String(), want) {
			t.Errorf("run lacks %q: %q", want, run.String())
		}
	}
	if strings.Contains(run.String(), "/hist:") || strings.Contains(run.String(), "safeclaw.variant") || !strings.HasSuffix(run.String(), " --label safeclaw.image=safeclaw sha256:base-id sleep infinity") {
		t.Errorf("run = %q", run.String())
	}

	// A volume recreate keeps the variant.
	w = existing()
	m, r = newTestManager(t, w)
	if _, err := m.Ensure(ctx, Options{Name: "p", Volume: "/new:/home/sclaw/new", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	run, _ = r.Find("run ")
	if !strings.Contains(run.String(), "--label safeclaw.variant=sandbox") || !strings.Contains(run.String(), "-v /new:/home/sclaw/new ") || strings.Contains(run.String(), "-v /proj:") {
		t.Errorf("volume recreate run = %q", run.String())
	}
}

func TestEnsureSandboxVariant(t *testing.T) {
	ctx := context.Background()
	w := &world{images: map[string]string{"safeclaw": "base-id", "safeclaw:sandbox": "sb-id"}, containers: map[string]*fakeContainer{}}
	m, r := newTestManager(t, w)
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: "plain", Variant: "base"}); err != nil {
		t.Fatal(err)
	}
	run, _ := r.Find("run -d --name safeclaw-plain")
	if strings.Contains(run.String(), "safeclaw.variant") || !strings.HasSuffix(run.String(), " --label safeclaw.image=safeclaw sha256:base-id sleep infinity") {
		t.Errorf("base sandbox run = %q", run.String())
	}
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Remove: true, Name: "job"}); err != nil {
		t.Fatal(err)
	}
	if c := w.containers["safeclaw-job"]; c.RunImage != "safeclaw:sandbox" || c.Labels["safeclaw.variant"] != "sandbox" {
		t.Errorf("one-off sandbox = %+v", c)
	}
}

func TestEnsureSandboxRecreateKeeps(t *testing.T) {
	ctx := context.Background()
	existing := func() *world {
		return &world{images: map[string]string{"safeclaw": "base-id", "safeclaw:sandbox": "sb-id"}, containers: map[string]*fakeContainer{
			"safeclaw-box": {Running: true, Image: "sb-id", Labels: map[string]string{"safeclaw.type": "sandbox", "safeclaw.variant": "sandbox"},
				Mounts: []string{"/in:/in:ro"}, Memory: 2 << 30, NanoCPUs: 500_000_000, PidsLimit: 64,
				Tmpfs: map[string]string{"/tmp": "rw,nosuid,nodev,size=256m", "/sandbox": "rw,nosuid,nodev,exec,size=536870912,uid=2000,gid=2000,mode=0700"}},
		}}
	}
	cases := []struct {
		name string
		opts SandboxOptions
		want []string
	}{
		{"variant", SandboxOptions{Name: "box", Variant: "base"},
			[]string{" --memory 2147483648 --pids-limit 64 --cpus 0.5 SIGS--mount type=bind,src=/in,dst=/in,readonly,bind-propagation=rprivate,bind-recursive=readonly --label safeclaw.image=safeclaw sha256:base-id sleep infinity"}},
		{"volume", SandboxOptions{Name: "box", Volumes: []string{"/new:/new"}},
			[]string{"--label safeclaw.variant=sandbox ", " --memory 2147483648 --pids-limit 64 --cpus 0.5 SIGS--mount type=bind,src=/new,dst=/new,readonly,bind-propagation=rprivate,bind-recursive=readonly --label safeclaw.image=safeclaw:sandbox sha256:sb-id sleep infinity"}},
		{"limit", SandboxOptions{Name: "box", Memory: "4g", Recreate: true},
			[]string{"--label safeclaw.variant=sandbox ", "size=536870912,", " --memory 4g --pids-limit 64 --cpus 0.5 SIGS--mount type=bind,src=/in,dst=/in,readonly,bind-propagation=rprivate,bind-recursive=readonly --label safeclaw.image=safeclaw:sandbox sha256:sb-id sleep infinity"}},
		{"disk", SandboxOptions{Name: "box", Disk: "2g", Recreate: true},
			[]string{"size=2147483648,", " --memory 2147483648 --pids-limit 64 --cpus 0.5 SIGS--mount type=bind,src=/in,dst=/in,readonly,bind-propagation=rprivate,bind-recursive=readonly --label safeclaw.image=safeclaw:sandbox sha256:sb-id sleep infinity"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m, r := newTestManager(t, existing())
			if _, err := m.EnsureSandbox(ctx, tc.opts); err != nil {
				t.Fatal(err)
			}
			if !hasCall(r, "rm -v -f safeclaw-box") {
				t.Errorf("not recreated: %v", r.Commands())
			}
			run, _ := r.Find("run ")
			for _, want := range tc.want {
				want = strings.ReplaceAll(want, " SIGS", sigMount(m)+" ")
				if !strings.Contains(run.String(), want) {
					t.Errorf("run = %q\nlacks %q", run.String(), want)
				}
			}
		})
	}

	// The same variant, or none, keeps the sandbox.
	for _, v := range []string{"", "sandbox"} {
		m, r := newTestManager(t, existing())
		if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: "box", Variant: v}); err != nil {
			t.Fatal(err)
		}
		if hasCall(r, "rm ") || hasCall(r, "run ") {
			t.Errorf("variant %q: recreated: %v", v, r.Commands())
		}
	}
}

func TestVariantErrors(t *testing.T) {
	ctx := context.Background()
	// Only the base image exists.
	w := &world{images: map[string]string{"safeclaw": "base-id"}, containers: map[string]*fakeContainer{}, native: true}
	m, r := newTestManager(t, w)

	_, err := m.EnsureSandbox(ctx, SandboxOptions{Name: "box"})
	if !errors.Is(err, ErrNoImage) || !strings.Contains(err.Error(), "'safeclaw:sandbox'") ||
		!strings.Contains(err.Error(), "`safeclaw pull --variant sandbox`") || !strings.Contains(err.Error(), "`safeclaw build --variant sandbox`") {
		t.Errorf("err = %v", err)
	}
	if _, _, err := m.PrepareEphemeral(ctx, SandboxOptions{}, ExecOptions{}, []string{"ls"}); !errors.Is(err, ErrNoImage) {
		t.Errorf("ephemeral err = %v", err)
	}
	if _, err := m.Ensure(ctx, Options{Name: "s", Variant: "sandbox", NoOpen: true}); !errors.Is(err, ErrNoImage) {
		t.Errorf("session err = %v", err)
	}
	if _, err := m.Ensure(ctx, Options{Name: "s", Variant: "nope", NoOpen: true}); !errors.Is(err, variant.ErrUnknown) {
		t.Errorf("unknown err = %v", err)
	}
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: "box", Variant: "nope"}); !errors.Is(err, variant.ErrUnknown) {
		t.Errorf("unknown sandbox err = %v", err)
	}
	if hasCall(r, "run ") {
		t.Errorf("created a container: %v", r.Commands())
	}

	// The base image error names the plain commands.
	m, _ = newTestManager(t, &world{containers: map[string]*fakeContainer{}})
	_, err = m.Ensure(ctx, Options{NoOpen: true})
	if !errors.Is(err, ErrNoImage) || err.Error() != "image 'safeclaw' not found. Run `safeclaw pull` or `safeclaw build` first" {
		t.Errorf("base err = %v", err)
	}

	// A broken config file fails what needs it.
	m.LoadVariants = func() (*variant.Set, error) { return nil, errors.New("bad config") }
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: "box"}); err == nil || err.Error() != "bad config" {
		t.Errorf("config err = %v", err)
	}
}

func TestConfiguredDefaults(t *testing.T) {
	ctx := context.Background()
	w := &world{image: "img", containers: map[string]*fakeContainer{}, native: true}
	m, _ := newTestManager(t, w)
	m.LoadVariants = variantsFrom(t, "defaults:\n  session: docs\n  sandbox: base\nvariants:\n  docs:\n    packages: [pandoc]\n")
	if _, err := m.Ensure(ctx, Options{Name: "s", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: "box"}); err != nil {
		t.Fatal(err)
	}
	if c := w.containers["safeclaw-s"]; c.RunImage != "safeclaw:docs" || c.Labels["safeclaw.variant"] != "docs" {
		t.Errorf("session = %+v", c)
	}
	if c := w.containers["safeclaw-box"]; c.RunImage != "safeclaw" || c.Labels["safeclaw.variant"] != "" {
		t.Errorf("sandbox = %+v", c)
	}
}
