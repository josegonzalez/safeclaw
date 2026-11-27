package session

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
)

// runImage returns the image reference a docker run call ran: the argument
// before "sleep infinity".
func runImage(t *testing.T, args []string) string {
	t.Helper()
	i := slices.Index(args, "sleep")
	if i < 1 {
		t.Fatalf("no image in %q", args)
	}
	return args[i-1]
}

// Sessions run as sclaw from the checked image ID, record the tag, and
// every exec that does not need root names sclaw too.
func TestEnsurePinsUserAndImage(t *testing.T) {
	w := &world{images: map[string]string{"safeclaw": "base-id"}, rootEnv: true, containers: map[string]*fakeContainer{}, native: true}
	m, r := newTestManager(t, w)
	if _, err := m.Ensure(context.Background(), Options{Name: "work", Query: "hi", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	run, ok := r.Find("run ")
	if !ok {
		t.Fatal("no docker run")
	}
	if got := runImage(t, run.Args); got != "sha256:base-id" {
		t.Errorf("ran %q, want the inspected ID", got)
	}
	s := run.String()
	if !strings.Contains(s, " --user sclaw ") || !strings.Contains(s, " --label safeclaw.image=safeclaw ") {
		t.Errorf("run = %q", s)
	}
	c := w.containers["safeclaw-work"]
	if c.User != config.SessionUser || c.RunImage != "safeclaw" || c.Labels[config.LabelImage] != "safeclaw" {
		t.Errorf("container = %+v", c)
	}
	execs := 0
	for _, call := range r.Calls {
		if call.Args[0] != "exec" {
			continue
		}
		execs++
		i := slices.Index(call.Args, "--user")
		if i < 0 || (call.Args[i+1] != config.SessionUser && call.Args[i+1] != "root") {
			t.Errorf("exec without an explicit user: %q", call.String())
		}
		if i >= 0 && call.Args[i+1] == "root" && !slices.Contains(call.Args, "/bin/sh") {
			t.Errorf("root exec not through rootShell: %q", call.String())
		}
	}
	if execs == 0 {
		t.Error("no execs")
	}
}

// The image whose labels were checked is the one that runs, even when its
// tag moves to another image between the check and the run.
func TestEnsureRunsCheckedImageAfterTagMoves(t *testing.T) {
	w := &world{images: map[string]string{"safeclaw": "old-id"}, containers: map[string]*fakeContainer{}, native: true}
	w.onInspectImage = func(tag string) {
		// A pull or build retags the image with a label only safeclaw may
		// set, which the check would have refused.
		w.images[tag] = "new-id"
		w.imageLabels = map[string]map[string]string{tag: {config.LabelType: config.TypeSandbox}}
	}
	m, r := newTestManager(t, w)
	if _, err := m.Ensure(context.Background(), Options{Name: "work", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	run, _ := r.Find("run ")
	if got := runImage(t, run.Args); got != "sha256:old-id" {
		t.Errorf("ran %q, want the checked sha256:old-id", got)
	}
	if c := w.containers["safeclaw-work"]; c.Image != "old-id" || TypeOf(dockerContainer(t, w, "safeclaw-work")) != config.TypeSession {
		t.Errorf("container = %+v", c)
	}
}

func TestSandboxesRunCheckedImageAfterTagMoves(t *testing.T) {
	ctx := context.Background()
	moving := func() *world {
		w := &world{images: map[string]string{"safeclaw": "base-id", "safeclaw:sandbox": "sb-id"}, containers: map[string]*fakeContainer{}}
		w.onInspectImage = func(tag string) { w.images[tag] = "moved-id" }
		return w
	}

	w := moving()
	m, r := newTestManager(t, w)
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: "box"}); err != nil {
		t.Fatal(err)
	}
	run, _ := r.Find("run ")
	if got := runImage(t, run.Args); got != "sha256:sb-id" || !strings.Contains(run.String(), " --label safeclaw.image=safeclaw:sandbox ") {
		t.Errorf("sandbox run = %q", run.String())
	}

	w = moving()
	m, r = newTestManager(t, w)
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: "job", Remove: true}); err != nil {
		t.Fatal(err)
	}
	run, _ = r.Find("run ")
	if got := runImage(t, run.Args); got != "sha256:sb-id" {
		t.Errorf("one-off sandbox ran %q", got)
	}

	w = moving()
	m, _ = newTestManager(t, w)
	argv, _, err := m.PrepareEphemeral(ctx, SandboxOptions{}, ExecOptions{}, []string{"ls"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(argv, "sha256:sb-id") || slices.Contains(argv, "safeclaw:sandbox") {
		t.Errorf("ephemeral argv = %q", argv)
	}
}

// The sign-in container runs as sclaw from the checked image ID too.
func TestSetupTokenPinsUserAndImage(t *testing.T) {
	m, r := newAuthManager(t, &authWorld{log: fakeToken + "\r\n"})
	if _, err := m.SetupToken(context.Background()); err != nil {
		t.Fatal(err)
	}
	run, _ := r.Find("run ")
	if got := runImage(t, run.Args); got != "sha256:img" || !strings.Contains(run.String(), " --user sclaw ") {
		t.Errorf("run = %q", run.String())
	}
}

// Ensure refuses every container that is not an interactive session, not
// only sandboxes, before checking the image or changing anything.
func TestEnsureRequiresSessionType(t *testing.T) {
	for typ, want := range map[string]error{config.TypeSandbox: ErrIsSandbox, "other": ErrNotManaged, "Session": ErrNotManaged} {
		w := &world{image: "img", containers: map[string]*fakeContainer{
			"safeclaw-work": {Running: true, Port: 7681, Labels: map[string]string{config.LabelType: typ}},
		}, native: true}
		m, r := newTestManager(t, w)
		_, err := m.Ensure(context.Background(), Options{Name: "work", Volume: "/proj:/proj", NoOpen: true})
		if !errors.Is(err, want) {
			t.Errorf("type %q: err = %v, want %v", typ, err, want)
		}
		for _, c := range r.Commands() {
			if strings.HasPrefix(c, "image ") || strings.HasPrefix(c, "rm ") || strings.HasPrefix(c, "run ") || strings.HasPrefix(c, "exec ") {
				t.Errorf("type %q: unexpected docker call %q", typ, c)
			}
		}
	}
}

// An image ID that is not a sha256 digest would be run as a name, so it
// is refused.
func TestCheckImageRefusesNonDigestID(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{}}
	m, r := newTestManager(t, w)
	r.Handler = func(args []string, stdin string) ([]byte, error) {
		if args[0] == "image" {
			return []byte(`{"Id":"safeclaw:evil","Config":{"Labels":null}}` + "\n"), nil
		}
		return w.handle(args, stdin)
	}
	if _, err := m.checkImage(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "not a sha256 digest") {
		t.Errorf("err = %v", err)
	}
}

// Sandbox run arguments refuse to be built without a checked image ID.
func TestSandboxRunArgsNeedImageID(t *testing.T) {
	if _, err := SandboxRunArgs("safeclaw-box", SandboxOptions{Variant: "sandbox"}); err == nil {
		t.Error("SandboxRunArgs without an image ID")
	}
	if _, err := EphemeralRunArgs("safeclaw-box", SandboxOptions{Variant: "sandbox"}, ExecOptions{}, []string{"ls"}); err == nil {
		t.Error("EphemeralRunArgs without an image ID")
	}
}

// sandbox inspect names the tag a sandbox run from an image ID recorded,
// and the image docker records for one run by tag.
func TestInspectSandboxImageTag(t *testing.T) {
	c := goodSandbox()
	cfg := c["Config"].(map[string]any)
	cfg["Image"] = "sha256:img"
	cfg["Labels"].(map[string]string)[config.LabelImage] = "safeclaw:sandbox"
	m, _ := newInspectManager(t, &inspectWorld{c: c})
	info, err := m.InspectSandbox(context.Background(), "box")
	if err != nil {
		t.Fatal(err)
	}
	if info.Image != "safeclaw:sandbox" || info.ImageID != "sha256:img" {
		t.Errorf("image = %q, id = %q", info.Image, info.ImageID)
	}
}

// dockerContainer returns the fake container as docker inspect reports it.
func dockerContainer(t *testing.T, w *world, name string) (c docker.Container) {
	t.Helper()
	var out []docker.Container
	if err := json.Unmarshal(w.inspectJSON([]string{name}), &out); err != nil || len(out) != 1 {
		t.Fatalf("inspect %s: %v", name, err)
	}
	return out[0]
}
