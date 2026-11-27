package session

import (
	"context"
	"errors"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/config"
)

func TestCheckImageLabels(t *testing.T) {
	for _, tc := range []struct {
		variant string
		labels  map[string]string
		ok      bool
	}{
		{"", nil, true},
		{"", map[string]string{"org.opencontainers.image.source": "x"}, true},
		{"sandbox", map[string]string{"safeclaw.variant": "sandbox"}, true},
		{"base", nil, true},
		{"", map[string]string{"safeclaw.variant": "sandbox"}, false},
		{"base", map[string]string{"safeclaw.variant": "base"}, false},
		{"docs", map[string]string{"safeclaw.variant": "sandbox"}, false},
		{"sandbox", map[string]string{"safeclaw.variant": "sandbox", "safeclaw.type": "session"}, false},
		{"", map[string]string{"safeclaw.type": "sandbox"}, false},
		{"", map[string]string{"safeclaw.secrets": ""}, false},
		{"", map[string]string{"safeclaw.ipc": "host"}, false},
		{"", map[string]string{"safeclaw.memory": "off"}, false},
		{"", map[string]string{"safeclaw.auth": "1"}, false},
		{"", map[string]string{"safeclaw.future": "x"}, false},
	} {
		err := checkImageLabels("img", tc.variant, tc.labels)
		if (err == nil) != tc.ok || (err != nil && !errors.Is(err, ErrImageLabel)) {
			t.Errorf("%q %v: err = %v, want ok %v", tc.variant, tc.labels, err, tc.ok)
		}
	}
}

// An image carrying safeclaw labels is refused before any container is made
// from it, whether new or reused, so its labels never reach a container.
func TestEnsureRefusesLabeledImage(t *testing.T) {
	ctx := context.Background()
	tainted := map[string]map[string]string{"safeclaw": {"safeclaw.ipc": "host"}}

	w := &world{image: "img", imageLabels: tainted, containers: map[string]*fakeContainer{}, native: true}
	m, r := newTestManager(t, w)
	if _, err := m.Ensure(ctx, Options{Name: "work", NoOpen: true}); !errors.Is(err, ErrImageLabel) {
		t.Errorf("new session: err = %v, want ErrImageLabel", err)
	}
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: "box", Variant: "base"}); !errors.Is(err, ErrImageLabel) {
		t.Errorf("new sandbox: err = %v, want ErrImageLabel", err)
	}
	if _, _, err := m.PrepareEphemeral(ctx, SandboxOptions{Variant: "base"}, ExecOptions{}, []string{"true"}); !errors.Is(err, ErrImageLabel) {
		t.Errorf("one-off sandbox: err = %v, want ErrImageLabel", err)
	}
	if hasCall(r, "run") {
		t.Errorf("created a container from a labeled image: %v", r.Commands())
	}

	w = &world{image: "img", imageLabels: tainted, containers: map[string]*fakeContainer{
		"safeclaw-work": {Running: true, Port: 7705, Image: "img", Labels: map[string]string{"safeclaw.ipc": "host"}},
	}, native: true}
	m, r = newTestManager(t, w)
	if _, err := m.Ensure(ctx, Options{Name: "work", NoOpen: true}); !errors.Is(err, ErrImageLabel) {
		t.Errorf("existing session: err = %v, want ErrImageLabel", err)
	}
	if hasCall(r, "exec") || hasCall(r, "rm") {
		t.Errorf("used a container of a labeled image: %v", r.Commands())
	}
}

// Sessions are labeled with their type, so it can't come from the image,
// and variant images keep working with their own variant label.
func TestEnsureLabelsSessionType(t *testing.T) {
	ctx := context.Background()
	w := &world{
		images:      map[string]string{"safeclaw": "base-id", "safeclaw:sandbox": "sb-id"},
		imageLabels: map[string]map[string]string{"safeclaw:sandbox": {"safeclaw.variant": "sandbox"}},
		containers:  map[string]*fakeContainer{}, native: true,
	}
	m, _ := newTestManager(t, w)
	for _, opts := range []Options{{Name: "plain", NoOpen: true}, {Name: "docs", Variant: "sandbox", NoOpen: true}} {
		if _, err := m.Ensure(ctx, opts); err != nil {
			t.Fatal(err)
		}
		c := w.containers[config.ContainerName(opts.Name)]
		if c.Labels["safeclaw.type"] != config.TypeSession {
			t.Errorf("%s: labels = %v", opts.Name, c.Labels)
		}
	}
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: "box"}); err != nil {
		t.Fatal(err)
	}
	if c := w.containers["safeclaw-box"]; c.Labels["safeclaw.type"] != config.TypeSandbox || c.Labels["safeclaw.variant"] != "sandbox" {
		t.Errorf("sandbox labels = %v", c.Labels)
	}
}
