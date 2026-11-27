package cli

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
	"github.com/josegonzalez/safeclaw/internal/session"
)

// fakeNames makes newManager inspect containers from names, which hold the
// only containers that exist.
func fakeNames(t *testing.T, names ...string) *dockertest.Runner {
	t.Helper()
	r := &dockertest.Runner{Handler: func(args []string, _ string) ([]byte, error) {
		if len(args) > 2 && args[0] == "container" && args[1] == "inspect" && slices.Contains(names, args[2]) {
			return []byte(`[{"Id":"id","Name":"/` + args[2] + `","State":{"Status":"running","Running":true}}]`), nil
		}
		return nil, dockertest.NotFound(args)
	}}
	orig := newManager
	t.Cleanup(func() { newManager = orig })
	newManager = func() *session.Manager {
		return &session.Manager{Docker: r.Client(), NetworkDir: t.TempDir(), ChoicesDir: t.TempDir()}
	}
	return r
}

// CLI names are lowercased like the dashboard's, and a container made with
// a mixed-case name before that is refused instead of being mistaken for
// the lowercase session.
func TestRunSessionNames(t *testing.T) {
	fakeNames(t, "safeclaw-Old")
	for in, want := range map[string]string{"": "", "work": "work", "Work": "work", "safeclaw-Work": "work"} {
		opts, err := parseRunFlags(t, "-s", in)
		if err != nil || opts.Name != want {
			t.Errorf("-s %q: name = %q, %v, want %q", in, opts.Name, err, want)
		}
	}
	for _, bad := range []string{"safeclaw-safeclaw-work", "a b"} {
		if _, err := parseRunFlags(t, "-s", bad); err == nil {
			t.Errorf("-s %q accepted", bad)
		}
	}
	if _, err := parseRunFlags(t, "-s", "Old"); !errors.Is(err, session.ErrLegacyName) {
		t.Errorf("-s Old: err = %v, want ErrLegacyName", err)
	}
}

func TestRunFreshHistoryFlag(t *testing.T) {
	fakeNames(t)
	for _, tc := range []struct {
		args []string
		want bool
	}{{nil, false}, {[]string{"--fresh-history"}, true}} {
		opts, err := parseRunFlags(t, tc.args...)
		if err != nil || opts.FreshHistory != tc.want {
			t.Errorf("%v: fresh history = %v, %v", tc.args, opts.FreshHistory, err)
		}
	}
}

// Commands taking a session name refuse a legacy mixed-case one before
// acting on anything.
func TestCommandsRefuseLegacyNames(t *testing.T) {
	r := fakeNames(t, "safeclaw-Old")
	for _, args := range [][]string{{"stop", "Old"}, {"rm", "-f", "Old"}, {"attach", "Old"}, {"net", "off", "Old"}, {"net", "on", "Old"}, {"url", "Old"}} {
		r.Calls = nil
		root := NewRootCommand()
		_, err := run(t, root, args...)
		if !errors.Is(err, session.ErrLegacyName) || !strings.Contains(err.Error(), "docker rm -f safeclaw-Old") {
			t.Errorf("%v: err = %v, want ErrLegacyName", args, err)
		}
		for _, c := range r.Commands() {
			if !strings.HasPrefix(c, "container inspect") {
				t.Errorf("%v: ran %q", args, c)
			}
		}
	}
}
