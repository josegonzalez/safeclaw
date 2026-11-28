package session

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
)

// nameConflict is the error docker run gives when the name is taken.
func nameConflict(name string) error {
	return &docker.Error{Args: []string{"run"}, Stderr: `docker: Error response from daemon: Conflict. The container name "/` + name + `" is already in use by container "0123abcd". You have to remove (or rename) that container to be able to reuse that name.`, Err: errors.New("exit status 125")}
}

// at is 2026-11-28 11:09:40 UTC, given in a zone east of UTC.
var at = time.Date(2026, 11, 28, 16, 39, 40, 0, time.FixedZone("IST", 5*3600+1800))

func TestPrefixedName(t *testing.T) {
	cases := map[int]string{0: "triage-20261128-110940", 1: "triage-20261128-110940-2", 8: "triage-20261128-110940-9"}
	for attempt, want := range cases {
		if got := prefixedName("triage", at, attempt); got != want {
			t.Errorf("prefixedName(attempt %d) = %q, want %q", attempt, got, want)
		}
	}
	if got := prefixedName("triage", at.UTC(), 0); got != cases[0] {
		t.Errorf("the same instant in UTC = %q, want %q", got, cases[0])
	}

	// 01:30 happens twice as US Eastern time leaves DST. The names follow
	// the instants, not the wall clock, and so does the order of names
	// made on each side of a time zone or DST change.
	edt := time.Date(2026, 11, 1, 1, 30, 0, 0, time.FixedZone("EDT", -4*3600))
	est := time.Date(2026, 11, 1, 1, 30, 0, 0, time.FixedZone("EST", -5*3600))
	a, b := prefixedName("job", edt, 0), prefixedName("job", est, 0)
	if a != "job-20261101-053000" || b != "job-20261101-063000" {
		t.Errorf("names across DST = %q, %q", a, b)
	}

	// Names sort in the order they were made: every suffix after the name
	// it was added to, and before the next second's name.
	var names []string
	for s := range 2 {
		for attempt := range prefixAttempts {
			names = append(names, prefixedName("job", at.Add(time.Duration(s)*time.Second), attempt))
		}
	}
	if !slices.IsSorted(names) {
		t.Errorf("names don't sort in the order they were made: %q", names)
	}
}

func TestResolveNamePrefix(t *testing.T) {
	good := map[string]string{
		"triage":          "triage",
		"Triage":          "triage",
		"safeclaw-triage": "triage",
		"a":               "a",
		"job_1.x-":        "job_1.x-",
	}
	for in, want := range good {
		if got, err := ResolveNamePrefix(in); err != nil || got != want {
			t.Errorf("ResolveNamePrefix(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	longest := strings.Repeat("a", MaxNamePrefix)
	if _, err := ResolveNamePrefix(longest); err != nil {
		t.Errorf("a %d character prefix: %v", MaxNamePrefix, err)
	}
	full := prefixedName(longest, at, prefixAttempts-1)
	if len(config.ContainerName(full)+".lock") != 255 || ValidateName(full) != nil {
		t.Errorf("the longest name %q should be valid and its lock file name 255 bytes", full)
	}
	bad := map[string]string{
		"":                           "invalid name prefix",
		"-job":                       "invalid name prefix",
		".job":                       "invalid name prefix",
		"a b":                        "invalid name prefix",
		"a/b":                        "invalid name prefix",
		"tri\x1bage":                 "invalid name prefix",
		"safeclaw-":                  "invalid name prefix",
		"safeclaw-safeclaw-x":        `may not start with "safeclaw-"`,
		longest + "a":                "at most 223 characters",
		"safeclaw-" + longest + "aa": "at most 223 characters",
	}
	for in, want := range bad {
		if _, err := ResolveNamePrefix(in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ResolveNamePrefix(%q) = %v, want an error with %q", in, err, want)
		}
	}
}

func newPrefixManager(t *testing.T, w *world) (*Manager, *dockertest.Runner, *bytes.Buffer) {
	t.Helper()
	m, r := newTestManager(t, w)
	m.Now = func() time.Time { return at }
	out := &bytes.Buffer{}
	m.Out = out
	return m, r, out
}

// runNames returns the names docker run was called with.
func runNames(r *dockertest.Runner) []string {
	var names []string
	for _, c := range r.Calls {
		if c.Args[0] != "run" {
			continue
		}
		if i := slices.Index(c.Args, "--name"); i > 0 {
			names = append(names, c.Args[i+1])
		}
	}
	return names
}

func TestEnsureSandboxNamePrefix(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{}}
	m, r, _ := newPrefixManager(t, w)
	res, err := m.EnsureSandbox(context.Background(), SandboxOptions{NamePrefix: "Triage", Remove: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Name != "triage-20261128-110940" || res.Container != "safeclaw-triage-20261128-110940" {
		t.Errorf("result = %+v", res)
	}
	if got := runNames(r); !slices.Equal(got, []string{"safeclaw-triage-20261128-110940"}) {
		t.Errorf("docker run names = %q", got)
	}
	if !hasCall(r, "run -d --rm --name safeclaw-triage-20261128-110940 ") {
		t.Errorf("not a one-off sandbox: %v", r.Commands())
	}
}

// A name an existing container has gets the next suffix, whatever that
// container is.
func TestEnsureSandboxNamePrefixTaken(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-triage-20261128-110940":   {Running: true, Image: "img", Labels: sandboxLabels},
		"safeclaw-triage-20261128-110940-2": {Running: false, Image: "img", Port: 7681},
	}}
	m, r, _ := newPrefixManager(t, w)
	res, err := m.EnsureSandbox(context.Background(), SandboxOptions{NamePrefix: "triage", Remove: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Name != "triage-20261128-110940-3" {
		t.Errorf("name = %q, want the -3 suffix", res.Name)
	}
	if got := runNames(r); !slices.Equal(got, []string{"safeclaw-triage-20261128-110940-3"}) {
		t.Errorf("docker run names = %q", got)
	}
	for _, p := range []string{"rm ", "stop ", "start "} {
		if hasCall(r, p) {
			t.Errorf("an existing container was touched: %v", r.Commands())
		}
	}
}

// A name taken between the check and docker run, which docker refuses, is
// retried with the next suffix.
func TestEnsureSandboxNamePrefixRace(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{},
		runErrs: []runErr{{err: nameConflict("safeclaw-job-20261128-110940")}}}
	m, r, out := newPrefixManager(t, w)
	res, err := m.EnsureSandbox(context.Background(), SandboxOptions{NamePrefix: "job", Remove: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Name != "job-20261128-110940-2" {
		t.Errorf("name = %q, want the -2 suffix", res.Name)
	}
	want := []string{"safeclaw-job-20261128-110940", "safeclaw-job-20261128-110940-2"}
	if got := runNames(r); !slices.Equal(got, want) {
		t.Errorf("docker run names = %q, want %q", got, want)
	}
	if hasCall(r, "rm ") {
		t.Errorf("the container that took the name was removed: %v", r.Commands())
	}
	if !strings.Contains(out.String(), "Name taken meanwhile: safeclaw-job-20261128-110940\n") {
		t.Errorf("output = %q", out.String())
	}
}

// After every suffix is taken it fails, naming the range, having tried
// each name once.
func TestEnsureSandboxNamePrefixExhausted(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-job-20261128-110940": {Running: true, Image: "img", Labels: sandboxLabels},
	}}
	for range prefixAttempts - 1 {
		w.runErrs = append(w.runErrs, runErr{err: nameConflict("x")})
	}
	m, r, _ := newPrefixManager(t, w)
	_, err := m.EnsureSandbox(context.Background(), SandboxOptions{NamePrefix: "job", Remove: true})
	if err == nil || !strings.Contains(err.Error(), "job-20261128-110940 through job-20261128-110940-9 are taken") {
		t.Errorf("err = %v", err)
	}
	if got := runNames(r); len(got) != prefixAttempts-1 || got[len(got)-1] != "safeclaw-job-20261128-110940-9" {
		t.Errorf("docker run names = %q", got)
	}

	// Any other docker run error fails at once.
	w = &world{image: "img", containers: map[string]*fakeContainer{},
		runErrs: []runErr{{err: &docker.Error{Args: []string{"run"}, Stderr: "no space left on device", Err: errors.New("exit status 125")}}}}
	m, r, _ = newPrefixManager(t, w)
	if _, err := m.EnsureSandbox(context.Background(), SandboxOptions{NamePrefix: "job", Remove: true}); err == nil || !strings.Contains(err.Error(), "no space left") {
		t.Errorf("err = %v", err)
	}
	if got := runNames(r); len(got) != 1 {
		t.Errorf("docker run names = %q, want one", got)
	}
}

// The clock is read once, so a retry keeps the timestamp.
func TestEnsureSandboxNamePrefixReadsClockOnce(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{},
		runErrs: []runErr{{err: nameConflict("x")}}}
	m, _, _ := newPrefixManager(t, w)
	calls := 0
	m.Now = func() time.Time {
		calls++
		return at.Add(time.Duration(calls-1) * time.Second)
	}
	res, err := m.EnsureSandbox(context.Background(), SandboxOptions{NamePrefix: "job", Remove: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Name != "job-20261128-110940-2" || calls != 1 {
		t.Errorf("name = %q after %d clock reads", res.Name, calls)
	}
}

func TestEnsureSandboxNamePrefixRefused(t *testing.T) {
	cases := map[string]SandboxOptions{
		"can't both be given":   {Name: "job", NamePrefix: "job", Remove: true},
		"only for one-off":      {NamePrefix: "job"},
		"invalid name prefix":   {NamePrefix: "a b", Remove: true},
		`may not start with "s`: {NamePrefix: "safeclaw-safeclaw-x", Remove: true},
	}
	for want, opts := range cases {
		m, r, _ := newPrefixManager(t, &world{image: "img", containers: map[string]*fakeContainer{}})
		if _, err := m.EnsureSandbox(context.Background(), opts); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%+v: err = %v, want %q", opts, err, want)
		}
		if len(r.Calls) != 0 {
			t.Errorf("%+v: docker was called: %v", opts, r.Commands())
		}
	}
	m, r, _ := newPrefixManager(t, &world{image: "img", containers: map[string]*fakeContainer{}})
	if _, _, err := m.PrepareEphemeral(context.Background(), SandboxOptions{NamePrefix: "job"}, ExecOptions{}, []string{"true"}); err == nil {
		t.Error("PrepareEphemeral took a name prefix")
	}
	if len(r.Calls) != 0 {
		t.Errorf("docker was called: %v", r.Commands())
	}
}

// When docker refuses the name of a sandbox to be verified, the container
// that has it isn't removed, even if ctx is done by then.
func TestCreateSandboxVerifiedNameConflict(t *testing.T) {
	r := &dockertest.Runner{Handler: func(args []string, _ string) ([]byte, error) {
		if args[0] == "run" {
			return nil, nameConflict("safeclaw-job")
		}
		return nil, nil
	}}
	m := &Manager{Docker: r.Client()}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	err := m.createSandboxVerified(ctx, "job", "safeclaw-job", SandboxOptions{image: "sha256:img"}.withDefaults())
	if !docker.IsNameConflict(err) {
		t.Errorf("err = %v, want the name conflict", err)
	}
	if hasCall(r, "rm ") {
		t.Errorf("the container with the name was removed: %v", r.Commands())
	}
}
