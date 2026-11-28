package session

import (
	"context"
	"strings"
	"testing"
)

// A sandbox created with a profile records it in two labels; one created
// without records none.
func TestSandboxProfileLabels(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{}}
	m, r := newTestManager(t, w)
	if _, err := m.EnsureSandbox(context.Background(), SandboxOptions{Name: "box", Profile: "triage", ProfileSHA256: "abc"}); err != nil {
		t.Fatal(err)
	}
	run, _ := r.Find("run ")
	if !strings.Contains(run.String(), " --label safeclaw.profile=triage --label safeclaw.profile.sha256=abc ") {
		t.Errorf("run = %q", run.String())
	}
	w = &world{image: "img", containers: map[string]*fakeContainer{}}
	m, r = newTestManager(t, w)
	if _, err := m.EnsureSandbox(context.Background(), SandboxOptions{Name: "box"}); err != nil {
		t.Fatal(err)
	}
	if run, _ := r.Find("run "); strings.Contains(run.String(), "safeclaw.profile") {
		t.Errorf("run without a profile = %q", run.String())
	}
	argv, _, err := m.PrepareEphemeral(context.Background(), SandboxOptions{Profile: "/p/triage.yaml", ProfileSHA256: "def"}, ExecOptions{}, []string{"true"})
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(argv, " "); !strings.Contains(got, " --label safeclaw.profile=/p/triage.yaml --label safeclaw.profile.sha256=def ") {
		t.Errorf("ephemeral argv = %q", got)
	}
}

// Limits given without Recreate, as a profile gives them, recreate an
// existing sandbox only when they differ from its own.
func TestEnsureSandboxLimitsDiffer(t *testing.T) {
	existing := func() *fakeContainer {
		return &fakeContainer{Running: true, Image: "img", Labels: sandboxLabels,
			Memory: 2 << 30, NanoCPUs: 1e9, PidsLimit: 256, Tmpfs: map[string]string{"/sandbox": "rw,size=1073741824"}}
	}
	for _, tc := range []struct {
		name     string
		opts     SandboxOptions
		recreate bool
	}{
		{"none", SandboxOptions{}, false},
		{"same", SandboxOptions{Memory: "2g", CPUs: "1", PidsLimit: 256, Disk: "1g"}, false},
		{"same in bytes", SandboxOptions{Memory: "2147483648", CPUs: "1.0", Disk: "1024m"}, false},
		{"memory", SandboxOptions{Memory: "1g"}, true},
		{"cpus", SandboxOptions{CPUs: "0.5"}, true},
		{"pids", SandboxOptions{PidsLimit: 64}, true},
		{"disk", SandboxOptions{Disk: "2g"}, true},
		{"unparsed memory", SandboxOptions{Memory: "2gb"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &world{image: "img", containers: map[string]*fakeContainer{"safeclaw-box": existing()}}
			m, r := newTestManager(t, w)
			tc.opts.Name = "box"
			if _, err := m.EnsureSandbox(context.Background(), tc.opts); err != nil {
				t.Fatal(err)
			}
			if got := hasCall(r, "rm -v -f safeclaw-box"); got != tc.recreate {
				t.Errorf("recreated = %v, want %v: %v", got, tc.recreate, r.Commands())
			}
		})
	}
}
