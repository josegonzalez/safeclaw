package cli

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/session"
)

func TestSandboxInspectVerifyRegistered(t *testing.T) {
	root := newSandboxCommand()
	for _, name := range []string{"inspect", "verify"} {
		cmd, _, err := root.Find([]string{name})
		if err != nil || cmd.Name() != name {
			t.Fatalf("sandbox %s: %v", name, err)
		}
		cmd.SetArgs(nil)
		cmd.SetOut(io.Discard)
		cmd.SetErr(io.Discard)
		if err := cmd.Args(cmd, nil); err == nil {
			t.Errorf("sandbox %s should need a NAME", name)
		}
	}
	verify, _, _ := root.Find([]string{"verify"})
	if verify.Flags().Lookup("json") == nil {
		t.Error("verify should have --json")
	}
}

func TestVerifyError(t *testing.T) {
	ok := session.SandboxReport{Name: "box", OK: true, Checks: []session.SandboxCheck{{Name: "network", OK: true}}}
	if err := verifyError(ok); err != nil {
		t.Errorf("passing report: %v", err)
	}
	r := session.SandboxReport{Name: "box", Checks: []session.SandboxCheck{
		{Name: "network", OK: true},
		{Name: "user"},
		{Name: "running"},
		{Name: "live-user", Skipped: true},
	}}
	want := `sandbox "box" failed 2 checks: user, running (1 check skipped)`
	if err := verifyError(r); err == nil || err.Error() != want {
		t.Errorf("err = %v, want %s", err, want)
	}
	r.Checks = r.Checks[:2]
	want = `sandbox "box" failed 1 check: user`
	if err := verifyError(r); err == nil || err.Error() != want {
		t.Errorf("err = %v, want %s", err, want)
	}
}

func TestWriteChecks(t *testing.T) {
	var b bytes.Buffer
	err := writeChecks(&b, []session.SandboxCheck{
		{Name: "network", OK: true, Detail: "network mode \"none\""},
		{Name: "user", Detail: "user \"root\""},
		{Name: "live-home", Skipped: true, Detail: "sandbox is not running"},
		{Name: "live-network", Detail: "bad\x1b[2Jname"},
	})
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n")
	want := []string{
		`ok    network       network mode "none"`,
		`FAIL  user          user "root"`,
		`SKIP  live-home     sandbox is not running`,
		`FAIL  live-network  "bad\x1b[2Jname"`,
	}
	if len(lines) != len(want) {
		t.Fatalf("output = %q", b.String())
	}
	for i := range want {
		if lines[i] != want[i] {
			t.Errorf("line %d = %q, want %q", i, lines[i], want[i])
		}
	}
}
