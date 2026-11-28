package cli

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/session"
)

func TestSandboxInspectVerifyRegistered(t *testing.T) {
	root := newSandboxCommand()
	for _, name := range []string{"status", "inspect", "verify"} {
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

func TestSandboxInspectField(t *testing.T) {
	fakeContainers(t, map[string]string{
		"safeclaw-up":   fakeContainer("safeclaw-up", "sandbox", true),
		"safeclaw-chat": fakeContainer("safeclaw-chat", "session", true),
	}, nil)
	for field, want := range map[string]string{
		"running":      "true\n",
		"status":       "running\n",
		"name":         "up\n",
		"user":         "sandbox\n",
		"schema":       "1\n",
		"networks":     "[]\n",
		"limits":       `{"memory_bytes":1048576,"cpus":0,"pids":0,"disk_bytes":0}` + "\n",
		"labels":       `{"safeclaw.type":"sandbox"}` + "\n",
		"network_mode": "none\n",
	} {
		out, _, err := runStderr("sandbox", "inspect", "up", "--field", field)
		if err != nil || out != want {
			t.Errorf("--field %s: %q, %v; want %q", field, out, err, want)
		}
	}

	out, _, err := runStderr("sandbox", "inspect", "up")
	if err != nil || !strings.HasPrefix(out, "{\n  \"schema\": 1,") {
		t.Errorf("without --field: %q, %v", out, err)
	}

	// An unknown field is refused, naming the known ones, even for a
	// sandbox that doesn't exist.
	for _, name := range []string{"up", "gone"} {
		for _, field := range []string{"Running", "limits.cpus", ""} {
			out, _, err := runStderr("sandbox", "inspect", name, "--field", field)
			if out != "" || err == nil || !strings.Contains(err.Error(), "unknown field") || !strings.Contains(err.Error(), "running, schema, status") {
				t.Errorf("%s --field %q: %q, %v", name, field, out, err)
			}
		}
	}

	if _, _, err := runStderr("sandbox", "inspect", "chat", "--field", "running"); !errors.Is(err, session.ErrNotSandbox) {
		t.Errorf("session: err = %v", err)
	}
	if _, _, err := runStderr("sandbox", "inspect", "gone", "--field", "running"); !errors.Is(err, session.ErrNotFound) {
		t.Errorf("missing: err = %v", err)
	}
}

func TestInspectFields(t *testing.T) {
	fields := inspectFields()
	for _, want := range []string{"schema", "running", "limits", "mounts", "labels"} {
		if !slices.Contains(fields, want) {
			t.Errorf("fields %v lack %s", fields, want)
		}
	}
	if !slices.IsSorted(fields) {
		t.Errorf("fields not sorted: %v", fields)
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
