package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/version"
)

// setVersion sets the build information for one test.
func setVersion(t *testing.T, v string) {
	t.Helper()
	old := [3]string{version.Version, version.Commit, version.Date}
	t.Cleanup(func() { version.Version, version.Commit, version.Date = old[0], old[1], old[2] })
	version.Version, version.Commit, version.Date = v, "8d41adf", "2026-11-28T11:18:28Z"
}

func TestVersionText(t *testing.T) {
	setVersion(t, "0.3.0")
	out, err := run(t, NewRootCommand(), "version")
	if err != nil {
		t.Fatal(err)
	}
	if want := "safeclaw 0.3.0 (commit 8d41adf, built 2026-11-28T11:18:28Z)\n"; out != want {
		t.Errorf("output = %q, want %q", out, want)
	}
}

func TestVersionJSON(t *testing.T) {
	setVersion(t, "0.3.0")
	out, err := run(t, NewRootCommand(), "version", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, out)
	}
	want := map[string]any{"schema": float64(1), "version": "0.3.0", "commit": "8d41adf", "built": "2026-11-28T11:18:28Z"}
	if len(got) != len(want) {
		t.Errorf("fields = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %v, want %v", k, got[k], v)
		}
	}
}

func TestVersionRequire(t *testing.T) {
	setVersion(t, "0.3.0")
	for _, req := range []string{"0.3.0", "v0.3.0", "0.2.9", "v0.0.1"} {
		out, err := run(t, NewRootCommand(), "version", "--require", req)
		if err != nil {
			t.Errorf("--require %s: %v", req, err)
		}
		if !strings.HasPrefix(out, "safeclaw 0.3.0 ") {
			t.Errorf("--require %s output = %q", req, out)
		}
	}

	_, err := run(t, NewRootCommand(), "version", "--require", "v0.3.1")
	if err == nil || err.Error() != "safeclaw 0.3.0 is older than the required 0.3.1" {
		t.Errorf("--require v0.3.1 error = %v", err)
	}

	out, err := run(t, NewRootCommand(), "version", "--json", "--require", "1.0.0")
	if err == nil || !strings.Contains(err.Error(), "older than the required 1.0.0") {
		t.Errorf("--json --require 1.0.0 error = %v", err)
	}
	if !json.Valid([]byte(out)) {
		t.Errorf("--json --require output is not JSON: %q", out)
	}
}

func TestVersionRequireMalformed(t *testing.T) {
	setVersion(t, "0.3.0")
	for _, req := range []string{"", "0.3", "latest", "0.3.0-rc.1", "v.0.3.0"} {
		out, err := run(t, NewRootCommand(), "version", "--require", req)
		if err == nil || !strings.Contains(err.Error(), "--require: invalid version") {
			t.Errorf("--require %q error = %v", req, err)
		}
		if out != "" {
			t.Errorf("--require %q printed %q before refusing", req, out)
		}
	}
}

func TestVersionRequireDevBuild(t *testing.T) {
	setVersion(t, "dev")
	out, err := run(t, NewRootCommand(), "version", "--require", "0.0.0")
	if err == nil || !strings.Contains(err.Error(), "safeclaw dev is a development build") {
		t.Errorf("dev --require 0.0.0 error = %v", err)
	}
	if !strings.HasPrefix(out, "safeclaw dev ") {
		t.Errorf("output = %q", out)
	}

	out, err = run(t, NewRootCommand(), "version", "--json")
	if err != nil {
		t.Fatal(err)
	}
	var info version.Info
	if err := json.Unmarshal([]byte(out), &info); err != nil {
		t.Fatal(err)
	}
	if info.Version != "dev" {
		t.Errorf("dev --json version = %q", info.Version)
	}
}
