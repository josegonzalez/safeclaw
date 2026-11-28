package cli

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/josegonzalez/safeclaw/internal/expand"
	"github.com/josegonzalez/safeclaw/internal/mail"
	"github.com/josegonzalez/safeclaw/internal/unpack"
)

func runExpand(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	cmd := newExpandCommand("safeclaw-expand")
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(t.Context())
	return out.String(), errOut.String(), err
}

// rejectedMail is a message over the part limit.
var rejectedMail = "Subject: x\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" + strings.Repeat("--b\r\nContent-Type: text/plain\r\n\r\nx\r\n", mail.MaxParts+1) + "--b--\r\n"

func TestExpandText(t *testing.T) {
	good := writeTestMail(t, testMail)
	bad := writeTestMail(t, rejectedMail)
	dest := filepath.Join(t.TempDir(), "out")
	out, errOut, err := runExpand(t, good, bad, dest)
	if err != nil {
		t.Fatalf("%v: %s", err, errOut)
	}
	want := "email\t1-m.eml\tUNPACKED,UNSAFE-NAME\t1-m.eml.unpacked\n" +
		"email\t2-m.eml\tREJECTED\t-\n"
	if out != want {
		t.Errorf("got\n%q\nwant\n%q", out, want)
	}
	if !strings.HasPrefix(errOut, "safeclaw-expand: left packed: 2-m.eml: rejected: ") || strings.Count(errOut, "\n") != 1 {
		t.Errorf("stderr = %q", errOut)
	}
	m, err := expand.ReadManifest(dest)
	if err != nil || len(m.Containers) != 2 {
		t.Fatalf("manifest = %+v, %v", m, err)
	}
	parts, err := os.ReadFile(filepath.Join(dest, "1-m.eml.unpacked", mail.PartsFile))
	if err != nil || !strings.Contains(string(parts), "1.2\tapplication/pdf\t4\t../in\\tv\\x1b.pdf\tATTACHMENT,UNSAFE-NAME\t1-_in v.pdf\n") {
		t.Errorf("parts.txt = %q, %v", parts, err)
	}
}

func TestExpandJSON(t *testing.T) {
	dest := filepath.Join(t.TempDir(), "out")
	out, _, err := runExpand(t, "--json", "--no-mail", "--depth", "1", "--max-size", "1k", writeTestMail(t, testMail), dest)
	if err != nil {
		t.Fatal(err)
	}
	var m expand.Manifest
	if err := json.Unmarshal([]byte(out), &m); err != nil {
		t.Fatal(err)
	}
	if m.Schema != expand.SchemaVersion || m.Status != "ok" || m.Options != (expand.ManifestOptions{Depth: 1, MaxSize: 1024}) || len(m.Inputs) != 1 || len(m.Containers) != 0 {
		t.Errorf("manifest = %+v", m)
	}
	disk, err := expand.ReadManifest(dest)
	if err != nil || disk.Options != m.Options {
		t.Errorf("manifest.json = %+v, %v", disk, err)
	}
}

// TestExpandEscapes checks that container paths are escaped in the text
// output and the rejected entries are listed, with the real 7z.
func TestExpandEscapes(t *testing.T) {
	if _, err := unpack.Find(); err != nil {
		t.Skip(err)
	}
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for name, body := range map[string]string{"evil\u202egpj.zip": "not a zip", "a\tb.eml": testMail} {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	h := &zip.FileHeader{Name: "link"}
	h.SetMode(os.ModeSymlink | 0o777)
	fw, err := w.CreateHeader(h)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write([]byte("/etc/passwd")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	inner := b.Bytes()
	var outer bytes.Buffer
	w = zip.NewWriter(&outer)
	for name, body := range map[string][]byte{"x\u202e.zip": inner, "y.zip": inner[:len(inner)-1]} {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	in := filepath.Join(t.TempDir(), "outer.zip")
	if err := os.WriteFile(in, outer.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	out, _, err := runExpand(t, in, filepath.Join(t.TempDir(), "out"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "zip\t1-outer.zip.unpacked/x\\u202e.zip\tREJECTED\t-\nentry\tfile\ta\\tb.eml\tUNSAFE-PATH\nentry\tsymlink\tlink\tLINK\nzip\t1-outer.zip.unpacked/y.zip\tFAILED\t-\n") {
		t.Errorf("output = %q", out)
	}
	if strings.Contains(out, "\u202e") {
		t.Errorf("unescaped: %q", out)
	}
}

func TestExpandFailures(t *testing.T) {
	file := writeTestMail(t, testMail)
	full := t.TempDir()
	if err := os.WriteFile(filepath.Join(full, "x"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name string
		args []string
	}{
		{"missing input", []string{filepath.Join(t.TempDir(), "nope"), filepath.Join(t.TempDir(), "out")}},
		{"dest not empty", []string{file, full}},
		{"bad size", []string{"--max-size", "nope", file, filepath.Join(t.TempDir(), "out")}},
		{"bad depth", []string{"--depth", "-1", file, filepath.Join(t.TempDir(), "out")}},
	} {
		_, errOut, err := runExpand(t, c.args...)
		if !errors.Is(err, exitCodeError{1}) || !strings.HasPrefix(errOut, "safeclaw-expand: ") {
			t.Errorf("%s: err = %v, stderr = %q", c.name, err, errOut)
		}
		out, _, _ := runExpand(t, append([]string{"--json"}, c.args...)...)
		var v expandFailureJSON
		if json.Unmarshal([]byte(out), &v) != nil || v.Code != 1 || v.Status != "failed" || v.Error == "" || v.Schema != expand.SchemaVersion {
			t.Errorf("%s: json = %q", c.name, out)
		}
	}
	if _, _, err := runExpand(t, file); err == nil {
		t.Error("one argument accepted")
	}
	t.Setenv("PW", "a\nb")
	if _, errOut, err := runExpand(t, "--password-env", "PW", file, filepath.Join(t.TempDir(), "out")); !errors.Is(err, exitCodeError{1}) || !strings.Contains(errOut, "line break") {
		t.Errorf("password with a line break: %v %q", err, errOut)
	}
}

// TestExpandResume checks reruns on one DEST: --skip and --unskip as the
// lines write paths, the options a rerun keeps, and --plan.
func TestExpandResume(t *testing.T) {
	good := writeTestMail(t, testMail)
	bad := writeTestMail(t, rejectedMail)
	dest := filepath.Join(t.TempDir(), "out")
	out, errOut, err := runExpand(t, "--depth", "1", "--max-size", "1m", "--skip", "1-m.eml", "--skip", `9-x\u202e.zip`, good, bad, dest)
	if err != nil {
		t.Fatalf("%v: %s", err, errOut)
	}
	if out != "email\t1-m.eml\tSKIPPED\t-\nemail\t2-m.eml\tREJECTED\t-\n" {
		t.Errorf("first run = %q", out)
	}
	if !strings.Contains(errOut, "safeclaw-expand: no container at 9-x\\u202e.zip yet; the skip is kept for a later run\n") {
		t.Errorf("stderr = %q", errOut)
	}
	m, err := expand.ReadManifest(dest)
	if err != nil || !slices.Equal(m.Skip, []string{"1-m.eml", "9-x\u202e.zip"}) {
		t.Fatalf("manifest = %+v, %v", m, err)
	}

	out, errOut, err = runExpand(t, "--plan", "--depth", "1", dest)
	if err != nil {
		t.Fatalf("%v: %s", err, errOut)
	}
	if !strings.HasPrefix(out, "email\t1-m.eml\tSKIPPED\t-\npart\t1\tmultipart/mixed\t") || !strings.Contains(out, "\npart\t1.2\tapplication/pdf\t4\t../in\\tv\\x1b.pdf\t") || !strings.HasSuffix(out, "\nemail\t2-m.eml\tREJECTED\t-\n") {
		t.Errorf("plan = %q", out)
	}
	out, _, err = runExpand(t, "--plan", "--json", "--depth", "1", dest)
	var plan struct {
		Status     string
		Containers []struct {
			Path  string
			Flags []string
			Parts []mailPartJSON
		}
	}
	if err != nil || json.Unmarshal([]byte(out), &plan) != nil || plan.Status != "ok" || len(plan.Containers) != 2 || len(plan.Containers[0].Parts) != 3 || plan.Containers[1].Parts != nil {
		t.Errorf("plan --json = %q, %v", out, err)
	}

	// A rerun must give DEST's depth; nothing in DEST sets it.
	for _, args := range [][]string{{"--depth", "2", dest}, {dest}, {"--plan", dest}} {
		if _, errOut, err := runExpand(t, args...); !errors.Is(err, exitCodeError{1}) || !strings.Contains(errOut, "a later run keeps it (--depth 1)") {
			t.Errorf("%v: %v %q", args, err, errOut)
		}
	}
	if _, errOut, err := runExpand(t, "--plan", "--skip", "1-m.eml", dest); !errors.Is(err, exitCodeError{1}) || !strings.Contains(errOut, "--plan") {
		t.Errorf("plan with skip: %v %q", err, errOut)
	}
	if _, errOut, err := runExpand(t, "--skip", `bad\q`, dest); !errors.Is(err, exitCodeError{1}) || !strings.Contains(errOut, "--skip") {
		t.Errorf("bad escape: %v %q", err, errOut)
	}
	out, errOut, err = runExpand(t, "--depth", "1", "--unskip", "1-m.eml", good, dest)
	if err != nil {
		t.Fatalf("%v: %s", err, errOut)
	}
	if out != "email\t1-m.eml\tUNPACKED,UNSAFE-NAME\t1-m.eml.unpacked\nemail\t2-m.eml\tREJECTED\t-\n" {
		t.Errorf("unskip = %q", out)
	}
	if m, err = expand.ReadManifest(dest); err != nil || m.Options.Depth != 1 || m.Options.MaxSize != 512<<20 || len(m.Inputs) != 2 {
		t.Errorf("manifest = %+v, %v", m, err)
	}
}

// TestExpandProgramName checks that the binary run as safeclaw-expand is
// `safeclaw expand`, and that `safeclaw expand` is registered.
func TestExpandProgramName(t *testing.T) {
	for arg0, want := range map[string]bool{
		"safeclaw-expand":                true,
		"/usr/local/bin/safeclaw-expand": true,
		"safeclaw":                       false,
		"safeclaw-unpack":                false,
		"safeclaw-expand-old":            false,
	} {
		if got := isExpandProgram(arg0); got != want {
			t.Errorf("isExpandProgram(%q) = %v", arg0, got)
		}
	}
	if code := executeExpand(t.Context(), []string{"--help"}); code != 0 {
		t.Errorf("--help exit = %d", code)
	}
	if code := executeExpand(t.Context(), []string{writeTestMail(t, testMail)}); code != 1 {
		t.Errorf("one argument exit = %d", code)
	}
	if code := executeExpand(t.Context(), []string{writeTestMail(t, testMail), filepath.Join(t.TempDir(), "out")}); code != 0 {
		t.Errorf("exit = %d", code)
	}
	var found *cobra.Command
	for _, c := range NewRootCommand().Commands() {
		if c.Name() == "expand" {
			found = c
		}
	}
	if found == nil {
		t.Error("safeclaw has no expand command")
	}
}

// TestExpandDirectory checks a directory input on the command line: its
// files are inputs, what is left out is noted on stderr, the same command
// line reruns, and a DEST inside it is refused.
func TestExpandDirectory(t *testing.T) {
	in := t.TempDir()
	if err := os.WriteFile(filepath.Join(in, "1-m.eml"), []byte(testMail), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc/passwd", filepath.Join(in, "2-link\tx")); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(t.TempDir(), "out")
	const lines = "email\t1-1-m.eml\tUNPACKED,UNSAFE-NAME\t1-1-m.eml.unpacked\n"
	out, errOut, err := runExpand(t, in, dest)
	if err != nil {
		t.Fatalf("%v: %s", err, errOut)
	}
	if out != lines {
		t.Errorf("out = %q", out)
	}
	if want := "safeclaw-expand: ignoring " + escapeField(filepath.Join(in, "2-link\tx")) + ": a symbolic link\n"; errOut != want {
		t.Errorf("stderr = %q, want %q", errOut, want)
	}
	out, _, err = runExpand(t, "--plan", in, dest)
	if err != nil || out != "" {
		t.Errorf("plan = %q, %v", out, err)
	}
	if out, _, err = runExpand(t, in, dest); err != nil || out != lines {
		t.Errorf("rerun = %q, %v", out, err)
	}
	if m, err := expand.ReadManifest(dest); err != nil || len(m.Inputs) != 1 {
		t.Errorf("manifest = %+v, %v", m, err)
	}

	empty, emptyDest := t.TempDir(), filepath.Join(t.TempDir(), "out")
	if out, errOut, err := runExpand(t, "--json", empty, emptyDest); err != nil || !strings.Contains(out, `"inputs":[]`) || errOut != "" {
		t.Errorf("empty = %q, %q, %v", out, errOut, err)
	}
	if _, errOut, err := runExpand(t, in, filepath.Join(in, "out")); !errors.Is(err, exitCodeError{1}) || !strings.Contains(errOut, "is inside the input directory") {
		t.Errorf("dest inside: %v %q", err, errOut)
	}
}
