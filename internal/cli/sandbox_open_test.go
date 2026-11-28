package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
	"github.com/josegonzalez/safeclaw/internal/secrets"
	"github.com/josegonzalez/safeclaw/internal/session"
)

// fakeDockerScript stands in for the docker binary the helpers run
// through. It records its arguments, one per line and each call ended by
// END, and what docker would read from --env-file /dev/fd/3, then prints
// HELPER.out and exits with HELPER.code from FAKE_DOCKER_DIR, after
// sleeping HELPER.sleep seconds when that is there.
const fakeDockerScript = `#!/bin/sh
d=$FAKE_DOCKER_DIR
for a do printf '%s\n' "$a" >> "$d/argv"; done
echo END >> "$d/argv"
case " $* " in *" --env-file /dev/fd/3 "*) cat /dev/fd/3 >> "$d/env";; esac
case " $* " in *" safeclaw-totext "*) h=totext;; *) h=expand;; esac
echo "$h" >> "$d/ran"
[ -f "$d/$h.sleep" ] && sleep "$(cat "$d/$h.sleep")"
[ -f "$d/$h.out" ] && cat "$d/$h.out"
exit "$(cat "$d/$h.code" 2>/dev/null || echo 0)"
`

// openWorld fakes docker for `sandbox open`: dockertest answers the
// inspect and helper probe, and a docker script on PATH runs the helpers.
type openWorld struct {
	dir     string
	r       *dockertest.Runner
	missing string
	// containers are the inspect JSON of each container, by name.
	containers map[string]string
}

func newOpenWorld(t *testing.T) *openWorld {
	t.Helper()
	w := &openWorld{dir: t.TempDir()}
	bin := t.TempDir()
	if err := os.WriteFile(filepath.Join(bin, "docker"), []byte(fakeDockerScript), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("FAKE_DOCKER_DIR", w.dir)
	cs := map[string]string{
		"safeclaw-box":  fakeContainer("safeclaw-box", "sandbox", true),
		"safeclaw-chat": fakeContainer("safeclaw-chat", "session", true),
	}
	w.containers = cs
	w.r = &dockertest.Runner{Handler: func(args []string, _ string) ([]byte, error) {
		if args[0] == "ps" {
			return []byte("safeclaw-box\nsafeclaw-chat\n"), nil
		}
		if len(args) > 2 && args[0] == "container" && args[1] == "inspect" {
			if c, ok := cs[args[2]]; ok {
				return []byte("[" + c + "]"), nil
			}
		}
		if args[0] == "exec" {
			return []byte(w.missing), nil
		}
		return nil, dockertest.NotFound(args)
	}}
	store := secrets.FileStore{Dir: filepath.Join(t.TempDir(), ".secrets")}
	orig := newManager
	t.Cleanup(func() { newManager = orig })
	newManager = func() *session.Manager {
		return &session.Manager{Docker: w.r.Client(), Secrets: store}
	}
	return w
}

// helper sets what the fake helper prints and exits with.
func (w *openWorld) helper(t *testing.T, name, out, code string) {
	t.Helper()
	for ext, v := range map[string]string{".out": out, ".code": code} {
		if err := os.WriteFile(filepath.Join(w.dir, name+ext), []byte(v), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func (w *openWorld) read(name string) string {
	b, _ := os.ReadFile(filepath.Join(w.dir, name))
	return string(b)
}

// calls returns the recorded docker argv of each helper run.
func (w *openWorld) calls() [][]string {
	var calls [][]string
	var cur []string
	for line := range strings.Lines(w.read("argv")) {
		line = strings.TrimSuffix(line, "\n")
		if line == "END" {
			calls = append(calls, append([]string{"docker"}, cur...))
			cur = nil
			continue
		}
		cur = append(cur, line)
	}
	return calls
}

const (
	openedOut = "email\t1-a.eml\tUNPACKED\t1-a.eml.unpacked\nzip\t1-a.eml.unpacked/1-b.zip\tREJECTED\t1-a.eml.unpacked/1-b.zip.unpacked\nentry\tsymlink\tlink\t-\n"
	packedOut = "email\t1-a.eml\tUNPACKED\t1-a.eml.unpacked\nzip\t1-a.eml.unpacked/1-b.zip\tNEEDS-PASSWORD\t-\n"
)

func TestSandboxOpenArgv(t *testing.T) {
	w := newOpenWorld(t)
	w.helper(t, "expand", openedOut, "0")
	w.helper(t, "totext", "tree\tok\t0\t0\tfolded\t-\n", "0")
	const password = "hunter2 -p $(x)"
	t.Setenv("TRIAGE_PASSWORD", password)
	out, stderr, err := runStderr("sandbox", "open", "box", "--password-env", "TRIAGE_PASSWORD", "--skip", "1-a.eml.unpacked/1-c.zip",
		"--unskip", "-x", "--depth", "5", "--no-mail", "--max-size", "200m", "--hold", "mail-archives", "--release", "1-a.eml.unpacked/1-d.zip", "--text", "--max-pages", "300", "--ocr-threshold", "40",
		"--max-files", "20000", "--timeout", "2h")
	if err != nil {
		t.Fatalf("err = %v, stderr = %q", err, stderr)
	}
	if out != openedOut+"tree\tok\t0\t0\tfolded\t-\n" || stderr != "" {
		t.Errorf("out = %q, stderr = %q", out, stderr)
	}
	exec := []string{"docker", "exec"}
	wrap := []string{"--user", "sandbox", "--workdir", "/sandbox", "safeclaw-box", "/bin/sh", "-c", `umask 022; exec "$@"`, "sh", "timeout", "--kill-after=5s", "--", "7200s"}
	want := [][]string{
		slices.Concat(exec, []string{"--env-file", "/dev/fd/3"}, wrap, []string{"safeclaw-expand", "--depth=5", "--max-size=200m", "--no-mail=true", "--hold=mail-archives",
			"--release=1-a.eml.unpacked/1-d.zip", "--skip=1-a.eml.unpacked/1-c.zip", "--unskip=-x", "--", "/sandbox/in", "/sandbox/tree"}),
		slices.Concat(exec, wrap, []string{"safeclaw-totext", "--recursive", "--replace", "--max-pages=300", "--ocr-threshold=40", "--max-files=20000",
			"--", "/sandbox/tree", "/sandbox/out"}),
	}
	if got := w.calls(); !slices.EqualFunc(got, want, slices.Equal[[]string]) {
		t.Errorf("argv =\n%q\nwant\n%q", got, want)
	}
	// The password reaches docker only through the pipe, and only for
	// safeclaw-expand.
	if strings.Contains(w.read("argv"), "hunter2") {
		t.Errorf("the password is in docker's argv:\n%s", w.read("argv"))
	}
	if got := w.read("env"); got != "SAFECLAW_UNPACK_PASSWORD="+password+"\n" {
		t.Errorf("env = %q", got)
	}
	for _, c := range w.r.Calls {
		if strings.Contains(strings.Join(c.Raw, " ")+c.Stdin, "hunter2") {
			t.Errorf("the password reached dockertest: %q", c.Raw)
		}
	}
}

func TestSandboxOpenNoPassword(t *testing.T) {
	w := newOpenWorld(t)
	w.helper(t, "expand", openedOut, "0")
	t.Setenv("EMPTY_PASSWORD", "")
	for _, args := range [][]string{{"--password-env", "UNSET_PASSWORD"}, {"--password-env", "EMPTY_PASSWORD"}, nil} {
		if _, stderr, err := runStderr(append([]string{"sandbox", "open", "box"}, args...)...); err != nil {
			t.Fatalf("%q: err = %v, stderr = %q", args, err, stderr)
		}
	}
	for _, c := range w.calls() {
		if slices.Contains(c, "--env-file") {
			t.Errorf("no password, but argv = %q", c)
		}
	}
	if w.read("env") != "" {
		t.Errorf("env = %q", w.read("env"))
	}
}

func TestSandboxOpenPlan(t *testing.T) {
	w := newOpenWorld(t)
	w.helper(t, "expand", packedOut, "0")
	// A plan lists packed containers, which is not a failure.
	out, stderr, err := runStderr("sandbox", "open", "box", "--plan", "--depth", "2", "--max-size", "1g", "--no-mail", "--hold", "mail-archives")
	if err != nil || out != packedOut || stderr != "" {
		t.Errorf("err = %v, out = %q, stderr = %q", err, out, stderr)
	}
	// The inputs are planned with the tree, with the same policy flags a
	// run gets.
	want := []string{"docker", "exec", "--user", "sandbox", "--workdir", "/sandbox", "safeclaw-box", "/bin/sh", "-c", `umask 022; exec "$@"`, "sh",
		"timeout", "--kill-after=5s", "--", "1800s", "safeclaw-expand", "--depth=2", "--max-size=1g", "--no-mail=true", "--hold=mail-archives",
		"--plan", "--", "/sandbox/in", "/sandbox/tree"}
	if got := w.calls(); len(got) != 1 || !slices.Equal(got[0], want) {
		t.Errorf("argv = %q\nwant %q", got, want)
	}
	// The probe looks for what the plan reads.
	probe, ok := w.r.Find("exec --user sandbox --workdir /sandbox safeclaw-box /bin/sh -c")
	if !ok || !slices.Equal(probe.Args[len(probe.Args)-3:], []string{"safeclaw-expand", "/sandbox/in", "/sandbox/tree"}) {
		t.Errorf("probe = %q", probe.Args)
	}
	w.helper(t, "expand", "", "1")
	if _, _, err := runStderr("sandbox", "open", "box", "--plan"); !errors.Is(err, exitCodeError{openExpandFailed}) {
		t.Errorf("failed plan: err = %v", err)
	}
}

// A plan takes the open section's policy from a profile, as a run does.
func TestSandboxOpenPlanProfile(t *testing.T) {
	w := newOpenWorld(t)
	w.helper(t, "expand", packedOut, "0")
	p := testProfile(t, "open:\n  depth: 3\n  hold: [mail-archives]\n  no-mail: true\n  max-size: 2g\n  max-pages: 300\n")
	if _, stderr, err := runStderr("sandbox", "open", "box", "--plan", "--profile", p); err != nil {
		t.Fatalf("err = %v, stderr = %q", err, stderr)
	}
	want := []string{"safeclaw-expand", "--depth=3", "--max-size=2g", "--no-mail=true", "--hold=mail-archives", "--plan", "--", "/sandbox/in", "/sandbox/tree"}
	if got := w.calls(); len(got) != 1 || !slices.Equal(got[0][len(got[0])-len(want):], want) {
		t.Errorf("argv = %q\nwant it to end %q", got, want)
	}
}

func TestSandboxOpenPlanNothing(t *testing.T) {
	// Nothing new and nothing packed: an empty plan, said on stderr.
	w := newOpenWorld(t)
	w.helper(t, "expand", "", "0")
	out, stderr, err := runStderr("sandbox", "open", "box", "--plan")
	if err != nil || out != "" || stderr != "Nothing to open: no archive or email in /sandbox/in is new, and none is left packed in /sandbox/tree\n" {
		t.Errorf("empty plan: err = %v, out = %q, stderr = %q", err, out, stderr)
	}

	// Nothing copied in: the tree alone is planned.
	w = newOpenWorld(t)
	w.missing = "/sandbox/in\n"
	w.helper(t, "expand", packedOut, "0")
	if out, _, err := runStderr("sandbox", "open", "box", "--plan"); err != nil || out != packedOut {
		t.Errorf("no inputs: err = %v, out = %q", err, out)
	}
	if got := w.calls(); len(got) != 1 || !slices.Equal(got[0][len(got[0])-4:], []string{"safeclaw-expand", "--plan", "--", "/sandbox/tree"}) {
		t.Errorf("no inputs: argv = %q", got)
	}

	// Nothing copied in or opened: no helper runs.
	w = newOpenWorld(t)
	w.missing = "/sandbox/tree\n/sandbox/in\n"
	out, stderr, err = runStderr("sandbox", "open", "box", "--plan")
	if err != nil || out != "" || stderr != "Nothing to plan: nothing has been copied into /sandbox/in, and /sandbox/tree has not been opened\n" {
		t.Errorf("nothing: err = %v, out = %q, stderr = %q", err, out, stderr)
	}
	if w.read("argv") != "" {
		t.Errorf("nothing: ran %s", w.read("argv"))
	}
}

func TestSandboxOpenNoInputs(t *testing.T) {
	wrap := []string{"docker", "exec", "--user", "sandbox", "--workdir", "/sandbox", "safeclaw-box",
		"/bin/sh", "-c", `umask 022; exec "$@"`, "sh", "timeout", "--kill-after=5s", "--", "1800s"}
	totext := slices.Concat(wrap, []string{"safeclaw-totext", "--recursive", "--replace", "--", "/sandbox/tree", "/sandbox/out"})
	for _, tc := range []struct {
		name, missing string
		args          []string
		expand        string
		code          int
		want          [][]string
		stderr        string
	}{
		// Nothing copied in: the tree is resumed with no new inputs, so
		// releases, retries, and skips still apply.
		{name: "release", missing: "/sandbox/in\n", args: []string{"--hold", "mail-archives", "--release", "1-a.eml.unpacked/1-b.zip", "--skip", "2-c.zip"},
			expand: openedOut, want: [][]string{slices.Concat(wrap, []string{"safeclaw-expand", "--hold=mail-archives", "--release=1-a.eml.unpacked/1-b.zip", "--skip=2-c.zip", "--", "/sandbox/tree"})}},
		{name: "retry, packed", missing: "/sandbox/in\n", expand: packedOut, code: openLeftPacked,
			want:   [][]string{slices.Concat(wrap, []string{"safeclaw-expand", "--", "/sandbox/tree"})},
			stderr: "Some containers were left packed in /sandbox/tree; see the lines above\n"},
		{name: "text", missing: "/sandbox/in\n", args: []string{"--text"}, expand: openedOut,
			want: [][]string{slices.Concat(wrap, []string{"safeclaw-expand", "--", "/sandbox/tree"}), totext}},
		// Nothing copied in or opened: a note, and no helper runs.
		{name: "nothing", missing: "/sandbox/in\n/sandbox/tree\n", args: []string{"--hold", "mail-archives"},
			stderr: "Nothing to open: nothing has been copied into /sandbox/in, and /sandbox/tree has not been opened\n"},
		{name: "nothing, text", missing: "/sandbox/in\n/sandbox/tree\n", args: []string{"--text", "--max-pages", "3"},
			stderr: "Nothing to open: nothing has been copied into /sandbox/in, and /sandbox/tree has not been opened, so /sandbox/out was not rebuilt\n"},
		// A container named with nothing to name it in fails in
		// safeclaw-expand, as on a first run.
		{name: "nothing, release", missing: "/sandbox/in\n/sandbox/tree\n", args: []string{"--hold", "mail-archives", "--release", "1-a.zip"},
			expand: "safeclaw-expand: no inputs, and no manifest in the destination to resume from\n", code: openExpandFailed,
			want:   [][]string{slices.Concat(wrap, []string{"safeclaw-expand", "--hold=mail-archives", "--release=1-a.zip", "--", "/sandbox/tree"})},
			stderr: "Error: safeclaw-expand failed with exit code 1\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newOpenWorld(t)
			w.missing = tc.missing
			code := "0"
			if tc.code == openExpandFailed {
				code = "1"
			}
			w.helper(t, "expand", tc.expand, code)
			w.helper(t, "totext", "", "0")
			_, stderr, err := runStderr(append([]string{"sandbox", "open", "box"}, tc.args...)...)
			if tc.code == 0 && err != nil || tc.code != 0 && !errors.Is(err, exitCodeError{tc.code}) {
				t.Errorf("err = %v, want exit %d", err, tc.code)
			}
			if got := w.calls(); !slices.EqualFunc(got, tc.want, slices.Equal[[]string]) {
				t.Errorf("argv =\n%q\nwant\n%q", got, tc.want)
			}
			if stderr != tc.stderr {
				t.Errorf("stderr = %q, want %q", stderr, tc.stderr)
			}
		})
	}
}

// A sandbox that keeps its inputs records a run that resumed the tree
// with no new inputs, as any run whose safeclaw-expand finished, and not
// one that had nothing to open.
func TestSandboxOpenNoInputsRecord(t *testing.T) {
	for _, tc := range []struct {
		missing string
		want    string
	}{
		{"/sandbox/in\n", `[{"args":["--hold=mail-archives","--release=1-a.zip"]}]`},
		{"/sandbox/in\n/sandbox/tree\n", `[]`},
	} {
		w := newOpenWorld(t)
		w.missing = tc.missing
		w.helper(t, "expand", openedOut, "0")
		dir := filepath.Join(t.TempDir(), "record")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, session.InputsFile), []byte(`{"schema":1,"verify":false,"files":[],"opens":[]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		w.containers["safeclaw-box"] = strings.Replace(fakeContainer("safeclaw-box", "sandbox", true),
			`"safeclaw.type":"sandbox"`, `"safeclaw.type":"sandbox","safeclaw.keep-inputs":"`+dir+`"`, 1)
		args := []string{"sandbox", "open", "box", "--hold", "mail-archives"}
		if tc.missing == "/sandbox/in\n" {
			args = append(args, "--release", "1-a.zip")
		}
		if _, stderr, err := runStderr(args...); err != nil {
			t.Fatalf("%q: err = %v, stderr = %q", tc.missing, err, stderr)
		}
		b, err := os.ReadFile(filepath.Join(dir, session.InputsFile))
		if err != nil {
			t.Fatal(err)
		}
		var rec struct {
			Opens json.RawMessage `json:"opens"`
		}
		if err := json.Unmarshal(b, &rec); err != nil {
			t.Fatal(err)
		}
		var got, want any
		_ = json.Unmarshal(rec.Opens, &got)
		_ = json.Unmarshal([]byte(tc.want), &want)
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%q: opens = %s, want %s", tc.missing, rec.Opens, tc.want)
		}
	}
}

func TestSandboxOpenEscapes(t *testing.T) {
	w := newOpenWorld(t)
	w.helper(t, "expand", "zip\t1-\x1b[2Ja.zip\tUNPACKED\t1-a.zip.unpacked\n\x07\xff", "0")
	out, _, err := runStderr("sandbox", "open", "box")
	if err != nil {
		t.Fatal(err)
	}
	if want := `zip` + "\t" + `1-\x1b[2Ja.zip` + "\t" + `UNPACKED` + "\t" + `1-a.zip.unpacked` + "\n" + `\x07\xff`; out != want {
		t.Errorf("out = %q, want %q", out, want)
	}
}

func TestSandboxOpenExitCodes(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		text                 bool
		expand, expandCode   string
		totext, totextCode   string
		code                 int
		ran, stderr, nostder string
	}{
		{name: "opened", expand: openedOut, expandCode: "0", ran: "expand\n"},
		{name: "packed", expand: packedOut, expandCode: "0", code: openLeftPacked, ran: "expand\n",
			stderr: "Some containers were left packed in /sandbox/tree; see the lines above\n"},
		{name: "expand failed", expand: "safeclaw-expand: oops\n", expandCode: "1", code: openExpandFailed, ran: "expand\n",
			stderr: "Error: safeclaw-expand failed with exit code 1\n"},
		{name: "text", text: true, expand: openedOut, expandCode: "0", totextCode: "0", ran: "expand\ntotext\n"},
		{name: "text, expand failed", text: true, expandCode: "1", code: openExpandFailed, ran: "expand\n",
			stderr: "Error: safeclaw-expand failed with exit code 1, so /sandbox/out was not rebuilt\n"},
		{name: "text, packed", text: true, expand: packedOut, expandCode: "0", totextCode: "6", code: openLeftPacked, ran: "expand\ntotext\n",
			stderr: "Some containers were left packed in /sandbox/tree; see the lines above. Converting the tree anyway\n"},
		{name: "text, packed and failed", text: true, expand: packedOut, expandCode: "0", totextCode: "1", code: openTextFailed, ran: "expand\ntotext\n",
			stderr: "Error: safeclaw-totext failed with exit code 1, so /sandbox/out is as it was\n"},
		{name: "text, partial", text: true, expand: openedOut, expandCode: "0", totextCode: "6", code: openTextPartial, ran: "expand\ntotext\n"},
		{name: "text, failed", text: true, expand: openedOut, expandCode: "0", totextCode: "1", code: openTextFailed, ran: "expand\ntotext\n"},
		// A signal that killed docker stops the run with its exit code.
		{name: "expand killed", text: true, expandCode: "130", code: 130, ran: "expand\n", nostder: "Error"},
		{name: "totext killed", text: true, expand: openedOut, expandCode: "0", totextCode: "143", code: 143, ran: "expand\ntotext\n", nostder: "Error"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := newOpenWorld(t)
			w.helper(t, "expand", tc.expand, tc.expandCode)
			w.helper(t, "totext", tc.totext, tc.totextCode)
			args := []string{"sandbox", "open", "box"}
			if tc.text {
				args = append(args, "--text")
			}
			_, stderr, err := runStderr(args...)
			if tc.code == 0 && err != nil || tc.code != 0 && !errors.Is(err, exitCodeError{tc.code}) {
				t.Errorf("err = %v, want exit %d", err, tc.code)
			}
			if got := w.read("ran"); got != tc.ran {
				t.Errorf("ran %q, want %q", got, tc.ran)
			}
			if !strings.Contains(stderr, tc.stderr) || tc.nostder != "" && strings.Contains(stderr, tc.nostder) {
				t.Errorf("stderr = %q", stderr)
			}
		})
	}
}

func TestSandboxOpenTimeout(t *testing.T) {
	for _, tc := range []struct {
		helper, ran, stderr string
	}{
		{"expand", "expand\n", "Error: the command timed out after 100ms\nError: safeclaw-expand timed out, so /sandbox/out was not rebuilt\n"},
		{"totext", "expand\ntotext\n", "Error: the command timed out after 100ms\nError: safeclaw-totext timed out, so /sandbox/out should be as it was\n"},
	} {
		w := newOpenWorld(t)
		w.helper(t, "expand", openedOut, "0")
		w.helper(t, "totext", "", "0")
		w.helper(t, tc.helper, "", "124")
		if err := os.WriteFile(filepath.Join(w.dir, tc.helper+".sleep"), []byte("0.3"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, stderr, err := runStderr("sandbox", "open", "box", "--text", "--timeout", "100ms")
		if !errors.Is(err, exitCodeError{timeoutExitCode}) || stderr != tc.stderr || w.read("ran") != tc.ran {
			t.Errorf("%s: err = %v, stderr = %q, ran %q", tc.helper, err, stderr, w.read("ran"))
		}
	}
}

func TestSandboxOpenRefuses(t *testing.T) {
	t.Setenv("GH_TOKEN", "g")
	for _, tc := range []struct {
		args    []string
		missing string
		want    string
	}{
		{[]string{"chat"}, "", "is an interactive session, not a sandbox"},
		{[]string{"box", "--text"}, "safeclaw-totext\n", "its image has no safeclaw-totext"},
		{[]string{"box", "--max-pages", "3"}, "", "--max-pages needs --text"},
		{[]string{"box", "--plan", "--skip", "a"}, "", "--plan can't be given with --skip or --unskip"},
		{[]string{"box", "--plan", "--text"}, "", "--plan can't be given with --text"},
		{[]string{"box", "--plan", "--hold", "mail-archives", "--release", "1-a.zip"}, "", "--plan can't be given with --release or --release-all"},
		{[]string{"box", "--plan", "--hold", "mail-archives", "--release-all"}, "", "--plan can't be given with --release or --release-all"},
		{[]string{"box", "--timeout", "0s"}, "", "invalid --timeout 0s"},
		{[]string{"box", "--password-env", "GH_TOKEN"}, "", "--password-env GH_TOKEN is the name of a safeclaw secret"},
	} {
		w := newOpenWorld(t)
		w.missing = tc.missing
		_, _, err := runStderr(append([]string{"sandbox", "open"}, tc.args...)...)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%q: err = %v, want %q", tc.args, err, tc.want)
		}
		if w.read("argv") != "" {
			t.Errorf("%q ran a helper: %s", tc.args, w.read("argv"))
		}
	}
}

func TestPackedLines(t *testing.T) {
	for _, tc := range []struct {
		out  string
		want bool
	}{
		{openedOut, false},
		{packedOut, true},
		{"zip\ta\tSKIPPED\t-\n", true},
		{"zip\ta\tHELD\t-\n", true},
		// An entry line ends with - for no flags.
		{"entry\tfile\t7\tsecret.txt\t-\n", false},
		{"entry\tsymlink\tlink\t-\n", false},
		// The last line has no newline yet, so it isn't counted.
		{"zip\ta\tFAILED\t-", false},
		{"zip\t" + strings.Repeat("x", 1<<20) + "\tFAILED\t-\n", true},
		{"zip\ta\tUNPACKED\t--\n", false},
	} {
		var p packedLines
		// Written a byte at a time and whole, lines split anywhere.
		for i := range len(tc.out) {
			_, _ = p.Write([]byte{tc.out[i]})
		}
		var q packedLines
		_, _ = q.Write([]byte(tc.out))
		if p.found != tc.want || q.found != tc.want {
			t.Errorf("%.40q: found = %v, %v, want %v", tc.out, p.found, q.found, tc.want)
		}
	}
}

func TestOpenPassThroughFlags(t *testing.T) {
	cmd := newSandboxOpenCommand()
	expandFlags := newExpandCommand(expandProgram).Flags()
	for _, name := range openExpandFlags {
		f, h := cmd.Flags().Lookup(name), expandFlags.Lookup(name)
		if f == nil || f.Value.Type() != h.Value.Type() || f.DefValue != h.DefValue {
			t.Errorf("--%s = %+v, want safeclaw-expand's %+v", name, f, h)
		}
	}
	if err := cmd.ParseFlags([]string{"--depth", "4", "--max-output", "1g", "--release", "a,b", "--hold", "mail-archives", "--release", "-c", "--release-all"}); err != nil {
		t.Fatal(err)
	}
	// Repeatable flags pass each value as given, a comma included.
	if got := passThrough(cmd.Flags(), openExpandFlags); !slices.Equal(got, []string{"--depth=4", "--hold=mail-archives", "--release=a,b", "--release=-c", "--release-all=true"}) {
		t.Errorf("expand args = %q", got)
	}
	if got := passThrough(cmd.Flags(), openTotextFlags); !slices.Equal(got, []string{"--max-output=1g"}) {
		t.Errorf("totext args = %q", got)
	}
}
