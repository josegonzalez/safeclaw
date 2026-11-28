package variant

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
)

func TestDefault(t *testing.T) {
	s := Default()
	if !slices.Equal(s.Names(), []string{"sandbox"}) {
		t.Errorf("names = %v", s.Names())
	}
	v, err := s.Get("sandbox")
	if err != nil || !v.Published() || v.Image() != "safeclaw:sandbox" {
		t.Errorf("sandbox = %+v, %v", v, err)
	}
	for _, p := range []string{"poppler-utils", "tesseract-ocr", "tesseract-ocr-eng", "7zip", "file", "clamav", "clamav-freshclam"} {
		if !slices.Contains(v.Packages, p) {
			t.Errorf("sandbox variant lacks %s", p)
		}
	}
	if !slices.Equal(v.Run, []string{UnpackLinkCommand, TotextLinkCommand, MailLinkCommand, ExpandLinkCommand}) || !strings.Contains(Dockerfile(v), `RUN ["/bin/sh","-c","ln -s safeclaw /usr/local/bin/safeclaw-unpack"]`) {
		t.Errorf("sandbox variant does not link safeclaw-unpack: %v", v.Run)
	}
	if !strings.Contains(Dockerfile(v), `RUN ["/bin/sh","-c","ln -s safeclaw /usr/local/bin/safeclaw-totext"]`) {
		t.Errorf("sandbox variant does not link safeclaw-totext: %v", v.Run)
	}
	if !strings.Contains(Dockerfile(v), `RUN ["/bin/sh","-c","ln -s safeclaw /usr/local/bin/safeclaw-mail"]`) {
		t.Errorf("sandbox variant does not link safeclaw-mail: %v", v.Run)
	}
	if !strings.Contains(Dockerfile(v), `RUN ["/bin/sh","-c","ln -s safeclaw /usr/local/bin/safeclaw-expand"]`) {
		t.Errorf("sandbox variant does not link safeclaw-expand: %v", v.Run)
	}
	if s.DefaultFor("session") != "" || s.DefaultFor("sandbox") != "sandbox" {
		t.Errorf("defaults = %q, %q", s.DefaultFor("session"), s.DefaultFor("sandbox"))
	}
	if !slices.Equal(s.DefaultTypes(""), []string{"session"}) || !slices.Equal(s.DefaultTypes("sandbox"), []string{"sandbox"}) {
		t.Errorf("default types = %v, %v", s.DefaultTypes(""), s.DefaultTypes("sandbox"))
	}
}

func TestParse(t *testing.T) {
	s, err := Parse([]byte(`
defaults:
  session: research
  sandbox: base
variants:
  research:
    packages: [pandoc, "jq=1.7.1-3"]
    run:
      - pip install --break-system-packages markitdown
  sandbox:
    packages: [file]
`))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(s.Names(), []string{"research", "sandbox"}) {
		t.Errorf("names = %v", s.Names())
	}
	r, _ := s.Get("research")
	if r.Source != SourceConfig || r.Published() || len(r.Run) != 1 || !slices.Equal(r.Packages, []string{"pandoc", "jq=1.7.1-3"}) {
		t.Errorf("research = %+v", r)
	}
	sb, _ := s.Get("sandbox")
	if sb.Source != SourceOverride || sb.Published() || !slices.Equal(sb.Packages, []string{"file"}) {
		t.Errorf("sandbox override = %+v", sb)
	}
	if s.DefaultFor("session") != "research" || s.DefaultFor("sandbox") != "" {
		t.Errorf("defaults = %q, %q", s.DefaultFor("session"), s.DefaultFor("sandbox"))
	}
}

func TestParsePartialDefaults(t *testing.T) {
	s, err := Parse([]byte("defaults:\n  session: sandbox\n"))
	if err != nil {
		t.Fatal(err)
	}
	if s.DefaultFor("session") != "sandbox" || s.DefaultFor("sandbox") != "sandbox" {
		t.Errorf("defaults = %q, %q", s.DefaultFor("session"), s.DefaultFor("sandbox"))
	}
	if s, err := Parse(nil); err != nil || len(s.Names()) != 1 {
		t.Errorf("empty file = %v, %v", s, err)
	}
}

func TestParseErrors(t *testing.T) {
	cases := map[string]string{
		"unknown top-level key":  "variant:\n  x:\n    packages: [a]\n",
		"unknown variant key":    "variants:\n  x:\n    package: [a]\n",
		"reserved base":          "variants:\n  base:\n    packages: [a]\n",
		"reserved latest":        "variants:\n  latest:\n    packages: [a]\n",
		"uppercase name":         "variants:\n  Docs:\n    packages: [a]\n",
		"long name":              "variants:\n  " + strings.Repeat("a", 65) + ":\n    packages: [a]\n",
		"empty variant":          "variants:\n  x: {}\n",
		"bad package":            "variants:\n  x:\n    packages: [\"a; rm -rf /\"]\n",
		"option package":         "variants:\n  x:\n    packages: [\"--allow-unauthenticated\"]\n",
		"multi-line run":         "variants:\n  x:\n    run:\n      - |\n        echo a\n        echo b\n",
		"blank run":              "variants:\n  x:\n    run: [\"  \"]\n",
		"unknown default":        "defaults:\n  sandbox: nope\n",
		"default needs variants": "defaults:\n  session: research\n",
		"not yaml":               "variants: [",
	}
	for name, in := range cases {
		if _, err := Parse([]byte(in)); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	s, err := Load(filepath.Join(dir, "missing.yaml"))
	if err != nil || len(s.Names()) != 1 {
		t.Errorf("missing file = %v, %v", s, err)
	}
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("variants:\n  x:\n    nope: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), path) {
		t.Errorf("err = %v, want one naming the file", err)
	}
}

func TestResolve(t *testing.T) {
	s := Default()
	for in, want := range map[string]string{"": "", "base": "", "sandbox": "sandbox"} {
		if got, err := s.Resolve(in); err != nil || got != want {
			t.Errorf("Resolve(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	_, err := s.Resolve("nope")
	if !errors.Is(err, ErrUnknown) || !strings.Contains(err.Error(), "base, sandbox") {
		t.Errorf("err = %v", err)
	}
	if _, err := s.Get("nope"); !errors.Is(err, ErrUnknown) {
		t.Errorf("Get err = %v", err)
	}
}

func TestImageAndRemoteRef(t *testing.T) {
	cases := map[string]string{"": "safeclaw", "base": "safeclaw", "sandbox": "safeclaw:sandbox"}
	for in, want := range cases {
		if got := Image(in); got != want {
			t.Errorf("Image(%q) = %q, want %q", in, got, want)
		}
	}
	refs := map[string]string{
		"latest": "ghcr.io/josegonzalez/safeclaw:sandbox",
		"":       "ghcr.io/josegonzalez/safeclaw:sandbox",
		"1.2.3":  "ghcr.io/josegonzalez/safeclaw:1.2.3-sandbox",
	}
	for tag, want := range refs {
		if got := RemoteRef(tag, "sandbox"); got != want {
			t.Errorf("RemoteRef(%q) = %q, want %q", tag, got, want)
		}
	}
	if Label("") != "base" || Label("sandbox") != "sandbox" {
		t.Error("Label")
	}
}

func TestDockerfile(t *testing.T) {
	got := Dockerfile(Variant{Name: "docs", Packages: []string{"pandoc", "file"}, Run: []string{"echo one", "echo two"}})
	want := `# safeclaw image variant "docs"
ARG BASE=safeclaw
FROM ${BASE}

ARG DEBIAN_FRONTEND=noninteractive
USER root
RUN apt-get update && \
    apt-get install -y --no-install-recommends pandoc file && \
    rm -rf /var/lib/apt/lists/*
RUN ["/bin/sh","-c","echo one"]
RUN ["/bin/sh","-c","echo two"]
USER sclaw
LABEL safeclaw.variant="docs"
`
	if got != want {
		t.Errorf("Dockerfile =\n%s\nwant\n%s", got, want)
	}
	runOnly := Dockerfile(Variant{Name: "x", Run: []string{"true"}})
	if strings.Contains(runOnly, "apt-get") || !strings.Contains(runOnly, `RUN ["/bin/sh","-c","true"]`+"\n") {
		t.Errorf("run-only Dockerfile =\n%s", runOnly)
	}
}

// Patterns from the Dockerfile parser (moby/buildkit frontend/dockerfile/parser).
var (
	directiveRe    = regexp.MustCompile(`^#\s*([a-zA-Z][a-zA-Z0-9]*)\s*=\s*(.+?)\s*$`)
	continuationRe = regexp.MustCompile(`\\[ \t]*$`)
	heredocRe      = regexp.MustCompile(`^(\d*)<<(-?)\s*(?:"([^"]*)"|'([^']*)'|([^<\s]*))$`)
)

// instructions splits a Dockerfile into its instructions the way the docker
// parser does: comments and blank lines are skipped, a line ending in a
// backslash continues into the next one, and a shell-form RUN with a heredoc
// takes the following lines up to the delimiter as its body. It errors on a
// heredoc that is never closed, which docker refuses to build.
func instructions(dockerfile string) ([]string, error) {
	lines := strings.Split(dockerfile, "\n")
	var out []string
	for i := 0; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		for continuationRe.MatchString(line) && i+1 < len(lines) {
			i++
			line = continuationRe.ReplaceAllString(line, "") + strings.TrimSpace(lines[i])
		}
		out = append(out, line)
		if !strings.HasPrefix(line, "RUN ") || strings.HasPrefix(line, "RUN [") {
			continue
		}
		for _, word := range strings.Fields(line) {
			m := heredocRe.FindStringSubmatch(word)
			if m == nil {
				continue
			}
			delim := m[3] + m[4] + m[5]
			for {
				i++
				if i >= len(lines) {
					return nil, fmt.Errorf("unterminated heredoc %q", delim)
				}
				if strings.TrimSpace(lines[i]) == delim {
					break
				}
			}
		}
	}
	return out, nil
}

// trickyRuns are run commands that, in shell form, could reach the next line
// or be read as Dockerfile syntax.
var trickyRuns = []string{
	`echo hi \`,
	`echo hi \   `,
	"echo hi \\\t",
	`echo hi \\`,
	`cat <<USER`,
	`cat <<-EOF`,
	`cat <<"sclaw"`,
	`<<USER`,
	`echo $((1 <<2))`,
	`cat <<< hello`,
	`echo '"]' \`,
	`echo "\"], \"x\"]"`,
	"# escape=`",
	`echo a > /tmp/b && echo c >> /tmp/b & wait`,
	"echo \u2028 done",
	`printf '\0'`,
}

func TestDockerfileEndsAsSclaw(t *testing.T) {
	for _, run := range trickyRuns {
		v := Variant{Name: "x", Packages: []string{"file"}, Run: []string{run, "true"}}
		if err := v.Validate(); err != nil {
			t.Errorf("%q: refused: %v", run, err)
			continue
		}
		df := Dockerfile(v)
		got, err := instructions(df)
		if err != nil {
			t.Errorf("%q: %v in\n%s", run, err, df)
			continue
		}
		n := len(got)
		if n < 2 || got[n-2] != "USER sclaw" || !strings.HasPrefix(got[n-1], "LABEL ") {
			t.Errorf("%q: instructions end %q, want USER sclaw then LABEL", run, got)
		}
		var runs [][]string
		for _, ins := range got {
			args, ok := strings.CutPrefix(ins, "RUN [")
			if !ok {
				continue
			}
			var argv []string
			if err := json.Unmarshal([]byte("["+args), &argv); err != nil {
				t.Errorf("%q: RUN [%s is not exec form: %v", run, args, err)
			}
			runs = append(runs, argv)
		}
		if len(runs) != 2 || !slices.Equal(runs[0], []string{"/bin/sh", "-c", run}) || !slices.Equal(runs[1], []string{"/bin/sh", "-c", "true"}) {
			t.Errorf("%q: run instructions = %q", run, runs)
		}
		for i, line := range strings.Split(df, "\n") {
			if strings.HasPrefix(line, "RUN [") && (strings.Contains(line, "<") || continuationRe.MatchString(line)) {
				t.Errorf("%q: line %d %q could be read as a heredoc or continuation", run, i+1, line)
			}
		}
	}
}

// TestInstructionsCatchesShellForm checks that the parser model above sees
// the problem the exec form avoids, so TestDockerfileEndsAsSclaw would fail
// if run commands went back to shell form.
func TestInstructionsCatchesShellForm(t *testing.T) {
	for _, run := range []string{`echo hi \`, `echo hi \  `, `cat <<USER`, `cat <<-sclaw`, `echo $((1 <<2))`} {
		df := "FROM x\nUSER root\nRUN " + run + "\nUSER sclaw\nLABEL a=b\n"
		got, err := instructions(df)
		if err == nil && len(got) > 1 && got[len(got)-2] == "USER sclaw" {
			t.Errorf("%q: shell form not caught: %q", run, got)
		}
	}
	got, err := instructions("FROM x\nRUN cat <<<hi\nUSER sclaw\n")
	if err != nil || got[len(got)-1] != "USER sclaw" {
		t.Errorf("here-string: %q, %v", got, err)
	}
}

// TestDockerfileHeaderNotDirective checks that the generated header comment
// can't be read as a parser directive (such as escape), which would change
// how the rest of the file is parsed.
func TestDockerfileHeaderNotDirective(t *testing.T) {
	for _, name := range []string{"x", "escape", "syntax.1", "0-_."} {
		first, _, _ := strings.Cut(Dockerfile(Variant{Name: name, Run: []string{"true"}}), "\n")
		if directiveRe.MatchString(first) {
			t.Errorf("%q: header %q reads as a parser directive", name, first)
		}
	}
}
