package variant

import (
	"errors"
	"os"
	"path/filepath"
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
	for _, p := range []string{"poppler-utils", "tesseract-ocr", "tesseract-ocr-eng", "7zip", "file"} {
		if !slices.Contains(v.Packages, p) {
			t.Errorf("sandbox variant lacks %s", p)
		}
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
RUN echo one
RUN echo two
USER sclaw
LABEL safeclaw.variant="docs"
`
	if got != want {
		t.Errorf("Dockerfile =\n%s\nwant\n%s", got, want)
	}
	runOnly := Dockerfile(Variant{Name: "x", Run: []string{"true"}})
	if strings.Contains(runOnly, "apt-get") || !strings.Contains(runOnly, "RUN true\n") {
		t.Errorf("run-only Dockerfile =\n%s", runOnly)
	}
}
