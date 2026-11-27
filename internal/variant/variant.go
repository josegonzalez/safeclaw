// Package variant describes image variants: images built on top of the base
// safeclaw image with extra packages or setup steps, defined by safeclaw
// itself or by the user's config file.
package variant

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strings"

	"go.yaml.in/yaml/v3"

	"github.com/josegonzalez/safeclaw/internal/config"
)

// Where a variant is defined.
const (
	SourceBuiltin  = "built-in"
	SourceConfig   = "config"
	SourceOverride = "config (overrides built-in)"
)

// Sandbox is the name of the built-in variant with document extraction
// tools, which sandboxes use by default.
const Sandbox = "sandbox"

var (
	nameRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]*$`)
	packageRe = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]*(=[A-Za-z0-9.+:~-]+)?$`)
)

// maxNameLen keeps "<version>-<name>" within docker's 128 character tag
// limit.
const maxNameLen = 64

// ErrUnknown is returned for a variant name that is neither built in nor
// defined in the config file.
var ErrUnknown = errors.New("unknown variant")

// Variant is one image variant.
type Variant struct {
	// Name is the variant name, also its local image tag.
	Name string `yaml:"-"`
	// Packages are apt packages installed on top of the base image.
	Packages []string `yaml:"packages"`
	// Run are shell commands run as root after the packages are installed,
	// one RUN instruction each.
	Run []string `yaml:"run"`
	// Source is SourceBuiltin, SourceConfig, or SourceOverride.
	Source string `yaml:"-"`
}

// Published reports whether the variant is the unmodified built-in, which
// releases publish to the registry.
func (v Variant) Published() bool {
	return v.Source == SourceBuiltin
}

// Image returns the variant's local image name.
func (v Variant) Image() string {
	return Image(v.Name)
}

// Builtins returns the variants safeclaw defines itself.
func Builtins() []Variant {
	return []Variant{
		{
			Name:     Sandbox,
			Packages: []string{"7zip", "file", "poppler-utils", "tesseract-ocr", "tesseract-ocr-eng"},
			Source:   SourceBuiltin,
		},
	}
}

// Defaults names the variant each session type uses when none is given.
// config.BaseVariant means the base image.
type Defaults struct {
	Session string `yaml:"session"`
	Sandbox string `yaml:"sandbox"`
}

// builtinDefaults are used for any default the config file leaves out.
var builtinDefaults = Defaults{Session: config.BaseVariant, Sandbox: Sandbox}

// File is the config file's layout.
type File struct {
	Defaults Defaults           `yaml:"defaults"`
	Variants map[string]Variant `yaml:"variants"`
}

// Set is every known variant along with the defaults.
type Set struct {
	variants map[string]Variant
	defaults Defaults
}

// Default returns the set of built-in variants and defaults, as used when
// there is no config file.
func Default() *Set {
	s, _ := New(File{})
	return s
}

// New merges a parsed config file over the built-ins and validates the
// result. A config variant with a built-in's name replaces it.
func New(f File) (*Set, error) {
	s := &Set{variants: map[string]Variant{}, defaults: builtinDefaults}
	for _, v := range Builtins() {
		s.variants[v.Name] = v
	}
	names := make([]string, 0, len(f.Variants))
	for name := range f.Variants {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		v := f.Variants[name]
		v.Name = name
		v.Source = SourceConfig
		if b, ok := s.variants[name]; ok && b.Source == SourceBuiltin {
			v.Source = SourceOverride
		}
		if err := v.Validate(); err != nil {
			return nil, err
		}
		s.variants[name] = v
	}
	if f.Defaults.Session != "" {
		s.defaults.Session = f.Defaults.Session
	}
	if f.Defaults.Sandbox != "" {
		s.defaults.Sandbox = f.Defaults.Sandbox
	}
	for typ, name := range map[string]string{config.TypeSession: s.defaults.Session, config.TypeSandbox: s.defaults.Sandbox} {
		if _, err := s.Resolve(name); err != nil {
			return nil, fmt.Errorf("defaults.%s: %w", typ, err)
		}
	}
	return s, nil
}

// Parse reads a config file's contents. Unknown keys are errors.
func Parse(data []byte) (*Set, error) {
	var f File
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return nil, err
	}
	return New(f)
}

// Load reads the config file at path. A missing file means the built-ins
// alone.
func Load(path string) (*Set, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Default(), nil
	}
	if err != nil {
		return nil, err
	}
	s, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return s, nil
}

// ValidateName checks that name can be used as a variant name.
func ValidateName(name string) error {
	if name == config.BaseVariant || name == "latest" {
		return fmt.Errorf("variant name %q is reserved", name)
	}
	if len(name) > maxNameLen || !nameRe.MatchString(name) {
		return fmt.Errorf("invalid variant name %q: use lowercase letters, numbers, '.', '_' and '-', starting with a letter or number, at most %d characters", name, maxNameLen)
	}
	return nil
}

// Validate checks a variant's name, packages, and run commands.
func (v Variant) Validate() error {
	if err := ValidateName(v.Name); err != nil {
		return err
	}
	if len(v.Packages) == 0 && len(v.Run) == 0 {
		return fmt.Errorf("variant %q: needs at least one package or run command", v.Name)
	}
	for _, p := range v.Packages {
		if !packageRe.MatchString(p) {
			return fmt.Errorf("variant %q: invalid package name %q", v.Name, p)
		}
	}
	for _, r := range v.Run {
		if strings.TrimSpace(r) == "" {
			return fmt.Errorf("variant %q: empty run command", v.Name)
		}
		if strings.ContainsAny(r, "\r\n") {
			return fmt.Errorf("variant %q: run commands must be one line each; split them into separate entries or join them with &&", v.Name)
		}
	}
	return nil
}

// Names returns every variant name, sorted.
func (s *Set) Names() []string {
	out := make([]string, 0, len(s.variants))
	for name := range s.variants {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// All returns every variant, sorted by name.
func (s *Set) All() []Variant {
	out := make([]Variant, 0, len(s.variants))
	for _, name := range s.Names() {
		out = append(out, s.variants[name])
	}
	return out
}

// Get returns the named variant.
func (s *Set) Get(name string) (Variant, error) {
	v, ok := s.variants[name]
	if !ok {
		return Variant{}, s.unknown(name)
	}
	return v, nil
}

func (s *Set) unknown(name string) error {
	known := append([]string{config.BaseVariant}, s.Names()...)
	return fmt.Errorf("%w %q: known variants are %s", ErrUnknown, name, strings.Join(known, ", "))
}

// Resolve checks a requested variant name and returns it, or "" for the
// base image.
func (s *Set) Resolve(name string) (string, error) {
	if name == config.BaseVariant || name == "" {
		return "", nil
	}
	if _, ok := s.variants[name]; !ok {
		return "", s.unknown(name)
	}
	return name, nil
}

// DefaultFor returns the default variant for a session type
// (config.TypeSession or config.TypeSandbox), or "" for the base image.
func (s *Set) DefaultFor(typ string) string {
	name := s.defaults.Session
	if typ == config.TypeSandbox {
		name = s.defaults.Sandbox
	}
	if name == config.BaseVariant {
		return ""
	}
	return name
}

// DefaultTypes returns the session types that default to the named variant
// ("" for the base image).
func (s *Set) DefaultTypes(name string) []string {
	var out []string
	for _, typ := range []string{config.TypeSession, config.TypeSandbox} {
		if s.DefaultFor(typ) == name {
			out = append(out, typ)
		}
	}
	return out
}

// Image returns the local image for a variant name, "" being the base image.
func Image(name string) string {
	if name == "" || name == config.BaseVariant {
		return config.ImageName
	}
	return config.ImageName + ":" + name
}

// RemoteRef returns the published reference of a built-in variant for an
// image tag: "<tag>-<name>", or just "<name>" for latest.
func RemoteRef(tag, name string) string {
	if tag == "" || tag == "latest" {
		return config.RemoteImage + ":" + name
	}
	return config.RemoteImage + ":" + tag + "-" + name
}

// Label returns a variant name for display: config.BaseVariant for "".
func Label(name string) string {
	if name == "" {
		return config.BaseVariant
	}
	return name
}

// Dockerfile returns the Dockerfile that builds the variant on top of the
// image named by the BASE build argument (the local base image by default).
func Dockerfile(v Variant) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# safeclaw image variant %q\n", v.Name)
	fmt.Fprintf(&b, "ARG BASE=%s\n", config.ImageName)
	b.WriteString("FROM ${BASE}\n\n")
	b.WriteString("ARG DEBIAN_FRONTEND=noninteractive\n")
	b.WriteString("USER root\n")
	if len(v.Packages) > 0 {
		fmt.Fprintf(&b, "RUN apt-get update && \\\n    apt-get install -y --no-install-recommends %s && \\\n    rm -rf /var/lib/apt/lists/*\n", strings.Join(v.Packages, " "))
	}
	for _, r := range v.Run {
		fmt.Fprintf(&b, "RUN %s\n", r)
	}
	b.WriteString("USER sclaw\n")
	fmt.Fprintf(&b, "LABEL %s=%q\n", config.LabelVariant, v.Name)
	return b.String()
}
