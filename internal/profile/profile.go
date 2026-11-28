// Package profile reads sandbox profiles: YAML files holding a caller's
// defaults for the sandbox commands, so each command can name one file
// instead of repeating the same flags.
//
// A profile has a section per command, whose keys are that command's flag
// names, and an optional require key with the minimum safeclaw version:
//
//	require: 0.6.0
//	run:
//	  rm: true
//	  verify: true
//	  disk: 1g
//	  memory: 2g
//	exec:
//	  escape-controls: true
//	  timeout: 30m
//	cp-out:
//	  only: ["*.txt"]
//	  replace: true
//	  max-files: 20000
//	open:
//	  depth: 3
//	  max-size: 200m
//	  password-env: TRIAGE_PASSWORD
//	  max-pages: 300
//
// Unknown keys are errors, and settings that weaken isolation are refused,
// so a profile can make a sandbox stricter or change its limits, but never
// turn a safety check off. Applying a profile to a command's flags is left
// to the caller, which knows the flags.
package profile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"unicode"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/session"
	"github.com/josegonzalez/safeclaw/internal/version"
)

// The sections of a profile, each named after the command it gives
// defaults to.
const (
	Run     = "run"
	Exec    = "exec"
	CopyOut = "cp-out"
	Open    = "open"
)

// RequireKey is the top-level key holding the minimum safeclaw version.
const RequireKey = "require"

// MaxSize is the largest profile read.
const MaxSize = 1 << 20

// key describes one key a section accepts.
type key struct {
	// list keys take a YAML list, one value per repeat of the flag.
	list bool
	// strict keys turn on a safety check, so only true is accepted.
	strict bool
	// limit keys are limits that 0 or less would turn off, which is
	// refused.
	limit bool
}

// sections are the keys each section accepts. They are the flag names of
// the command the section is named after.
var sections = map[string]map[string]key{
	Run: {
		"memory":            {limit: true},
		"pids-limit":        {limit: true},
		"cpus":              {limit: true},
		"disk":              {limit: true},
		"variant":           {},
		"rm":                {},
		"name-prefix":       {},
		"keep-inputs-under": {},
		"verify":            {strict: true},
	},
	Exec: {
		"escape-controls": {strict: true},
		"timeout":         {},
	},
	CopyOut: {
		"only":      {list: true},
		"replace":   {},
		"mkdir":     {},
		"max-files": {limit: true},
		"max-size":  {limit: true},
	},
	Open: {
		"depth":         {},
		"max-size":      {},
		"no-mail":       {},
		"hold":          {list: true},
		"password-env":  {},
		"timeout":       {},
		"max-pages":     {},
		"ocr-threshold": {},
		"ocr-dpi":       {},
		"ocr-lang":      {},
		"max-files":     {},
		"max-output":    {},
	},
}

// refused are keys a profile can never set, in any section, with why:
// each weakens a sandbox's isolation or turns a safety check off.
var refused = map[string]string{
	"volume":        "it would mount host directories into the sandbox",
	"network":       "it would give the sandbox a network",
	"secrets":       "it would give the sandbox secrets",
	"env":           "it would pass values from the host into the sandbox",
	"env-if-set":    "it would pass values from the host into the sandbox",
	"no-scan":       "it would skip cp-out's malware scan",
	"allow-flagged": "it would copy out files the malware scan flags",
	"release":       "it would open containers --hold leaves packed",
	"release-all":   "it would open containers --hold leaves packed",
}

// Sections returns the section names, sorted.
func Sections() []string {
	return slices.Sorted(maps.Keys(sections))
}

// Keys returns a section's keys, sorted, and whether each takes a list.
func Keys(section string) map[string]bool {
	keys := map[string]bool{}
	for k, d := range sections[section] {
		keys[k] = d.list
	}
	return keys
}

// Setting is one key of a section and its values: one for a scalar key,
// one or more for a list key.
type Setting struct {
	Key    string
	Values []string
	List   bool
}

// Profile is a parsed profile.
type Profile struct {
	// Ref is the profile's NAME, or the absolute path of its FILE, as
	// recorded on the sandboxes created with it.
	Ref string
	// Path is the file it was read from.
	Path string
	// SHA256 is the hex SHA-256 of its contents.
	SHA256 string
	// Require is the minimum safeclaw version, empty for none.
	Require string
	// sections holds each section's settings in file order.
	sections map[string][]Setting
}

// Section returns a section's settings, in the order the file gives them.
func (p *Profile) Section(name string) []Setting {
	return p.sections[name]
}

// IsFile reports whether a --profile value names a file rather than a
// profile in ProfilesDir: it holds a / or ends in .yaml.
func IsFile(ref string) bool {
	return strings.Contains(ref, "/") || strings.HasSuffix(ref, ".yaml")
}

// Resolve returns the file a --profile value names, and the ref recorded
// for it: a NAME, which follows the session name rules, is
// ProfilesDir/NAME.yaml, and a FILE is made absolute.
func Resolve(ref string) (path, recorded string, err error) {
	if ref == "" {
		return "", "", errors.New("--profile needs a FILE or NAME")
	}
	if IsFile(ref) {
		abs, err := filepath.Abs(ref)
		if err != nil {
			return "", "", err
		}
		if !printable(abs) {
			return "", "", fmt.Errorf("profile path %q is not printable text", abs)
		}
		return abs, abs, nil
	}
	if session.ValidateName(ref) != nil {
		return "", "", fmt.Errorf("invalid profile name %q: use lowercase letters, numbers, '.', '_' and '-', starting with a letter or number, as for session names, or give a FILE with a / or ending in .yaml", ref)
	}
	return filepath.Join(config.ProfilesDir(), ref+".yaml"), ref, nil
}

// printable reports whether s is valid UTF-8 with no control or other
// unprintable characters.
func printable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// Load reads the profile a --profile value names, checking the file and
// its contents (see Read and Parse).
func Load(ref string) (*Profile, error) {
	path, recorded, err := Resolve(ref)
	if err != nil {
		return nil, err
	}
	data, err := Read(path)
	if err != nil {
		if !IsFile(ref) && errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("profile %q not found: create %s", ref, path)
		}
		return nil, fmt.Errorf("profile %s: %w", recorded, err)
	}
	p, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("profile %s: %w", recorded, err)
	}
	p.Ref, p.Path = recorded, path
	return p, nil
}

// Read returns a profile file's contents. The file must be a regular file
// owned by the current user that neither its group nor anyone else can
// write, since it decides how sandboxes are created and what leaves them:
// whoever can change it could raise the limits, widen what cp-out copies,
// or point --password-env at another variable for every command that
// names it. It is checked after it is opened, so swapping the path for
// another file in between changes nothing.
func Read(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if err := checkFile(path, info); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, MaxSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > MaxSize {
		return nil, fmt.Errorf("%s is larger than %d bytes", path, MaxSize)
	}
	return data, nil
}

// checkFile returns an error unless info, the file at path, is a regular
// file owned by the current user and neither group- nor world-writable.
func checkFile(path string, info os.FileInfo) error {
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return fmt.Errorf("can't tell who owns %s", path)
	}
	if uid := os.Geteuid(); int(st.Uid) != uid {
		return fmt.Errorf("%s is owned by uid %d, not by you (uid %d)", path, st.Uid, uid)
	}
	if perm := info.Mode().Perm(); perm&0o022 != 0 {
		return fmt.Errorf("%s is group- or world-writable (mode %#o); run chmod go-w %s", path, perm, path)
	}
	return nil
}

// Parse reads a profile's contents. require is checked first, against the
// running safeclaw's version, so a safeclaw too old for a profile says so
// rather than refusing a key it doesn't know. Then every key must be known,
// and none may weaken isolation.
func Parse(data []byte) (*Profile, error) {
	sum := sha256.Sum256(data)
	p := &Profile{SHA256: hex.EncodeToString(sum[:]), sections: map[string][]Setting{}}
	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return p, nil
		}
		return nil, err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("a profile is a single YAML document")
	}
	root := doc.Content[0]
	if root.Kind == yaml.ScalarNode && root.Tag == "!!null" {
		return p, nil
	}
	pairs, err := mapping(root, "the profile")
	if err != nil {
		return nil, err
	}
	for _, kv := range pairs {
		if kv[0].Value == RequireKey {
			if err := p.require(kv[1]); err != nil {
				return nil, err
			}
		}
	}
	for _, kv := range pairs {
		name, value := kv[0].Value, kv[1]
		if name == RequireKey {
			continue
		}
		if why, ok := refused[name]; ok {
			return nil, fmt.Errorf("%s is refused: %s", name, why)
		}
		keys, ok := sections[name]
		if !ok {
			return nil, fmt.Errorf("unknown key %s: want %s, or one of the sections %s", name, RequireKey, strings.Join(Sections(), ", "))
		}
		settings, err := section(name, value, keys)
		if err != nil {
			return nil, err
		}
		p.sections[name] = settings
	}
	return p, nil
}

// require checks the require key against the running version.
func (p *Profile) require(n *yaml.Node) error {
	if n.Kind != yaml.ScalarNode || n.Tag == "!!null" {
		return fmt.Errorf("%s: want a version, such as 0.6.0", RequireKey)
	}
	want, err := version.ParseRelease(n.Value)
	if err != nil {
		return fmt.Errorf("%s: %w", RequireKey, err)
	}
	if err := version.Require(version.Version, want); err != nil {
		return fmt.Errorf("%s: %w", RequireKey, err)
	}
	p.Require = n.Value
	return nil
}

// mapping returns a mapping node's key and value pairs, refusing anything
// else, keys that aren't plain strings, and keys given twice.
func mapping(n *yaml.Node, what string) ([][2]*yaml.Node, error) {
	if n.Kind == yaml.AliasNode {
		return nil, fmt.Errorf("%s: anchors and aliases aren't supported", what)
	}
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%s: want a mapping of keys to values", what)
	}
	var pairs [][2]*yaml.Node
	seen := map[string]bool{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := n.Content[i]
		if k.Kind != yaml.ScalarNode || k.Tag != "!!str" {
			return nil, fmt.Errorf("%s: keys must be strings, not %q", what, k.Value)
		}
		if seen[k.Value] {
			return nil, fmt.Errorf("%s: %s is given twice", what, k.Value)
		}
		seen[k.Value] = true
		pairs = append(pairs, [2]*yaml.Node{k, n.Content[i+1]})
	}
	return pairs, nil
}

// section reads one section's settings.
func section(name string, n *yaml.Node, keys map[string]key) ([]Setting, error) {
	pairs, err := mapping(n, name)
	if err != nil {
		return nil, err
	}
	var settings []Setting
	for _, kv := range pairs {
		k := kv[0].Value
		path := name + "." + k
		if why, ok := refused[k]; ok {
			return nil, fmt.Errorf("%s is refused: %s", path, why)
		}
		d, ok := keys[k]
		if !ok {
			return nil, fmt.Errorf("unknown key %s: want one of %s", path, strings.Join(slices.Sorted(maps.Keys(keys)), ", "))
		}
		values, err := settingValues(path, kv[1], d)
		if err != nil {
			return nil, err
		}
		settings = append(settings, Setting{Key: k, Values: values, List: d.list})
	}
	return settings, nil
}

// settingValues returns a key's values, checking that a strict key is true
// and a limit is not turned off.
func settingValues(path string, n *yaml.Node, d key) ([]string, error) {
	var values []string
	if d.list {
		if n.Kind != yaml.SequenceNode {
			return nil, fmt.Errorf("%s: want a list, such as [a, b]", path)
		}
		if len(n.Content) == 0 {
			return nil, fmt.Errorf("%s: want at least one value", path)
		}
		for _, c := range n.Content {
			v, err := scalar(path, c)
			if err != nil {
				return nil, err
			}
			values = append(values, v)
		}
		return values, nil
	}
	v, err := scalar(path, n)
	if err != nil {
		return nil, err
	}
	if d.strict {
		on, err := strconv.ParseBool(v)
		if n.Tag != "!!bool" || err != nil {
			return nil, fmt.Errorf("%s: want true", path)
		}
		if !on {
			return nil, fmt.Errorf("%s: false is refused: it would turn a safety check off, and a profile can only make a sandbox stricter", path)
		}
	}
	if d.limit && turnsOff(v) {
		return nil, fmt.Errorf("%s: %s is refused: it would turn the limit off, and a profile can only change limits", path, v)
	}
	return []string{v}, nil
}

// scalar returns a single value.
func scalar(path string, n *yaml.Node) (string, error) {
	switch {
	case n.Kind == yaml.AliasNode:
		return "", fmt.Errorf("%s: anchors and aliases aren't supported", path)
	case n.Kind != yaml.ScalarNode:
		return "", fmt.Errorf("%s: want a single value", path)
	case n.Tag == "!!null":
		return "", fmt.Errorf("%s: needs a value", path)
	}
	return n.Value, nil
}

// turnsOff reports whether a limit's value is 0 or less, which docker and
// cp-out read as no limit at all. Values that aren't numbers are left for
// the flag to refuse.
func turnsOff(v string) bool {
	s := strings.ToLower(strings.TrimSpace(v))
	s = strings.TrimSuffix(s, "b")
	s = strings.TrimRight(s, "kmgt")
	f, err := strconv.ParseFloat(s, 64)
	return err == nil && f <= 0
}
