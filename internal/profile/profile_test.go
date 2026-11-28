package profile

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/version"
)

// setVersion makes the running safeclaw v for the test.
func setVersion(t *testing.T, v string) {
	t.Helper()
	old := version.Version
	t.Cleanup(func() { version.Version = old })
	version.Version = v
}

const full = `require: 0.6.0
run:
  rm: true
  verify: true
  disk: 1g
  memory: 2g
  pids-limit: 128
  cpus: 0.5
  variant: sandbox
  name-prefix: triage
exec:
  escape-controls: true
  timeout: 30m
cp-out:
  only: ["*.txt", "*.json"]
  replace: true
  max-files: 20000
  max-size: 1g
  mkdir: true
open:
  depth: 3
  max-size: 200m
  no-mail: false
  hold: [mail-archives]
  password-env: TRIAGE_PASSWORD
  timeout: 2h
  max-pages: 300
  ocr-threshold: 40
  ocr-dpi: 200
  ocr-lang: eng+deu
  max-files: 500
  max-output: 1g
`

func TestParse(t *testing.T) {
	setVersion(t, "v0.6.0")
	p, err := Parse([]byte(full))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(full))
	if p.SHA256 != hex.EncodeToString(sum[:]) || p.Require != "0.6.0" {
		t.Errorf("sha256 = %s, require = %q", p.SHA256, p.Require)
	}
	want := []Setting{
		{Key: "only", Values: []string{"*.txt", "*.json"}, List: true},
		{Key: "replace", Values: []string{"true"}},
		{Key: "max-files", Values: []string{"20000"}},
		{Key: "max-size", Values: []string{"1g"}},
		{Key: "mkdir", Values: []string{"true"}},
	}
	if got := p.Section(CopyOut); !reflect.DeepEqual(got, want) {
		t.Errorf("cp-out = %+v\nwant %+v", got, want)
	}
	if got := p.Section(Run); len(got) != 8 || got[0].Key != "rm" || got[7].Key != "name-prefix" {
		t.Errorf("run, in file order = %+v", got)
	}
	if got := p.Section(Open); len(got) != 12 {
		t.Errorf("open = %+v", got)
	}
	for _, s := range []string{"", "\n", "# nothing\n", "---\n", "~\n"} {
		p, err := Parse([]byte(s))
		if err != nil {
			t.Errorf("Parse(%q): %v", s, err)
			continue
		}
		if p.Section(Run) != nil || p.Require != "" {
			t.Errorf("Parse(%q) = %+v", s, p)
		}
	}
	// Every section's keys must agree with Keys.
	for _, sec := range Sections() {
		for k, list := range Keys(sec) {
			if sections[sec][k].list != list {
				t.Errorf("%s.%s list = %v", sec, k, list)
			}
		}
	}
}

func TestParseErrors(t *testing.T) {
	setVersion(t, "0.6.0")
	for _, tc := range []struct{ yaml, want string }{
		// Unknown keys and malformed profiles.
		{"runs: {}\n", "unknown key runs: want require, or one of the sections cp-out, exec, open, run"},
		{"run:\n  memroy: 2g\n", "unknown key run.memroy: want one of cpus, disk, keep-inputs-under, memory, name-prefix, pids-limit, rm, variant, verify"},
		{"exec:\n  tty: true\n", "unknown key exec.tty"},
		{"cp-out:\n  force: true\n", "unknown key cp-out.force"},
		{"open:\n  text: true\n", "unknown key open.text"},
		{"- run\n", "the profile: want a mapping"},
		{"run: 1\n", "run: want a mapping"},
		{"run:\n  memory: 2g\n  memory: 3g\n", "run: memory is given twice"},
		{"run: {}\nrun: {}\n", "the profile: run is given twice"},
		{"1: x\n", "keys must be strings"},
		{"run: {}\n---\nexec: {}\n", "a single YAML document"},
		{"run:\n  memory: [2g]\n", "run.memory: want a single value"},
		{"run:\n  memory:\n", "run.memory: needs a value"},
		{"cp-out:\n  only: '*.txt'\n", "cp-out.only: want a list"},
		{"cp-out:\n  only: []\n", "cp-out.only: want at least one value"},
		{"cp-out:\n  only: [[a]]\n", "cp-out.only: want a single value"},
		{"x: &a 1g\nrun:\n  memory: *a\n", "unknown key x"},
		{"run:\n  memory: &a 1g\n  disk: *a\n", "anchors and aliases"},
		{"run: [", "did not find"},
		// Settings that weaken isolation, named.
		{"run:\n  verify: false\n", "run.verify: false is refused"},
		{"run:\n  verify: yes\n", "run.verify: want true"},
		{"exec:\n  escape-controls: false\n", "exec.escape-controls: false is refused"},
		{"run:\n  volume: [/a:/a]\n", "run.volume is refused: it would mount host directories"},
		{"run:\n  network: bridge\n", "run.network is refused: it would give the sandbox a network"},
		{"run:\n  secrets: [GH_TOKEN]\n", "run.secrets is refused"},
		{"exec:\n  env: [A=1]\n", "exec.env is refused"},
		{"exec:\n  env-if-set: [A]\n", "exec.env-if-set is refused"},
		{"cp-out:\n  no-scan: true\n", "cp-out.no-scan is refused: it would skip cp-out's malware scan"},
		{"cp-out:\n  allow-flagged: true\n", "cp-out.allow-flagged is refused"},
		{"open:\n  release-all: true\n", "open.release-all is refused"},
		{"open:\n  release: [a]\n", "open.release is refused"},
		{"network: host\n", "network is refused"},
		{"run:\n  memory: 0\n", "run.memory: 0 is refused: it would turn the limit off"},
		{"run:\n  cpus: 0.0\n", "run.cpus: 0.0 is refused"},
		{"run:\n  pids-limit: -1\n", "run.pids-limit: -1 is refused"},
		{"run:\n  disk: 0g\n", "run.disk: 0g is refused"},
		{"cp-out:\n  max-files: 0\n", "cp-out.max-files: 0 is refused"},
		{"cp-out:\n  max-size: 0\n", "cp-out.max-size: 0 is refused"},
		// require.
		{"require: 0.7.0\n", "require: safeclaw 0.6.0 is older than the required 0.7.0"},
		{"require: 1.0\n", `require: invalid version "1.0"`},
		{"require:\n", "require: want a version"},
		// require is checked before the keys, so a safeclaw too old for
		// a profile says so rather than refusing a key it doesn't know.
		{"run:\n  newer-flag: x\nrequire: 0.9.0\n", "older than the required 0.9.0"},
	} {
		_, err := Parse([]byte(tc.yaml))
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("Parse(%q): err = %v, want %q", tc.yaml, err, tc.want)
		}
	}
	// Limits that aren't 0 are left for the flags to check.
	for _, ok := range []string{"run:\n  memory: 512m\n", "run:\n  cpus: 0.25\n", "cp-out:\n  max-size: 1kb\n", "open:\n  max-files: 0\n", "run:\n  memory: lots\n"} {
		if _, err := Parse([]byte(ok)); err != nil {
			t.Errorf("Parse(%q): %v", ok, err)
		}
	}
}

// require uses version.Require: a newer or equal release passes, and a
// development build fails, since its version is unknown.
func TestParseRequire(t *testing.T) {
	for _, tc := range []struct {
		installed string
		ok        bool
	}{
		{"0.6.0", true}, {"v0.6.1", true}, {"1.0.0", true}, {"0.5.9", false},
		{"dev", false}, {"v0.6.0-5-g8d41adf", false}, {"v0.6.0-dirty", false},
	} {
		setVersion(t, tc.installed)
		_, err := Parse([]byte("require: v0.6.0\n"))
		if (err == nil) != tc.ok {
			t.Errorf("installed %s: err = %v, want ok %v", tc.installed, err, tc.ok)
		}
	}
	setVersion(t, "dev")
	if _, err := Parse([]byte("run:\n  rm: true\n")); err != nil {
		t.Errorf("a profile without require works on a development build: %v", err)
	}
	if _, err := Parse([]byte("require: 0.1.0\n")); err == nil || !strings.Contains(err.Error(), "development build") {
		t.Errorf("dev build: err = %v", err)
	}
}

func TestIsFileAndResolve(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", "/xdg")
	for ref, file := range map[string]bool{
		"triage": false, "triage.v2": false, "a/b": true, "./triage": true, "/abs/p": true, "triage.yaml": true, "triage.yml": false,
	} {
		if got := IsFile(ref); got != file {
			t.Errorf("IsFile(%q) = %v, want %v", ref, got, file)
		}
	}
	path, ref, err := Resolve("triage")
	if err != nil || path != "/xdg/safeclaw/profiles/triage.yaml" || ref != "triage" {
		t.Errorf("Resolve(triage) = %q, %q, %v", path, ref, err)
	}
	cwd, _ := os.Getwd()
	path, ref, err = Resolve("p.yaml")
	if want := filepath.Join(cwd, "p.yaml"); err != nil || path != want || ref != want {
		t.Errorf("Resolve(p.yaml) = %q, %q, %v", path, ref, err)
	}
	for _, bad := range []string{"", "Triage", "-x", "safeclaw-x", "a b", "a\x1bb.yaml"} {
		if _, _, err := Resolve(bad); err == nil {
			t.Errorf("Resolve(%q) should fail", bad)
		}
	}
}

// writeProfile writes a profile file with mode perm.
func writeProfile(t *testing.T, path, data string, perm os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, perm); err != nil {
		t.Fatal(err)
	}
}

func TestLoad(t *testing.T) {
	setVersion(t, "0.6.0")
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	named := filepath.Join(dir, "safeclaw", "profiles", "triage.yaml")
	writeProfile(t, named, "run:\n  disk: 1g\n", 0o644)
	p, err := Load("triage")
	if err != nil {
		t.Fatal(err)
	}
	if p.Ref != "triage" || p.Path != named || p.Section(Run)[0].Values[0] != "1g" {
		t.Errorf("Load(triage) = %+v", p)
	}
	file := filepath.Join(dir, "elsewhere", "job.yaml")
	writeProfile(t, file, "exec:\n  timeout: 5m\n", 0o600)
	if p, err := Load(file); err != nil || p.Ref != file || p.Path != file {
		t.Errorf("Load(file) = %+v, %v", p, err)
	}
	// A symlink is followed, and its target is checked.
	link := filepath.Join(dir, "link.yaml")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(link); err != nil {
		t.Errorf("Load(link): %v", err)
	}

	if _, err := Load("missing"); err == nil || !strings.Contains(err.Error(), `profile "missing" not found: create `+filepath.Join(dir, "safeclaw", "profiles", "missing.yaml")) {
		t.Errorf("missing name: err = %v", err)
	}
	if _, err := Load(filepath.Join(dir, "none.yaml")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: err = %v", err)
	}
	writeProfile(t, named, "run:\n  verify: false\n", 0o600)
	if _, err := Load("triage"); err == nil || !strings.Contains(err.Error(), "profile triage: run.verify: false is refused") {
		t.Errorf("refused key: err = %v", err)
	}
}

// A profile must be a regular file owned by the user that no one else can
// write.
func TestLoadPermissions(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "p.yaml")
	for _, tc := range []struct {
		perm os.FileMode
		want string
	}{
		{0o664, "is group- or world-writable (mode 0664); run chmod go-w"},
		{0o646, "is group- or world-writable (mode 0646)"},
		{0o640, ""},
		{0o400, ""},
	} {
		writeProfile(t, p, "run: {}\n", tc.perm)
		_, err := Load(p)
		if tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("mode %#o: err = %v, want %q", tc.perm, err, tc.want)
		}
	}
	if _, err := Load(dir + "/"); err == nil || !strings.Contains(err.Error(), "is not a regular file") {
		t.Errorf("directory: err = %v", err)
	}
	big := filepath.Join(dir, "big.yaml")
	writeProfile(t, big, "# "+strings.Repeat("x", MaxSize)+"\n", 0o600)
	if _, err := Load(big); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Errorf("big: err = %v", err)
	}
}

func TestCheckFileOwner(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "p.yaml")
	writeProfile(t, p, "", 0o600)
	info, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkFile(p, info); err != nil {
		t.Errorf("own file: %v", err)
	}
	// A file owned by someone else, root's /etc/hosts here, is refused.
	if os.Geteuid() != 0 {
		info, err := os.Stat("/etc/hosts")
		if err != nil {
			t.Skip(err)
		}
		if err := checkFile("/etc/hosts", info); err == nil || !strings.Contains(err.Error(), "is owned by uid 0, not by you") {
			t.Errorf("root's file: err = %v", err)
		}
	}
}
