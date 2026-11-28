package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/josegonzalez/safeclaw/internal/profile"
)

// testProfile writes a profile file and returns its path.
func testProfile(t *testing.T, data string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "p.yaml")
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// withProfile parses args on cmd and runs its argument check, which
// applies the profile.
func withProfile(t *testing.T, cmd *cobra.Command, args ...string) (*cobra.Command, error) {
	t.Helper()
	if err := cmd.ParseFlags(args); err != nil {
		t.Fatal(err)
	}
	return cmd, cmd.Args(cmd, cmd.Flags().Args())
}

// Every key a section accepts is a flag of its command, taking a list
// exactly when the flag repeats.
func TestProfileKeysAreFlags(t *testing.T) {
	cmds := profileCommands()
	for _, section := range profile.Sections() {
		for key, list := range profile.Keys(section) {
			f := cmds[section].Flags().Lookup(key)
			if f == nil {
				t.Errorf("%s.%s is not a flag of sandbox %s", section, key, section)
				continue
			}
			if _, repeats := f.Value.(pflag.SliceValue); repeats != list {
				t.Errorf("%s.%s: list = %v, but the flag repeats = %v", section, key, list, repeats)
			}
		}
		if cmds[section].Flags().Lookup(profileFlag) == nil {
			t.Errorf("sandbox %s has no --profile", section)
		}
	}
}

func TestProfileRun(t *testing.T) {
	p := testProfile(t, "run:\n  memory: 2g\n  disk: 1g\n  verify: true\n  variant: base\n  rm: true\n  name-prefix: job\n")
	cmd, err := withProfile(t, newSandboxRunCommand(), "--profile", p, "--memory", "1g")
	if err != nil {
		t.Fatal(err)
	}
	fs := cmd.Flags()
	// The command line wins.
	if v, _ := fs.GetString("memory"); v != "1g" {
		t.Errorf("memory = %q, want the command line's 1g", v)
	}
	for name, want := range map[string]string{"disk": "1g", "verify": "true", "variant": "base", "rm": "true", "name-prefix": "job"} {
		if got := fs.Lookup(name).Value.String(); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	set, typed := flagSources(cmd)
	if !set("disk") || typed("disk") || !typed("memory") || !set("memory") {
		t.Error("flag sources wrong")
	}
	if ref, sum := appliedProfile(cmd); ref != p || len(sum) != 64 {
		t.Errorf("applied profile = %q, %q", ref, sum)
	}

	// name-prefix applies only with --rm and without -s.
	p = testProfile(t, "run:\n  name-prefix: job\n")
	cmd, err = withProfile(t, newSandboxRunCommand(), "--profile", p, "-s", "box")
	if err != nil || cmd.Flags().Changed("name-prefix") {
		t.Errorf("without --rm: err = %v, name-prefix set = %v", err, cmd.Flags().Changed("name-prefix"))
	}
	cmd, err = withProfile(t, newSandboxRunCommand(), "--profile", p, "--rm", "-s", "box")
	if err != nil || cmd.Flags().Changed("name-prefix") {
		t.Errorf("with -s: err = %v, name-prefix set = %v", err, cmd.Flags().Changed("name-prefix"))
	}
	cmd, err = withProfile(t, newSandboxRunCommand(), "--profile", p, "--rm")
	if v, _ := cmd.Flags().GetString("name-prefix"); err != nil || v != "job" {
		t.Errorf("with --rm: err = %v, name-prefix = %q", err, v)
	}
	// keep-inputs-under applies only with --rm, and gives way to a
	// --keep-inputs or --restore-from on the command line, which it can't
	// be used with.
	p = testProfile(t, "run:\n  keep-inputs-under: jobs\n")
	for _, args := range [][]string{{"-s", "box"}, {"--rm", "--keep-inputs", "d"}, {"--rm", "--restore-from", "d"}} {
		cmd, err = withProfile(t, newSandboxRunCommand(), append([]string{"--profile", p}, args...)...)
		if err != nil || cmd.Flags().Changed("keep-inputs-under") {
			t.Errorf("%v: err = %v, keep-inputs-under set = %v", args, err, cmd.Flags().Changed("keep-inputs-under"))
		}
	}
	cmd, err = withProfile(t, newSandboxRunCommand(), "--profile", p, "--rm", "--name-prefix", "job")
	if v, _ := cmd.Flags().GetString("keep-inputs-under"); err != nil || v != "jobs" {
		t.Errorf("with --rm: err = %v, keep-inputs-under = %q", err, v)
	}
	cmd, err = withProfile(t, newSandboxRunCommand(), "--profile", p, "--rm", "--keep-inputs-under", "mine")
	if v, _ := cmd.Flags().GetString("keep-inputs-under"); err != nil || v != "mine" {
		t.Errorf("typed: err = %v, keep-inputs-under = %q", err, v)
	}
	// Without --profile, nothing is applied.
	cmd, err = withProfile(t, newSandboxRunCommand(), "-s", "box")
	if ref, _ := appliedProfile(cmd); err != nil || ref != "" {
		t.Errorf("no profile: err = %v, ref = %q", err, ref)
	}
}

// Limits a profile gives are passed on without Recreate, so they recreate
// an existing sandbox only when they differ; typed ones recreate it.
func TestProfileRunOptions(t *testing.T) {
	p := testProfile(t, "run:\n  memory: 2g\n  pids-limit: 64\n")
	cmd, err := withProfile(t, newSandboxRunCommand(), "--profile", p, "-s", "box")
	if err != nil {
		t.Fatal(err)
	}
	f := sandboxFlags{memory: "2g", pidsLimit: 64, session: "box"}
	opts := f.options(flagSources(cmd))
	if opts.Memory != "2g" || opts.PidsLimit != 64 || opts.Recreate {
		t.Errorf("opts = %+v", opts)
	}
	cmd, _ = withProfile(t, newSandboxRunCommand(), "--profile", p, "-s", "box", "--cpus", "2")
	if opts := f.options(flagSources(cmd)); !opts.Recreate {
		t.Errorf("a typed limit should recreate: %+v", opts)
	}
}

func TestProfileExec(t *testing.T) {
	p := testProfile(t, "exec:\n  escape-controls: true\n  timeout: 30m\nrun:\n  memory: 3g\n  verify: true\n  rm: true\n  name-prefix: job\n")
	cmd, err := withProfile(t, newSandboxExecCommand(), "--profile", p, "box", "--", "ls")
	if err != nil {
		t.Fatal(err)
	}
	fs := cmd.Flags()
	if e, _ := fs.GetBool("escape-controls"); !e {
		t.Error("escape-controls not applied")
	}
	if d, _ := fs.GetDuration("timeout"); d != 30*time.Minute {
		t.Errorf("timeout = %s", d)
	}
	// The run section is for creating a sandbox, so a named one doesn't
	// get it, which would also be refused without --ephemeral.
	if fs.Changed("memory") || fs.Changed("verify") {
		t.Error("run section applied to a named sandbox")
	}
	cmd, err = withProfile(t, newSandboxExecCommand(), "--profile", p, "--ephemeral", "--timeout", "1m", "--", "ls")
	if err != nil {
		t.Fatal(err)
	}
	fs = cmd.Flags()
	if m, _ := fs.GetString("memory"); m != "3g" {
		t.Errorf("ephemeral memory = %q", m)
	}
	if v, _ := fs.GetBool("verify"); !v {
		t.Error("ephemeral verify not applied")
	}
	if d, _ := fs.GetDuration("timeout"); d != time.Minute {
		t.Errorf("timeout = %s, want the command line's", d)
	}
	// -t can't be used with the profile's escape-controls, unless the
	// command line turns it off.
	_, err = withProfile(t, newSandboxExecCommand(), "--profile", p, "-t", "box", "--", "sh")
	if err == nil || !strings.Contains(err.Error(), "sets exec.escape-controls, which can't be used with -t; pass --escape-controls=false") {
		t.Errorf("-t: err = %v", err)
	}
	if _, err = withProfile(t, newSandboxExecCommand(), "--profile", p, "-t", "--escape-controls=false", "box", "--", "sh"); err != nil {
		t.Errorf("-t --escape-controls=false: %v", err)
	}
}

// A list given on the command line replaces the profile's whole list.
func TestProfileCopyOutLists(t *testing.T) {
	p := testProfile(t, "cp-out:\n  only: ['*.txt', '*.json']\n  max-files: 20\n  replace: true\n")
	cmd, err := withProfile(t, newSandboxCopyOutCommand(), "--profile", p, "box", "/sandbox/out", "out")
	if err != nil {
		t.Fatal(err)
	}
	if only, _ := cmd.Flags().GetStringArray("only"); !slices.Equal(only, []string{"*.txt", "*.json"}) {
		t.Errorf("only = %q", only)
	}
	// The profile's --only satisfies the required flag.
	if err := cmd.ValidateRequiredFlags(); err != nil {
		t.Errorf("required: %v", err)
	}
	cmd, err = withProfile(t, newSandboxCopyOutCommand(), "--profile", p, "--only", "*.md", "box", "/sandbox/out", "out")
	if err != nil {
		t.Fatal(err)
	}
	if only, _ := cmd.Flags().GetStringArray("only"); !slices.Equal(only, []string{"*.md"}) {
		t.Errorf("only = %q, want the command line's alone", only)
	}
}

func TestProfileOpen(t *testing.T) {
	p := testProfile(t, "open:\n  depth: 3\n  hold: [mail-archives]\n  password-env: PW\n  max-pages: 300\n  timeout: 2h\n")
	cmd, err := withProfile(t, newSandboxOpenCommand(), "--profile", p, "box")
	if err != nil {
		t.Fatal(err)
	}
	fs := cmd.Flags()
	// safeclaw-totext's policy needs --text, so it waits for it.
	if got := passThrough(fs, openTotextFlags); got != nil {
		t.Errorf("totext args without --text = %q", got)
	}
	if got := passThrough(fs, openExpandFlags); !slices.Equal(got, []string{"--depth=3", "--hold=mail-archives"}) {
		t.Errorf("expand args = %q", got)
	}
	if v, _ := fs.GetString("password-env"); v != "PW" {
		t.Errorf("password-env = %q", v)
	}
	cmd, err = withProfile(t, newSandboxOpenCommand(), "--profile", p, "--text", "--hold", "none-such", "box")
	if err != nil {
		t.Fatal(err)
	}
	fs = cmd.Flags()
	if got := passThrough(fs, openTotextFlags); !slices.Equal(got, []string{"--max-pages=300"}) {
		t.Errorf("totext args with --text = %q", got)
	}
	if got := passThrough(fs, openExpandFlags); !slices.Equal(got, []string{"--depth=3", "--hold=none-such"}) {
		t.Errorf("expand args = %q, want the command line's --hold alone", got)
	}
}

// Every section is checked against its command's flags, whichever command
// names the profile.
func TestProfileCheckedWhole(t *testing.T) {
	for _, tc := range []struct{ yaml, want string }{
		{"exec:\n  timeout: 5x\n", "exec.timeout: invalid argument \"5x\""},
		{"open:\n  depth: deep\n", "open.depth: invalid argument"},
		{"cp-out:\n  replace: maybe\n", "cp-out.replace: invalid argument"},
	} {
		p := testProfile(t, tc.yaml)
		_, err := withProfile(t, newSandboxRunCommand(), "--profile", p, "-s", "box")
		if err == nil || !strings.Contains(err.Error(), "profile "+p+": "+tc.want) {
			t.Errorf("%q: err = %v, want %q", tc.yaml, err, tc.want)
		}
	}
	p := testProfile(t, "run:\n  verify: false\n")
	if _, err := withProfile(t, newSandboxOpenCommand(), "--profile", p, "box"); err == nil || !strings.Contains(err.Error(), "run.verify: false is refused") {
		t.Errorf("refused key: err = %v", err)
	}
}

// --profile NAME reads $XDG_CONFIG_HOME/safeclaw/profiles/NAME.yaml.
func TestProfileName(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)
	path := filepath.Join(dir, "safeclaw", "profiles", "triage.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("exec:\n  timeout: 5m\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd, err := withProfile(t, newSandboxExecCommand(), "--profile", "triage", "box", "--", "ls")
	if err != nil {
		t.Fatal(err)
	}
	if ref, _ := appliedProfile(cmd); ref != "triage" {
		t.Errorf("ref = %q", ref)
	}
	if _, err := withProfile(t, newSandboxExecCommand(), "--profile", "other", "box", "--", "ls"); err == nil || !strings.Contains(err.Error(), `profile "other" not found`) {
		t.Errorf("missing: err = %v", err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	if _, err := withProfile(t, newSandboxExecCommand(), "--profile", "triage", "box", "--", "ls"); err == nil || !strings.Contains(err.Error(), "group- or world-writable") {
		t.Errorf("writable: err = %v", err)
	}
}
