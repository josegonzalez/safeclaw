package session

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
)

// The helpers `sandbox open` runs, and the fixed paths it runs them on.
const (
	// ExpandHelper and TotextHelper are the names the sandbox image
	// variant links to its safeclaw binary.
	ExpandHelper = "safeclaw-expand"
	TotextHelper = "safeclaw-totext"
	// OpenInDir is what `sandbox open` opens: everything cp-in copied in.
	OpenInDir = DefaultCopyDest
	// OpenTreeDir is the tree safeclaw-expand opens OpenInDir into.
	OpenTreeDir = config.SandboxDir + "/tree"
	// OpenOutDir is the text safeclaw-totext rebuilds from OpenTreeDir.
	OpenOutDir = config.SandboxDir + "/out"
	// DefaultOpenTimeout bounds each helper run.
	DefaultOpenTimeout = 30 * time.Minute
)

// ErrNoHelpers is returned by PrepareOpen for a sandbox whose image lacks
// safeclaw-expand or safeclaw-totext.
var ErrNoHelpers = errors.New("lacks the helpers `sandbox open` runs")

// openProbeScript prints each of its arguments that is missing, and
// always exits 0: an absolute path that doesn't exist, as a link or
// anything else, or a name that isn't a command on the sandbox user's
// PATH.
const openProbeScript = `for p do case $p in /*) [ -e "$p" ] || [ -L "$p" ] || printf '%s\n' "$p";; *) command -v "$p" >/dev/null 2>&1 || printf '%s\n' "$p";; esac; done`

// OpenOptions configures `sandbox open`.
type OpenOptions struct {
	// Plan runs safeclaw-expand --plan, which opens and changes nothing.
	Plan bool
	// Skip and Unskip are passed to safeclaw-expand as --skip and
	// --unskip, written as its container lines write paths.
	Skip, Unskip []string
	// Text also rebuilds OpenOutDir from the tree with safeclaw-totext
	// --recursive --replace once safeclaw-expand has finished.
	Text bool
	// ExpandArgs and TotextArgs are policy flags passed to each helper as
	// given, each --NAME or --NAME=VALUE.
	ExpandArgs, TotextArgs []string
	// EnvFile, when set, is the path docker reads safeclaw-expand's
	// environment from, which holds the archive password.
	EnvFile string
	// Timeout bounds each helper run, as `sandbox exec --timeout` does.
	Timeout time.Duration
}

// OpenRun is the docker argv of each helper run `sandbox open` makes.
type OpenRun struct {
	// Name is the sandbox's session name.
	Name string
	// Expand runs safeclaw-expand on OpenInDir into OpenTreeDir, or with
	// OpenOptions.Plan plans from both. Without OpenInDir nothing was
	// copied in, so it resumes or plans OpenTreeDir alone. It is nil when
	// there is nothing to open or plan from (see PrepareOpen).
	Expand []string
	// Totext, set with OpenOptions.Text, runs safeclaw-totext on
	// OpenTreeDir into OpenOutDir. It is nil when Expand is.
	Totext []string
	// KeepInputs is the directory of the sandbox's input record, when it
	// keeps one, which RecordOpen appends this run to.
	KeepInputs string
}

func (o OpenOptions) validate() error {
	if o.Plan && (len(o.Skip) > 0 || len(o.Unskip) > 0) {
		return errors.New("--plan can't be given with --skip or --unskip")
	}
	if o.Plan && o.Text {
		return errors.New("--plan can't be given with --text: a plan opens nothing to convert")
	}
	for _, a := range o.ExpandArgs {
		if name, v, _ := strings.Cut(a, "="); o.Plan && (name == "--release" || name == "--release-all" && v != "false") {
			return errors.New("--plan can't be given with --release or --release-all: a plan opens nothing")
		}
	}
	if o.Timeout <= 0 {
		return fmt.Errorf("invalid timeout %s: must be more than 0", o.Timeout)
	}
	if !o.Text && len(o.TotextArgs) > 0 {
		return fmt.Errorf("%s needs --text", strings.SplitN(o.TotextArgs[0], "=", 2)[0])
	}
	for _, a := range slices.Concat(o.ExpandArgs, o.TotextArgs) {
		if !strings.HasPrefix(a, "--") || len(a) < 3 {
			return fmt.Errorf("invalid helper flag %q: want --NAME or --NAME=VALUE", a)
		}
	}
	return nil
}

// namesContainers reports whether the run names containers in the tree,
// with --skip, --unskip, --release, or --release-all.
func (o OpenOptions) namesContainers() bool {
	if len(o.Skip) > 0 || len(o.Unskip) > 0 {
		return true
	}
	for _, a := range o.ExpandArgs {
		if name, v, _ := strings.Cut(a, "="); name == "--release" || name == "--release-all" && v != "false" {
			return true
		}
	}
	return false
}

// OpenArgv returns the docker argv of each helper run for the named
// sandbox. Every path and flag value is one argument of its own, after
// the flag's = so none can be read as another flag, and the fixed paths
// follow a --. A plan plans from OpenInDir and OpenTreeDir, so it lists
// the inputs not opened yet as well as what is left packed in the tree.
func OpenArgv(name string, o OpenOptions) OpenRun {
	return openArgv(name, o, true)
}

// openArgv is OpenArgv, but safeclaw-expand gets OpenInDir only when in
// is set, and otherwise OpenTreeDir alone, which it resumes or plans with
// no new inputs.
func openArgv(name string, o OpenOptions, in bool) OpenRun {
	name = config.SessionName(name)
	expand := []string{ExpandHelper}
	expand = append(expand, o.ExpandArgs...)
	if o.Plan {
		expand = append(expand, "--plan")
	} else {
		for _, p := range o.Skip {
			expand = append(expand, "--skip="+p)
		}
		for _, p := range o.Unskip {
			expand = append(expand, "--unskip="+p)
		}
	}
	expand = append(expand, "--")
	if in {
		expand = append(expand, OpenInDir)
	}
	expand = append(expand, OpenTreeDir)
	run := OpenRun{
		Name:   name,
		Expand: SandboxExecArgv(name, ExecOptions{EnvFile: o.EnvFile, Timeout: o.Timeout}, expand),
	}
	if o.Text {
		totext := slices.Concat([]string{TotextHelper, "--recursive", "--replace"}, o.TotextArgs, []string{"--", OpenTreeDir, OpenOutDir})
		run.Totext = SandboxExecArgv(name, ExecOptions{Timeout: o.Timeout}, totext)
	}
	return run
}

// PrepareOpen checks `sandbox open`'s options and that the named sandbox
// is running and its image has the helpers this run needs, and returns
// the docker argv of each run. Interactive sessions are refused.
func (m *Manager) PrepareOpen(ctx context.Context, name string, o OpenOptions) (OpenRun, error) {
	if err := o.validate(); err != nil {
		return OpenRun{}, err
	}
	c, err := m.runningSandbox(ctx, name)
	if err != nil {
		return OpenRun{}, err
	}
	name = config.SessionName(name)
	helpers := []string{ExpandHelper}
	if o.Text {
		helpers = append(helpers, TotextHelper)
	}
	// It also looks for what it opens or plans from.
	look := slices.Concat(helpers, []string{OpenInDir, OpenTreeDir})
	probe := docker.ExecOptions{User: config.SandboxUser, Workdir: config.SandboxDir, MaxOutput: 256}
	out, err := m.Docker.Exec(ctx, c.ShortName(), probe, slices.Concat([]string{"/bin/sh", "-c", openProbeScript, "sh"}, look)...)
	if err != nil {
		return OpenRun{}, fmt.Errorf("could not look for %s in sandbox %q: %w", strings.Join(look, " and "), name, err)
	}
	var missing []string
	gone := map[string]bool{}
	for line := range strings.Lines(string(out)) {
		line = strings.TrimSuffix(line, "\n")
		if !slices.Contains(look, line) || gone[line] {
			return OpenRun{}, fmt.Errorf("could not look for %s in sandbox %q: unexpected output %q", strings.Join(look, " and "), name, out)
		}
		gone[line] = true
		if slices.Contains(helpers, line) {
			missing = append(missing, line)
		}
	}
	if len(missing) > 0 {
		return OpenRun{}, fmt.Errorf("sandbox %q %w: its image has no %s. Recreate it with the sandbox image variant: `safeclaw sandbox run -s %s --variant sandbox`",
			name, ErrNoHelpers, strings.Join(missing, " or "), name)
	}
	// A missing OpenInDir means nothing was copied in, so there are no
	// new inputs, and the tree is resumed or planned on its own. With no
	// tree either, there is nothing to open or plan from, unless the run
	// names containers to skip, unskip, or release, which then fails in
	// safeclaw-expand as it would on a first run, rather than being
	// dropped.
	run := openArgv(name, o, !gone[OpenInDir])
	if gone[OpenInDir] && gone[OpenTreeDir] && !o.namesContainers() {
		run.Expand, run.Totext = nil, nil
	}
	run.KeepInputs = c.Label(config.LabelKeepInputs)
	return run, nil
}

// OpenPasswordEnv returns the env file that passes the archive password,
// the value of the caller's variable from (looked up with lookup), to
// safeclaw-expand as its variable to, or "" when from is "", unset, or
// set to "", which all mean no password. from is checked as
// `sandbox exec --env-if-set` checks a name, whether or not it is set: it
// must be a portable name and not a stored secret's or a token's. The
// value must be UTF-8 text without newlines, carriage returns, or NUL
// bytes, which an env file can't hold.
func (m *Manager) OpenPasswordEnv(from, to string, lookup func(string) (string, bool)) (string, error) {
	if from == "" {
		return "", nil
	}
	if before, _, ok := strings.Cut(from, "="); ok {
		return "", fmt.Errorf("invalid --password-env %q: it takes a NAME only, with no =VALUE", before)
	}
	if !envName.MatchString(from) {
		return "", fmt.Errorf("invalid --password-env %q: expected NAME, where NAME is letters, digits, and _", from)
	}
	secretNames, err := m.secretNameSet()
	if err != nil {
		return "", fmt.Errorf("could not list the stored secrets to check --password-env against: %w", err)
	}
	if secretNames[from] {
		return "", fmt.Errorf("--password-env %s %w", from, ErrSecretEnv)
	}
	value, ok := lookup(from)
	if !ok || value == "" {
		return "", nil
	}
	if !utf8.ValidString(value) || strings.ContainsAny(value, "\n\r\x00") {
		return "", fmt.Errorf("--password-env %s: the value must be UTF-8 text without newlines, carriage returns, or NUL bytes", from)
	}
	env := to + "=" + value + "\n"
	if len(env) > MaxExecEnvBytes {
		return "", fmt.Errorf("--password-env %s: the value takes %d bytes, more than the %d allowed", from, len(env), MaxExecEnvBytes)
	}
	return env, nil
}
