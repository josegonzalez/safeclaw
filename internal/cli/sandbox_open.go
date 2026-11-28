package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/session"
)

// openExpandFlags and openTotextFlags are the helpers' policy flags that
// `sandbox open` passes through: each is registered on it with the
// helper's own type, default, and help, and passed on only when set.
var (
	openExpandFlags = []string{"depth", "max-size", "no-mail", "hold", "release", "release-all"}
	openTotextFlags = []string{"max-pages", "ocr-threshold", "ocr-dpi", "ocr-lang", "max-files", "max-output"}
)

// `sandbox open`'s exit codes, other than 0, 124, and 128 plus a signal
// number.
const (
	openFailed       = 1
	openExpandFailed = 2
	openLeftPacked   = 3
	openTextFailed   = 4
	openTextPartial  = 5
)

const openHelp = `Exit codes:
  0    every container was opened, and with --text every file was converted
  1    failed before running a helper: a usage error, NAME is not a running sandbox, its image lacks the helpers, or docker failed;
       or, for a sandbox that keeps its inputs, safeclaw-expand finished but the run could not be recorded, and nothing was converted
  2    safeclaw-expand failed (with --plan too), so the tree is as it was before this run; with --text nothing was converted
  3    safeclaw-expand finished but left containers packed; with --text the tree was converted anyway, ok or partial
  4    with --text, safeclaw-totext failed, so ` + session.OpenOutDir + ` is as it was
  5    with --text, every container was opened but the conversion was partial
  124  a helper ran past --timeout; when it was safeclaw-expand, nothing was converted
A signal that killed docker gives 128 plus its number, and nothing more is run.`

func newSandboxOpenCommand() *cobra.Command {
	var o session.OpenOptions
	var passwordEnv string
	cmd := &cobra.Command{
		Use:   "open NAME [--plan] [--skip PATH]... [--unskip PATH]... [--password-env NAME] [--text] [--timeout DUR]",
		Short: "Open the files copied into a sandbox with safeclaw-expand, and convert them to text",
		Long: "Run safeclaw-expand in a sandbox on everything `sandbox cp-in` copied into " + session.OpenInDir + ", opening it into " + session.OpenTreeDir + ". " +
			"A rerun resumes the tree, as safeclaw-expand does, so files copied in since are added and containers left packed are tried again. " +
			"Its container lines are printed, and --plan prints what is not opened yet and what a rerun would open, without opening or changing anything. " +
			"--skip and --unskip take paths as the lines write them, and are kept in the tree's manifest.\n\n" +
			"--password-env NAME reads the archive password from NAME in safeclaw's environment and passes it to safeclaw-expand " +
			"through a pipe, never in an argument, as `sandbox exec --env-if-set` does. NAME unset, or set to an empty value, means no password. " +
			"The names of stored secrets, CLAUDE_CODE_OAUTH_TOKEN, and GH_TOKEN are refused.\n\n" +
			"With --text, once safeclaw-expand has finished, " + session.OpenOutDir + " is rebuilt from the tree with safeclaw-totext --recursive --replace, " +
			"replacing an earlier run's results only once the new ones are complete. " +
			"A tree with containers left packed (any outcome but opened, SKIPPED, HELD, and DEPTH-LIMIT included) is converted anyway, " +
			"since the files around them are worth reading, and the exit code says so; when safeclaw-expand fails or times out nothing is converted.\n\n" +
			"The policy flags (--depth, --max-size, --no-mail, --hold, --release, and --release-all for safeclaw-expand, and --max-pages, --ocr-threshold, --ocr-dpi, --ocr-lang, " +
			"--max-files, and --max-output for safeclaw-totext, which need --text) are passed to the helper when given, and otherwise the helper's own defaults apply. " +
			"As with safeclaw-expand, a rerun must give the tree's --depth, --no-mail, and --hold.\n\n" +
			"The helpers' output is escaped as `sandbox exec --escape-controls` escapes it, so control characters from untrusted files never reach the terminal, " +
			"and each helper run gets --timeout as `sandbox exec --timeout` does. " +
			"The sandbox must be running, and its image must have the helpers, which the sandbox image variant links; an interactive session is refused.\n\n" +
			"For a one-off sandbox made with `sandbox run --rm --keep-inputs` or `--restore-from`, each run whose safeclaw-expand finished, --plan aside, is recorded: " +
			"its --skip, --unskip, --hold, --release, --release-all, --depth, --max-size, and --no-mail, never the password, " +
			"so that a restore can print the runs to make again.\n\n" + openHelp,
		Example: `  safeclaw sandbox cp-in triage ~/Downloads/report.eml
  safeclaw sandbox open triage
  TRIAGE_PASSWORD=infected safeclaw sandbox open triage --password-env TRIAGE_PASSWORD
  safeclaw sandbox open triage --plan
  safeclaw sandbox open triage --skip 1-report.eml.unpacked/1-dump.tar.gz --text --max-pages 300
  safeclaw sandbox cp-out triage /sandbox/out ./text --only '*.txt' --mkdir`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeType(config.TypeSandbox),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := resolveArg(cmd, args); err != nil {
				return err
			}
			if cmd.Flags().Changed("timeout") && o.Timeout <= 0 {
				return fmt.Errorf("invalid --timeout %s: must be more than 0", o.Timeout)
			}
			o.ExpandArgs = passThrough(cmd.Flags(), openExpandFlags)
			o.TotextArgs = passThrough(cmd.Flags(), openTotextFlags)
			m := newManager()
			env, err := m.OpenPasswordEnv(passwordEnv, unpackPasswordEnv, os.LookupEnv)
			if err != nil {
				return err
			}
			if env != "" {
				o.EnvFile = "/dev/fd/3"
			}
			run, err := m.PrepareOpen(cmd.Context(), args[0], o)
			if err != nil {
				return err
			}
			return runOpen(cmd, m, run, o, env)
		},
	}
	cmd.Flags().BoolVar(&o.Plan, "plan", false, "print the containers not opened yet, with their entries or parts, without opening or changing anything")
	cmd.Flags().StringArrayVar(&o.Skip, "skip", nil, "leave the container at this path in the tree packed, flagged SKIPPED, on this run and later ones (repeatable)")
	cmd.Flags().StringArrayVar(&o.Unskip, "unskip", nil, "take a path off the skip list, so this run opens it (repeatable)")
	cmd.Flags().StringVar(&passwordEnv, "password-env", "", "read the archive password from this variable in safeclaw's environment, if it is set")
	cmd.Flags().BoolVar(&o.Text, "text", false, "then rebuild "+session.OpenOutDir+" from the tree with safeclaw-totext --recursive --replace")
	cmd.Flags().DurationVar(&o.Timeout, "timeout", session.DefaultOpenTimeout, "stop each helper run after this long, such as 30s or 2h, and exit 124")
	addPassThrough(cmd.Flags(), newExpandCommand(expandProgram).Flags(), openExpandFlags, expandProgram)
	addPassThrough(cmd.Flags(), newTotextCommand(totextProgram).Flags(), openTotextFlags, totextProgram+", with --text")
	return cmd
}

// addPassThrough registers each named flag of a helper's flag set on fs,
// with the helper's type, default, and help, noting which helper gets it.
func addPassThrough(fs, helper *pflag.FlagSet, names []string, to string) {
	for _, name := range names {
		f := helper.Lookup(name)
		if f == nil {
			panic("no " + to + " flag --" + name)
		}
		c := *f
		c.Shorthand = ""
		usage := strings.TrimPrefix(f.Usage, "with --recursive, ")
		c.Usage = strings.ReplaceAll(usage, "DEST", "the tree") + " (passed to " + to + ")"
		fs.AddFlag(&c)
	}
}

// passThrough returns the named flags that were set, each as one
// --NAME=VALUE argument, repeated for each value of a repeatable flag.
func passThrough(fs *pflag.FlagSet, names []string) []string {
	var args []string
	for _, name := range names {
		f := fs.Lookup(name)
		if f == nil || !f.Changed {
			continue
		}
		if s, ok := f.Value.(pflag.SliceValue); ok {
			for _, v := range s.GetSlice() {
				args = append(args, "--"+name+"="+v)
			}
			continue
		}
		args = append(args, "--"+name+"="+f.Value.String())
	}
	return args
}

// runOpen runs safeclaw-expand, then with --text safeclaw-totext, and
// returns `sandbox open`'s exit code for how they ended.
func runOpen(cmd *cobra.Command, m *session.Manager, run session.OpenRun, o session.OpenOptions, env string) error {
	stderr := cmd.ErrOrStderr()
	notConverted := ""
	if o.Text {
		notConverted = ", so " + session.OpenOutDir + " was not rebuilt"
	}
	var packed packedLines
	code, err := runOpenHelper(cmd, m, run.Name, run.Expand, o.Timeout, &packed, env)
	if err != nil {
		return err
	}
	switch {
	case code == timeoutExitCode:
		printError(stderr, fmt.Errorf("%s timed out%s", session.ExpandHelper, notConverted))
		return exitCodeError{code}
	case code > 128:
		return exitCodeError{code}
	case code != 0:
		printError(stderr, fmt.Errorf("%s failed with exit code %d%s", session.ExpandHelper, code, notConverted))
		return exitCodeError{openExpandFailed}
	}
	if o.Plan {
		return nil
	}
	if run.KeepInputs != "" {
		if err := m.RecordOpen(cmd.Context(), run.KeepInputs, o); err != nil {
			return fmt.Errorf("%s finished, but this run could not be recorded in %s, so a restore won't replay it: %w", session.ExpandHelper, run.KeepInputs, err)
		}
	}
	if packed.found {
		msg := "Some containers were left packed in " + session.OpenTreeDir + "; see the lines above"
		if o.Text {
			msg += ". Converting the tree anyway"
		}
		_, _ = fmt.Fprintln(stderr, msg)
	}
	if !o.Text {
		if packed.found {
			return exitCodeError{openLeftPacked}
		}
		return nil
	}
	code, err = runOpenHelper(cmd, m, run.Name, run.Totext, o.Timeout, nil, "")
	if err != nil {
		return err
	}
	switch {
	case code == timeoutExitCode:
		printError(stderr, fmt.Errorf("%s timed out, so %s should be as it was", session.TotextHelper, session.OpenOutDir))
		return exitCodeError{code}
	case code > 128:
		return exitCodeError{code}
	case code != 0 && code != totextPartial:
		printError(stderr, fmt.Errorf("%s failed with exit code %d, so %s is as it was", session.TotextHelper, code, session.OpenOutDir))
		return exitCodeError{openTextFailed}
	case packed.found:
		return exitCodeError{openLeftPacked}
	case code == totextPartial:
		return exitCodeError{openTextPartial}
	}
	return nil
}

// totextPartial is safeclaw-totext --recursive's exit code for a tree it
// converted only in part.
const totextPartial = 6

// runOpenHelper runs one helper's docker argv as `sandbox exec
// --escape-controls --timeout` runs a command, with env, when set, on fd
// 3, and argv's timeout, which runSandboxExec needs to tell a timeout
// apart. Its escaped stdout is also written to tee, when set. It returns
// the exit code, which is 124 when it timed out, or an error when docker
// could not be run.
func runOpenHelper(cmd *cobra.Command, m *session.Manager, name string, argv []string, timeout time.Duration, tee io.Writer, env string) (int, error) {
	out := cmd.OutOrStdout()
	if tee != nil {
		out = io.MultiWriter(out, tee)
	}
	c := &cobra.Command{}
	c.SetOut(out)
	c.SetErr(cmd.ErrOrStderr())
	c.SetContext(cmd.Context())
	r := execRun{escape: true, timeout: timeout, name: name}
	if env != "" {
		f, err := envPipe(env)
		if err != nil {
			return 0, err
		}
		defer f.Close()
		r.envFile = f
	}
	err := runSandboxExec(c, m, argv, r)
	if exit, ok := errors.AsType[exitCodeError](err); ok {
		return exit.code, nil
	}
	return 0, err
}

// packedLines watches safeclaw-expand's escaped stdout for a container
// line whose DIR is -, a container left packed. It keeps only what it
// needs of each line, however long the line is.
type packedLines struct {
	found bool
	// head is the start of the current line, to tell entry lines apart.
	head []byte
	// last is the start of the current line's last field.
	last []byte
	tabs int
}

func (p *packedLines) Write(b []byte) (int, error) {
	for _, c := range b {
		switch c {
		case '\n':
			if p.tabs == 3 && string(p.last) == "-" && string(p.head) != "entry\t" {
				p.found = true
			}
			p.head, p.last, p.tabs = p.head[:0], p.last[:0], 0
			continue
		case '\t':
			p.tabs++
			p.last = p.last[:0]
		default:
			if len(p.last) < 2 {
				p.last = append(p.last, c)
			}
		}
		if len(p.head) < len("entry\t") {
			p.head = append(p.head, c)
		}
	}
	return len(b), nil
}
