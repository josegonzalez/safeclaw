package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/josegonzalez/safeclaw/internal/expand"
	"github.com/josegonzalez/safeclaw/internal/mail"
	"github.com/josegonzalez/safeclaw/internal/session"
	"github.com/josegonzalez/safeclaw/internal/termtext"
	"github.com/josegonzalez/safeclaw/internal/unpack"
)

// expandProgram is the name the sandbox image variant links to the
// safeclaw binary; run under it, safeclaw is `safeclaw expand`.
const expandProgram = "safeclaw-expand"

const expandHelp = `Exit codes:
  0  the run finished, including with containers left packed and flagged
  1  failed: a usage or I/O error, an input that is missing or not a regular file or a directory, an input directory that is DEST, holds it, or is inside it, DEST is not a missing or empty directory and has no manifest, the manifest was refused, or the run was interrupted
Codes 2 to 5 are not used for the run: a container's own failure is recorded with the code safeclaw-unpack or safeclaw-mail would have exited with.

Each container in the manifest is printed as a tab-separated line: KIND, PATH, FLAGS, and DIR. KIND is email or the archive format (` + unpackFormats + `). PATH is the container in DEST, escaped as safeclaw-unpack list escapes paths. FLAGS is a comma-separated list: UNPACKED (opened into DIR), REJECTED, NEEDS-PASSWORD, TOO-LARGE, FAILED, DEPTH-LIMIT, SKIPPED, or HELD (left packed), then for an email UNSAFE-NAME, BAD-ENCODING, or MALFORMED when its parts had them. DIR is the directory it was opened into, - when it was left packed. Each entry that got an archive rejected follows it as an entry line: entry, TYPE, PATH (inside the archive), and FLAGS. Each container left packed for a failure is also reported on stderr. --json prints the manifest instead, with the paths unescaped.

--plan prints each container not opened yet as the same container line, with NEW as the flag of an input not in DEST yet. One a rerun could open (NEEDS-PASSWORD, TOO-LARGE, FAILED, SKIPPED, HELD, or NEW) is followed by its entries, each as entry and then the TYPE, SIZE, PATH, and FLAGS that safeclaw-unpack list prints, or for an email by its parts, each as part and then the PART, TYPE, SIZE, NAME, and FLAGS that safeclaw-mail list prints. One that can't be listed is reported on stderr. --plan --json prints {"schema", "status", "code", "containers"}, each container its manifest record with its "entries" or "parts", or "list_error".`

// newExpandCommand builds `safeclaw expand`, named use: "expand" under
// safeclaw, or safeclaw-expand when run through that link.
func newExpandCommand(use string) *cobra.Command {
	var f unpackFlags
	var maxSize string
	var noMail, plan bool
	var skip, unskip, release []string
	var o expand.Options
	cmd := &cobra.Command{
		Use:   use + " [IN...] DEST",
		Short: "Open a tree of untrusted emails and archives into DEST, leaving the ones that fail packed and flagged",
		Long: "Open a tree of untrusted emails and archives into DEST, which must not be a symbolic link, and must be missing or an empty directory unless an earlier run left its manifest there. Run it inside a sandbox: the sandbox image variant has 7z and links this command as " + expandProgram + ".\n\n" +
			"An input that is a directory stands for every regular file directly in it, in order of name, as if each were given; links, directories, and anything else in it are left out without being followed, each noted on stderr, and a directory with none is no inputs. A link given as an input, to a file or a directory, is followed. An input directory must not be DEST, hold it, or be inside it. A run given only directories with no files in them still writes the manifest, making DEST if it's missing, so the same command line works on every run.\n\n" +
			"Each input is copied into DEST as N-NAME, N counting the inputs from 1 and NAME its base name made safe as safeclaw-mail makes attachment names safe. Every file that starts like a " + unpackFormats + " archive, or like an email, is a container: it is opened into PATH.unpacked next to it (PATH.unpacked-2 and so on when that name is taken), an archive as safeclaw-unpack extract unpacks it and an email as safeclaw-mail extract extracts it, with its part listing in parts.txt beside body.txt. The files in that directory are then looked at in turn, except body.txt and parts.txt, which are never taken for emails. " +
			"--depth limits how many levels of containers are opened below the inputs, emails and archives alike, a forwarded message counting as a level; and --max-size limits the total size of everything opened, across the whole tree, the input copies not included. --password-env applies to every encrypted archive. --no-mail leaves emails as plain files.\n\n" +
			"Every level keeps going, the inputs included: a container that is rejected, needs a password, would take the total past --max-size, fails otherwise, or is past --depth is left packed, flagged REJECTED, NEEDS-PASSWORD, TOO-LARGE, FAILED, or DEPTH-LIMIT, and what it extracted is removed, without following links. Everything else is kept. A nested file that only starts like an archive, which 7z can't open, is left as it is, as safeclaw-unpack leaves it. " +
			"The manifest, DEST/manifest.json, records each input's copy and every container with its path, kind, depth, outcome, flags, the directory it was opened into, and the entries that got it rejected. On a failure of a first run DEST is emptied, without following links.\n\n" +
			"Running again on a DEST with a manifest resumes it. The manifest is checked first, and one that names a path outside DEST, reaches a container through a link, no longer matches the files in DEST, or is otherwise not what a run writes is refused, changing nothing. Containers already opened, rejected, skipped, held, or past --depth are kept as they are; the ones left NEEDS-PASSWORD, TOO-LARGE, or FAILED are tried again with this run's password and --max-size, which counts what is already in DEST. The inputs given are then copied in and opened as usual, except one with the same name and content as an input already in DEST, which isn't copied again. --depth, --no-mail, and --hold are DEST's, set by its first run: a rerun must give the same ones (nothing in DEST sets a limit), and one with others is refused. A rerun that fails removes what it added and leaves the manifest as it was.\n\n" +
			"--skip PATH (repeatable) leaves the container at PATH, written as the lines below write it, packed and flagged SKIPPED, now or whenever a later run finds it; the skip is kept in the manifest. --unskip PATH takes a skip off, so that run opens the container. --plan prints what is not opened yet and what a rerun would open, without opening or changing anything.\n\n" +
			"--hold " + expand.HoldMailArchives + " leaves every archive that came out of an email, including one in a message forwarded in it, packed and flagged HELD, so --plan can list it before anything opens it. A later run opens a held archive only when it is released, with --release PATH (repeatable) or --release-all, which releases every held archive but the ones --skip gives; one not released stays held. Archives in a released archive are opened as usual, and so are emails in it, but the archives in those emails are held again. An unskipped archive the hold applies to is held, unless it is released too. --hold is DEST's, set by its first run, like --depth and --no-mail. Releasing a path that is not held, or giving --release with --skip for the same path or with --release-all, fails the run with nothing changed.\n\n" + expandHelp,
		Example: `  safeclaw sandbox exec --ephemeral -v ~/Downloads/report:/in -- safeclaw-expand /in/report.eml /in/logs.zip /sandbox/out
  SAFECLAW_UNPACK_PASSWORD=infected safeclaw-expand --json --depth 5 /sandbox/in/1-report.eml /sandbox/out
  safeclaw-expand --no-mail --max-size 2g /sandbox/in/1-dump.tar.gz /sandbox/out
  safeclaw-expand /sandbox/in /sandbox/out
  safeclaw-expand --plan /sandbox/out
  SAFECLAW_UNPACK_PASSWORD=infected safeclaw-expand --skip 2-logs.zip /sandbox/out
  safeclaw-expand --hold mail-archives /sandbox/in /sandbox/out
  safeclaw-expand --hold mail-archives --release 1-report.eml.unpacked/1-logs.zip /sandbox/out`,
		Args:          cobra.MinimumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			inputs, dest := args[:len(args)-1], args[len(args)-1]
			n, err := session.ParseSize(maxSize)
			if err != nil || n <= 0 {
				return expandFailure(cmd, f.json, fmt.Errorf("--max-size: invalid size %q: want a positive number of bytes with an optional k, m, g, or t suffix", maxSize))
			}
			o.MaxSize = n
			if o.Depth < 0 {
				return expandFailure(cmd, f.json, errors.New("--depth can't be negative"))
			}
			o.NoMail = noMail
			o.Ignore = func(p, why string) {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s: ignoring %s: %s\n", cmd.Root().Name(), escapeField(p), why)
			}
			for _, s := range []struct {
				flag string
				in   []string
				out  *[]string
			}{{"--skip", skip, &o.Skip}, {"--unskip", unskip, &o.Unskip}, {"--release", release, &o.Release}} {
				for _, p := range s.in {
					u, err := termtext.UnescapeField(p)
					if err != nil {
						return expandFailure(cmd, f.json, fmt.Errorf("%s: %w", s.flag, err))
					}
					*s.out = append(*s.out, u)
				}
			}
			if plan && (len(skip) > 0 || len(unskip) > 0 || len(release) > 0 || o.ReleaseAll) {
				return expandFailure(cmd, f.json, errors.New("--plan can't be given with --skip, --unskip, --release, or --release-all"))
			}
			if o.Password, err = f.password(); err != nil {
				return expandFailure(cmd, f.json, err)
			}
			// Without 7z, emails are still opened and archives are left
			// packed, flagged FAILED.
			if z, err := unpack.Find(); err == nil {
				o.Runner = z
			}
			if plan {
				items, err := expand.Plan(cmd.Context(), inputs, dest, o)
				if err != nil {
					return expandFailure(cmd, f.json, err)
				}
				return writePlan(cmd, f.json, items)
			}
			m, err := expand.Run(cmd.Context(), inputs, dest, o)
			if err != nil {
				return expandFailure(cmd, f.json, err)
			}
			if err := writeExpanded(cmd, f.json, m); err != nil {
				return err
			}
			found := map[string]bool{}
			for _, c := range m.Containers {
				found[c.Path] = true
			}
			for _, p := range o.Skip {
				if !found[p] {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s: no container at %s yet; the skip is kept for a later run\n", cmd.Root().Name(), escapeField(p))
				}
			}
			return nil
		},
	}
	f.register(cmd)
	cmd.Flags().Lookup("json").Usage = "print the manifest instead of tab-separated lines"
	cmd.Flags().StringVar(&maxSize, "max-size", "512m", "limit on the total size of everything opened, across the whole tree, counting what earlier runs opened in DEST (k, m, g, or t suffix)")
	cmd.Flags().IntVar(&o.Depth, "depth", expand.DefaultDepth, "levels of containers to open below the inputs, 0 for only the inputs; a rerun must give DEST's")
	cmd.Flags().BoolVar(&noMail, "no-mail", false, "leave emails as plain files instead of opening them; a rerun must give DEST's")
	cmd.Flags().StringArrayVar(&skip, "skip", nil, "leave the container at this path in DEST packed, flagged SKIPPED, on this run and later ones (repeatable)")
	cmd.Flags().StringArrayVar(&unskip, "unskip", nil, "take a path off the skip list, so this run opens it (repeatable)")
	cmd.Flags().StringArrayVar(&o.Hold, "hold", nil, "leave containers of this kind packed, flagged HELD, until a later run releases them: "+expand.HoldMailArchives+" holds every archive that came out of an email; a rerun must give DEST's (repeatable)")
	cmd.Flags().StringArrayVar(&release, "release", nil, "open the held container at this path in DEST (repeatable)")
	cmd.Flags().BoolVar(&o.ReleaseAll, "release-all", false, "open every held container, but the ones --skip gives")
	cmd.Flags().BoolVar(&plan, "plan", false, "print the containers not opened yet, with their entries or parts, without opening or changing anything")
	return cmd
}

// expandPlanJSON is --plan --json's output.
type expandPlanJSON struct {
	Schema     int                  `json:"schema"`
	Status     string               `json:"status"`
	Code       int                  `json:"code"`
	Containers []expandPlanItemJSON `json:"containers"`
}

type expandPlanItemJSON struct {
	expand.Container
	Entries   []entryJSON    `json:"entries,omitempty"`
	Parts     []mailPartJSON `json:"parts,omitempty"`
	ListError string         `json:"list_error,omitempty"`
}

// writePlan prints a plan: a line per container, each a rerun could open
// followed by its entries or parts, or the plan as JSON.
func writePlan(cmd *cobra.Command, asJSON bool, items []expand.PlanItem) error {
	out := cmd.OutOrStdout()
	if asJSON {
		v := expandPlanJSON{Schema: expand.SchemaVersion, Status: "ok", Containers: []expandPlanItemJSON{}}
		for _, it := range items {
			j := expandPlanItemJSON{Container: it.Container, ListError: it.ListError}
			if len(it.Entries) > 0 {
				j.Entries = jsonEntries(it.Entries)
			}
			if len(it.Parts) > 0 {
				j.Parts = mailResultJSON(&mail.Result{Parts: it.Parts}).Parts
			}
			v.Containers = append(v.Containers, j)
		}
		return writeExpandJSON(out, v)
	}
	var b strings.Builder
	for _, it := range items {
		fmt.Fprintf(&b, "%s\t%s\t%s\t-\n", it.Kind, escapeField(it.Path), strings.Join(it.Flags, ","))
		var lines strings.Builder
		prefix := "entry\t"
		if it.Kind == expand.KindEmail {
			prefix = "part\t"
			writeMailParts(&lines, it.Parts, false)
		} else if err := writeEntries(&lines, it.Entries); err != nil {
			return err
		}
		for line := range strings.Lines(lines.String()) {
			b.WriteString(prefix + line)
		}
	}
	if _, err := io.WriteString(out, b.String()); err != nil {
		return err
	}
	for _, it := range items {
		if it.ListError != "" {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s: can't list %s: %s\n", cmd.Root().Name(), escapeField(it.Path), termtext.Escape(it.ListError))
		}
	}
	return nil
}

// writeExpanded prints a finished run: a line per container, or the
// manifest, and each container left packed for a failure on stderr.
func writeExpanded(cmd *cobra.Command, asJSON bool, m *expand.Manifest) error {
	out := cmd.OutOrStdout()
	if asJSON {
		return writeExpandJSON(out, m)
	}
	var b strings.Builder
	for _, c := range m.Containers {
		dir := "-"
		if c.Unpacked != "" {
			dir = escapeField(c.Unpacked)
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\n", c.Kind, escapeField(c.Path), strings.Join(c.Flags, ","), dir)
		for _, e := range c.Rejected {
			flags := "-"
			if len(e.Flags) > 0 {
				flags = strings.Join(e.Flags, ",")
			}
			fmt.Fprintf(&b, "entry\t%s\t%s\t%s\n", e.Type, escapeField(e.Path), flags)
		}
	}
	if _, err := io.WriteString(out, b.String()); err != nil {
		return err
	}
	for _, c := range m.Containers {
		if c.Code != 0 {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s: left packed: %s: %s\n", cmd.Root().Name(), escapeField(c.Path), termtext.Escape(c.Error))
		}
	}
	return nil
}

// expandFailureJSON is --json's output for a run that failed.
type expandFailureJSON struct {
	Schema int    `json:"schema"`
	Status string `json:"status"`
	Code   int    `json:"code"`
	Error  string `json:"error"`
}

func writeExpandJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// expandFailure prints err and returns exit code 1.
func expandFailure(cmd *cobra.Command, asJSON bool, err error) error {
	code := int(unpack.Failed)
	if asJSON {
		if werr := writeExpandJSON(cmd.OutOrStdout(), expandFailureJSON{Schema: expand.SchemaVersion, Status: unpack.Failed.String(), Code: code, Error: err.Error()}); werr != nil {
			return werr
		}
	} else {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s: %s\n", cmd.Root().Name(), termtext.Escape(err.Error()))
	}
	return exitCodeError{code}
}

// isExpandProgram reports whether safeclaw was run as safeclaw-expand,
// argv[0] being its name or path.
func isExpandProgram(arg0 string) bool {
	return filepath.Base(arg0) == expandProgram
}

// executeExpand runs safeclaw-expand: `safeclaw expand` as its own root
// command. It needs no config directory, so unlike Execute it doesn't
// check one.
func executeExpand(ctx context.Context, args []string) int {
	cmd := newExpandCommand(expandProgram)
	cmd.CompletionOptions.DisableDefaultCmd = true
	cmd.SetArgs(args)
	if err := cmd.ExecuteContext(ctx); err != nil {
		var exit exitCodeError
		if errors.As(err, &exit) {
			return exit.code
		}
		printError(os.Stderr, err)
		return int(unpack.Failed)
	}
	return 0
}
