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
	"github.com/josegonzalez/safeclaw/internal/session"
	"github.com/josegonzalez/safeclaw/internal/termtext"
	"github.com/josegonzalez/safeclaw/internal/unpack"
)

// expandProgram is the name the sandbox image variant links to the
// safeclaw binary; run under it, safeclaw is `safeclaw expand`.
const expandProgram = "safeclaw-expand"

const expandHelp = `Exit codes:
  0  the run finished, including with containers left packed and flagged
  1  failed: a usage or I/O error, an input that is missing or not a regular file, DEST is not a missing or empty directory, or the run was interrupted
Codes 2 to 5 are not used for the run: a container's own failure is recorded with the code safeclaw-unpack or safeclaw-mail would have exited with.

Each container is printed as a tab-separated line: KIND, PATH, FLAGS, and DIR. KIND is email or the archive format (` + unpackFormats + `). PATH is the container in DEST, escaped as safeclaw-unpack list escapes paths. FLAGS is a comma-separated list: UNPACKED (opened into DIR), REJECTED, NEEDS-PASSWORD, TOO-LARGE, FAILED, or DEPTH-LIMIT (left packed), then for an email UNSAFE-NAME, BAD-ENCODING, or MALFORMED when its parts had them. DIR is the directory it was opened into, - when it was left packed. Each entry that got an archive rejected follows it as an entry line: entry, TYPE, PATH (inside the archive), and FLAGS. Each container left packed for a failure is also reported on stderr. --json prints the manifest instead, with the paths unescaped.`

// newExpandCommand builds `safeclaw expand`, named use: "expand" under
// safeclaw, or safeclaw-expand when run through that link.
func newExpandCommand(use string) *cobra.Command {
	var f unpackFlags
	var maxSize string
	var noMail bool
	var o expand.Options
	cmd := &cobra.Command{
		Use:   use + " IN... DEST",
		Short: "Open a tree of untrusted emails and archives into DEST, leaving the ones that fail packed and flagged",
		Long: "Open a tree of untrusted emails and archives into DEST, which must be missing or an empty directory, and not a symbolic link. Run it inside a sandbox: the sandbox image variant has 7z and links this command as " + expandProgram + ".\n\n" +
			"Each input is copied into DEST as N-NAME, N counting the inputs from 1 and NAME its base name made safe as safeclaw-mail makes attachment names safe. Every file that starts like a " + unpackFormats + " archive, or like an email, is a container: it is opened into PATH.unpacked next to it (PATH.unpacked-2 and so on when that name is taken), an archive as safeclaw-unpack extract unpacks it and an email as safeclaw-mail extract extracts it, with its part listing in parts.txt beside body.txt. The files in that directory are then looked at in turn, except body.txt and parts.txt, which are never taken for emails. " +
			"--depth limits how many levels of containers are opened below the inputs, emails and archives alike, a forwarded message counting as a level; and --max-size limits the total size of everything opened, across the whole tree, the input copies not included. --password-env applies to every encrypted archive. --no-mail leaves emails as plain files.\n\n" +
			"Every level keeps going, the inputs included: a container that is rejected, needs a password, would take the total past --max-size, fails otherwise, or is past --depth is left packed, flagged REJECTED, NEEDS-PASSWORD, TOO-LARGE, FAILED, or DEPTH-LIMIT, and what it extracted is removed, without following links. Everything else is kept. A nested file that only starts like an archive, which 7z can't open, is left as it is, as safeclaw-unpack leaves it. " +
			"The manifest, DEST/manifest.json, records each input's copy and every container with its path, kind, depth, outcome, flags, the directory it was opened into, and the entries that got it rejected. On a failure of the run itself DEST is emptied, without following links.\n\n" + expandHelp,
		Example: `  safeclaw sandbox exec --ephemeral -v ~/Downloads/report:/in -- safeclaw-expand /in/report.eml /in/logs.zip /sandbox/out
  SAFECLAW_UNPACK_PASSWORD=infected safeclaw-expand --json --depth 5 /sandbox/in/1-report.eml /sandbox/out
  safeclaw-expand --no-mail --max-size 2g /sandbox/in/1-dump.tar.gz /sandbox/out`,
		Args:          cobra.MinimumNArgs(2),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			n, err := session.ParseSize(maxSize)
			if err != nil || n <= 0 {
				return expandFailure(cmd, f.json, fmt.Errorf("--max-size: invalid size %q: want a positive number of bytes with an optional k, m, g, or t suffix", maxSize))
			}
			o.MaxSize = n
			if o.Depth < 0 {
				return expandFailure(cmd, f.json, errors.New("--depth can't be negative"))
			}
			o.NoMail = noMail
			if o.Password, err = f.password(); err != nil {
				return expandFailure(cmd, f.json, err)
			}
			// Without 7z, emails are still opened and archives are left
			// packed, flagged FAILED.
			if z, err := unpack.Find(); err == nil {
				o.Runner = z
			}
			m, err := expand.Run(cmd.Context(), args[:len(args)-1], args[len(args)-1], o)
			if err != nil {
				return expandFailure(cmd, f.json, err)
			}
			return writeExpanded(cmd, f.json, m)
		},
	}
	f.register(cmd)
	cmd.Flags().Lookup("json").Usage = "print the manifest instead of tab-separated lines"
	cmd.Flags().StringVar(&maxSize, "max-size", "512m", "limit on the total size of everything opened, across the whole tree (k, m, g, or t suffix)")
	cmd.Flags().IntVar(&o.Depth, "depth", expand.DefaultDepth, "levels of containers to open below the inputs, 0 for only the inputs")
	cmd.Flags().BoolVar(&noMail, "no-mail", false, "leave emails as plain files instead of opening them")
	return cmd
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
