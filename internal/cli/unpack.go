package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/josegonzalez/safeclaw/internal/session"
	"github.com/josegonzalez/safeclaw/internal/termtext"
	"github.com/josegonzalez/safeclaw/internal/unpack"
)

const (
	// unpackProgram is the name the sandbox image variant links to the
	// safeclaw binary; run under it, safeclaw is `safeclaw unpack`.
	unpackProgram = "safeclaw-unpack"
	// unpackPasswordEnv is the default variable the password is read from.
	unpackPasswordEnv = "SAFECLAW_UNPACK_PASSWORD"
)

// unpackFormats are the formats detect knows, which are the ones nested
// archives are unpacked in.
const unpackFormats = "zip, 7z, rar, tar, gzip, bzip2, xz, or zstd"

const unpackNotArchiveHelp = `A file 7z can't open as an archive is not an archive (exit 5) when it doesn't start like a ` + unpackFormats + ` archive, the formats detect knows, and corrupt (exit 1) when it does. A file in some other format 7z can open, such as an ISO image, is listed and extracted as usual.`

const unpackHelp = `Exit codes:
  0  success, including an extract --nested keep-going that left some nested archives packed and flagged
  1  failed: 7z failed, the archive is corrupt, or a usage or I/O error
  2  rejected: the archive has links, special files, or unsafe paths (or 7z made some)
  3  needs password: the archive is encrypted and no password, or the wrong one, was given
  4  too large: the contents are over --max-size
  5  not an archive: 7z can't open the file, and it doesn't start like an archive

` + unpackNotArchiveHelp + `

The password is read from the SAFECLAW_UNPACK_PASSWORD environment variable, or the one --password-env names, never from the arguments, and is passed to 7z on its stdin.

Each entry is printed as a tab-separated line: TYPE, SIZE, PATH, and FLAGS. TYPE is file, dir, symlink, hardlink, or special (a device, fifo, or socket). SIZE is in bytes, - when unknown. PATH is escaped as in a Go string, with backslashes doubled and tabs, newlines, and other unprintable characters written as \t, \n, \xNN, or \uNNNN. FLAGS is a comma-separated list, - for none: ENCRYPTED, LINK, SPECIAL, UNSAFE-PATH (empty, absolute, a drive letter, a .. segment, or control characters), DROPPED (left out by --drop-bad), UNPACKED (a nested archive unpacked into PATH.unpacked), DEPTH-LIMIT (a nested archive left packed), and, with extract --nested keep-going, REJECTED, NEEDS-PASSWORD, TOO-LARGE, or FAILED (a nested archive left packed because it failed that way). --json prints one JSON object instead, with the paths unescaped.`

// newUnpackCommand builds `safeclaw unpack`, named use: "unpack" under
// safeclaw, or safeclaw-unpack when run through that link.
func newUnpackCommand(use string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   use,
		Short: "Detect, list, or extract an untrusted archive with 7z, refusing links and unsafe paths",
		Long: "Detect, list, or extract an untrusted archive with 7z, refusing links and unsafe paths. Run it inside a sandbox: the sandbox image variant has 7z and links this command as " + unpackProgram + ".\n\n" +
			unpackHelp,
		Example: `  safeclaw sandbox exec --ephemeral -v ~/Downloads:/in -- safeclaw-unpack detect /in/report.zip
  safeclaw sandbox exec --ephemeral -v ~/Downloads:/in -- safeclaw-unpack list /in/report.zip
  safeclaw-unpack extract --json /sandbox/in/1-report.zip /sandbox/out/report
  SAFECLAW_UNPACK_PASSWORD=infected safeclaw-unpack extract --drop-bad sample.7z out
  safeclaw-unpack extract --nested keep-going --json /sandbox/in/1-report.zip /sandbox/out/report`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(newUnpackDetectCommand(), newUnpackListCommand(), newUnpackExtractCommand())
	return cmd
}

func newUnpackDetectCommand() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "detect FILE",
		Short: "Print the archive format a file starts like, or none",
		Long: "Print the archive format FILE starts like, from its first bytes: " + unpackFormats + ", or none. These are the formats extract unpacks nested archives in, found the same way, so detect and extract never disagree. Nothing is run, and 7z isn't needed.\n\n" +
			"Exit codes:\n  0  FILE starts like an archive\n  1  failed: FILE is missing, not a regular file, or can't be read\n  5  not an archive: FILE doesn't start like one, and none is printed\n\n" +
			"For list and extract: " + unpackNotArchiveHelp + "\n\n" +
			"--json prints one JSON object: status (ok, not an archive, or failed), code (the exit code), type (the format, or none), and error when it failed.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			format, err := unpack.DetectFile(args[0])
			if err != nil {
				return unpackFailure(cmd, asJSON, err, nil)
			}
			v := unpackJSON{Status: "ok", Type: format}
			if format == "" {
				v = unpackJSON{Status: unpack.NotArchive.String(), Code: int(unpack.NotArchive), Type: "none"}
			}
			if asJSON {
				err = writeUnpackJSON(cmd.OutOrStdout(), v)
			} else {
				_, err = fmt.Fprintln(cmd.OutOrStdout(), v.Type)
			}
			if err == nil && v.Code != 0 {
				err = exitCodeError{v.Code}
			}
			return err
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print one JSON object instead of the format")
	return cmd
}

type unpackFlags struct {
	json        bool
	passwordEnv string
}

func (f *unpackFlags) register(cmd *cobra.Command) {
	cmd.Flags().BoolVar(&f.json, "json", false, "print one JSON object instead of tab-separated lines")
	cmd.Flags().StringVar(&f.passwordEnv, "password-env", unpackPasswordEnv, "environment variable to read the password from")
}

// password reads the password from its variable and removes the variable
// from the environment, so 7z doesn't inherit it. An empty or unset
// variable means no password.
func (f *unpackFlags) password() (*string, error) {
	pw, ok := os.LookupEnv(f.passwordEnv)
	if !ok || pw == "" {
		return nil, nil
	}
	_ = os.Unsetenv(f.passwordEnv)
	if strings.ContainsAny(pw, "\r\n") {
		return nil, fmt.Errorf("the password in %s has a line break, which 7z can't read", f.passwordEnv)
	}
	return &pw, nil
}

func newUnpackListCommand() *cobra.Command {
	var f unpackFlags
	cmd := &cobra.Command{
		Use:   "list ARCHIVE",
		Short: "List an archive's entries with their type, size, path, and flags",
		Long:  "List an archive's entries with their type, size, path, and flags, from 7z's listing. Nothing is extracted, so nested archives are not listed.\n\n" + unpackHelp,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			out := cmd.OutOrStdout()
			pw, err := f.password()
			if err != nil {
				return unpackFailure(cmd, f.json, &unpack.Error{Kind: unpack.Failed, Msg: err.Error()}, nil)
			}
			z, err := unpack.Find()
			if err != nil {
				return unpackFailure(cmd, f.json, &unpack.Error{Kind: unpack.Failed, Msg: err.Error()}, nil)
			}
			l, err := unpack.List(cmd.Context(), z, args[0], pw)
			if err != nil {
				return unpackFailure(cmd, f.json, err, nil)
			}
			if f.json {
				return writeUnpackJSON(out, unpackJSON{Status: "ok", Type: l.Type, Entries: jsonEntries(l.Entries)})
			}
			return writeEntries(out, l.Entries)
		},
	}
	f.register(cmd)
	return cmd
}

func newUnpackExtractCommand() *cobra.Command {
	var f unpackFlags
	var maxSize, nested string
	var o unpack.Options
	cmd := &cobra.Command{
		Use:   "extract ARCHIVE DEST",
		Short: "Extract an archive into DEST, a new or empty directory, refusing links and unsafe paths",
		Long: "Extract an archive into DEST, which must be missing or an empty directory, and not a symbolic link.\n\n" +
			"The archive is listed first. One with links, special files, or unsafe paths is rejected, or with --drop-bad those entries are left out. One whose listed size is over --max-size is refused before anything is extracted, and the size is checked again while 7z extracts and afterwards, for formats that don't record sizes. " +
			"After extracting, any link or special file 7z made is deleted (which rejects the archive unless --drop-bad is given, since the listing didn't show it), setuid and setgid bits are cleared, and every path must resolve inside DEST. " +
			"Each extracted file that starts like a " + unpackFormats + " archive (one detect names a format for) is then unpacked the same way into PATH.unpacked next to it (PATH.unpacked-2 and so on when that name is taken), up to --depth levels; the archive itself is kept. A file 7z can't open as an archive is left as it is. " +
			"On any failure DEST is emptied, without following links. Each path in DEST is printed when it succeeds, and the entries that got it rejected when it is rejected.\n\n" +
			"With --nested keep-going, a nested archive that is rejected, needs a password, would take the total past --max-size, or fails otherwise is left packed instead, flagged REJECTED, NEEDS-PASSWORD, TOO-LARGE, or FAILED, and everything it extracted is removed, without following links. The other files are kept, and the run exits 0. Each archive left packed is also reported on stderr, or in --json under nested_failures with its status, code, error, and the entries that got it rejected. The size limit is shared by the whole tree, and the archive given still fails the run for its own problems.\n\n" + unpackHelp,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			n, err := session.ParseSize(maxSize)
			if err != nil || n <= 0 {
				return unpackFailure(cmd, f.json, &unpack.Error{Kind: unpack.Failed, Msg: fmt.Sprintf("--max-size: invalid size %q: want a positive number of bytes with an optional k, m, g, or t suffix", maxSize)}, nil)
			}
			o.MaxSize = n
			if o.Depth < 0 {
				return unpackFailure(cmd, f.json, &unpack.Error{Kind: unpack.Failed, Msg: "--depth can't be negative"}, nil)
			}
			switch nested {
			case nestedFail:
			case nestedKeepGoing:
				o.KeepGoing = true
			default:
				return unpackFailure(cmd, f.json, &unpack.Error{Kind: unpack.Failed, Msg: fmt.Sprintf("--nested: invalid value %q: want %s or %s", nested, nestedFail, nestedKeepGoing)}, nil)
			}
			if o.Password, err = f.password(); err != nil {
				return unpackFailure(cmd, f.json, &unpack.Error{Kind: unpack.Failed, Msg: err.Error()}, nil)
			}
			z, err := unpack.Find()
			if err != nil {
				return unpackFailure(cmd, f.json, &unpack.Error{Kind: unpack.Failed, Msg: err.Error()}, nil)
			}
			o.Runner = z
			res, err := unpack.Extract(cmd.Context(), args[0], args[1], o)
			if err != nil {
				var dropped []unpack.Entry
				if res != nil {
					dropped = res.Dropped
				}
				return unpackFailure(cmd, f.json, err, dropped)
			}
			return writeExtracted(cmd, f.json, res)
		},
	}
	f.register(cmd)
	cmd.Flags().StringVar(&maxSize, "max-size", "512m", "limit on the total size of what is extracted, nested archives and the archives they came from included (k, m, g, or t suffix)")
	cmd.Flags().IntVar(&o.Depth, "depth", unpack.DefaultDepth, "levels of nested archives to unpack, 0 for none")
	cmd.Flags().BoolVar(&o.DropBad, "drop-bad", false, "leave out links, special files, and entries with unsafe paths instead of rejecting the archive")
	cmd.Flags().StringVar(&nested, "nested", nestedFail, "what a failing nested archive does: "+nestedFail+" fails the whole extraction, "+nestedKeepGoing+" leaves it packed and flagged")
	return cmd
}

// --nested values.
const (
	nestedFail      = "fail"
	nestedKeepGoing = "keep-going"
)

// writeExtracted prints a successful extraction: each path in DEST, then
// the dropped entries, and each nested archive left packed on stderr, or
// one JSON object.
func writeExtracted(cmd *cobra.Command, asJSON bool, res *unpack.Result) error {
	out := cmd.OutOrStdout()
	if asJSON {
		v := unpackJSON{Status: "ok", Entries: jsonEntries(res.Entries), Dropped: jsonEntries(res.Dropped)}
		for _, e := range res.Failed {
			n := nestedJSON{Archive: e.Archive, Status: e.Kind.String(), Code: int(e.Kind), Error: e.Error()}
			if len(e.Bad) > 0 {
				n.Rejected = jsonEntries(e.Bad)
			}
			v.NestedFailures = append(v.NestedFailures, n)
		}
		return writeUnpackJSON(out, v)
	}
	if err := writeEntries(out, append(res.Entries, res.Dropped...)); err != nil {
		return err
	}
	for _, e := range res.Failed {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s: left packed: %s\n", cmd.Root().Name(), termtext.Escape(e.Error()))
	}
	return nil
}

// unpackJSON is the --json output.
type unpackJSON struct {
	// Status is "ok" or the failure kind, such as "rejected".
	Status string `json:"status"`
	// Code is the exit code.
	Code int `json:"code"`
	// Error says what went wrong.
	Error string `json:"error,omitempty"`
	// Archive is the nested archive the failure happened in, relative to
	// DEST.
	Archive string `json:"archive,omitempty"`
	// Type is the archive's format: 7z's name for it for list, and the
	// format it starts like, or none, for detect.
	Type string `json:"type,omitempty"`
	// Entries are the archive's entries for list, and the paths in DEST
	// for extract.
	Entries []entryJSON `json:"entries,omitempty"`
	// Rejected are the entries that got the archive rejected.
	Rejected []entryJSON `json:"rejected,omitempty"`
	// Dropped are the entries left out by --drop-bad.
	Dropped []entryJSON `json:"dropped,omitempty"`
	// NestedFailures are the nested archives extract --nested keep-going
	// left packed.
	NestedFailures []nestedJSON `json:"nested_failures,omitempty"`
}

// nestedJSON is a nested archive left packed by --nested keep-going.
type nestedJSON struct {
	// Archive is its path relative to DEST.
	Archive string `json:"archive"`
	// Status and Code are what its own failure would have been.
	Status string `json:"status"`
	Code   int    `json:"code"`
	Error  string `json:"error"`
	// Rejected are the entries that got it rejected.
	Rejected []entryJSON `json:"rejected,omitempty"`
}

type entryJSON struct {
	Type string `json:"type"`
	// Size is null when unknown.
	Size     *int64   `json:"size"`
	Path     string   `json:"path"`
	Flags    []string `json:"flags"`
	Link     string   `json:"link,omitempty"`
	Unpacked string   `json:"unpacked,omitempty"`
}

func jsonEntries(entries []unpack.Entry) []entryJSON {
	out := make([]entryJSON, 0, len(entries))
	for _, e := range entries {
		j := entryJSON{Type: e.Type, Path: e.Path, Flags: e.Flags(), Link: e.Link, Unpacked: e.Unpacked}
		if j.Flags == nil {
			j.Flags = []string{}
		}
		if e.Size >= 0 {
			size := e.Size
			j.Size = &size
		}
		out = append(out, j)
	}
	return out
}

func writeUnpackJSON(w io.Writer, v unpackJSON) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// writeEntries writes entries as TYPE, SIZE, PATH, FLAGS lines.
func writeEntries(w io.Writer, entries []unpack.Entry) error {
	var b strings.Builder
	for _, e := range entries {
		size := "-"
		if e.Size >= 0 {
			size = strconv.FormatInt(e.Size, 10)
		}
		flags := "-"
		if f := e.Flags(); len(f) > 0 {
			flags = strings.Join(f, ",")
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\n", e.Type, size, escapeField(e.Path), flags)
	}
	_, err := io.WriteString(w, b.String())
	return err
}

// escapeField escapes a path for one tab-separated field: backslashes are
// doubled, then everything termtext.Escape escapes, then tabs and newlines,
// so the result is unambiguous and has no control characters.
func escapeField(s string) string {
	s = termtext.Escape(strings.ReplaceAll(s, `\`, `\\`))
	return strings.NewReplacer("\t", `\t`, "\n", `\n`).Replace(s)
}

// unpackFailure prints err, and the entries that got the archive rejected,
// and returns the exit code for its kind.
func unpackFailure(cmd *cobra.Command, asJSON bool, err error, dropped []unpack.Entry) error {
	kind := unpack.KindOf(err)
	var ue *unpack.Error
	var bad []unpack.Entry
	archive := ""
	msg := err.Error()
	if errors.As(err, &ue) {
		bad, archive = ue.Bad, ue.Archive
	}
	if asJSON {
		v := unpackJSON{Status: kind.String(), Code: int(kind), Error: msg, Archive: archive, Rejected: jsonEntries(bad), Dropped: jsonEntries(dropped)}
		if len(bad) == 0 {
			v.Rejected = nil
		}
		if len(dropped) == 0 {
			v.Dropped = nil
		}
		if werr := writeUnpackJSON(cmd.OutOrStdout(), v); werr != nil {
			return werr
		}
	} else {
		if werr := writeEntries(cmd.OutOrStdout(), bad); werr != nil {
			return werr
		}
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s: %s\n", cmd.Root().Name(), termtext.Escape(msg))
	}
	return exitCodeError{int(kind)}
}

// isUnpackProgram reports whether safeclaw was run as safeclaw-unpack,
// argv[0] being its name or path.
func isUnpackProgram(arg0 string) bool {
	return filepath.Base(arg0) == unpackProgram
}

// executeUnpack runs safeclaw-unpack: `safeclaw unpack` as its own root
// command. It needs no config directory, so unlike Execute it doesn't
// check one.
func executeUnpack(ctx context.Context, args []string) int {
	cmd := newUnpackCommand(unpackProgram)
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
