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
	"github.com/josegonzalez/safeclaw/internal/totext"
)

// totextProgram is the name the sandbox image variant links to the
// safeclaw binary; run under it, safeclaw is `safeclaw totext`.
const totextProgram = "safeclaw-totext"

const totextHelp = `Exit codes:
  0  ok: every page was converted
  1  failed: a tool failed on the whole file, the file is corrupt, or a usage or I/O error
  3  encrypted: the PDF needs a password, or its permissions don't allow extracting text
  5  unsupported: not a PDF, a PNG, JPEG, GIF, TIFF, BMP, or WebP image, or UTF-8 text
  6  partial: text was written, but pages over --max-pages, or a page whose extraction or OCR timed out or failed, were skipped
  7  timed out: pdfinfo, or tesseract on an image, ran past --timeout, so nothing was written

1, 3, and 5 mean what they do for safeclaw-unpack, which uses 2 and 4 for rejected and too large archives. On every exit but 0 and 6, OUTDIR is emptied.

Output is printed as tab-separated lines. The first is "type", the detected type (pdf, png, jpeg, gif, tiff, bmp, webp, text, or unknown), the page count, and ENCRYPTED or -. Then a "page" line for each file written: the page, its characters not counting whitespace, the file's name in OUTDIR, and OCR or -. Then a "skipped" line for each thing skipped: the first and last page (0 and 0 for the whole file), the reason (encrypted, page-limit, timed-out, unsupported, or failed), the tool or -, and the detail escaped as in a Go string, or -. --json prints one JSON object instead, with a "schema" field: fields may be added within a schema version, but are never renamed, removed, or given a new meaning without a new one.

With --recursive, SRC is a directory and the exit codes are for the whole run:
  0  ok: every file was converted
  1  failed: a usage or I/O error, OUTDIR is not a missing or empty directory (or, with --replace, one holding only an earlier run's results) or is inside SRC, or the run was interrupted; OUTDIR is emptied, or with --replace left as it was
  6  partial: something wasn't converted in full: a file that was partial, encrypted, unsupported, timed out, or failed, a link or special file, a file past --max-files or --max-output, or an email or archive safeclaw-expand left packed

The manifest, OUTDIR/` + totext.ManifestText + `, holds the same tab-separated lines that are printed. The first is "tree": the status, the number of entries, the bytes of text written, and the safeclaw-expand manifest (folded, none, or invalid) with why it was invalid, or -. Then, for each entry, its INDEX (zero-padded, as its outputs start with it) on every line: a "file" line with INDEX, the path in SRC, the status (a single file's, or skipped), the type, the size, the page count, and flags (ENCRYPTED, EXPAND-OUTPUT for a file safeclaw-expand wrote, or -); an "error" line with what went wrong, when something did; a "container" line for an email or archive in safeclaw-expand's manifest, with its kind, depth, outcome, flags, parent, and error; "page" lines with the page, characters, output file, and OCR or -; and "skipped" lines as above, a skipped entry's reason being link, special, file-limit, output-limit, unpacked, expand-manifest, or missing. --json prints one JSON object instead.`

// newTotextCommand builds `safeclaw totext`, named use: "totext" under
// safeclaw, or safeclaw-totext when run through that link.
func newTotextCommand(use string) *cobra.Command {
	o := totext.DefaultOptions()
	var asJSON, recursive, replace bool
	var maxFiles int
	var maxOutput string
	cmd := &cobra.Command{
		Use:   use + " FILE OUTDIR | --recursive SRC OUTDIR",
		Short: "Turn an untrusted PDF, image, or text file into text files with control characters removed",
		Long: "Turn an untrusted PDF, image, or text file into text files with control characters removed. Run it inside a sandbox: the sandbox image variant has poppler-utils and tesseract and links this command as " + totextProgram + ".\n\n" +
			"OUTDIR must be missing or an empty directory, and not a symbolic link. The type comes from the file's first bytes, never its name. " +
			"A PDF's page count is read with pdfinfo, and each page up to --max-pages is extracted with pdftotext -layout into p001.txt, p002.txt, and so on; the rest are skipped. " +
			"A page with fewer than --ocr-threshold characters, not counting whitespace, is rendered with pdftoppm at --ocr-dpi (lowered for a page whose longer side would pass 10000 pixels) and OCR'd with tesseract in --ocr-lang, and the OCR text replaces the page's unless it has fewer characters. " +
			"An image is OCR'd into " + totext.ImageOutput + ", and a text file is copied into " + totext.TextOutput + ". " +
			"Control characters other than newline and tab, and bidirectional formatting characters, are removed from every file, and bytes that aren't UTF-8 become U+FFFD. " +
			"Every tool runs under its own --timeout, in a process group of its own that is killed when the timeout passes, and file names reach the tools as absolute paths in their arguments, never through a shell.\n\n" +
			"With --recursive, the first argument is a directory, SRC, and every regular file under it is converted, without following links, in lexical order, into OUTDIR, flat: each output is named NNN-NAME.pNNN.txt, NNN-NAME.ocr.txt, or NNN-NAME.text.txt, NNN being the file's index and NAME its path made safe as safeclaw-mail makes attachment names safe, so names never collide and match cp-out --only '*.txt'. OUTDIR can't be inside SRC. " +
			"Every file gets an entry in the manifest, " + totext.ManifestText + " in OUTDIR, whether it was converted or not; a file that fails leaves nothing in OUTDIR. --max-files limits how many files are converted, and --max-output the total size of the text written; what is past either is skipped. " +
			"When SRC holds a safeclaw-expand manifest.json, each email and archive in it is listed with its outcome and flags, one that was opened is skipped since its files are converted, manifest.json is skipped, and body.txt and parts.txt are converted and flagged EXPAND-OUTPUT. A manifest.json that isn't a valid safeclaw-expand manifest is reported and converted as a plain file. " +
			"With --replace, OUTDIR may also hold an earlier --recursive run's results, so a rerun rebuilds it from the current tree: its " + totext.ManifestText + " must be exactly as this command writes it for a run that ended ok or partial, and everything else in it a regular file that manifest lists as an output, or it is refused. The run writes into a new directory beside OUTDIR, which takes OUTDIR's place once the run succeeds, and the earlier results are then removed without following links; a run that fails leaves them as they were.\n\n" +
			totextHelp,
		Example: `  safeclaw sandbox exec --ephemeral -v ~/Downloads:/in -- safeclaw-totext /in/report.pdf /sandbox/out/report
  safeclaw-totext --json --max-pages 20 --ocr-lang eng+deu /sandbox/in/1-scan.pdf /sandbox/out/scan
  safeclaw-totext --ocr-threshold 0 --timeout 30s statement.pdf out
  safeclaw-expand /sandbox/in/1-report.eml /sandbox/tree && safeclaw-totext --recursive /sandbox/tree /sandbox/out/text
  safeclaw-totext --recursive --replace /sandbox/tree /sandbox/out/text`,
		Args:          cobra.ExactArgs(2),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if recursive {
				n, err := session.ParseSize(maxOutput)
				if err != nil || n <= 0 {
					return totextTreeFailure(cmd, asJSON, fmt.Errorf("--max-output: invalid size %q: want a positive number of bytes with an optional k, m, g, or t suffix", maxOutput))
				}
				return runTotextTree(cmd, asJSON, args[0], args[1], totext.TreeOptions{Options: o, MaxFiles: maxFiles, MaxOutput: n, Replace: replace})
			}
			for _, name := range []string{"max-files", "max-output", "replace"} {
				if cmd.Flags().Changed(name) {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s: --%s needs --recursive\n", cmd.Root().Name(), name)
					return exitCodeError{int(totext.Failed)}
				}
			}
			r := totext.Convert(cmd.Context(), args[0], args[1], o)
			out := cmd.OutOrStdout()
			if asJSON {
				if err := writeTotextJSON(out, r); err != nil {
					return err
				}
			} else {
				if err := writeTotextReport(out, r); err != nil {
					return err
				}
				if r.Error != "" {
					_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s: %s: %s\n", cmd.Root().Name(), r.Status, termtext.Escape(r.Error))
				}
			}
			if r.Code != 0 {
				return exitCodeError{r.Code}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print one JSON object instead of tab-separated lines")
	cmd.Flags().IntVar(&o.MaxPages, "max-pages", totext.DefaultMaxPages, "how many of a PDF's pages to convert; the rest are skipped")
	cmd.Flags().IntVar(&o.OCRThreshold, "ocr-threshold", totext.DefaultOCRThreshold, "OCR a PDF page with fewer characters than this, not counting whitespace; 0 for never")
	cmd.Flags().IntVar(&o.OCRDPI, "ocr-dpi", totext.DefaultOCRDPI, "resolution to render PDF pages at for OCR")
	cmd.Flags().StringVar(&o.OCRLang, "ocr-lang", totext.DefaultOCRLang, "tesseract languages, joined with + (such as eng+deu)")
	cmd.Flags().DurationVar(&o.Timeout, "timeout", totext.DefaultTimeout, "limit on each run of each tool")
	cmd.Flags().BoolVar(&recursive, "recursive", false, "convert every regular file under the directory SRC into OUTDIR, flat, with a manifest")
	cmd.Flags().IntVar(&maxFiles, "max-files", totext.DefaultMaxFiles, "with --recursive, how many files to convert; the rest are skipped")
	cmd.Flags().StringVar(&maxOutput, "max-output", "512m", "with --recursive, limit on the total size of the text files written (k, m, g, or t suffix)")
	cmd.Flags().BoolVar(&replace, "replace", false, "with --recursive, let OUTDIR hold an earlier run's results, and replace them once this run succeeds")
	return cmd
}

// runTotextTree runs `safeclaw totext --recursive`.
func runTotextTree(cmd *cobra.Command, asJSON bool, src, outdir string, o totext.TreeOptions) error {
	r := totext.ConvertTree(cmd.Context(), src, outdir, o)
	out := cmd.OutOrStdout()
	if asJSON {
		if err := writeTotextJSON(out, r); err != nil {
			return err
		}
	} else {
		if r.Code != int(totext.Failed) {
			if err := r.WriteText(out); err != nil {
				return err
			}
		}
		stderr := cmd.ErrOrStderr()
		name := cmd.Root().Name()
		if r.Error != "" {
			_, _ = fmt.Fprintf(stderr, "%s: %s: %s\n", name, r.Status, termtext.Escape(r.Error))
		}
		if r.Warning != "" {
			_, _ = fmt.Fprintf(stderr, "%s: warning: %s\n", name, termtext.Escape(r.Warning))
		}
		if r.ExpandError != "" {
			_, _ = fmt.Fprintf(stderr, "%s: %s is not a valid safeclaw-expand manifest, so it was converted as a plain file: %s\n", name, expand.ManifestFile, termtext.Escape(r.ExpandError))
		}
		for _, e := range r.Entries {
			if e.Error != "" {
				_, _ = fmt.Fprintf(stderr, "%s: %s: %s: %s\n", name, e.Status, escapeField(e.Path), termtext.Escape(e.Error))
			}
		}
	}
	if r.Code != 0 {
		return exitCodeError{r.Code}
	}
	return nil
}

// totextTreeFailure prints a usage error for --recursive and returns exit
// code 1.
func totextTreeFailure(cmd *cobra.Command, asJSON bool, err error) error {
	r := &totext.TreeReport{Schema: totext.Schema, Status: totext.Failed.String(), Code: int(totext.Failed), Error: err.Error(), Expand: totext.ExpandNone, Entries: []totext.Entry{}}
	if asJSON {
		if werr := writeTotextJSON(cmd.OutOrStdout(), r); werr != nil {
			return werr
		}
	} else {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s: %s: %s\n", cmd.Root().Name(), r.Status, termtext.Escape(r.Error))
	}
	return exitCodeError{r.Code}
}

func writeTotextJSON(w io.Writer, r any) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

// writeTotextReport writes the report as tab-separated lines.
func writeTotextReport(w io.Writer, r *totext.Report) error {
	var b strings.Builder
	flags := "-"
	if r.Encrypted {
		flags = "ENCRYPTED"
	}
	fmt.Fprintf(&b, "type\t%s\t%d\t%s\n", r.Type, r.Pages, flags)
	for _, f := range r.Files {
		ocr := "-"
		if f.OCR {
			ocr = "OCR"
		}
		fmt.Fprintf(&b, "page\t%d\t%d\t%s\t%s\n", f.Page, f.Chars, escapeField(f.Path), ocr)
	}
	for _, s := range r.Skipped {
		fmt.Fprintf(&b, "skipped\t%d\t%d\t%s\t%s\t%s\n", s.FirstPage, s.LastPage, s.Reason, orDash(s.Tool), orDash(escapeField(s.Detail)))
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// isTotextProgram reports whether safeclaw was run as safeclaw-totext,
// argv[0] being its name or path.
func isTotextProgram(arg0 string) bool {
	return filepath.Base(arg0) == totextProgram
}

// executeTotext runs safeclaw-totext: `safeclaw totext` as its own root
// command. Like safeclaw-unpack it needs no config directory, so it
// doesn't check one.
func executeTotext(ctx context.Context, args []string) int {
	cmd := newTotextCommand(totextProgram)
	cmd.CompletionOptions.DisableDefaultCmd = true
	cmd.SetArgs(args)
	if err := cmd.ExecuteContext(ctx); err != nil {
		var exit exitCodeError
		if errors.As(err, &exit) {
			return exit.code
		}
		printError(os.Stderr, err)
		return int(totext.Failed)
	}
	return 0
}
