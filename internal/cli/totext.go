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

Output is printed as tab-separated lines. The first is "type", the detected type (pdf, png, jpeg, gif, tiff, bmp, webp, text, or unknown), the page count, and ENCRYPTED or -. Then a "page" line for each file written: the page, its characters not counting whitespace, the file's name in OUTDIR, and OCR or -. Then a "skipped" line for each thing skipped: the first and last page (0 and 0 for the whole file), the reason (encrypted, page-limit, timed-out, unsupported, or failed), the tool or -, and the detail escaped as in a Go string, or -. --json prints one JSON object instead, with a "schema" field: fields may be added within a schema version, but are never renamed, removed, or given a new meaning without a new one.`

// newTotextCommand builds `safeclaw totext`, named use: "totext" under
// safeclaw, or safeclaw-totext when run through that link.
func newTotextCommand(use string) *cobra.Command {
	o := totext.DefaultOptions()
	var asJSON bool
	cmd := &cobra.Command{
		Use:   use + " FILE OUTDIR",
		Short: "Turn an untrusted PDF, image, or text file into text files with control characters removed",
		Long: "Turn an untrusted PDF, image, or text file into text files with control characters removed. Run it inside a sandbox: the sandbox image variant has poppler-utils and tesseract and links this command as " + totextProgram + ".\n\n" +
			"OUTDIR must be missing or an empty directory, and not a symbolic link. The type comes from the file's first bytes, never its name. " +
			"A PDF's page count is read with pdfinfo, and each page up to --max-pages is extracted with pdftotext -layout into p001.txt, p002.txt, and so on; the rest are skipped. " +
			"A page with fewer than --ocr-threshold characters, not counting whitespace, is rendered with pdftoppm at --ocr-dpi (lowered for a page whose longer side would pass 10000 pixels) and OCR'd with tesseract in --ocr-lang, and the OCR text replaces the page's unless it has fewer characters. " +
			"An image is OCR'd into " + totext.ImageOutput + ", and a text file is copied into " + totext.TextOutput + ". " +
			"Control characters other than newline and tab, and bidirectional formatting characters, are removed from every file, and bytes that aren't UTF-8 become U+FFFD. " +
			"Every tool runs under its own --timeout, in a process group of its own that is killed when the timeout passes, and file names reach the tools as absolute paths in their arguments, never through a shell.\n\n" +
			totextHelp,
		Example: `  safeclaw sandbox exec --ephemeral -v ~/Downloads:/in -- safeclaw-totext /in/report.pdf /sandbox/out/report
  safeclaw-totext --json --max-pages 20 --ocr-lang eng+deu /sandbox/in/1-scan.pdf /sandbox/out/scan
  safeclaw-totext --ocr-threshold 0 --timeout 30s statement.pdf out`,
		Args:          cobra.ExactArgs(2),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
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
	return cmd
}

func writeTotextJSON(w io.Writer, r *totext.Report) error {
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
