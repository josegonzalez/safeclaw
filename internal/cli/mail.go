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

	"github.com/josegonzalez/safeclaw/internal/mail"
	"github.com/josegonzalez/safeclaw/internal/session"
	"github.com/josegonzalez/safeclaw/internal/termtext"
)

// mailProgram is the name the sandbox image variant links to the safeclaw
// binary; run under it, safeclaw is `safeclaw mail`.
const mailProgram = "safeclaw-mail"

const mailHelp = `Exit codes:
  0  success
  1  failed: a usage or I/O error, or DEST is not a missing or empty directory
  2  rejected: the message is over a limit on its structure: over 1000 parts, parts nested over 32 levels deep, or a header over 256 KiB, over 1000 fields, or with a line over 64 KiB
  4  too large: the extracted contents are over --max-size
  5  not a message: the file doesn't start with a message header
Code 3 is not used, as it means needs password in safeclaw-unpack.

Each part is printed as a tab-separated line: PART, TYPE, SIZE, NAME, and FLAGS, and for extract FILE. PART is the part's position: 1 for the message's content, X.N for the Nth part of multipart X, and X.1 for the content of nested message X. TYPE is its media type. SIZE is its decoded size in bytes, - for a multipart. NAME is its original file name, decoded and escaped as in a Go string, with backslashes doubled and tabs, newlines, and other unprintable characters written as \t, \n, \xNN, or \uNNNN, - for none. FLAGS is a comma-separated list, - for none: BODY (its text is in body.txt), SKIPPED (an alternative left out of body.txt), ATTACHMENT (written to its own file), NESTED-MESSAGE (a message/rfc822 part that was followed), DEPTH-LIMIT (a nested message past --depth, written as an attachment), UNSAFE-NAME (its name was changed to make it safe), BAD-ENCODING (its transfer encoding or charset couldn't be decoded in full), and MALFORMED (an unreadable Content-Type or part header, or a multipart without a boundary or cut short). FILE is where it was written in DEST, - for nowhere. --json prints one JSON object instead, with the names unescaped.`

// newMailCommand builds `safeclaw mail`, named use: "mail" under safeclaw,
// or safeclaw-mail when run through that link.
func newMailCommand(use string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   use,
		Short: "List or extract an untrusted email message: its text and its attachments under safe names",
		Long: "List or extract an untrusted email message (an .eml file): its headers, the text of its body parts and forwarded messages, and its attachments under safe, numbered names. Everything it prints is stripped of control characters. Run it inside a sandbox: the sandbox image variant links this command as " + mailProgram + ".\n\n" +
			mailHelp,
		Example: `  safeclaw sandbox exec --ephemeral -v ~/Downloads:/in -- safeclaw-mail list /in/invoice.eml
  safeclaw-mail extract --json /sandbox/in/1-invoice.eml /sandbox/out/invoice`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(newMailListCommand(), newMailExtractCommand())
	return cmd
}

func newMailListCommand() *cobra.Command {
	var asJSON bool
	var o mail.Options
	cmd := &cobra.Command{
		Use:   "list FILE",
		Short: "List a message's main headers and its parts with their type, size, name, and flags",
		Long: "List a message's main headers (From, Reply-To, To, Cc, Date, Subject, and Message-ID), decoded and stripped of control characters, as Name: Value lines, then an empty line, then one line per part. Nested messages are followed up to --depth. Nothing is written.\n\n" +
			mailHelp,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if o.Depth < 0 {
				return mailFailure(cmd, asJSON, &mail.Error{Kind: mail.Failed, Msg: "--depth can't be negative"})
			}
			res, err := mail.List(cmd.Context(), args[0], o)
			if err != nil {
				return mailFailure(cmd, asJSON, err)
			}
			out := cmd.OutOrStdout()
			if asJSON {
				return writeMailJSON(out, mailResultJSON(res))
			}
			var b strings.Builder
			writeMailHeaders(&b, res.Headers)
			b.WriteString("\n")
			writeMailParts(&b, res.Parts, false)
			_, err = io.WriteString(out, b.String())
			return err
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print one JSON object instead of lines")
	cmd.Flags().IntVar(&o.Depth, "depth", mail.DefaultDepth, "levels of nested messages to follow, 0 for none")
	return cmd
}

func newMailExtractCommand() *cobra.Command {
	var asJSON bool
	var maxSize string
	var o mail.Options
	cmd := &cobra.Command{
		Use:   "extract FILE DEST",
		Short: "Extract a message's text to DEST/body.txt and its attachments under safe, numbered names",
		Long: "Extract a message into DEST, which must be missing or an empty directory, and not a symbolic link.\n\n" +
			"body.txt gets the main headers and the text of every body part: text/plain, and text/html turned into text without scripts or styles. In a multipart/alternative only one part is used: the first text/plain one, else the last one with text. Nested message/rfc822 parts, such as forwarded messages, are followed up to --depth, each adding a separator, its main headers, and its text; one past --depth is written as an attachment. " +
			"Every other part is written as N-NAME, N counting attachments from 1 and NAME the original name made safe: slashes and backslashes become _, control and other unprintable characters are dropped, runs of dots are shortened so no .. is left, leading dots, dashes, and spaces are trimmed, and it is cut to 100 bytes, keeping a short extension. A part with no name is N-attachment, or N-message.eml for a message. " +
			"Transfer encodings, charsets, and encoded words in headers and names are decoded before anything is made safe. The total size of what is written is limited by --max-size. On any failure DEST is emptied, without following links. Each part is printed when it succeeds.\n\n" + mailHelp,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			n, err := session.ParseSize(maxSize)
			if err != nil || n <= 0 {
				return mailFailure(cmd, asJSON, &mail.Error{Kind: mail.Failed, Msg: fmt.Sprintf("--max-size: invalid size %q: want a positive number of bytes with an optional k, m, g, or t suffix", maxSize)})
			}
			o.MaxSize = n
			if o.Depth < 0 {
				return mailFailure(cmd, asJSON, &mail.Error{Kind: mail.Failed, Msg: "--depth can't be negative"})
			}
			res, err := mail.Extract(cmd.Context(), args[0], args[1], o)
			if err != nil {
				return mailFailure(cmd, asJSON, err)
			}
			out := cmd.OutOrStdout()
			if asJSON {
				return writeMailJSON(out, mailResultJSON(res))
			}
			var b strings.Builder
			writeMailParts(&b, res.Parts, true)
			_, err = io.WriteString(out, b.String())
			return err
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print one JSON object instead of lines")
	cmd.Flags().StringVar(&maxSize, "max-size", "512m", "limit on the total size of what is written (k, m, g, or t suffix)")
	cmd.Flags().IntVar(&o.Depth, "depth", mail.DefaultDepth, "levels of nested messages to follow, 0 for none")
	return cmd
}

// mailJSON is the --json output.
type mailJSON struct {
	// Status is "ok" or the failure kind, such as "rejected".
	Status string `json:"status"`
	// Code is the exit code.
	Code int `json:"code"`
	// Error says what went wrong.
	Error string `json:"error,omitempty"`
	// Part is the part the failure happened in.
	Part    string           `json:"part,omitempty"`
	Headers []mailHeaderJSON `json:"headers,omitempty"`
	Parts   []mailPartJSON   `json:"parts,omitempty"`
	// Body is body.txt, for extract.
	Body string `json:"body,omitempty"`
}

type mailHeaderJSON struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type mailPartJSON struct {
	Part string `json:"part"`
	Type string `json:"type"`
	// Size is null for a multipart.
	Size    *int64           `json:"size"`
	Name    string           `json:"name,omitempty"`
	Flags   []string         `json:"flags"`
	File    string           `json:"file,omitempty"`
	Headers []mailHeaderJSON `json:"headers,omitempty"`
}

func mailHeadersJSON(headers []mail.Header) []mailHeaderJSON {
	out := make([]mailHeaderJSON, 0, len(headers))
	for _, h := range headers {
		out = append(out, mailHeaderJSON(h))
	}
	return out
}

func mailResultJSON(res *mail.Result) mailJSON {
	v := mailJSON{Status: "ok", Headers: mailHeadersJSON(res.Headers), Body: res.Body}
	for _, p := range res.Parts {
		j := mailPartJSON{Part: p.ID, Type: p.Type, Name: p.Name, Flags: p.Flags(), File: p.File}
		if j.Flags == nil {
			j.Flags = []string{}
		}
		if p.Size >= 0 {
			size := p.Size
			j.Size = &size
		}
		if len(p.Headers) > 0 {
			j.Headers = mailHeadersJSON(p.Headers)
		}
		v.Parts = append(v.Parts, j)
	}
	return v
}

func writeMailJSON(w io.Writer, v mailJSON) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	return enc.Encode(v)
}

// writeMailHeaders writes headers as Name: Value lines. The values are
// already stripped of control characters.
func writeMailHeaders(b *strings.Builder, headers []mail.Header) {
	for _, h := range headers {
		fmt.Fprintf(b, "%s: %s\n", h.Name, termtext.Escape(h.Value))
	}
}

// writeMailParts writes parts as PART, TYPE, SIZE, NAME, FLAGS lines, and
// FILE with withFile.
func writeMailParts(b *strings.Builder, parts []mail.Part, withFile bool) {
	_ = mail.WriteParts(b, parts, withFile)
}

// mailFailure prints err and returns the exit code for its kind.
func mailFailure(cmd *cobra.Command, asJSON bool, err error) error {
	kind := mail.KindOf(err)
	var me *mail.Error
	part := ""
	if errors.As(err, &me) {
		part = me.Part
	}
	if asJSON {
		if werr := writeMailJSON(cmd.OutOrStdout(), mailJSON{Status: kind.String(), Code: int(kind), Error: err.Error(), Part: part}); werr != nil {
			return werr
		}
	} else {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "%s: %s\n", cmd.Root().Name(), termtext.Escape(err.Error()))
	}
	return exitCodeError{int(kind)}
}

// isMailProgram reports whether safeclaw was run as safeclaw-mail, argv[0]
// being its name or path.
func isMailProgram(arg0 string) bool {
	return filepath.Base(arg0) == mailProgram
}

// executeMail runs safeclaw-mail: `safeclaw mail` as its own root command.
// It needs no config directory, so unlike Execute it doesn't check one.
func executeMail(ctx context.Context, args []string) int {
	cmd := newMailCommand(mailProgram)
	cmd.CompletionOptions.DisableDefaultCmd = true
	cmd.SetArgs(args)
	if err := cmd.ExecuteContext(ctx); err != nil {
		var exit exitCodeError
		if errors.As(err, &exit) {
			return exit.code
		}
		printError(os.Stderr, err)
		return int(mail.Failed)
	}
	return 0
}
