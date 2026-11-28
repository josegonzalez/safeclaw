package cli

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/josegonzalez/safeclaw/internal/scan"
	"github.com/josegonzalez/safeclaw/internal/session"
)

// Exit codes of `sandbox scan`, like clamscan's own.
const (
	scanInfectedExitCode = 1
	scanErrorExitCode    = 2
)

// scanSchema is the version of `sandbox scan --json`'s output.
const scanSchema = 1

// scanJSON is `sandbox scan --json`'s output.
type scanJSON struct {
	Schema int `json:"schema"`
	// Advisory is always true: the scan ran inside the sandbox.
	Advisory   bool             `json:"advisory"`
	Signatures *scan.Signatures `json:"signatures"`
	Results    []scan.Result    `json:"results"`
}

func newSandboxScanCommand() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "scan NAME PATH...",
		Short: "Scan files in a running sandbox for malware (advisory)",
		Long: "Scan files in a running sandbox with ClamAV's clamscan and the signatures from `safeclaw sandbox update-signatures`, " +
			"which every sandbox mounts read-only. Each file's result is printed: clean, infected with the signature name, " +
			"or error with the reason, such as a missing file, one over the scanner's size limits, or an encrypted archive. " +
			"A directory gets a result for each file directly in it. Relative paths are under /sandbox.\n\n" +
			"The scan is advisory: it runs inside the sandbox, as the sandbox user, where anything the untrusted files left running " +
			"can change its result. cp-out scans the files it copies again outside the sandbox, which is the scan to rely on.\n\n" +
			"It exits 1 when any file is infected, otherwise 2 when any could not be scanned, and 0 when all are clean. " +
			"With --json, the schema field is the version of the output: fields may be added within a version, but are never renamed, " +
			"removed, or given a new meaning without a new version.",
		Example: `  safeclaw sandbox scan triage /sandbox/in/1-report.zip
  safeclaw sandbox scan triage out --json`,
		Args:              cobra.MinimumNArgs(2),
		ValidArgsFunction: completeSandboxFirst,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := resolveArg(cmd, args); err != nil {
				return err
			}
			report, err := newManager().ScanSandbox(cmd.Context(), args[0], args[1:])
			if err != nil {
				return err
			}
			if asJSON {
				err = writeJSON(cmd.OutOrStdout(), scanJSON{Schema: scanSchema, Advisory: true, Signatures: report.Signatures, Results: report.Results})
			} else {
				fmt.Fprintf(cmd.ErrOrStderr(), "Scanned inside the sandbox (advisory) with ClamAV signatures %s\n", report.Signatures)
				err = writeScanResults(cmd.OutOrStdout(), report.Results, "")
			}
			if err != nil {
				return err
			}
			if code := scanExitCode(report.Results); code != 0 {
				return exitCodeError{code}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the signatures and results as JSON")
	return cmd
}

// scanExitCode returns scanInfectedExitCode when any result is infected,
// otherwise scanErrorExitCode when any is an error, and 0 when all are
// clean.
func scanExitCode(results []scan.Result) int {
	code := 0
	for _, r := range results {
		switch r.Status {
		case scan.Infected:
			return scanInfectedExitCode
		case scan.Error:
			code = scanErrorExitCode
		}
	}
	return code
}

// writeScanResults writes a line for each result, its result and then its
// path, quoted when it is not printable, with note after each flagged one.
func writeScanResults(out io.Writer, results []scan.Result, note string) error {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	for _, r := range results {
		line := fmt.Sprintf("%s\t%s", session.QuotePath(r.String()), session.QuotePath(r.Path))
		if r.Flagged() && note != "" {
			line += "\t" + note
		}
		if _, err := fmt.Fprintln(w, line); err != nil {
			return err
		}
	}
	return w.Flush()
}

func newSandboxUpdateSignaturesCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "update-signatures",
		Short: "Download the latest malware signatures for scanning sandbox files",
		Long: "Download the latest ClamAV signatures with freshclam into the safeclaw cache directory " +
			"($XDG_CACHE_HOME/safeclaw/clamav, by default ~/.cache/safeclaw/clamav), which every sandbox mounts read-only " +
			"and cp-out scans with.\n\n" +
			"freshclam runs in a short-lived container of the sandbox variant with network access but no secrets, no web terminal, " +
			"and no mount but a staging directory in the cache directory. The first run downloads about 110 MB; later runs only what changed. " +
			"The new signatures replace the old ones only once freshclam succeeds and they are complete, so a failed update keeps the old ones. " +
			"The installed signatures' date and version are printed.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			m := newManager()
			m.Out = cmd.ErrOrStderr()
			sigs, err := m.UpdateSignatures(cmd.Context())
			if err != nil {
				return err
			}
			return writeSignatures(cmd.OutOrStdout(), sigs)
		},
	}
}

// writeSignatures writes the signatures' date and version, then each
// database.
func writeSignatures(out io.Writer, sigs *scan.Signatures) error {
	if _, err := fmt.Fprintf(out, "Signatures: %s\n", sigs); err != nil {
		return err
	}
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	for _, db := range sigs.Databases {
		fmt.Fprintf(w, "  %s\tversion %d\t%d signatures\tbuilt %s\n", db.File, db.Version, db.Signatures, db.Built.UTC().Format("2006-01-02 15:04 MST"))
	}
	return w.Flush()
}
