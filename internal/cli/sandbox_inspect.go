package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/session"
)

func newSandboxInspectCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect NAME",
		Short: "Print a sandbox's isolation settings as JSON",
		Long: "Print a sandbox's name, status, variant, network, user, capabilities, read-only root, limits, tmpfs mounts, " +
			"bind mounts, and safeclaw labels as JSON, as docker reports them. Nothing in the sandbox is changed or run.\n\n" +
			"The schema field is the version of the output: fields may be added within a version, but are never renamed, " +
			"removed, or given a new meaning without a new version. See docs/architecture.md for the fields.",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeType(config.TypeSandbox),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := resolveArg(cmd, args); err != nil {
				return err
			}
			info, err := session.NewManager(nil).InspectSandbox(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return writeJSON(cmd.OutOrStdout(), info)
		},
	}
}

func newSandboxVerifyCommand() *cobra.Command {
	var asJSON bool
	cmd := &cobra.Command{
		Use:   "verify NAME",
		Short: "Check that a sandbox keeps its isolation guarantees",
		Long: "Check a sandbox against the isolation every sandbox promises: no network, the sandbox user, all capabilities dropped, " +
			"no-new-privileges, a read-only root, read-only mounts, no secrets, its own namespaces, limits, and a bounded /sandbox and /tmp. " +
			"The docker configuration is checked first, then, when the sandbox is running, what the sandbox user sees inside it: " +
			"uid 2000, an unreadable /home/sclaw, only a loopback interface, no capabilities, and read-only mounts. " +
			"The live checks only read, and a stopped sandbox fails the running check.\n\n" +
			"Each check is printed with ok or FAIL. It exits non-zero, naming the failed checks, if any check fails. " +
			"With --json the report is printed as JSON instead.",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeType(config.TypeSandbox),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := resolveArg(cmd, args); err != nil {
				return err
			}
			report, err := session.NewManager(nil).VerifySandbox(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if asJSON {
				err = writeJSON(cmd.OutOrStdout(), report)
			} else {
				err = writeChecks(cmd.OutOrStdout(), report.Checks)
			}
			if err != nil {
				return err
			}
			return verifyError(*report)
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the report as JSON")
	return cmd
}

// verifyError returns the error verify exits with, naming the failed
// checks, or nil when every check passed.
func verifyError(r session.SandboxReport) error {
	if r.OK {
		return nil
	}
	failed, skipped := r.Failed(), r.Skipped()
	msg := fmt.Sprintf("sandbox %q failed %d %s: %s", r.Name, len(failed), plural(len(failed), "check"), strings.Join(failed, ", "))
	if len(skipped) > 0 {
		msg += fmt.Sprintf(" (%d %s skipped)", len(skipped), plural(len(skipped), "check"))
	}
	return errors.New(msg)
}

func plural(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

func writeJSON(out io.Writer, v any) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// writeChecks writes the `safeclaw sandbox verify` table. Details can carry
// text from inside the sandbox, so they are quoted where it is not
// printable.
func writeChecks(out io.Writer, checks []session.SandboxCheck) error {
	w := tabwriter.NewWriter(out, 0, 0, 2, ' ', 0)
	for _, c := range checks {
		result := "FAIL"
		switch {
		case c.OK:
			result = "ok"
		case c.Skipped:
			result = "SKIP"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\n", result, c.Name, session.QuotePath(c.Detail))
	}
	return w.Flush()
}
