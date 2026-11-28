package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"slices"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/session"
)

func newSandboxInspectCommand() *cobra.Command {
	var field string
	cmd := &cobra.Command{
		Use:   "inspect NAME",
		Short: "Print a sandbox's isolation settings as JSON",
		Long: "Print a sandbox's name, status, variant, network, user, capabilities, read-only root, limits, tmpfs mounts, " +
			"bind mounts, and safeclaw labels as JSON, as docker reports them. Nothing in the sandbox is changed or run.\n\n" +
			"The schema field is the version of the output: fields may be added within a version, but are never renamed, " +
			"removed, or given a new meaning without a new version. See docs/architecture.md for the fields.\n\n" +
			"With --field, only that top-level field is printed: a string as plain text, anything else as JSON.",
		Example: `  safeclaw sandbox inspect triage
  safeclaw sandbox inspect triage --field running
  safeclaw sandbox inspect triage --field limits`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeType(config.TypeSandbox),
		RunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Flags().Changed("field") && !slices.Contains(inspectFields(), field) {
				return fmt.Errorf("unknown field %q: want one of %s", field, strings.Join(inspectFields(), ", "))
			}
			if err := resolveArg(cmd, args); err != nil {
				return err
			}
			info, err := newManager().InspectSandbox(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if cmd.Flags().Changed("field") {
				return writeField(cmd.OutOrStdout(), info, field)
			}
			return writeJSON(cmd.OutOrStdout(), info)
		},
	}
	cmd.Flags().StringVar(&field, "field", "", "print only this top-level field of the JSON")
	_ = cmd.RegisterFlagCompletionFunc("field", func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
		return inspectFields(), cobra.ShellCompDirectiveNoFileComp
	})
	return cmd
}

// inspectFields returns the top-level fields of `sandbox inspect`'s JSON,
// sorted.
func inspectFields() []string {
	fields, err := jsonFields(session.SandboxInfo{})
	if err != nil {
		panic(err)
	}
	return slices.Sorted(maps.Keys(fields))
}

func jsonFields(v any) (map[string]json.RawMessage, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(b, &fields); err != nil {
		return nil, err
	}
	return fields, nil
}

// writeField writes one top-level field of v's JSON on a line of its own:
// a string unquoted, anything else as compact JSON.
func writeField(out io.Writer, v any, name string) error {
	fields, err := jsonFields(v)
	if err != nil {
		return err
	}
	raw, ok := fields[name]
	if !ok {
		return fmt.Errorf("unknown field %q", name)
	}
	var s string
	if json.Unmarshal(raw, &s) == nil {
		_, err = fmt.Fprintln(out, s)
		return err
	}
	var b bytes.Buffer
	if err := json.Compact(&b, raw); err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, b.String())
	return err
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
			"The checks of the docker configuration are authoritative. The live checks are advisory: they are reported by a probe " +
			"running as the sandbox user, which code already in the sandbox can write to or trace, so a sandbox can lie to them. " +
			"Probe output that is repeated, out of order, or past 1 MiB fails every live check, but output faked to look right can't be told apart.\n\n" +
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
	return r.Err()
}

// verifyReport writes the report of a sandbox that failed --verify to
// stderr, and returns err.
func verifyReport(stderr io.Writer, err error) error {
	var ve *session.SandboxVerifyError
	if errors.As(err, &ve) && ve.Report != nil {
		if werr := writeChecks(stderr, ve.Report.Checks); werr != nil {
			return errors.Join(err, werr)
		}
	}
	return err
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
