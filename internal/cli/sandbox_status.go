package cli

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/session"
)

// The exit codes of `safeclaw sandbox status` other than 0 for running and
// 1 for any other error.
const (
	statusStoppedExitCode    = 3
	statusMissingExitCode    = 4
	statusNotSandboxExitCode = 5
)

func newSandboxStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status NAME",
		Short: "Print whether a sandbox is running, stopped, or missing",
		Long: "Print running, stopped, or missing for a sandbox, exiting 0 when it is running, 3 when it is stopped, and 4 when there is no container by that name. " +
			"When the name is an interactive session, nothing is printed and it exits 5 with an error, so a script can refuse it instead of treating it as missing. " +
			"Any other error, such as docker failing, exits 1. Nothing in the sandbox is changed or run.",
		Example: `  safeclaw sandbox status triage
  if safeclaw sandbox status triage >/dev/null; then echo up; fi`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeType(config.TypeSandbox),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := resolveArg(cmd, args); err != nil {
				return err
			}
			state, code, err := sandboxStatus(newManager().InspectSandbox(cmd.Context(), args[0]))
			if err != nil {
				if code == 1 {
					return err
				}
				printError(cmd.ErrOrStderr(), err)
				return exitCodeError{code}
			}
			fmt.Fprintln(cmd.OutOrStdout(), state)
			if code != 0 {
				return exitCodeError{code}
			}
			return nil
		},
	}
}

// sandboxStatus maps InspectSandbox's result to the state `sandbox status`
// prints and the code it exits with. err is set, and state empty, when the
// name is not a sandbox (code statusNotSandboxExitCode) or the lookup
// failed (code 1).
func sandboxStatus(info *session.SandboxInfo, err error) (state string, code int, _ error) {
	switch {
	case err == nil && info.Running:
		return "running", 0, nil
	case err == nil:
		return "stopped", statusStoppedExitCode, nil
	case errors.Is(err, session.ErrNotFound):
		return "missing", statusMissingExitCode, nil
	case errors.Is(err, session.ErrNotSandbox):
		return "", statusNotSandboxExitCode, err
	default:
		return "", 1, err
	}
}
