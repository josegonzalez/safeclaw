package cli

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/josegonzalez/safeclaw/internal/session"
)

func newNetCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "net",
		Short: "Take a session offline and bring it back",
		Long: "Disconnect a session from its networks while it handles something untrusted, and reconnect it to exactly those networks afterwards. " +
			"Each `net off` records a hold for its --owner, and the session is reconnected once every hold is released.",
		Args: cobra.NoArgs,
	}
	cmd.AddCommand(newNetOffCommand(), newNetOnCommand())
	return cmd
}

func newNetOffCommand() *cobra.Command {
	var opts session.NetOffOptions
	cmd := &cobra.Command{
		Use:   "off NAME",
		Short: "Disconnect a session from every network",
		Long: "Save the session's networks and disconnect it from them, recording a hold for --owner (or the unnamed hold). " +
			"Its web terminal is unreachable while it is offline, and it stays offline across restarts. Taking an offline session offline again adds another hold.",
		Example: `  safeclaw net off work
  safeclaw net off work --owner triage --reason "opening an emailed pdf"`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeSessions,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := session.NewManager(cmd.OutOrStdout()).NetOff(cmd.Context(), args[0], opts)
			return err
		},
	}
	cmd.Flags().StringVar(&opts.Owner, "owner", "", "name the hold, so only the same owner (or --force) releases it")
	cmd.Flags().StringVar(&opts.Reason, "reason", "", "why the session is offline, shown with the hold")
	return cmd
}

func newNetOnCommand() *cobra.Command {
	var opts session.NetOnOptions
	cmd := &cobra.Command{
		Use:   "on NAME",
		Short: "Release a hold and reconnect a session once none remain",
		Long: "Release the hold for --owner (or the unnamed hold). Once no holds remain, reconnect the session to the networks it had when it was taken offline, " +
			"or to its network mode if none were saved. Fails if other owners hold it and --owner names none of them.",
		Example: `  safeclaw net on work
  safeclaw net on work --owner triage
  safeclaw net on work --force`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeSessions,
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := session.NewManager(cmd.OutOrStdout()).NetOn(cmd.Context(), args[0], opts)
			return err
		},
	}
	cmd.Flags().StringVar(&opts.Owner, "owner", "", "release this owner's hold")
	cmd.Flags().BoolVar(&opts.Force, "force", false, "release every hold and reconnect")
	return cmd
}

// networkColumn returns a session's network status for `safeclaw ls`, with
// the owners holding it offline.
func networkColumn(s session.Session) string {
	if s.Network == "" {
		return "-"
	}
	if len(s.Holds) == 0 {
		return s.Network
	}
	return s.Network + " (" + strings.Join(session.HoldLabels(s.Holds), ", ") + ")"
}
