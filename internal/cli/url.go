package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newURLCommand() *cobra.Command {
	var open bool
	cmd := &cobra.Command{
		Use:   "url NAME",
		Short: "Print a session's web terminal URL, with its credential",
		Long: "Print the URL of a running session's web terminal, with the session's credential in it, like `safeclaw run` does, without restarting anything. " +
			"With --open, also open the terminal in the browser: the dashboard's terminal page when `safeclaw dashboard` is running, which keeps the credential out of the process list and browser history, and otherwise the printed URL.",
		Example: `  safeclaw url work
  safeclaw url work --open`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeSessions,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			m := newManager()
			m.Out = cmd.ErrOrStderr()
			t, err := m.Terminal(ctx, args[0])
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), t.URL())
			if open {
				return m.OpenTerminal(ctx, args[0], t.URL())
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&open, "open", false, "also open the terminal in the browser, through the dashboard when one is running")
	return cmd
}
