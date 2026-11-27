// Package cli defines the safeclaw command line.
package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/session"
	"github.com/josegonzalez/safeclaw/internal/version"
)

// Execute runs the CLI and returns the process exit code.
func Execute() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := NewRootCommand().ExecuteContext(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		return 1
	}
	return 0
}

// NewRootCommand builds the command tree.
func NewRootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "safeclaw",
		Short:         "Run Claude Code sessions in isolated Docker containers",
		Long:          "SafeClaw runs each Claude Code session in its own container, with a web terminal per session and a dashboard to manage them all.",
		Version:       version.String(),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetVersionTemplate("safeclaw {{.Version}}\n")
	root.AddCommand(
		newBuildCommand(),
		newPullCommand(),
		newRunCommand(),
		newNewCommand(),
		newDashboardCommand(),
		newEnvCommand(),
		newListCommand(),
		newStopCommand(),
		newRemoveCommand(),
		newAttachCommand(),
		newSandboxCommand(),
		newVariantCommand(),
		newTTYDWrapperCommand(),
		newVersionCommand(),
	)
	return root
}

func newVersionCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, _ []string) {
			fmt.Fprintf(cmd.OutOrStdout(), "safeclaw %s\n", version.String())
		},
	}
}

// completeSessions completes interactive session names for commands taking
// one.
var completeSessions = completeType(config.TypeSession)

// completeType returns a completion function for session names of one type.
func completeType(want string) cobra.CompletionFunc {
	return func(cmd *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
		if len(args) > 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		list, err := session.NewManager(nil).List(cmd.Context())
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}
		names := make([]string, 0, len(list))
		for _, s := range list {
			if s.Type == want {
				names = append(names, s.Name)
			}
		}
		return names, cobra.ShellCompDirectiveNoFileComp
	}
}

// completeVariants completes variant names, base included, for --variant.
func completeVariants(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	set, err := loadVariants()
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}
	return append([]string{config.BaseVariant}, set.Names()...), cobra.ShellCompDirectiveNoFileComp
}
