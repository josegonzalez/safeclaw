// Package cli defines the safeclaw command line.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/session"
	"github.com/josegonzalez/safeclaw/internal/termtext"
	"github.com/josegonzalez/safeclaw/internal/version"
)

// Execute runs the CLI and returns the process exit code.
func Execute() int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if isUnpackProgram(os.Args[0]) {
		return executeUnpack(ctx, os.Args[1:])
	}
	if isTotextProgram(os.Args[0]) {
		return executeTotext(ctx, os.Args[1:])
	}
	if isMailProgram(os.Args[0]) {
		return executeMail(ctx, os.Args[1:])
	}
	if isExpandProgram(os.Args[0]) {
		return executeExpand(ctx, os.Args[1:])
	}
	// Every command may read or write the config directory, which holds
	// session history and credentials, so it is checked before any runs.
	if err := config.SecureDir(os.Stderr); err != nil {
		printError(os.Stderr, err)
		return 1
	}
	if err := NewRootCommand().ExecuteContext(context.WithValue(ctx, ownProcessKey{}, true)); err != nil {
		var exit exitCodeError
		if errors.As(err, &exit) {
			return exit.code
		}
		printError(os.Stderr, err)
		return 1
	}
	return 0
}

// ownProcessKey marks the context Execute runs the command tree with.
type ownProcessKey struct{}

// ownsProcess reports whether cmd was run by Execute, as the safeclaw
// program, rather than in-process by other code through NewRootCommand.
// Only then may a command replace the process with another program, since
// nothing else in it is left to run and the command's output streams are
// the process's own.
func ownsProcess(cmd *cobra.Command) bool {
	ctx := cmd.Context()
	return ctx != nil && ctx.Value(ownProcessKey{}) == true
}

// printError prints a command's error with control characters escaped.
// Errors can carry text from inside a container, such as docker's stderr
// or a sandbox file name, which must not reach the terminal as escapes.
func printError(w io.Writer, err error) {
	_, _ = fmt.Fprintln(w, "Error:", termtext.Escape(err.Error()))
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
		newAuthCommand(),
		newEnvCommand(),
		newListCommand(),
		newURLCommand(),
		newStopCommand(),
		newRemoveCommand(),
		newAttachCommand(),
		newNetCommand(),
		newSandboxCommand(),
		newVariantCommand(),
		newTTYDWrapperCommand(),
		newUnpackCommand("unpack"),
		newTotextCommand("totext"),
		newMailCommand("mail"),
		newExpandCommand("expand"),
		newVersionCommand(),
	)
	return root
}

func newVersionCommand() *cobra.Command {
	var (
		asJSON  bool
		require string
	)
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Long: "Print this build's version, commit, and build time.\n\n" +
			"With --json they are printed as JSON, as {\"schema\", \"version\", \"commit\", \"built\"}. The schema field is the version of the output: " +
			"fields may be added within a version, but are never renamed, removed, or given a new meaning without a new version.\n\n" +
			"With --require VERSION it also exits non-zero, naming the installed and required versions, when the installed version is older " +
			"than VERSION, given as MAJOR.MINOR.PATCH with or without a leading v. A development build, which has no release version, " +
			"fails any --require, since its version is unknown.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var required version.Release
			if cmd.Flags().Changed("require") {
				r, err := version.ParseRelease(require)
				if err != nil {
					return fmt.Errorf("--require: %w", err)
				}
				required = r
			}
			if asJSON {
				if err := writeJSON(cmd.OutOrStdout(), version.Get()); err != nil {
					return err
				}
			} else if _, err := fmt.Fprintf(cmd.OutOrStdout(), "safeclaw %s\n", version.String()); err != nil {
				return err
			}
			if cmd.Flags().Changed("require") {
				return version.Require(version.Version, required)
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&asJSON, "json", false, "print the version information as JSON")
	cmd.Flags().StringVar(&require, "require", "", "exit non-zero unless this build is at least `VERSION`")
	return cmd
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

// completeSecrets completes the stored secret names for --secrets.
func completeSecrets(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	names, err := session.NewManager(nil).SecretNames()
	if err != nil {
		return nil, cobra.ShellCompDirectiveError
	}
	return names, cobra.ShellCompDirectiveNoFileComp
}
