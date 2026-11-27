package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/josegonzalez/safeclaw/internal/envtui"
	"github.com/josegonzalez/safeclaw/internal/secrets"
)

func newEnvCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "env",
		Short: "Manage environment variables injected into sessions",
		Long:  "Manage the secrets injected into sessions as environment variables. Without a subcommand, it opens an interactive menu.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return envtui.Run(openSecrets(cmd), cmd.OutOrStdout())
		},
	}
	cmd.AddCommand(newEnvSetCommand(), newEnvListCommand(), newEnvRemoveCommand())
	return cmd
}

func newEnvSetCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "set NAME",
		Short: "Store a secret read from stdin",
		Long:  "Store a secret. On a terminal it asks for the value with hidden input; otherwise it reads it from stdin, with trailing newlines removed.",
		Example: `  safeclaw env set OPENAI_API_KEY
  gh auth token | safeclaw env set GH_TOKEN`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			if err := secrets.ValidateName(name); err != nil {
				return fmt.Errorf("invalid name %q: %w", name, err)
			}
			v, err := readValue(cmd, "Value:")
			if err != nil {
				return err
			}
			store := openSecrets(cmd)
			if err := store.Set(name, v); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Saved %s to %s\n", name, store.Location())
			return nil
		},
	}
}

func newEnvListCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List secret names (never values)",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			keys, err := openSecrets(cmd).Keys()
			if err != nil {
				return err
			}
			for _, k := range keys {
				fmt.Fprintln(cmd.OutOrStdout(), k)
			}
			return nil
		},
	}
}

func newEnvRemoveCommand() *cobra.Command {
	return &cobra.Command{
		Use:               "rm NAME",
		Aliases:           []string{"delete"},
		Short:             "Delete a secret",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeSecrets,
		RunE: func(cmd *cobra.Command, args []string) error {
			err := openSecrets(cmd).Delete(args[0])
			if errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("secret %s is not set", args[0])
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Deleted %s\n", args[0])
			return nil
		},
	}
}
