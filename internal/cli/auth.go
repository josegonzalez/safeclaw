package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/prompt"
	"github.com/josegonzalez/safeclaw/internal/secrets"
	"github.com/josegonzalez/safeclaw/internal/session"
)

// openSecrets opens the secrets store, warning on stderr when it falls back
// to files.
func openSecrets(cmd *cobra.Command) secrets.Store {
	return secrets.Open(config.SecretsDir(), config.SecretsLockPath(), cmd.ErrOrStderr())
}

// stdinIsTerminal reports whether the command's stdin is a terminal.
func stdinIsTerminal(cmd *cobra.Command) bool {
	f, ok := cmd.InOrStdin().(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// readValue asks for a value with hidden input on a terminal, and otherwise
// reads all of stdin with trailing newlines removed, so a value never has
// to appear in process arguments.
func readValue(cmd *cobra.Command, title string) (string, error) {
	var v string
	if stdinIsTerminal(cmd) {
		var err error
		if v, err = prompt.Secret(title, true); err != nil {
			return "", err
		}
	} else {
		b, err := io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return "", err
		}
		v = strings.TrimRight(string(b), "\r\n")
	}
	if strings.TrimSpace(v) == "" {
		return "", errors.New("no value given on stdin")
	}
	return v, nil
}

func newAuthCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Set up the Claude Code token sessions log in with",
		Long: "Manage CLAUDE_CODE_OAUTH_TOKEN, the long-lived token from `claude setup-token` that sessions use to log in to Claude Code. " +
			"Tokens are valid for one year from when they are created.",
	}
	cmd.AddCommand(newAuthLoginCommand(), newAuthSetCommand(), newAuthStatusCommand(), newAuthLogoutCommand())
	return cmd
}

func newAuthLoginCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "login",
		Short: "Sign in with `claude setup-token` in a container and store the token",
		Long: "Run `claude setup-token` in a short-lived container from the safeclaw image, so Claude Code doesn't need to be installed on the host. " +
			"Open the URL it prints, sign in, and paste the code back. The token it creates replaces any stored one.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !stdinIsTerminal(cmd) {
				return errors.New("auth login needs a terminal; pipe an existing token to `safeclaw auth set` instead")
			}
			m := session.NewManager(cmd.OutOrStdout())
			tok, err := m.SetupToken(cmd.Context())
			if err != nil {
				return err
			}
			return storeClaudeToken(cmd, m.Secrets, tok)
		},
	}
}

func newAuthSetCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "set",
		Short: "Store a Claude Code token read from stdin",
		Long:  "Store a token from `claude setup-token`. On a terminal it asks for the token with hidden input; otherwise it reads it from stdin.",
		Example: `  safeclaw auth set
  printf '%s' "$TOKEN" | safeclaw auth set`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			tok, err := readValue(cmd, "Token:")
			if err != nil {
				return err
			}
			tok = strings.TrimSpace(tok)
			if strings.ContainsAny(tok, " \t\r\n") {
				return errors.New("the token can't contain spaces or line breaks")
			}
			return storeClaudeToken(cmd, openSecrets(cmd), tok)
		},
	}
}

func storeClaudeToken(cmd *cobra.Command, store secrets.Store, tok string) error {
	if err := store.Set(secrets.ClaudeToken, tok); err != nil {
		return err
	}
	out := cmd.OutOrStdout()
	fmt.Fprintf(out, "Saved %s to %s\n", secrets.ClaudeToken, store.Location())
	fmt.Fprintln(out, "Running sessions pick it up the next time they are started with `safeclaw run`.")
	return nil
}

func newAuthStatusCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show whether a Claude Code token is stored and when it expires",
		Long:  "Show whether a Claude Code token is stored, when it was set, and when it expires. Exits non-zero when no token is stored or it has expired.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			m := session.NewManager(nil)
			st, err := m.ClaudeTokenStatus(time.Now())
			if err != nil {
				return err
			}
			return writeTokenStatus(cmd.OutOrStdout(), st, m.Secrets.Location())
		},
	}
}

// errTokenUnusable is returned by `auth status` so it exits non-zero.
var errTokenUnusable = errors.New("no usable Claude Code token")

func writeTokenStatus(out io.Writer, st session.TokenStatus, location string) error {
	if st.State == session.TokenMissing {
		fmt.Fprintf(out, "No Claude Code token stored. Run `safeclaw auth login`, or pipe one to `safeclaw auth set`.\n")
		return errTokenUnusable
	}
	fmt.Fprintf(out, "Claude Code token stored in %s\n", location)
	fmt.Fprintf(out, "  Set:     %s\n", st.SetAt.Local().Format(time.DateOnly))
	fmt.Fprintf(out, "  Expires: %s (estimated, one year after it was set)\n", st.ExpiresAt.Local().Format(time.DateOnly))
	switch st.State {
	case session.TokenExpired:
		fmt.Fprintf(out, "Expired %d days ago. Run `safeclaw auth login` to replace it.\n", -st.DaysLeft)
		return errTokenUnusable
	case session.TokenExpiring:
		fmt.Fprintf(out, "Warning: expires in %d days. Run `safeclaw auth login` to replace it.\n", st.DaysLeft)
	default:
		fmt.Fprintf(out, "Valid for %d more days.\n", st.DaysLeft)
	}
	return nil
}

func newAuthLogoutCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "logout",
		Short: "Delete the stored Claude Code token",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out := cmd.OutOrStdout()
			err := openSecrets(cmd).Delete(secrets.ClaudeToken)
			if errors.Is(err, os.ErrNotExist) {
				fmt.Fprintln(out, "No Claude Code token stored.")
				return nil
			}
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "Deleted %s.\n", secrets.ClaudeToken)
			fmt.Fprintln(out, "Running sessions keep it until they are started again with `safeclaw run`.")
			return nil
		},
	}
}
