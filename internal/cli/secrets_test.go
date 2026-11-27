package cli

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/josegonzalez/safeclaw/internal/session"
)

// parseRunFlags parses args with the run flags and returns the options.
func parseRunFlags(t *testing.T, args ...string) (session.Options, error) {
	t.Helper()
	var f runFlags
	var opts session.Options
	cmd := &cobra.Command{
		Use:  "run",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			var err error
			opts, err = f.options(cmd, false)
			return err
		},
	}
	f.register(cmd)
	cmd.SetArgs(args)
	cmd.SilenceUsage, cmd.SilenceErrors = true, true
	return opts, cmd.Execute()
}

func TestRunSecretFlags(t *testing.T) {
	cases := []struct {
		args []string
		want string // "" for no set
	}{
		{nil, ""},
		{[]string{"--secrets", "GH_TOKEN,CLAUDE_CODE_OAUTH_TOKEN"}, "CLAUDE_CODE_OAUTH_TOKEN,GH_TOKEN"},
		{[]string{"--secrets", "A", "--secrets", "B,A"}, "A,B"},
		{[]string{"--no-secrets"}, "none"},
		{[]string{"--all-secrets"}, "all"},
	}
	for _, tc := range cases {
		opts, err := parseRunFlags(t, tc.args...)
		if err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		got := ""
		if opts.Secrets != nil {
			got = opts.Secrets.String()
		}
		if got != tc.want {
			t.Errorf("%v: secrets = %q, want %q", tc.args, got, tc.want)
		}
	}

	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"--secrets", "A", "--no-secrets"}, "none of the others can be"},
		{[]string{"--no-secrets", "--all-secrets"}, "none of the others can be"},
		{[]string{"--secrets="}, "use --no-secrets"},
		{[]string{"--secrets", "bad-name"}, `invalid secret name "bad-name"`},
	} {
		if _, err := parseRunFlags(t, tc.args...); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: err = %v, want %q", tc.args, err, tc.want)
		}
	}
}
