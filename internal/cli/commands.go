package cli

import (
	"errors"
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/dashboard"
	"github.com/josegonzalez/safeclaw/internal/prompt"
	"github.com/josegonzalez/safeclaw/internal/session"
	"github.com/josegonzalez/safeclaw/internal/version"
	"github.com/josegonzalez/safeclaw/internal/wrapper"
)

func newPullCommand() *cobra.Command {
	var tag string
	var variants []string
	cmd := &cobra.Command{
		Use:   "pull",
		Short: "Pull the published safeclaw image and its variants, and tag them locally",
		Long: "Pull the published safeclaw image and tag it locally. Then fetch each variant named with --variant, and every variant already present locally: " +
			"built-in variants are pulled, and variants from the config file are built on the pulled image.",
		Example: `  safeclaw pull
  safeclaw pull --variant sandbox`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			out := cmd.OutOrStdout()
			if tag == "" {
				tag = version.ImageTag()
			}
			set, err := loadVariants()
			if err != nil {
				return err
			}
			d := newDocker()
			refresh, err := variantsToRefresh(ctx, d, set, variants)
			if err != nil {
				return err
			}
			ref := config.RemoteImage + ":" + tag
			if err := d.R.Passthrough(ctx, "pull", ref); err != nil {
				return err
			}
			if err := d.Tag(ctx, ref, config.ImageName); err != nil {
				return err
			}
			fmt.Fprintf(out, "Tagged %s as %s\n", ref, config.ImageName)
			for _, v := range refresh {
				if err := pullVariant(ctx, d, out, v, tag); err != nil {
					return err
				}
			}
			return reportStale(ctx, d, out, false)
		},
	}
	cmd.Flags().StringVar(&tag, "tag", "", "image tag to pull (default: this binary's version, or latest)")
	cmd.Flags().StringSliceVar(&variants, "variant", nil, "also fetch this image variant (repeatable)")
	_ = cmd.RegisterFlagCompletionFunc("variant", completeVariants)
	return cmd
}

type runFlags struct {
	session, volume, variant, query string
	noOpen                          bool
	secrets                         []string
	noSecrets, allSecrets           bool
	hostIPC, freshHistory, noMemory bool
}

func (f *runFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&f.session, "session", "s", "", "session name (default \"default\")")
	cmd.Flags().StringVarP(&f.volume, "volume", "v", "", "mount a host directory, /host/path:/container/path (recreates an existing container)")
	cmd.Flags().StringVar(&f.variant, "variant", "", "image variant, or base for the base image (default from the config file, else base; a different one recreates an existing container)")
	_ = cmd.RegisterFlagCompletionFunc("variant", completeVariants)
	cmd.Flags().BoolVarP(&f.noOpen, "no-open", "n", false, "do not open the browser")
	cmd.Flags().StringVarP(&f.query, "query", "q", "", "send this query to Claude Code once it starts")
	cmd.Flags().StringSliceVar(&f.secrets, "secrets", nil, "give the session only these secrets, comma-separated (a different set recreates an existing container)")
	_ = cmd.RegisterFlagCompletionFunc("secrets", completeSecrets)
	cmd.Flags().BoolVar(&f.noSecrets, "no-secrets", false, "give the session no secrets")
	cmd.Flags().BoolVar(&f.allSecrets, "all-secrets", false, "give the session every secret, including ones added later (default for new sessions)")
	cmd.MarkFlagsMutuallyExclusive("secrets", "no-secrets", "all-secrets")
	cmd.Flags().BoolVar(&f.freshHistory, "fresh-history", false, "move the session's history aside to NAME.old-TIMESTAMP and start with an empty one (recreates an existing container)")
	cmd.Flags().BoolVar(&f.hostIPC, "host-ipc", false, "share the docker host's IPC namespace and /dev/shm with the session, or --host-ipc=false for a private one (new sessions get a private one; a different choice recreates an existing container)")
	cmd.Flags().BoolVar(&f.noMemory, "no-memory", false, "turn Claude Code's auto memory off for the session, or --no-memory=false to turn it back on (new sessions keep it on; a different choice recreates an existing container)")
}

// noMemoryChoice returns the auto memory choice the flags ask for, nil to
// keep the session's current one.
func (f *runFlags) noMemoryChoice(cmd *cobra.Command) *bool {
	if !cmd.Flags().Changed("no-memory") {
		return nil
	}
	return &f.noMemory
}

// hostIPCChoice returns the IPC choice the flags ask for, nil to keep the
// session's current one.
func (f *runFlags) hostIPCChoice(cmd *cobra.Command) *bool {
	if !cmd.Flags().Changed("host-ipc") {
		return nil
	}
	return &f.hostIPC
}

// secretSet returns the secret set the flags ask for, nil to keep the
// session's current one.
func (f *runFlags) secretSet(cmd *cobra.Command) (*session.SecretSet, error) {
	var set session.SecretSet
	switch {
	case f.noSecrets:
		set = session.NoSecrets()
	case f.allSecrets:
		set = session.AllSecrets()
	case cmd.Flags().Changed("secrets"):
		if len(f.secrets) == 0 {
			return nil, errors.New("--secrets needs at least one name; use --no-secrets for none")
		}
		var err error
		if set, err = session.OnlySecrets(f.secrets...); err != nil {
			return nil, err
		}
	default:
		return nil, nil
	}
	return &set, nil
}

func (f *runFlags) options(cmd *cobra.Command, interactive bool) (session.Options, error) {
	set, err := f.secretSet(cmd)
	if err != nil {
		return session.Options{}, err
	}
	name, err := resolveName(cmd, f.session)
	if err != nil {
		return session.Options{}, err
	}
	return session.Options{
		Name:         name,
		Volume:       f.volume,
		Variant:      f.variant,
		Secrets:      set,
		HostIPC:      f.hostIPCChoice(cmd),
		NoMemory:     f.noMemoryChoice(cmd),
		FreshHistory: f.freshHistory,
		Query:        f.query,
		NoOpen:       f.noOpen,
		Interactive:  interactive,
	}, nil
}

// resolveName returns the canonical session name for a name given on the
// command line, lowercased as the dashboard does. An empty name stays empty.
func resolveName(cmd *cobra.Command, name string) (string, error) {
	if name == "" {
		return "", nil
	}
	return newManager().ResolveName(cmd.Context(), name)
}

// resolveArg replaces args[0] with its canonical session name.
func resolveArg(cmd *cobra.Command, args []string) error {
	name, err := resolveName(cmd, args[0])
	if err != nil {
		return err
	}
	args[0] = name
	return nil
}

func newRunCommand() *cobra.Command {
	var f runFlags
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Start or reuse a session container and its web terminal",
		Long: "Start or reuse a session container, inject secrets, configure git, and start the ttyd web terminal. Prompts for tokens on first run when attached to a terminal. " +
			"New sessions get every secret unless --secrets or --no-secrets says otherwise, and the choice is remembered for the session.",
		Example: `  safeclaw run
  safeclaw run -s work
  safeclaw run -s myproject -v ~/myproject:/home/sclaw/myproject
  safeclaw run -s research -n -q "Research topic X"
  safeclaw run -s chat --secrets CLAUDE_CODE_OAUTH_TOKEN
  safeclaw run -s triage --no-memory`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			// Without a terminal there is no one to prompt, so behave like `new`.
			opts, err := f.options(cmd, stdinIsTerminal(cmd))
			if err != nil {
				return err
			}
			m := session.NewManager(cmd.OutOrStdout())
			m.Prompter = prompt.Terminal{
				Out:   cmd.OutOrStdout(),
				Login: func() (string, error) { return m.SetupToken(cmd.Context()) },
			}
			_, err = m.Ensure(cmd.Context(), opts)
			return err
		},
	}
	f.register(cmd)
	return cmd
}

func newNewCommand() *cobra.Command {
	var f runFlags
	cmd := &cobra.Command{
		Use:   "new",
		Short: "Like run, but never prompts (fails if the Claude token is missing)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts, err := f.options(cmd, false)
			if err != nil {
				return err
			}
			_, err = session.NewManager(cmd.OutOrStdout()).Ensure(cmd.Context(), opts)
			return err
		},
	}
	f.register(cmd)
	return cmd
}

func newDashboardCommand() *cobra.Command {
	var port int
	var dev bool
	cmd := &cobra.Command{
		Use:   "dashboard",
		Short: "Serve the web dashboard for managing sessions",
		Long:  "Serve the web dashboard for managing sessions.\n\nEvery request needs the random token made at start. Open the printed URL once to log the browser in, or send `Authorization: Bearer` with the token from the printed file (" + config.DashboardTokenFile(config.DashboardPort) + " for the default port).",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			srv, err := dashboard.New(dashboard.Options{
				Manager: session.NewManager(nil),
				Port:    port,
				Dev:     dev,
			})
			if err != nil {
				return err
			}
			return srv.ListenAndServe(cmd.Context(), cmd.OutOrStdout())
		},
	}
	cmd.Flags().IntVar(&port, "port", config.DashboardPort, "port to listen on (bound to 127.0.0.1)")
	cmd.Flags().BoolVar(&dev, "dev", false, "serve templates and static files from ./internal/dashboard for live editing; it must be owned by you and not group- or world-writable, and symlinks out of it are refused")
	return cmd
}

func newListCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List sessions",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			list, err := session.NewManager(nil).List(cmd.Context())
			if err != nil {
				return err
			}
			return writeSessions(cmd.OutOrStdout(), list)
		},
	}
}

// writeSessions writes the `safeclaw ls` table.
func writeSessions(out io.Writer, list []session.Session) error {
	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "SESSION\tTYPE\tVARIANT\tSTATUS\tNETWORK\tURL\tVOLUME")
	for _, s := range list {
		url := s.URL
		if url == "" {
			url = "-"
		}
		typ := s.Type
		if s.IsOneOff() {
			typ += " (one-off)"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", s.Name, typ, variantColumn(s), s.Status, networkColumn(s), url, s.Volume)
	}
	return w.Flush()
}

func newStopCommand() *cobra.Command {
	return &cobra.Command{
		Use:               "stop NAME",
		Short:             "Stop a session",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeSessions,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := resolveArg(cmd, args); err != nil {
				return err
			}
			m := session.NewManager(nil)
			if err := m.RequireType(cmd.Context(), args[0], config.TypeSession); err != nil {
				return err
			}
			return m.Stop(cmd.Context(), args[0])
		},
	}
}

func newRemoveCommand() *cobra.Command {
	var opts session.DeleteOptions
	cmd := &cobra.Command{
		Use:               "rm NAME",
		Aliases:           []string{"delete"},
		Short:             "Delete a session container (history and its secrets and auto memory choices are kept on the host)",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeSessions,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := resolveArg(cmd, args); err != nil {
				return err
			}
			m := newManager()
			if err := m.RequireType(cmd.Context(), args[0], config.TypeSession); err != nil {
				return err
			}
			return m.DeleteWith(cmd.Context(), args[0], opts)
		},
	}
	cmd.Flags().BoolVarP(&opts.Force, "force", "f", false, "remove a running session too")
	cmd.Flags().BoolVar(&opts.ReleaseHolds, "release-holds", false, "remove a session held offline too, releasing every hold")
	return cmd
}

func newAttachCommand() *cobra.Command {
	return &cobra.Command{
		Use:               "attach NAME",
		Short:             "Attach to a session's tmux session in this terminal",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeSessions,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := resolveArg(cmd, args); err != nil {
				return err
			}
			if err := session.NewManager(nil).RequireType(cmd.Context(), args[0], config.TypeSession); err != nil {
				return err
			}
			// The tmux server runs as the session's own user, so code in
			// the session can make it send anything to attached clients.
			// Its output is filtered on the host, not passed straight to
			// this terminal.
			argv := []string{"docker", "exec", "-it", "--user", config.SessionUser, config.ContainerName(args[0]), "tmux", "attach", "-t", config.TmuxSession}
			code, err := attachTerminal(argv)
			if err != nil {
				return err
			}
			if code != 0 {
				return exitCodeError{code}
			}
			return nil
		},
	}
}

func newTTYDWrapperCommand() *cobra.Command {
	var noAttach bool
	cmd := &cobra.Command{
		Use:    "ttyd-wrapper",
		Short:  "Start Claude Code in tmux and attach (runs inside the container)",
		Hidden: true,
		Args:   cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return wrapper.Run(wrapper.OSCommander{}, !noAttach)
		},
	}
	cmd.Flags().BoolVar(&noAttach, "no-attach", false, "only make sure the tmux session exists")
	return cmd
}
