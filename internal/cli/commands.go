package cli

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/dashboard"
	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/envtui"
	"github.com/josegonzalez/safeclaw/internal/prompt"
	"github.com/josegonzalez/safeclaw/internal/secrets"
	"github.com/josegonzalez/safeclaw/internal/session"
	"github.com/josegonzalez/safeclaw/internal/version"
	"github.com/josegonzalez/safeclaw/internal/wrapper"
)

func newPullCommand() *cobra.Command {
	var tag string
	cmd := &cobra.Command{
		Use:   "pull",
		Short: "Pull the published safeclaw image and tag it locally",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if tag == "" {
				tag = version.ImageTag()
			}
			ref := config.RemoteImage + ":" + tag
			d := docker.New()
			if err := d.R.Passthrough(cmd.Context(), "pull", ref); err != nil {
				return err
			}
			if err := d.Tag(cmd.Context(), ref, config.ImageName); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Tagged %s as %s\n", ref, config.ImageName)
			return reportStale(cmd.Context(), d, cmd.OutOrStdout(), false)
		},
	}
	cmd.Flags().StringVar(&tag, "tag", "", "image tag to pull (default: this binary's version, or latest)")
	return cmd
}

type runFlags struct {
	session, volume, query string
	noOpen                 bool
}

func (f *runFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&f.session, "session", "s", "", "session name (default \"default\")")
	cmd.Flags().StringVarP(&f.volume, "volume", "v", "", "mount a host directory, /host/path:/container/path (recreates an existing container)")
	cmd.Flags().BoolVarP(&f.noOpen, "no-open", "n", false, "do not open the browser")
	cmd.Flags().StringVarP(&f.query, "query", "q", "", "send this query to Claude Code once it starts")
}

func (f *runFlags) options(interactive bool) session.Options {
	return session.Options{
		Name:        f.session,
		Volume:      f.volume,
		Query:       f.query,
		NoOpen:      f.noOpen,
		Interactive: interactive,
	}
}

func newRunCommand() *cobra.Command {
	var f runFlags
	cmd := &cobra.Command{
		Use:   "run",
		Short: "Start or reuse a session container and its web terminal",
		Long:  "Start or reuse a session container, inject secrets, configure git, and start the ttyd web terminal. Prompts for tokens on first run.",
		Example: `  safeclaw run
  safeclaw run -s work
  safeclaw run -s myproject -v ~/myproject:/home/sclaw/myproject
  safeclaw run -s research -n -q "Research topic X"`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			m := session.NewManager(cmd.OutOrStdout())
			m.Prompter = prompt.Terminal{Out: cmd.OutOrStdout()}
			_, err := m.Ensure(cmd.Context(), f.options(true))
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
			_, err := session.NewManager(cmd.OutOrStdout()).Ensure(cmd.Context(), f.options(false))
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
	cmd.Flags().BoolVar(&dev, "dev", false, "serve templates and static files from ./internal/dashboard for live editing")
	return cmd
}

func newEnvCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "env",
		Short: "Manage environment variables injected into sessions",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return envtui.Run(secrets.Store{Dir: config.SecretsDir()}, cmd.OutOrStdout())
		},
	}
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
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "SESSION\tSTATUS\tURL\tVOLUME")
			for _, s := range list {
				url := s.URL
				if url == "" {
					url = "-"
				}
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", s.Name, s.Status, url, s.Volume)
			}
			return w.Flush()
		},
	}
}

func newStopCommand() *cobra.Command {
	return &cobra.Command{
		Use:               "stop NAME",
		Short:             "Stop a session",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeSessions,
		RunE: func(cmd *cobra.Command, args []string) error {
			return session.NewManager(nil).Stop(cmd.Context(), args[0])
		},
	}
}

func newRemoveCommand() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:               "rm NAME",
		Aliases:           []string{"delete"},
		Short:             "Delete a session container (history is kept on the host)",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeSessions,
		RunE: func(cmd *cobra.Command, args []string) error {
			return session.NewManager(nil).Delete(cmd.Context(), args[0], force)
		},
	}
	cmd.Flags().BoolVarP(&force, "force", "f", false, "remove a running session too")
	return cmd
}

func newAttachCommand() *cobra.Command {
	return &cobra.Command{
		Use:               "attach NAME",
		Short:             "Attach to a session's tmux session in this terminal",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeSessions,
		RunE: func(_ *cobra.Command, args []string) error {
			bin, err := exec.LookPath("docker")
			if err != nil {
				return err
			}
			argv := []string{"docker", "exec", "-it", config.ContainerName(args[0]), "tmux", "attach", "-t", config.TmuxSession}
			return syscall.Exec(bin, argv, os.Environ())
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
