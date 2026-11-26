package cli

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/session"
)

func newSandboxCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sandbox",
		Short: "Manage headless sandboxes for opening untrusted files",
		Long: "A sandbox is a headless container for opening untrusted files with `docker exec`. " +
			"It gets no secrets, git config, web terminal or Claude Code, has no network, " +
			"and runs as an unprivileged user that cannot read /home/sclaw.",
	}
	cmd.AddCommand(
		newSandboxRunCommand(),
		newSandboxExecCommand(),
		newSandboxListCommand(),
		newSandboxStopCommand(),
		newSandboxRemoveCommand(),
	)
	return cmd
}

type sandboxFlags struct {
	session, volume, memory, cpus string
	pidsLimit                     int
}

// limitFlags are the sandbox run flags that recreate an existing sandbox
// when set.
var limitFlags = []string{"memory", "pids-limit", "cpus"}

// options maps the flags to SandboxOptions. changed reports whether a flag
// was set on the command line.
func (f sandboxFlags) options(changed func(name string) bool) session.SandboxOptions {
	opts := session.SandboxOptions{
		Name:      f.session,
		Volume:    f.volume,
		Memory:    f.memory,
		PidsLimit: f.pidsLimit,
		CPUs:      f.cpus,
	}
	for _, name := range limitFlags {
		if changed(name) {
			opts.Recreate = true
		}
	}
	return opts
}

func newSandboxRunCommand() *cobra.Command {
	var f sandboxFlags
	cmd := &cobra.Command{
		Use:   "run -s NAME",
		Short: "Create or start a sandbox",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts := f.options(func(name string) bool { return cmd.Flags().Changed(name) })
			_, err := session.NewManager(cmd.OutOrStdout()).EnsureSandbox(cmd.Context(), opts)
			return err
		},
	}
	cmd.Flags().StringVarP(&f.session, "session", "s", "", "sandbox name (required)")
	cmd.Flags().StringVarP(&f.volume, "volume", "v", "", "mount a host directory read-only, /host/path:/container/path (recreates an existing sandbox)")
	cmd.Flags().StringVar(&f.memory, "memory", session.DefaultSandboxMemory, "memory limit (recreates an existing sandbox)")
	cmd.Flags().IntVar(&f.pidsLimit, "pids-limit", session.DefaultSandboxPidsLimit, "process limit (recreates an existing sandbox)")
	cmd.Flags().StringVar(&f.cpus, "cpus", session.DefaultSandboxCPUs, "CPU limit (recreates an existing sandbox)")
	_ = cmd.MarkFlagRequired("session")
	return cmd
}

// sandboxExecArgv returns the docker argv for running a command in a sandbox.
func sandboxExecArgv(name string, interactive, tty bool, command []string) []string {
	argv := []string{"docker", "exec"}
	if interactive {
		argv = append(argv, "-i")
	}
	if tty {
		argv = append(argv, "-t")
	}
	argv = append(argv, "--user", config.SandboxUser, "--workdir", config.SandboxDir, config.ContainerName(name))
	return append(argv, command...)
}

func newSandboxExecCommand() *cobra.Command {
	var interactive, tty bool
	cmd := &cobra.Command{
		Use:               "exec NAME [-i] [-t] -- COMMAND [ARG...]",
		Short:             "Run a command in a sandbox as the sandbox user",
		Args:              cobra.MinimumNArgs(2),
		ValidArgsFunction: completeType(config.TypeSandbox),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := session.NewManager(nil).RequireType(cmd.Context(), args[0], config.TypeSandbox); err != nil {
				return err
			}
			bin, err := exec.LookPath("docker")
			if err != nil {
				return err
			}
			return syscall.Exec(bin, sandboxExecArgv(args[0], interactive, tty, args[1:]), os.Environ())
		},
	}
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "keep stdin open")
	cmd.Flags().BoolVarP(&tty, "tty", "t", false, "allocate a TTY")
	return cmd
}

func newSandboxListCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List sandboxes",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			list, err := session.NewManager(nil).List(cmd.Context())
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 3, ' ', 0)
			fmt.Fprintln(w, "SANDBOX\tSTATUS\tVOLUME")
			for _, s := range list {
				if s.IsSandbox() {
					fmt.Fprintf(w, "%s\t%s\t%s\n", s.Name, s.Status, s.Volume)
				}
			}
			return w.Flush()
		},
	}
}

func newSandboxStopCommand() *cobra.Command {
	return &cobra.Command{
		Use:               "stop NAME",
		Short:             "Stop a sandbox",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeType(config.TypeSandbox),
		RunE: func(cmd *cobra.Command, args []string) error {
			m := session.NewManager(nil)
			if err := m.RequireType(cmd.Context(), args[0], config.TypeSandbox); err != nil {
				return err
			}
			return m.Stop(cmd.Context(), args[0])
		},
	}
}

func newSandboxRemoveCommand() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:               "rm NAME",
		Aliases:           []string{"delete"},
		Short:             "Delete a sandbox and its /sandbox volume",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeType(config.TypeSandbox),
		RunE: func(cmd *cobra.Command, args []string) error {
			m := session.NewManager(nil)
			if err := m.RequireType(cmd.Context(), args[0], config.TypeSandbox); err != nil {
				return err
			}
			return m.Delete(cmd.Context(), args[0], force)
		},
	}
	cmd.Flags().BoolVarP(&force, "force", "f", false, "remove a running sandbox too")
	return cmd
}
