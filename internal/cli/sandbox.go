package cli

import (
	"errors"
	"fmt"
	"io"
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
	remove                        bool
}

// limitFlags are the sandbox run flags that recreate an existing sandbox
// when set.
var limitFlags = []string{"memory", "pids-limit", "cpus"}

// createFlags are the flags that configure a new sandbox.
var createFlags = append([]string{"session", "volume"}, limitFlags...)

// register adds the flags that configure a new sandbox. recreates is
// appended to the help of the flags that recreate an existing sandbox.
func (f *sandboxFlags) register(cmd *cobra.Command, nameHelp, recreates string) {
	cmd.Flags().StringVarP(&f.session, "session", "s", "", nameHelp)
	cmd.Flags().StringVarP(&f.volume, "volume", "v", "", "mount a host directory read-only, /host/path:/container/path"+recreates)
	cmd.Flags().StringVar(&f.memory, "memory", session.DefaultSandboxMemory, "memory limit"+recreates)
	cmd.Flags().IntVar(&f.pidsLimit, "pids-limit", session.DefaultSandboxPidsLimit, "process limit"+recreates)
	cmd.Flags().StringVar(&f.cpus, "cpus", session.DefaultSandboxCPUs, "CPU limit"+recreates)
}

// options maps the flags to SandboxOptions. changed reports whether a flag
// was set on the command line.
func (f sandboxFlags) options(changed func(name string) bool) session.SandboxOptions {
	opts := session.SandboxOptions{
		Name:      f.session,
		Volume:    f.volume,
		Memory:    f.memory,
		PidsLimit: f.pidsLimit,
		CPUs:      f.cpus,
		Remove:    f.remove,
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
		Use:   "run [-s NAME] [--rm]",
		Short: "Create or start a sandbox",
		Long: "Create or start a sandbox. -s is required unless --rm is set.\n\n" +
			"With --rm, a new one-off sandbox is created and removed with its /sandbox volume when it stops. " +
			"Without -s it gets a random name. Its name is the only thing printed to stdout, and an existing name is refused.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts := f.options(func(name string) bool { return cmd.Flags().Changed(name) })
			if !opts.Remove {
				_, err := session.NewManager(cmd.OutOrStdout()).EnsureSandbox(cmd.Context(), opts)
				return err
			}
			res, err := session.NewManager(cmd.ErrOrStderr()).EnsureSandbox(cmd.Context(), opts)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), res.Name)
			return err
		},
	}
	f.register(cmd, "sandbox name (required without --rm)", " (recreates an existing sandbox)")
	cmd.Flags().BoolVar(&f.remove, "rm", false, "create a one-off sandbox that is removed when it stops")
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

// sandboxExecArgs validates exec's arguments: COMMAND with --ephemeral,
// otherwise NAME COMMAND, with the sandbox creation flags refused.
func sandboxExecArgs(cmd *cobra.Command, args []string) error {
	if ephemeral, _ := cmd.Flags().GetBool("ephemeral"); ephemeral {
		if len(args) == 0 {
			return errors.New("a command is required: exec --ephemeral -- COMMAND [ARG...]")
		}
		return nil
	}
	for _, name := range createFlags {
		if cmd.Flags().Changed(name) {
			return fmt.Errorf("--%s can only be used with --ephemeral", name)
		}
	}
	if len(args) < 2 {
		return errors.New("a sandbox name and command are required: exec NAME -- COMMAND [ARG...]")
	}
	return nil
}

func newSandboxExecCommand() *cobra.Command {
	var interactive, tty, ephemeral bool
	var f sandboxFlags
	cmd := &cobra.Command{
		Use:   "exec {NAME | --ephemeral [-s NAME]} [-i] [-t] -- COMMAND [ARG...]",
		Short: "Run a command in a sandbox as the sandbox user",
		Long: "Run a command in a sandbox as the sandbox user.\n\n" +
			"With --ephemeral, no NAME is given: the command runs in a new one-off sandbox that is removed when it exits, " +
			"and the command's exit code is returned. Without -s the sandbox gets a random name, and an existing name is refused.",
		Args: sandboxExecArgs,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if ephemeral {
				return nil, cobra.ShellCompDirectiveDefault
			}
			return completeType(config.TypeSandbox)(cmd, args, toComplete)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			var argv []string
			if ephemeral {
				opts := f.options(func(string) bool { return false })
				var err error
				argv, _, err = session.NewManager(nil).PrepareEphemeral(cmd.Context(), opts, interactive, tty, args)
				if err != nil {
					return err
				}
			} else {
				if err := session.NewManager(nil).RequireType(cmd.Context(), args[0], config.TypeSandbox); err != nil {
					return err
				}
				argv = sandboxExecArgv(args[0], interactive, tty, args[1:])
			}
			bin, err := exec.LookPath("docker")
			if err != nil {
				return err
			}
			return syscall.Exec(bin, argv, os.Environ())
		},
	}
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "keep stdin open")
	cmd.Flags().BoolVarP(&tty, "tty", "t", false, "allocate a TTY")
	cmd.Flags().BoolVar(&ephemeral, "ephemeral", false, "run the command in a new one-off sandbox that is removed when it exits")
	f.register(cmd, "name for the --ephemeral sandbox (random by default)", " (with --ephemeral)")
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
			return writeSandboxes(cmd.OutOrStdout(), list)
		},
	}
}

// writeSandboxes writes the `safeclaw sandbox ls` table.
func writeSandboxes(out io.Writer, list []session.Session) error {
	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "SANDBOX\tSTATUS\tONE-OFF\tVOLUME")
	for _, s := range list {
		if s.IsSandbox() {
			oneOff := "-"
			if s.IsOneOff() {
				oneOff = "yes"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", s.Name, s.Status, oneOff, s.Volume)
		}
	}
	return w.Flush()
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
