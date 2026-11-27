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
	"golang.org/x/term"

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
		newSandboxCopyInCommand(),
		newSandboxCopyOutCommand(),
		newSandboxListCommand(),
		newSandboxInspectCommand(),
		newSandboxVerifyCommand(),
		newSandboxStopCommand(),
		newSandboxRemoveCommand(),
	)
	return cmd
}

type sandboxFlags struct {
	session, volume, variant, memory, cpus, disk string
	pidsLimit                                    int
	remove                                       bool
}

// limitFlags are the sandbox run flags that recreate an existing sandbox
// when set.
var limitFlags = []string{"memory", "pids-limit", "cpus", "disk"}

// createFlags are the flags that configure a new sandbox.
var createFlags = append([]string{"session", "volume", "variant"}, limitFlags...)

// register adds the flags that configure a new sandbox. recreates is
// appended to the help of the flags that recreate an existing sandbox.
func (f *sandboxFlags) register(cmd *cobra.Command, nameHelp, recreates string) {
	cmd.Flags().StringVarP(&f.session, "session", "s", "", nameHelp)
	cmd.Flags().StringVarP(&f.volume, "volume", "v", "", "mount a host directory read-only, /host/path:/container/path"+recreates)
	cmd.Flags().StringVar(&f.variant, "variant", "", "image variant, or base for the base image (default from the config file, else sandbox)"+recreates)
	_ = cmd.RegisterFlagCompletionFunc("variant", completeVariants)
	cmd.Flags().StringVar(&f.memory, "memory", session.DefaultSandboxMemory, "memory limit"+recreates)
	cmd.Flags().IntVar(&f.pidsLimit, "pids-limit", session.DefaultSandboxPidsLimit, "process limit"+recreates)
	cmd.Flags().StringVar(&f.cpus, "cpus", session.DefaultSandboxCPUs, "CPU limit"+recreates)
	cmd.Flags().StringVar(&f.disk, "disk", session.DefaultSandboxDisk, "size of /sandbox, a tmpfs that counts toward --memory"+recreates)
}

// options maps the flags to SandboxOptions. changed reports whether a flag
// was set on the command line. Limits are only passed when set, so a
// recreated sandbox keeps the others.
func (f sandboxFlags) options(changed func(name string) bool) session.SandboxOptions {
	opts := session.SandboxOptions{
		Name:    f.session,
		Volume:  f.volume,
		Variant: f.variant,
		Remove:  f.remove,
	}
	if changed("memory") {
		opts.Memory = f.memory
	}
	if changed("pids-limit") {
		opts.PidsLimit = f.pidsLimit
	}
	if changed("cpus") {
		opts.CPUs = f.cpus
	}
	if changed("disk") {
		opts.Disk = f.disk
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
			"/sandbox is a tmpfs of --disk bytes: writes past it fail, its pages count toward --memory, and it is emptied when the sandbox stops.\n\n" +
			"With --rm, a new one-off sandbox is created and removed when it stops. " +
			"Without -s it gets a random name. Its name is the only thing printed to stdout, and an existing name is refused.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts := f.options(func(name string) bool { return cmd.Flags().Changed(name) })
			var err error
			if opts.Name, err = resolveName(cmd, opts.Name); err != nil {
				return err
			}
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

// sandboxExecArgv returns the docker argv for running a command in a
// sandbox, wrapped with session.SandboxCommand for a fixed umask.
func sandboxExecArgv(name string, interactive, tty bool, command []string) []string {
	argv := []string{"docker", "exec"}
	if interactive {
		argv = append(argv, "-i")
	}
	if tty {
		argv = append(argv, "-t")
	}
	argv = append(argv, "--user", config.SandboxUser, "--workdir", config.SandboxDir, config.ContainerName(name))
	return append(argv, session.SandboxCommand(command)...)
}

// sandboxExecArgs validates exec's arguments: COMMAND with --ephemeral,
// otherwise NAME COMMAND, with the sandbox creation flags refused.
func sandboxExecArgs(cmd *cobra.Command, args []string) error {
	escape, _ := cmd.Flags().GetBool("escape-controls")
	if tty, _ := cmd.Flags().GetBool("tty"); escape && tty {
		return errors.New("--escape-controls can't be used with -t: a TTY needs its control characters, and docker merges stdout and stderr into it")
	}
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
	var interactive, tty, ephemeral, escape bool
	var f sandboxFlags
	cmd := &cobra.Command{
		Use:   "exec {NAME | --ephemeral [-s NAME]} [-i] [-t | --escape-controls] -- COMMAND [ARG...]",
		Short: "Run a command in a sandbox as the sandbox user",
		Long: "Run a command in a sandbox as the sandbox user.\n\n" +
			"With --ephemeral, no NAME is given: the command runs in a new one-off sandbox that is removed when it exits, " +
			"and the command's exit code is returned. Without -s the sandbox gets a random name, and an existing name is refused.\n\n" +
			"With --escape-controls, the command's stdout and stderr are kept apart and passed through safeclaw, which writes control characters " +
			"other than newline and tab, invalid UTF-8, and other unprintable characters as visible escapes such as \\x1b, " +
			"so escape sequences from untrusted files never reach the terminal. The exit code is returned as is " +
			"(128 plus the signal number when a signal killed docker), and SIGINT, SIGTERM, SIGHUP and SIGQUIT are forwarded. " +
			"It can't be used with -t.",
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
				opts := f.options(func(name string) bool { return cmd.Flags().Changed(name) })
				var err error
				if opts.Name, err = resolveName(cmd, opts.Name); err != nil {
					return err
				}
				argv, _, err = session.NewManager(nil).PrepareEphemeral(cmd.Context(), opts, interactive, tty, args)
				if err != nil {
					return err
				}
			} else {
				if err := resolveArg(cmd, args); err != nil {
					return err
				}
				if err := session.NewManager(nil).RequireType(cmd.Context(), args[0], config.TypeSandbox); err != nil {
					return err
				}
				argv = sandboxExecArgv(args[0], interactive, tty, args[1:])
			}
			if escape {
				return runEscapedExec(cmd, argv, interactive)
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
	cmd.Flags().BoolVar(&escape, "escape-controls", false, "escape control characters in the command's output before they reach the terminal")
	cmd.Flags().BoolVar(&ephemeral, "ephemeral", false, "run the command in a new one-off sandbox that is removed when it exits")
	f.register(cmd, "name for the --ephemeral sandbox (random by default)", " (with --ephemeral)")
	return cmd
}

// runEscapedExec runs a sandbox exec argv through runEscaped. The command
// shares safeclaw's process group only when it reads stdin from a
// terminal, which a background process group can't do.
func runEscapedExec(cmd *cobra.Command, argv []string, interactive bool) error {
	var stdin io.Reader
	shareGroup := false
	if interactive {
		stdin = cmd.InOrStdin()
		if f, ok := stdin.(*os.File); ok {
			shareGroup = term.IsTerminal(int(f.Fd()))
		}
	}
	code, err := runEscaped(argv, stdin, cmd.OutOrStdout(), cmd.ErrOrStderr(), shareGroup)
	if err != nil {
		return err
	}
	if code != 0 {
		return exitCodeError{code}
	}
	return nil
}

// completeSandboxFirst completes NAME as a sandbox and leaves the other
// arguments to the shell's file completion.
func completeSandboxFirst(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	if len(args) == 0 {
		return completeType(config.TypeSandbox)(cmd, args, toComplete)
	}
	return nil, cobra.ShellCompDirectiveDefault
}

// writePaths writes each path to out on its own line, quoted when it is not
// printable so it can't send escapes to the terminal or split a line.
func writePaths(out io.Writer, paths []string) error {
	for _, p := range paths {
		if _, err := fmt.Fprintln(out, session.QuotePath(p)); err != nil {
			return err
		}
	}
	return nil
}

func newSandboxCopyInCommand() *cobra.Command {
	var to string
	cmd := &cobra.Command{
		Use:   "cp-in NAME FILE...",
		Short: "Copy host files into a running sandbox",
		Long: "Copy regular host files into a running sandbox, owned by the sandbox user.\n\n" +
			"Symbolic links and anything that is not a regular file are refused before anything is copied. " +
			"Each file is named N-NAME, with N continuing after the highest number already in the destination, " +
			"so files with the same name never overwrite each other. The container path of each file is printed, in order, " +
			"quoted when it is not printable text.",
		Args:              cobra.MinimumNArgs(2),
		ValidArgsFunction: completeSandboxFirst,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := resolveArg(cmd, args); err != nil {
				return err
			}
			paths, err := session.NewManager(nil).CopyIn(cmd.Context(), args[0], args[1:], to)
			if err != nil {
				return err
			}
			return writePaths(cmd.OutOrStdout(), paths)
		},
	}
	cmd.Flags().StringVar(&to, "to", session.DefaultCopyDest, "destination directory, under "+config.SandboxDir)
	return cmd
}

func newSandboxCopyOutCommand() *cobra.Command {
	var only []string
	var force bool
	var maxSize string
	var maxFiles int
	cmd := &cobra.Command{
		Use:   "cp-out NAME CONTAINER_DIR HOST_DIR --only GLOB...",
		Short: "Copy matching files out of a running sandbox",
		Long: "Copy the regular files directly in CONTAINER_DIR whose names match an --only glob into the existing HOST_DIR.\n\n" +
			"Symbolic links, hard links, directories, sparse files, other file types, and anything in subdirectories are dropped. " +
			"A kept file whose name is not printable UTF-8 or starts with - refuses the whole copy, and as in a shell, " +
			"names starting with . only match a glob that starts with . too. " +
			"Files are read as the sandbox user and written with mode 0644, less the umask. Nothing is written unless every file arrives, " +
			"and existing files are refused unless --force is set. More files than --max-files, or more bytes than --max-size, refuse the whole copy. The host path of each file is printed, quoted when it is not printable text.",
		Args:              cobra.ExactArgs(3),
		ValidArgsFunction: completeSandboxFirst,
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := resolveArg(cmd, args); err != nil {
				return err
			}
			limit, err := session.ParseSize(maxSize)
			if err != nil {
				return fmt.Errorf("--max-size: %w", err)
			}
			paths, err := session.NewManager(nil).CopyOut(cmd.Context(), args[0], args[1], args[2], session.CopyOutOptions{
				Only:     only,
				Force:    force,
				MaxSize:  limit,
				MaxFiles: maxFiles,
			})
			if err != nil {
				return err
			}
			return writePaths(cmd.OutOrStdout(), paths)
		},
	}
	cmd.Flags().StringArrayVar(&only, "only", nil, "keep files whose names match this glob (repeatable)")
	_ = cmd.MarkFlagRequired("only")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "overwrite existing host files")
	cmd.Flags().StringVar(&maxSize, "max-size", session.DefaultCopyMaxSize, "limit on the total size of the files kept, with a k, m, g, or t suffix (0 for none)")
	cmd.Flags().IntVar(&maxFiles, "max-files", session.DefaultCopyMaxFiles, "limit on the number of files kept (0 for none)")
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
	fmt.Fprintln(w, "SANDBOX\tVARIANT\tSTATUS\tONE-OFF\tVOLUME")
	for _, s := range list {
		if s.IsSandbox() {
			oneOff := "-"
			if s.IsOneOff() {
				oneOff = "yes"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", s.Name, variantColumn(s), s.Status, oneOff, s.Volume)
		}
	}
	return w.Flush()
}

func newSandboxStopCommand() *cobra.Command {
	return &cobra.Command{
		Use:               "stop NAME",
		Short:             "Stop a sandbox",
		Long:              "Stop a sandbox. Its /sandbox is a tmpfs, so the files in it are lost. A one-off sandbox is removed.",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeType(config.TypeSandbox),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := resolveArg(cmd, args); err != nil {
				return err
			}
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
		Short:             "Delete a sandbox",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeType(config.TypeSandbox),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := resolveArg(cmd, args); err != nil {
				return err
			}
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

// variantColumn returns a session's variant for listings, "-" for the base
// image.
func variantColumn(s session.Session) string {
	if s.Variant == "" {
		return "-"
	}
	return s.Variant
}
