package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"sync/atomic"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
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
		newSandboxOpenCommand(),
		newSandboxScanCommand(),
		newSandboxUpdateSignaturesCommand(),
		newSandboxListCommand(),
		newSandboxStatusCommand(),
		newSandboxInspectCommand(),
		newSandboxVerifyCommand(),
		newSandboxStopCommand(),
		newSandboxRemoveCommand(),
	)
	return cmd
}

type sandboxFlags struct {
	session, variant, memory, cpus, disk string
	volumes                              []string
	pidsLimit                            int
	remove, verify                       bool
}

// limitFlags are the sandbox run flags that recreate an existing sandbox
// when set.
var limitFlags = []string{"memory", "pids-limit", "cpus", "disk"}

// createFlags are the flags that configure a new sandbox.
var createFlags = append([]string{"session", "volume", "variant", "verify"}, limitFlags...)

// register adds the flags that configure a new sandbox. recreates is
// appended to the help of the flags that recreate an existing sandbox.
func (f *sandboxFlags) register(cmd *cobra.Command, nameHelp, recreates string) {
	cmd.Flags().StringVarP(&f.session, "session", "s", "", nameHelp)
	cmd.Flags().StringArrayVarP(&f.volumes, "volume", "v", nil, "mount a host directory and everything mounted below it read-only, /host/path:/container/path (repeatable, needs Docker Engine 25+ and Linux 5.12+)"+recreates)
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
		Volumes: f.volumes,
		Variant: f.variant,
		Remove:  f.remove,
		Verify:  f.verify,
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

// sandboxRunArgs refuses --name-prefix with -s or without --rm.
func sandboxRunArgs(cmd *cobra.Command, _ []string) error {
	if !cmd.Flags().Changed("name-prefix") {
		return nil
	}
	if cmd.Flags().Changed("session") {
		return errors.New("-s and --name-prefix can't be used together: -s names the sandbox, --name-prefix has a name picked")
	}
	if rm, _ := cmd.Flags().GetBool("rm"); !rm {
		return errors.New("--name-prefix can only be used with --rm")
	}
	if p, _ := cmd.Flags().GetString("name-prefix"); p == "" {
		return errors.New("--name-prefix can't be empty")
	}
	return nil
}

func newSandboxRunCommand() *cobra.Command {
	var f sandboxFlags
	var namePrefix string
	cmd := &cobra.Command{
		Use:   "run [-s NAME] [--rm [--name-prefix PREFIX]]",
		Short: "Create or start a sandbox",
		Long: "Create or start a sandbox. -s is required unless --rm is set.\n\n" +
			"/sandbox is a tmpfs of --disk bytes: writes past it fail, its pages count toward --memory, and it is emptied when the sandbox stops.\n\n" +
			"With --rm, a new one-off sandbox is created and removed when it stops. " +
			"Without -s it gets a random name. Its name is the only thing printed to stdout, and an existing name is refused.\n\n" +
			"With --rm --name-prefix PREFIX, it is named PREFIX-YYYYMMDD-HHMMSS in UTC, so names sort by creation time, " +
			"with -2 to -9 added when that name is taken. The prefix follows the session name rules, and can't be used with -s.\n\n" +
			"With --verify, the sandbox gets the checks of `safeclaw sandbox verify` once it has started. If any fails, the report is printed " +
			"to stderr and it exits non-zero naming the failed checks. A sandbox this run created or recreated is then removed, " +
			"including when safeclaw is interrupted before the checks end; one that already existed is left as it was.",
		Example: `  safeclaw sandbox run -s triage -v ~/inbox:/in
  name=$(safeclaw sandbox run --rm -v ~/inbox:/in)
  name=$(safeclaw sandbox run --rm --name-prefix triage)   # triage-20261128-110940`,
		Args: cobra.MatchAll(cobra.NoArgs, sandboxRunArgs),
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts := f.options(func(name string) bool { return cmd.Flags().Changed(name) })
			opts.NamePrefix = namePrefix
			var err error
			if opts.Name, err = resolveName(cmd, opts.Name); err != nil {
				return err
			}
			m := newManager()
			m.Out = cmd.OutOrStdout()
			if opts.Remove {
				m.Out = cmd.ErrOrStderr()
			}
			res, err := m.EnsureSandbox(cmd.Context(), opts)
			if err != nil {
				return verifyReport(cmd.ErrOrStderr(), err)
			}
			if !opts.Remove {
				return nil
			}
			_, err = fmt.Fprintln(cmd.OutOrStdout(), res.Name)
			return err
		},
	}
	f.register(cmd, "sandbox name (required without --rm)", " (recreates an existing sandbox)")
	cmd.Flags().BoolVar(&f.remove, "rm", false, "create a one-off sandbox that is removed when it stops")
	cmd.Flags().StringVar(&namePrefix, "name-prefix", "", "with --rm, name the sandbox PREFIX-YYYYMMDD-HHMMSS in UTC, adding -2 to -9 when that name is taken")
	cmd.Flags().BoolVar(&f.verify, "verify", false, "run the sandbox verify checks once it has started, and remove it if a check fails and this run created it")
	return cmd
}

// sandboxExecArgs validates exec's arguments: COMMAND with --ephemeral,
// otherwise NAME COMMAND, with the sandbox creation flags refused.
func sandboxExecArgs(cmd *cobra.Command, args []string) error {
	escape, _ := cmd.Flags().GetBool("escape-controls")
	if tty, _ := cmd.Flags().GetBool("tty"); escape && tty {
		return errors.New("--escape-controls can't be used with -t: a TTY needs its control characters, and docker merges stdout and stderr into it")
	}
	if timeout, _ := cmd.Flags().GetDuration("timeout"); cmd.Flags().Changed("timeout") && timeout <= 0 {
		return fmt.Errorf("invalid --timeout %s: must be more than 0", timeout)
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
	var timeout time.Duration
	var envSpecs, envIfSet []string
	var f sandboxFlags
	cmd := &cobra.Command{
		Use:   "exec {NAME | --ephemeral [-s NAME]} [-i] [-t | --escape-controls] [--timeout DUR] [-e NAME[=VALUE]]... [--env-if-set NAME]... -- COMMAND [ARG...]",
		Short: "Run a command in a sandbox as the sandbox user",
		Long: "Run a command in a sandbox as the sandbox user.\n\n" +
			"With --ephemeral, no NAME is given: the command runs in a new one-off sandbox that is removed when it exits, " +
			"and the command's exit code is returned. Without -s the sandbox gets a random name, and an existing name is refused.\n\n" +
			"With --ephemeral --verify, the one-off sandbox gets the checks of `safeclaw sandbox verify` once it has started, and the command " +
			"starts only after every check has passed. If any fails, the report is printed to stderr, the sandbox is removed without running the command, " +
			"and it exits non-zero naming the failed checks. The sandbox is also removed when safeclaw is interrupted before the checks end.\n\n" +
			"With --escape-controls, the command's stdout and stderr are kept apart and passed through safeclaw, which writes control characters " +
			"other than newline and tab, invalid UTF-8, and other unprintable characters as visible escapes such as \\x1b, " +
			"so escape sequences from untrusted files never reach the terminal. The exit code is returned as is " +
			"(128 plus the signal number when a signal killed docker), and SIGINT, SIGTERM, SIGHUP and SIGQUIT are forwarded. " +
			"It can't be used with -t.\n\n" +
			"With --timeout, the command gets SIGTERM once it has run for DUR (such as 30s or 5m) and SIGKILL 5 seconds later, " +
			"and safeclaw exits 124 with an error saying it timed out.\n\n" +
			"-e sets an environment variable for the command only, NAME=VALUE or NAME to take the value from safeclaw's environment. " +
			"-e NAME for a variable that isn't set is an error. " +
			"--env-if-set NAME passes NAME from safeclaw's environment like -e NAME when it is set, even to an empty value, and leaves it out when it isn't. " +
			"A name can be given only once across -e and --env-if-set. " +
			"Values reach docker through a pipe rather than its arguments, so they don't show in ps. " +
			"The names of stored secrets, CLAUDE_CODE_OAUTH_TOKEN, and GH_TOKEN are refused, for --env-if-set whether or not they are set.",
		Args: sandboxExecArgs,
		ValidArgsFunction: func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if ephemeral {
				return nil, cobra.ShellCompDirectiveDefault
			}
			return completeType(config.TypeSandbox)(cmd, args, toComplete)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			m := newManager()
			env, err := m.ExecEnv(envSpecs, envIfSet, os.LookupEnv)
			if err != nil {
				return err
			}
			run := execRun{escape: escape, interactive: interactive, timeout: timeout, ephemeral: ephemeral}
			if ephemeral && f.verify {
				run.verify = func(ctx context.Context, exited <-chan struct{}) error {
					return m.VerifyEphemeral(ctx, run.name, exited)
				}
			}
			// Without --timeout, --escape-controls or --verify safeclaw
			// replaces itself with docker, which then inherits the env
			// pipe as is.
			replace := !escape && timeout == 0 && run.verify == nil
			x := session.ExecOptions{Interactive: interactive, TTY: tty, Timeout: timeout}
			if env != "" {
				if run.envFile, err = envPipe(env); err != nil {
					return err
				}
				defer run.envFile.Close()
				x.EnvFile = "/dev/fd/3"
				if replace {
					if _, err := unix.FcntlInt(run.envFile.Fd(), unix.F_SETFD, 0); err != nil {
						return err
					}
					x.EnvFile = fmt.Sprintf("/dev/fd/%d", run.envFile.Fd())
				}
			}
			var argv []string
			if ephemeral {
				opts := f.options(func(name string) bool { return cmd.Flags().Changed(name) })
				if opts.Name, err = resolveName(cmd, opts.Name); err != nil {
					return err
				}
				argv, run.name, err = m.PrepareEphemeral(cmd.Context(), opts, x, args)
				if err != nil {
					return err
				}
			} else {
				if err := resolveArg(cmd, args); err != nil {
					return err
				}
				if err := m.RequireType(cmd.Context(), args[0], config.TypeSandbox); err != nil {
					return err
				}
				run.name = config.SessionName(args[0])
				argv = session.SandboxExecArgv(args[0], x, args[1:])
			}
			if !replace {
				return runSandboxExec(cmd, m, argv, run)
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
	cmd.Flags().DurationVar(&timeout, "timeout", 0, "stop the command after this long, such as 30s or 5m, and exit 124")
	cmd.Flags().StringArrayVarP(&envSpecs, "env", "e", nil, "set NAME=VALUE, or NAME from safeclaw's environment, for the command (repeatable)")
	cmd.Flags().StringArrayVar(&envIfSet, "env-if-set", nil, "pass NAME from safeclaw's environment to the command when it is set, and leave it out when it isn't (repeatable)")
	cmd.Flags().BoolVar(&ephemeral, "ephemeral", false, "run the command in a new one-off sandbox that is removed when it exits")
	f.register(cmd, "name for the --ephemeral sandbox (random by default)", " (with --ephemeral)")
	cmd.Flags().BoolVar(&f.verify, "verify", false, "run the sandbox verify checks on the --ephemeral sandbox before the command, and remove it without running the command if a check fails")
	return cmd
}

// envPipe returns the read end of a pipe holding env, for docker to read
// with --env-file /dev/fd/N. The values never touch the disk or an argv.
// env is at most session.MaxExecEnvBytes, which fits in the pipe's buffer,
// so it is written before anything reads it.
func envPipe(env string) (*os.File, error) {
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	_, err = io.WriteString(w, env)
	if err = errors.Join(err, w.Close()); err != nil {
		_ = r.Close()
		return nil, err
	}
	return r, nil
}

// timeoutExitCode is what a timed-out sandbox command exits with, as
// coreutils timeout does.
const timeoutExitCode = 124

// timeoutGrace is how long after the in-container timeout's SIGKILL
// safeclaw waits before stopping docker itself.
var timeoutGrace = 5 * time.Second

// execRun is how runSandboxExec runs a sandbox command.
type execRun struct {
	escape, interactive, ephemeral bool
	timeout                        time.Duration
	// envFile is inherited by docker as fd 3.
	envFile *os.File
	// name is the sandbox's session name.
	name string
	// verify, when set, is called once docker has started, and lets the
	// command start or returns why it must not. exited is closed when
	// docker exits.
	verify func(ctx context.Context, exited <-chan struct{}) error
}

// runSandboxExec runs a sandbox exec argv as a child of safeclaw, for
// --escape-controls and --timeout. The command shares safeclaw's process
// group only when it reads stdin from a terminal, which a background
// process group can't do.
//
// With a timeout, the in-container coreutils timeout stops the command.
// If docker is still running timeoutGrace after that should have finished
// it (the command left timeout's process group, or killed timeout), a
// one-off sandbox is removed, which ends everything in it, and docker is
// killed. A named sandbox can't be cleaned up without stopping its other
// commands, so the error says the command may still be running there.
func runSandboxExec(cmd *cobra.Command, m *session.Manager, argv []string, r execRun) error {
	o := childOptions{stdout: cmd.OutOrStdout(), stderr: cmd.ErrOrStderr(), escape: r.escape}
	if r.interactive {
		o.stdin = cmd.InOrStdin()
		if f, ok := o.stdin.(*os.File); ok {
			o.shareGroup = term.IsTerminal(int(f.Fd()))
		}
	}
	if r.envFile != nil {
		o.extraFiles = []*os.File{r.envFile}
	}
	var forced atomic.Bool
	deadline := r.timeout + session.TimeoutKillAfter + timeoutGrace
	onDeadline := func(p *os.Process) {
		forced.Store(true)
		if r.ephemeral {
			_ = m.Docker.Remove(context.Background(), config.ContainerName(r.name), true)
		}
		_ = p.Kill()
	}
	if r.timeout > 0 && r.verify == nil {
		o.deadline, o.onDeadline = deadline, onDeadline
	}
	start := time.Now()
	// With verify, the command starts once it returns, so the timeout is
	// counted from then. start and timer are only read after verified
	// has been received.
	var timer *time.Timer
	// launched is set when docker started, by runChild before it returns.
	launched := false
	verified := make(chan error, 1)
	exited := make(chan struct{})
	if r.verify != nil {
		ctx := cmd.Context()
		if ctx == nil {
			ctx = context.Background()
		}
		o.started = func(p *os.Process) {
			launched = true
			go func() {
				err := r.verify(ctx, exited)
				if err == nil {
					start = time.Now()
					if r.timeout > 0 {
						timer = time.AfterFunc(deadline, func() { onDeadline(p) })
					}
				} else {
					// docker exits once its container is gone; this
					// only makes sure it does.
					_ = p.Kill()
				}
				verified <- err
			}()
		}
	}
	code, err := runChild(argv, o)
	close(exited)
	if launched {
		verr := <-verified
		if timer != nil {
			timer.Stop()
		}
		if verr != nil && !errors.Is(verr, session.ErrExited) {
			return verifyReport(cmd.ErrOrStderr(), errors.Join(verr, err))
		}
	}
	if err != nil {
		return err
	}
	if timedOut(r.timeout, time.Since(start), code, forced.Load()) {
		msg := fmt.Sprintf("the command timed out after %s", r.timeout)
		if forced.Load() && !r.ephemeral {
			msg += fmt.Sprintf(", and may still be running in sandbox %q: stop it with `safeclaw sandbox stop %s`", r.name, r.name)
		}
		printError(cmd.ErrOrStderr(), errors.New(msg))
		return exitCodeError{timeoutExitCode}
	}
	if code != 0 {
		return exitCodeError{code}
	}
	return nil
}

// timedOut reports whether a command run with timeout was stopped by it:
// safeclaw had to stop docker itself, or the in-container timeout exited
// 124 (after SIGTERM) or 137 (after SIGKILL) once timeout had passed. A
// command that exits 124 on its own sooner is not mistaken for one that
// timed out.
func timedOut(timeout, elapsed time.Duration, code int, forced bool) bool {
	if timeout <= 0 {
		return false
	}
	return forced || elapsed >= timeout && (code == timeoutExitCode || code == 128+int(syscall.SIGKILL))
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
			"so files with the same name never overwrite each other. Numbers above 999999999 are ignored, and a destination " +
			"whose listing is over 8 MiB is refused. The container path of each file is printed, in order, " +
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
	var force, replace, noScan, allowFlagged, mkdir bool
	var maxSize string
	var maxFiles int
	cmd := &cobra.Command{
		Use:   "cp-out NAME CONTAINER_DIR HOST_DIR --only GLOB...",
		Short: "Copy matching files out of a running sandbox",
		Long: "Copy the regular files directly in CONTAINER_DIR whose names match an --only glob into HOST_DIR.\n\n" +
			"Symbolic links, hard links, directories, sparse files, other file types, and anything in subdirectories are dropped. " +
			"A kept file whose name is not printable UTF-8 or starts with - refuses the whole copy, and as in a shell, " +
			"names starting with . only match a glob that starts with . too. " +
			"HOST_DIR must exist unless --mkdir is set, which creates it and its missing parents with mode 0755, less the umask, " +
			"only once every file has arrived and passed every check, so a refused or failed copy creates nothing. " +
			"An existing HOST_DIR, or a symbolic link to a directory, is used as it is, with or without --mkdir, and anything else that exists is refused. " +
			"--mkdir refuses a dangling symbolic link, or one to a non-directory, as HOST_DIR or its nearest existing parent, so it never creates anything through one; " +
			"other links among the existing parents are followed, as mkdir -p does. " +
			"Files are read as the sandbox user and written with mode 0644, less the umask. Nothing is written unless every file arrives, " +
			"and existing files are refused unless --force is set. " +
			"--replace implies --force and, once every file has arrived and passed every check, also removes the regular files in HOST_DIR that match an --only glob but were not copied, " +
			"keeping symbolic links, directories, and everything else; if any move fails, HOST_DIR is left as it was. More files than --max-files, or more bytes than --max-size, refuse the whole copy. The host path of each file is printed, quoted when it is not printable text.\n\n" +
			"Every file is scanned for malware with ClamAV before anything is placed, in a fresh container with no network that sees only the copied files and the signatures, " +
			"so nothing running in the sandbox can change the result. A file flagged as infected, or that could not be scanned (over the scanner's size limits, or an encrypted archive or document), " +
			"refuses the whole copy, naming each file and the reason, and HOST_DIR is left as it was, with --force and --replace too. --allow-flagged copies them anyway, and --no-scan skips the scan. " +
			"Each file's result and the signatures' date are printed to stderr. With no signatures installed the copy is refused: run `safeclaw sandbox update-signatures` first, or pass --no-scan. " +
			"The scan needs the sandbox variant's image, and gets the sandbox's CPU and process limits with at least " + session.DefaultScanMemory + " of memory, since clamscan holds the whole signature database in memory.",
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
			if noScan && allowFlagged {
				return errors.New("--allow-flagged can't be used with --no-scan")
			}
			res, err := newManager().CopyOutReport(cmd.Context(), args[0], args[1], args[2], session.CopyOutOptions{
				Only:         only,
				Force:        force,
				Replace:      replace,
				MaxSize:      limit,
				MaxFiles:     maxFiles,
				NoScan:       noScan,
				AllowFlagged: allowFlagged,
				Mkdir:        mkdir,
			})
			if flagged, ok := errors.AsType[*session.FlaggedError](err); ok {
				writeCopyScan(cmd.ErrOrStderr(), flagged.Report, "refused")
			}
			if err != nil {
				return err
			}
			switch {
			case res.Scan != nil:
				writeCopyScan(cmd.ErrOrStderr(), res.Scan, "copied because of --allow-flagged")
			case noScan:
				fmt.Fprintln(cmd.ErrOrStderr(), "Not scanned for malware (--no-scan)")
			}
			return writePaths(cmd.OutOrStdout(), res.Paths)
		},
	}
	cmd.Flags().StringArrayVar(&only, "only", nil, "keep files whose names match this glob (repeatable)")
	_ = cmd.MarkFlagRequired("only")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "overwrite existing host files")
	cmd.Flags().BoolVar(&replace, "replace", false, "overwrite existing host files and remove other host files matching --only")
	cmd.Flags().StringVar(&maxSize, "max-size", session.DefaultCopyMaxSize, "limit on the total size of the files kept, with a k, m, g, or t suffix (0 for none)")
	cmd.Flags().IntVar(&maxFiles, "max-files", session.DefaultCopyMaxFiles, "limit on the number of files kept (0 for none)")
	cmd.Flags().BoolVar(&noScan, "no-scan", false, "copy without scanning the files for malware")
	cmd.Flags().BoolVar(&allowFlagged, "allow-flagged", false, "copy files the malware scan flags as infected or could not scan")
	cmd.Flags().BoolVar(&mkdir, "mkdir", false, "create HOST_DIR and its missing parents once the copy has passed every check")
	return cmd
}

// writeCopyScan writes cp-out's scan report to stderr: the signatures, then
// each file's result, with note after each flagged one.
func writeCopyScan(out io.Writer, report *session.ScanReport, note string) {
	fmt.Fprintf(out, "Scanned %d file(s) for malware with ClamAV signatures %s\n", len(report.Results), report.Signatures)
	_ = writeScanResults(out, report.Results, note)
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
	var missingOK bool
	cmd := &cobra.Command{
		Use:   "stop NAME",
		Short: "Stop a sandbox",
		Long: "Stop a sandbox. Its /sandbox is a tmpfs, so the files in it are lost. A one-off sandbox is removed. " +
			"With --missing-ok, a sandbox that doesn't exist, including a one-off one removed meanwhile, or is already stopped is left alone: " +
			"it prints which on stderr and exits 0. A name that belongs to an interactive session is still refused.",
		Example: `  safeclaw sandbox stop triage
  safeclaw sandbox stop --missing-ok "$name"`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeType(config.TypeSandbox),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := resolveArg(cmd, args); err != nil {
				return err
			}
			skipped, err := newManager().StopSandbox(cmd.Context(), args[0], session.SandboxStopOptions{MissingOK: missingOK})
			printSkipped(cmd, args[0], skipped, "stop")
			return err
		},
	}
	cmd.Flags().BoolVar(&missingOK, "missing-ok", false, "exit 0 when the sandbox doesn't exist or is already stopped")
	return cmd
}

func newSandboxRemoveCommand() *cobra.Command {
	var force, missingOK bool
	cmd := &cobra.Command{
		Use:     "rm NAME",
		Aliases: []string{"delete"},
		Short:   "Delete a sandbox",
		Long: "Delete a sandbox. A running one needs -f. " +
			"With --missing-ok, a sandbox that doesn't exist, including a one-off one removed meanwhile, is left alone: " +
			"it prints that on stderr and exits 0. It doesn't stand in for -f, and a name that belongs to an interactive session is still refused.",
		Example: `  safeclaw sandbox rm -f triage
  safeclaw sandbox rm -f --missing-ok "$name"`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeType(config.TypeSandbox),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := resolveArg(cmd, args); err != nil {
				return err
			}
			skipped, err := newManager().DeleteSandbox(cmd.Context(), args[0], session.SandboxStopOptions{Force: force, MissingOK: missingOK})
			printSkipped(cmd, args[0], skipped, "remove")
			return err
		},
	}
	cmd.Flags().BoolVarP(&force, "force", "f", false, "remove a running sandbox too")
	cmd.Flags().BoolVar(&missingOK, "missing-ok", false, "exit 0 when the sandbox doesn't exist")
	return cmd
}

// printSkipped tells stderr why `sandbox stop` or `sandbox rm` did nothing,
// keeping stdout empty for scripts. verb is "stop" or "remove".
func printSkipped(cmd *cobra.Command, name string, skipped session.Skipped, verb string) {
	if skipped != session.NotSkipped {
		fmt.Fprintf(cmd.ErrOrStderr(), "Sandbox %q is %s, nothing to %s\n", name, skipped, verb)
	}
}

// variantColumn returns a session's variant for listings, "-" for the base
// image.
func variantColumn(s session.Session) string {
	if s.Variant == "" {
		return "-"
	}
	return s.Variant
}
