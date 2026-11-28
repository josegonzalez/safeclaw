package cli

import (
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/spf13/cobra"

	"github.com/josegonzalez/safeclaw/internal/secrets"
	"github.com/josegonzalez/safeclaw/internal/session"
)

const keepInputsHelp = "With --rm --keep-inputs DIR, the sandbox keeps a record of its inputs in DIR/" + session.InputsFile + ": " +
	"each file `sandbox cp-in` copies in, by its absolute host path, sha256, size, and container path, and the flags of each `sandbox open` run, " +
	"never a copy of a file, so keep the originals where they are. DIR is created mode 0700 if it doesn't exist; " +
	"an existing one must not be a symbolic link, must be yours and mode 0700, and must not hold a record already.\n\n" +
	"With --rm --restore-from DIR, a new one-off sandbox is created from that record, verified if it was made with --verify or --verify is given, " +
	"and each recorded file is copied again from its host path to the same container path. " +
	"Before anything is created, every source is hashed, and any that is missing, is no longer a regular file, or whose size or sha256 changed refuses the restore, naming each. " +
	"The files are only hashed and copied, never opened. The new sandbox keeps recording to DIR. " +
	"The recorded `sandbox open` runs are not run again: they are printed to stderr as commands, in order, " +
	"so that the helpers run only when you run them. Other creation flags, such as --variant, -v, and the limits, are not recorded and apply as given."

// inputFlags are `sandbox run`'s --keep-inputs and --restore-from.
type inputFlags struct {
	keep, restore string
}

func (f *inputFlags) register(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.keep, "keep-inputs", "", "with --rm, record what cp-in copies in and the sandbox open runs made in `DIR`, created mode 0700, so --restore-from can rebuild the sandbox")
	cmd.Flags().StringVar(&f.restore, "restore-from", "", "with --rm, create the sandbox from the record in `DIR`, copying each recorded file from its host path again, and keep recording there")
	_ = cmd.MarkFlagDirname("keep-inputs")
	_ = cmd.MarkFlagDirname("restore-from")
}

// sandboxInputArgs refuses --keep-inputs and --restore-from without --rm,
// empty, or together.
func sandboxInputArgs(cmd *cobra.Command, _ []string) error {
	keep, restore := cmd.Flags().Changed("keep-inputs"), cmd.Flags().Changed("restore-from")
	if !keep && !restore {
		return nil
	}
	if keep && restore {
		return errors.New("--keep-inputs and --restore-from can't be used together: a restored sandbox keeps recording to the --restore-from directory")
	}
	flag := "--keep-inputs"
	if restore {
		flag = "--restore-from"
	}
	if rm, _ := cmd.Flags().GetBool("rm"); !rm {
		return fmt.Errorf("%s can only be used with --rm", flag)
	}
	if v, _ := cmd.Flags().GetString(flag[2:]); v == "" {
		return fmt.Errorf("%s can't be empty", flag)
	}
	return nil
}

// ensure creates the sandbox as `sandbox run` asks: keeping its inputs,
// restored from a record, or neither. A restore's recorded `sandbox open`
// runs are printed to stderr, never run.
func (f inputFlags) ensure(cmd *cobra.Command, m *session.Manager, opts session.SandboxOptions) (*session.Result, error) {
	switch {
	case f.keep != "":
		return m.KeepInputs(cmd.Context(), opts, f.keep)
	case f.restore != "":
		r, err := m.RestoreSandbox(cmd.Context(), opts, f.restore)
		if err != nil {
			return nil, err
		}
		writeReplay(cmd.ErrOrStderr(), r.Name, r.Opens)
		return r.Result, nil
	}
	return m.EnsureSandbox(cmd.Context(), opts)
}

// writeReplay prints the `sandbox open` commands that rebuild a restored
// sandbox's tree, in the order they were run.
func writeReplay(out io.Writer, name string, opens [][]string) {
	if len(opens) == 0 {
		return
	}
	fmt.Fprintf(out, "The record has %d sandbox open run(s). To rebuild %s, run them again in order, adding --password-env where one needed a password:\n", len(opens), session.OpenTreeDir)
	for _, args := range opens {
		words := []string{"safeclaw", "sandbox", "open", name}
		for _, a := range args {
			words = append(words, shellWord(a))
		}
		fmt.Fprintf(out, "  %s\n", strings.Join(words, " "))
	}
}

var plainWord = regexp.MustCompile(`^[A-Za-z0-9_./=:+,@%-]+$`)

// shellWord quotes s for sh when it holds anything but plain characters.
func shellWord(s string) string {
	if plainWord.MatchString(s) {
		return s
	}
	return secrets.ShellQuote(s)
}
