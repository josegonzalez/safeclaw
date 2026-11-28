package cli

import (
	"fmt"
	"slices"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/josegonzalez/safeclaw/internal/profile"
)

const (
	// profileFlag is the flag naming a sandbox profile.
	profileFlag = "profile"
	// profileSet is the annotation on each flag a profile set.
	profileSet = "safeclaw/profile-set"
	// profileRefKey and profileSumKey are the command annotations holding
	// the ref and SHA-256 of the profile applied to it.
	profileRefKey = "safeclaw/profile"
	profileSumKey = "safeclaw/profile-sha256"
)

// profileCommands returns a new command for each profile section, whose
// flags a profile is checked against.
func profileCommands() map[string]*cobra.Command {
	return map[string]*cobra.Command{
		profile.Run:     newSandboxRunCommand(),
		profile.Exec:    newSandboxExecCommand(),
		profile.CopyOut: newSandboxCopyOutCommand(),
		profile.Open:    newSandboxOpenCommand(),
	}
}

// useProfile adds --profile to cmd, whose profile section is section. The
// profile is applied to cmd's flags before its arguments are checked, so
// every check after that, and RunE, sees its values as if they had been
// given on the command line. A flag given on the command line wins over
// the profile, and for a list flag replaces the profile's whole list.
func useProfile(cmd *cobra.Command, section string) {
	cmd.Flags().String(profileFlag, "", "read defaults for this command's flags from the "+section+" section of a sandbox profile: "+
		"a FILE (a path with a / or ending in .yaml), or a NAME for ~/.config/safeclaw/profiles/NAME.yaml ($XDG_CONFIG_HOME/safeclaw/profiles); flags given here win")
	args := cmd.Args
	cmd.Args = func(c *cobra.Command, a []string) error {
		if err := applyProfile(c, section); err != nil {
			return err
		}
		if args == nil {
			return nil
		}
		return args(c, a)
	}
}

// applyProfile loads the profile --profile names, checks all of it against
// the commands' flags, and sets the flags of section that the command line
// didn't. Some keys apply only when they make sense with the rest:
// run.name-prefix with --rm and without -s, open's safeclaw-totext policy
// with --text, and, for `sandbox exec --ephemeral`, the run section's
// limits, variant, and verify, since that creates a sandbox too.
func applyProfile(cmd *cobra.Command, section string) error {
	if !cmd.Flags().Changed(profileFlag) {
		return nil
	}
	ref, _ := cmd.Flags().GetString(profileFlag)
	p, err := profile.Load(ref)
	if err != nil {
		return err
	}
	if err := checkProfile(p); err != nil {
		return err
	}
	fs := cmd.Flags()
	type pending struct {
		section string
		s       profile.Setting
		when    func() bool
	}
	var settings []pending
	add := func(sec string, when func(profile.Setting) func() bool) {
		for _, s := range p.Section(sec) {
			settings = append(settings, pending{sec, s, when(s)})
		}
	}
	always := func(profile.Setting) func() bool { return nil }
	flagOn := func(name string) func() bool {
		return func() bool { on, _ := fs.GetBool(name); return on }
	}
	switch section {
	case profile.Run:
		add(section, func(s profile.Setting) func() bool {
			if s.Key == "name-prefix" {
				return func() bool { return flagOn("rm")() && !fs.Changed("session") }
			}
			return nil
		})
	case profile.Exec:
		add(section, always)
		add(profile.Run, func(s profile.Setting) func() bool {
			if fs.Lookup(s.Key) == nil {
				return func() bool { return false }
			}
			return flagOn("ephemeral")
		})
	case profile.Open:
		add(section, func(s profile.Setting) func() bool {
			if slices.Contains(openTotextFlags, s.Key) {
				return flagOn("text")
			}
			return nil
		})
	default:
		add(section, always)
	}
	// Unconditional settings first, so the conditions see them.
	for _, conditional := range []bool{false, true} {
		for _, s := range settings {
			if (s.when != nil) != conditional || s.when != nil && !s.when() {
				continue
			}
			if err := setFromProfile(fs, p.Ref, s.section, s.s); err != nil {
				return err
			}
		}
	}
	if section == profile.Exec && fromProfile(fs, "escape-controls") {
		if tty, _ := fs.GetBool("tty"); tty {
			return fmt.Errorf("profile %s sets exec.escape-controls, which can't be used with -t; pass --escape-controls=false to run with a TTY", p.Ref)
		}
	}
	if cmd.Annotations == nil {
		cmd.Annotations = map[string]string{}
	}
	cmd.Annotations[profileRefKey], cmd.Annotations[profileSumKey] = p.Ref, p.SHA256
	return nil
}

// setFromProfile sets a flag to a setting's values, unless the command line
// gave it, and marks it as set by the profile.
func setFromProfile(fs *pflag.FlagSet, ref, section string, s profile.Setting) error {
	f := fs.Lookup(s.Key)
	if f == nil {
		return fmt.Errorf("profile %s: %s.%s has no --%s flag here", ref, section, s.Key, s.Key)
	}
	if f.Changed && !fromProfile(fs, s.Key) {
		return nil
	}
	for _, v := range s.Values {
		if err := fs.Set(s.Key, v); err != nil {
			return fmt.Errorf("profile %s: %s.%s: %w", ref, section, s.Key, err)
		}
	}
	return fs.SetAnnotation(s.Key, profileSet, []string{ref})
}

// fromProfile reports whether a profile set the named flag.
func fromProfile(fs *pflag.FlagSet, name string) bool {
	f := fs.Lookup(name)
	return f != nil && f.Annotations[profileSet] != nil
}

// checkProfile sets every setting of every section on a new command of its
// own, so a value no flag takes fails every command that names the
// profile, not just the one whose section has it.
func checkProfile(p *profile.Profile) error {
	cmds := profileCommands()
	for _, section := range profile.Sections() {
		for _, s := range p.Section(section) {
			if err := setFromProfile(cmds[section].Flags(), p.Ref, section, s); err != nil {
				return err
			}
		}
	}
	return nil
}

// flagSources returns whether each flag was set, by the command line or a
// profile, and whether it was typed on the command line.
func flagSources(cmd *cobra.Command) (set, typed func(string) bool) {
	fs := cmd.Flags()
	return fs.Changed, func(name string) bool { return fs.Changed(name) && !fromProfile(fs, name) }
}

// appliedProfile returns the ref and SHA-256 of the profile applied to
// cmd, empty when there is none.
func appliedProfile(cmd *cobra.Command) (ref, sum string) {
	return cmd.Annotations[profileRefKey], cmd.Annotations[profileSumKey]
}
