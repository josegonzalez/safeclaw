package cli

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/variant"
)

func newVariantCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "variant",
		Short: "Inspect image variants",
		Long: "An image variant is the safeclaw image with extra packages or setup steps, tagged safeclaw:NAME. " +
			"The built-in sandbox variant adds document extraction tools and is what sandboxes use by default. " +
			"More variants, and the defaults, can be set in " + config.File() + ".",
	}
	cmd.AddCommand(newVariantListCommand(), newVariantDockerfileCommand())
	return cmd
}

func newVariantListCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "ls",
		Aliases: []string{"list"},
		Short:   "List image variants and whether their images exist",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			set, err := loadVariants()
			if err != nil {
				return err
			}
			d := newDocker()
			present := map[string]bool{}
			for _, name := range append([]string{""}, set.Names()...) {
				id, err := d.ImageID(cmd.Context(), variant.Image(name))
				if err != nil {
					return err
				}
				present[name] = id != ""
			}
			return writeVariants(cmd.OutOrStdout(), set, present)
		},
	}
}

// writeVariants writes the `safeclaw variant ls` table. present reports
// which variants' images exist, keyed by name ("" for the base image).
func writeVariants(out io.Writer, set *variant.Set, present map[string]bool) error {
	w := tabwriter.NewWriter(out, 0, 0, 3, ' ', 0)
	fmt.Fprintln(w, "VARIANT\tSOURCE\tPACKAGES\tIMAGE\tDEFAULT FOR")
	row := func(name, source, packages string) {
		image := variant.Image(name)
		if present[name] {
			image += " (present)"
		} else {
			image += " (missing)"
		}
		defaults := strings.Join(set.DefaultTypes(name), ", ")
		if defaults == "" {
			defaults = "-"
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", variant.Label(name), source, packages, image, defaults)
	}
	row("", variant.SourceBuiltin, "-")
	for _, v := range set.All() {
		packages := strings.Join(v.Packages, " ")
		if len(v.Run) > 0 {
			if packages != "" {
				packages += " "
			}
			packages += fmt.Sprintf("(+%d run)", len(v.Run))
		}
		row(v.Name, v.Source, packages)
	}
	return w.Flush()
}

func newVariantDockerfileCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "dockerfile NAME",
		Short: "Print the Dockerfile that builds a variant",
		Long:  "Print the Dockerfile that builds a variant on top of the image named by its BASE build argument (the local safeclaw image by default).",
		Args:  cobra.ExactArgs(1),
		ValidArgsFunction: func(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
			if len(args) > 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			set, err := loadVariants()
			if err != nil {
				return nil, cobra.ShellCompDirectiveError
			}
			return set.Names(), cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			set, err := loadVariants()
			if err != nil {
				return err
			}
			v, err := set.Get(args[0])
			if err != nil {
				return err
			}
			_, err = io.WriteString(cmd.OutOrStdout(), variant.Dockerfile(v))
			return err
		},
	}
}
