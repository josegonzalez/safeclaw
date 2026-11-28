package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/josegonzalez/safeclaw"
	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/session"
	"github.com/josegonzalez/safeclaw/internal/variant"
	"github.com/josegonzalez/safeclaw/internal/version"
)

// newDocker, newManager, and loadVariants are replaced in tests.
var (
	newDocker    = docker.New
	newManager   = func() *session.Manager { return session.NewManager(nil) }
	loadVariants = func() (*variant.Set, error) { return variant.Load(config.File()) }
)

func newBuildCommand() *cobra.Command {
	var contextDir string
	var variants []string
	var noCache, recreate bool
	cmd := &cobra.Command{
		Use:   "build",
		Short: "Build the safeclaw image and its variants",
		Long: "Build the safeclaw image from the build context embedded in this binary, or from a checkout with --context. " +
			"Then build each variant named with --variant, and rebuild every variant already built locally, so none is left on the old image. " +
			"Afterwards, warns about session containers that still run an older image.",
		Example: `  safeclaw build
  safeclaw build --variant sandbox`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			out := cmd.OutOrStdout()
			set, err := loadVariants()
			if err != nil {
				return err
			}
			d := newDocker()
			// Find the variants to rebuild before the base image changes.
			refresh, err := variantsToRefresh(ctx, d, set, variants)
			if err != nil {
				return err
			}
			dir := contextDir
			if dir == "" {
				tmp, err := os.MkdirTemp("", "safeclaw-build-")
				if err != nil {
					return err
				}
				defer func() { _ = os.RemoveAll(tmp) }()
				if err := extractFS(safeclaw.BuildContext, tmp); err != nil {
					return err
				}
				dir = tmp
			}

			fmt.Fprintln(out, "Building image...")
			args := []string{"build", "-t", config.ImageName,
				"--build-arg", "VERSION=" + version.Version,
				"--build-arg", "COMMIT=" + version.Commit,
				"--build-arg", "DATE=" + version.Date,
			}
			if noCache {
				args = append(args, "--no-cache")
			}
			args = append(args, dir)
			if err := d.R.Passthrough(ctx, args...); err != nil {
				return err
			}
			for _, v := range refresh {
				if err := buildVariant(ctx, d, out, v, noCache); err != nil {
					return err
				}
			}
			return reportStale(ctx, d, out, recreate)
		},
	}
	cmd.Flags().StringVar(&contextDir, "context", "", "build from this directory instead of the embedded build context")
	cmd.Flags().StringSliceVar(&variants, "variant", nil, "also build this image variant (repeatable)")
	_ = cmd.RegisterFlagCompletionFunc("variant", completeVariants)
	cmd.Flags().BoolVar(&noCache, "no-cache", false, "do not use the docker build cache")
	cmd.Flags().BoolVar(&recreate, "recreate", false, "remove session containers built from an older image (history and their secrets and auto memory choices are kept on the host)")
	return cmd
}

// variantsToRefresh returns the requested variants plus every variant whose
// image exists locally, sorted by name. Requesting base is a no-op.
func variantsToRefresh(ctx context.Context, d *docker.Client, set *variant.Set, requested []string) ([]variant.Variant, error) {
	want := map[string]bool{}
	for _, name := range requested {
		name, err := set.Resolve(name)
		if err != nil {
			return nil, err
		}
		if name != "" {
			want[name] = true
		}
	}
	var out []variant.Variant
	for _, v := range set.All() {
		if !want[v.Name] {
			id, err := d.ImageID(ctx, v.Image())
			if err != nil {
				return nil, err
			}
			if id == "" {
				continue
			}
		}
		out = append(out, v)
	}
	return out, nil
}

// buildVariant builds a variant on top of the local base image.
func buildVariant(ctx context.Context, d *docker.Client, out io.Writer, v variant.Variant, noCache bool) error {
	dir, err := os.MkdirTemp("", "safeclaw-variant-")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(variant.Dockerfile(v)), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(out, "Building variant %s...\n", v.Name)
	args := []string{"build", "-t", v.Image(), "--build-arg", "BASE=" + config.ImageName}
	if noCache {
		args = append(args, "--no-cache")
	}
	return d.R.Passthrough(ctx, append(args, dir)...)
}

// pullVariant pulls a published built-in variant for tag and tags it
// locally, verifying it first when ver is set. Variants from the config
// file are built on the local base image instead.
func pullVariant(ctx context.Context, d *docker.Client, out io.Writer, ver *verifier, v variant.Variant, tag string) error {
	if !v.Published() {
		return buildVariant(ctx, d, out, v, false)
	}
	ref := variant.RemoteRef(tag, v.Name)
	if err := pullImage(ctx, d, out, ver, ref, v.Image()); err != nil {
		return fmt.Errorf("pull %s: %w (build it locally with `safeclaw build --variant %s`)", ref, err, v.Name)
	}
	return nil
}

// extractFS writes an fs.FS to dir.
func extractFS(src fs.FS, dir string) error {
	return fs.WalkDir(src, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		target := filepath.Join(dir, filepath.FromSlash(path))
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		in, err := src.Open(path)
		if err != nil {
			return err
		}
		defer func() { _ = in.Close() }()
		mode := os.FileMode(0o644)
		if filepath.Ext(path) == ".sh" {
			mode = 0o755
		}
		f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
		if err != nil {
			return err
		}
		if _, err := io.Copy(f, in); err != nil {
			_ = f.Close()
			return err
		}
		return f.Close()
	})
}

// reportStale lists session containers that are not running the current
// image of their variant, and removes them if recreate is set.
func reportStale(ctx context.Context, d *docker.Client, out io.Writer, recreate bool) error {
	m := newManager()
	m.Docker = d
	cs, err := d.List(ctx, config.ContainerPrefix)
	if err != nil {
		return err
	}
	ids := map[string]string{}
	var stale []docker.Container
	for _, c := range cs {
		image := variant.Image(c.Label(config.LabelVariant))
		id, ok := ids[image]
		if !ok {
			if id, err = d.ImageID(ctx, image); err != nil {
				return err
			}
			ids[image] = id
		}
		// A container whose image is gone is stale too.
		if id == "" || c.Image != id {
			stale = append(stale, c)
		}
	}
	if len(stale) == 0 {
		return nil
	}
	if recreate {
		for _, c := range stale {
			name := config.SessionName(c.ShortName())
			removed, err := m.RemoveStale(ctx, c)
			switch {
			case errors.Is(err, session.ErrOffline):
				fmt.Fprintf(out, "Skipping offline session: %s (run `safeclaw net on %s`, then rebuild with --recreate)\n", name, name)
			case errors.Is(err, session.ErrUnreadableState):
				fmt.Fprintf(out, "Skipping session: %v\n", err)
			case err != nil:
				return err
			case removed:
				fmt.Fprintf(out, "Removed old container: %s\n", c.ShortName())
			}
		}
		return nil
	}
	fmt.Fprintln(out, "\nThese sessions still use an older image:")
	sandboxes := false
	for _, c := range stale {
		name := config.SessionName(c.ShortName())
		if session.TypeOf(c) == config.TypeSandbox {
			sandboxes = true
			name += " (sandbox)"
		}
		if held, _ := m.OfflineOrHeld(c); held {
			name += " (offline)"
		}
		fmt.Fprintf(out, "  %s\n", name)
	}
	fmt.Fprintln(out, "\nRemove them with `safeclaw rm -f <name>` (or rebuild with --recreate) so the next run uses the new image. Conversation history is kept on the host, and the next run keeps their secrets and auto memory choices.")
	if sandboxes {
		fmt.Fprintln(out, "Remove sandboxes with `safeclaw sandbox rm -f <name>`.")
	}
	return nil
}
