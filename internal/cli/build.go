package cli

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/josegonzalez/safeclaw"
	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/version"
)

func newBuildCommand() *cobra.Command {
	var contextDir string
	var noCache, recreate bool
	cmd := &cobra.Command{
		Use:   "build",
		Short: "Build the safeclaw image",
		Long:  "Build the safeclaw image from the build context embedded in this binary, or from a checkout with --context. Afterwards, warns about session containers that still run an older image.",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			out := cmd.OutOrStdout()
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
			d := docker.New()
			if err := d.R.Passthrough(ctx, args...); err != nil {
				return err
			}
			return reportStale(ctx, d, out, recreate)
		},
	}
	cmd.Flags().StringVar(&contextDir, "context", "", "build from this directory instead of the embedded build context")
	cmd.Flags().BoolVar(&noCache, "no-cache", false, "do not use the docker build cache")
	cmd.Flags().BoolVar(&recreate, "recreate", false, "remove session containers built from an older image (history is kept on the host)")
	return cmd
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
// image, and removes them if recreate is set.
func reportStale(ctx context.Context, d *docker.Client, out io.Writer, recreate bool) error {
	imageID, err := d.ImageID(ctx, config.ImageName)
	if err != nil || imageID == "" {
		return err
	}
	cs, err := d.List(ctx, config.ContainerPrefix)
	if err != nil {
		return err
	}
	var stale []string
	for _, c := range cs {
		if c.Image != imageID {
			stale = append(stale, c.ShortName())
		}
	}
	if len(stale) == 0 {
		return nil
	}
	if recreate {
		for _, name := range stale {
			fmt.Fprintf(out, "Removing old container: %s\n", name)
			if err := d.Remove(ctx, name, true); err != nil {
				return err
			}
		}
		return nil
	}
	fmt.Fprintln(out, "\nThese sessions still use an older image:")
	for _, name := range stale {
		fmt.Fprintf(out, "  %s\n", config.SessionName(name))
	}
	fmt.Fprintln(out, "\nRemove them with `safeclaw rm -f <name>` (or rebuild with --recreate) so the next run uses the new image. Conversation history is kept on the host.")
	return nil
}
