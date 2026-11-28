package expand

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// source is a file to copy in as an input.
type source struct {
	path string
	// inDir is set for a file found in an input directory, which is opened
	// without following a link, as it was listed.
	inDir bool
}

// resolveInputs checks the inputs and returns the files they name, in
// order: an input that is a regular file, or a link to one, is itself; one
// that is a directory, or a link to one, is every regular file directly in
// it, sorted by name. Anything else in a directory is left out without
// being followed, and given to ignore with why. A directory must not be
// dest, hold dest, or be inside it.
func resolveInputs(inputs []string, dest string, ignore func(path, why string)) ([]source, error) {
	var out []source
	var destReal string
	for _, in := range inputs {
		fi, err := os.Stat(in)
		if err != nil {
			return nil, err
		}
		if fi.Mode().IsRegular() {
			out = append(out, source{path: in})
			continue
		}
		if !fi.IsDir() {
			return nil, fmt.Errorf("%s is not a regular file or a directory", in)
		}
		dir, err := realPath(in)
		if err != nil {
			return nil, err
		}
		if destReal == "" {
			if destReal, err = realPath(dest); err != nil {
				return nil, err
			}
		}
		switch {
		case within(destReal, dir):
			return nil, fmt.Errorf("%s is inside the input directory %s", dest, in)
		case within(dir, destReal):
			return nil, fmt.Errorf("the input directory %s is inside %s", in, dest)
		}
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			p := filepath.Join(in, e.Name())
			switch t := e.Type(); {
			case t.IsRegular():
				out = append(out, source{path: filepath.Join(dir, e.Name()), inDir: true})
			case ignore == nil:
			case t&fs.ModeSymlink != 0:
				ignore(p, "a symbolic link")
			case t.IsDir():
				ignore(p, "a directory")
			default:
				ignore(p, "not a regular file")
			}
		}
	}
	return out, nil
}

// realPath is p made absolute with every link resolved, the part of it that
// doesn't exist yet kept as it is.
func realPath(p string) (string, error) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	var rest []string
	for {
		real, err := filepath.EvalSymlinks(abs)
		if err == nil {
			return filepath.Join(append([]string{real}, rest...)...), nil
		}
		parent := filepath.Dir(abs)
		if !errors.Is(err, fs.ErrNotExist) || parent == abs {
			return "", err
		}
		rest = append([]string{filepath.Base(abs)}, rest...)
		abs = parent
	}
}

// within reports whether p is dir or inside it, both clean absolute paths.
func within(p, dir string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}
