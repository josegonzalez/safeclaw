package session

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
)

const (
	// DefaultCopyDest is where cp-in puts files unless told otherwise.
	DefaultCopyDest = config.SandboxDir + "/in"
	// DefaultCopyMaxSize is cp-out's default limit on the total size of the
	// files it keeps.
	DefaultCopyMaxSize = "1g"
	// DefaultCopyMaxFiles is cp-out's default limit on the number of files
	// it keeps.
	DefaultCopyMaxFiles = 1000

	// The in-container tools copies use. Absolute paths, so nothing on the
	// sandbox's PATH is consulted.
	tarBin   = "/usr/bin/tar"
	mkdirBin = "/usr/bin/mkdir"
	lsBin    = "/usr/bin/ls"

	// copyFileMode is the mode of every copied file, in either direction.
	copyFileMode = 0o644
)

// ErrSymlink is returned when cp-in is given a symbolic link.
var ErrSymlink = errors.New("is a symbolic link")

// ErrNotRegular is returned when cp-in is given anything but a regular file.
var ErrNotRegular = errors.New("is not a regular file")

// ErrCopyDest is returned when a cp-in destination is outside /sandbox.
var ErrCopyDest = errors.New("must be " + config.SandboxDir + " or a directory under it")

// ErrNoGlob is returned when cp-out is given no --only glob.
var ErrNoGlob = errors.New("at least one --only glob is required")

// ErrTooLarge is returned when the files cp-out keeps exceed its limit.
var ErrTooLarge = errors.New("exceeds the --max-size limit")

// ErrTooManyFiles is returned when cp-out would keep more files than its
// limit.
var ErrTooManyFiles = errors.New("exceeds the --max-files limit")

// ErrFileExists is returned when cp-out would overwrite a host file.
var ErrFileExists = errors.New("already exists (--force overwrites)")

// ErrIsDirectory is returned when cp-out would replace a host directory.
var ErrIsDirectory = errors.New("is a directory")

// ErrUnsafeName is returned when cp-out would keep a file whose name is not
// safe to create and print on the host.
var ErrUnsafeName = errors.New("is not a safe file name: names must be printable UTF-8 and must not start with -")

// copyExec runs copy commands as the sandbox user, so a copy can only read
// and write what the sandbox user can.
var copyExec = docker.ExecOptions{User: config.SandboxUser, Workdir: config.SandboxDir}

// copyTarget returns the short name of the running sandbox a copy applies
// to, refusing interactive sessions and stopped sandboxes.
func (m *Manager) copyTarget(ctx context.Context, name string) (string, error) {
	name = config.SessionName(name)
	if err := ValidateName(name); err != nil {
		return "", err
	}
	c, err := m.Docker.InspectOne(ctx, config.ContainerName(name))
	if err != nil {
		return "", err
	}
	if c == nil {
		return "", fmt.Errorf("session %q %w", name, ErrNotFound)
	}
	if TypeOf(*c) != config.TypeSandbox {
		return "", wrongType(name, ErrNotSandbox)
	}
	if !c.State.Running {
		return "", fmt.Errorf("sandbox %q %w: start it with `safeclaw sandbox run -s %s`", name, ErrNotRunning, name)
	}
	return name, nil
}

func (m *Manager) copyDir() string {
	if m.CopyDir != "" {
		return m.CopyDir
	}
	return config.CopyDir()
}

// source is a host file checked for cp-in. f stays open until it is sent,
// so the file checked is the file sent.
type source struct {
	path    string
	f       *os.File
	size    int64
	modTime time.Time
}

// openSource opens a host file for cp-in, refusing symbolic links and
// anything that is not a regular file.
func openSource(p string) (*source, error) {
	fi, err := os.Lstat(p)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s %w", p, ErrSymlink)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s %w", p, ErrNotRegular)
	}
	// O_NOFOLLOW refuses a symlink swapped in since the Lstat, and
	// O_NONBLOCK keeps a swapped-in fifo from blocking the open.
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	if !st.Mode().IsRegular() || !os.SameFile(fi, st) {
		_ = f.Close()
		return nil, fmt.Errorf("%s changed while being checked", p)
	}
	return &source{path: p, f: f, size: st.Size(), modTime: st.ModTime()}, nil
}

// sandboxDest returns the cleaned cp-in destination: DefaultCopyDest when
// empty, relative paths resolved against /sandbox, and nothing outside it.
func sandboxDest(dest string) (string, error) {
	if dest == "" {
		return DefaultCopyDest, nil
	}
	d := dest
	if !path.IsAbs(d) {
		d = path.Join(config.SandboxDir, d)
	}
	d = path.Clean(d)
	if d != config.SandboxDir && !strings.HasPrefix(d, config.SandboxDir+"/") {
		return "", fmt.Errorf("destination %q %w", dest, ErrCopyDest)
	}
	return d, nil
}

// nextIndex returns the number after the highest N in the N-name entries
// of an `ls -1A` listing, 1 when there are none.
func nextIndex(listing []byte) int {
	highest := 0
	for line := range strings.SplitSeq(string(listing), "\n") {
		digits, _, ok := strings.Cut(line, "-")
		if !ok || digits == "" || strings.TrimLeft(digits, "0123456789") != "" {
			continue
		}
		n, err := strconv.Atoi(digits)
		if err != nil || n == math.MaxInt {
			continue
		}
		highest = max(highest, n)
	}
	return highest + 1
}

// writeTar writes each source as a regular file named names[i], sending
// exactly the size that was checked.
func writeTar(w io.Writer, srcs []*source, names []string) error {
	tw := tar.NewWriter(w)
	for i, s := range srcs {
		hdr := &tar.Header{
			Typeflag: tar.TypeReg,
			Name:     names[i],
			Mode:     copyFileMode,
			Size:     s.size,
			ModTime:  s.modTime,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if _, err := io.CopyN(tw, s.f, s.size); err != nil {
			if errors.Is(err, io.EOF) {
				return fmt.Errorf("%s shrank while being copied", s.path)
			}
			return fmt.Errorf("%s: %w", s.path, err)
		}
	}
	return tw.Close()
}

// errCopyDone stops the cp-in tar writer once docker has exited.
var errCopyDone = errors.New("copy finished")

// CopyIn copies regular host files into a running sandbox's dest (default
// DefaultCopyDest), naming each N-basename with N continuing after the
// highest number already there, so names never collide. Files are
// extracted by the sandbox user, so it owns them. It returns the container
// path of each file, in the order given.
func (m *Manager) CopyIn(ctx context.Context, name string, files []string, dest string) ([]string, error) {
	if len(files) == 0 {
		return nil, errors.New("at least one file is required")
	}
	dest, err := sandboxDest(dest)
	if err != nil {
		return nil, err
	}
	name, err = m.copyTarget(ctx, name)
	if err != nil {
		return nil, err
	}
	srcs := make([]*source, 0, len(files))
	defer func() {
		for _, s := range srcs {
			_ = s.f.Close()
		}
	}()
	for _, f := range files {
		s, err := openSource(f)
		if err != nil {
			return nil, err
		}
		srcs = append(srcs, s)
	}

	// The lock keeps concurrent copies from picking the same numbers; tar's
	// -k refuses to overwrite anything regardless.
	unlock, err := lockFile(m.copyDir())
	if err != nil {
		return nil, err
	}
	defer unlock()
	container := config.ContainerName(name)
	if _, err := m.Docker.Exec(ctx, container, copyExec, mkdirBin, "-p", "--", dest); err != nil {
		return nil, err
	}
	listing, err := m.Docker.Exec(ctx, container, copyExec, lsBin, "-1A", "--", dest)
	if err != nil {
		return nil, err
	}
	first := nextIndex(listing)
	names := make([]string, len(srcs))
	paths := make([]string, len(srcs))
	for i, s := range srcs {
		names[i] = fmt.Sprintf("%d-%s", first+i, filepath.Base(s.path))
		paths[i] = path.Join(dest, names[i])
	}

	pr, pw := io.Pipe()
	done := make(chan error, 1)
	go func() {
		err := writeTar(pw, srcs, names)
		_ = pw.CloseWithError(err)
		done <- err
	}()
	opts := copyExec
	opts.Stdin = pr
	_, execErr := m.Docker.Exec(ctx, container, opts, tarBin, "-x", "-f", "-", "-k", "-C", dest)
	// Unblock the writer if docker exited before reading everything.
	_ = pr.CloseWithError(errCopyDone)
	if err := <-done; err != nil && !errors.Is(err, errCopyDone) {
		return nil, err
	}
	if execErr != nil {
		return nil, execErr
	}
	return paths, nil
}

// CopyOutOptions configures CopyOut.
type CopyOutOptions struct {
	// Only lists the globs (path.Match) a file name must match one of.
	Only []string
	// Force overwrites existing host files.
	Force bool
	// MaxSize caps the total size of the files kept. 0 means no limit.
	MaxSize int64
	// MaxFiles caps the number of files kept. 0 means no limit.
	MaxFiles int
}

// CopyOut copies the regular files directly in a running sandbox's src
// whose names match opts.Only into the existing hostDir. Links,
// directories, other file types, and anything nested are dropped. The
// files are read by the sandbox user and land with mode 0644, less the
// umask. Nothing is written to hostDir unless every file arrives, and
// existing names are refused unless opts.Force is set. It returns the host
// path of each file, sorted.
func (m *Manager) CopyOut(ctx context.Context, name, src, hostDir string, opts CopyOutOptions) ([]string, error) {
	if len(opts.Only) == 0 {
		return nil, ErrNoGlob
	}
	for _, g := range opts.Only {
		if _, err := path.Match(g, ""); err != nil {
			return nil, fmt.Errorf("--only %q: %w", g, err)
		}
	}
	if opts.MaxSize < 0 {
		return nil, errors.New("--max-size must not be negative")
	}
	if opts.MaxFiles < 0 {
		return nil, errors.New("--max-files must not be negative")
	}
	if src == "" {
		return nil, errors.New("a sandbox directory is required")
	}
	fi, err := os.Stat(hostDir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", hostDir)
	}
	name, err = m.copyTarget(ctx, name)
	if err != nil {
		return nil, err
	}

	tmp, err := os.MkdirTemp(hostDir, ".safeclaw-cp-*")
	if err != nil {
		return nil, err
	}
	defer func() { _ = os.RemoveAll(tmp) }()
	// The exclude only saves sending nested files; extractTop drops them
	// anyway.
	out, wait, err := m.Docker.ExecStream(ctx, config.ContainerName(name), copyExec,
		tarBin, "-c", "-f", "-", "--exclude=./*/*", "-C", src, ".")
	if err != nil {
		return nil, err
	}
	names, err := extractTop(out, tmp, opts)
	if err == nil {
		// Read to the end so tar can exit.
		_, err = io.Copy(io.Discard, out)
	}
	_ = out.Close()
	if waitErr := wait(); err == nil {
		err = waitErr
	}
	if err != nil {
		return nil, err
	}
	return placeFiles(tmp, hostDir, names, opts.Force)
}

// topLevel returns the name of a tar entry directly in the archive's root
// (as written by `tar -C DIR .`), or false for the root itself, nested
// entries, and names that try to leave it.
func topLevel(name string) (string, bool) {
	n := strings.TrimPrefix(name, "./")
	if n == "" || n == "." || n == ".." || strings.Contains(n, "/") || strings.ContainsRune(n, 0) {
		return "", false
	}
	return n, true
}

// printable reports whether s is valid UTF-8 made only of printable runes
// (unicode.IsPrint: no control, format, or non-ASCII space characters).
func printable(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// safeName reports whether a sandbox file name is safe to create and print
// on the host: printable, and not starting with - so it can't pass for an
// option.
func safeName(name string) bool {
	return printable(name) && !strings.HasPrefix(name, "-")
}

// QuotePath returns p as is when it is printable, and quoted with Go
// escapes otherwise, so it prints as one line with no terminal escapes.
func QuotePath(p string) string {
	if printable(p) {
		return p
	}
	return strconv.Quote(p)
}

// extractTop writes the top-level regular files of a tar stream whose
// names match one of opts.Only into dir, returning their names. Sparse
// entries are dropped, so a small stream can't expand into a large file. A
// MaxSize above zero caps the files' total size and a MaxFiles above zero
// their number. Two entries with the same name, or a kept name that
// safeName refuses, are an error.
func extractTop(r io.Reader, dir string, opts CopyOutOptions) ([]string, error) {
	globs, limit := opts.Only, opts.MaxSize
	tr := tar.NewReader(r)
	var names []string
	seen := map[string]bool{}
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return names, nil
		}
		if err != nil {
			return nil, err
		}
		name, ok := topLevel(hdr.Name)
		if !ok || hdr.Typeflag != tar.TypeReg || sparse(hdr) || !matchAny(globs, name) {
			continue
		}
		if !safeName(name) {
			return nil, fmt.Errorf("%q %w", name, ErrUnsafeName)
		}
		if seen[name] {
			return nil, fmt.Errorf("%q appears more than once", name)
		}
		if opts.MaxFiles > 0 && len(names) >= opts.MaxFiles {
			return nil, fmt.Errorf("files matching --only %w (%d files)", ErrTooManyFiles, opts.MaxFiles)
		}
		seen[name] = true
		// Compare against what is left rather than adding first: total never
		// exceeds limit, so limit-total can't overflow, while a declared size
		// near math.MaxInt64 would wrap the sum.
		if limit > 0 && hdr.Size > limit-total {
			return nil, fmt.Errorf("files matching --only %w (%d bytes)", ErrTooLarge, limit)
		}
		total += hdr.Size
		f, err := os.OpenFile(filepath.Join(dir, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, copyFileMode)
		if err != nil {
			return nil, err
		}
		_, err = io.CopyN(f, tr, hdr.Size)
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return nil, fmt.Errorf("%q: %w", name, err)
		}
		names = append(names, name)
	}
}

// sparse reports whether a regular-file entry is a GNU sparse file in PAX
// form, which the reader expands to its logical size. The old GNU form has
// its own type flag and is dropped with the other non-regular types. The
// tar cp-out runs never writes either, since it isn't given --sparse.
func sparse(hdr *tar.Header) bool {
	for k := range hdr.PAXRecords {
		if strings.HasPrefix(k, "GNU.sparse.") {
			return true
		}
	}
	return false
}

// matchAny reports whether name matches one of globs. As in a shell, a
// name starting with . only matches a glob that starts with . too, so a
// glob like * can't bring hidden files onto the host.
func matchAny(globs []string, name string) bool {
	for _, g := range globs {
		if strings.HasPrefix(name, ".") && !strings.HasPrefix(g, ".") {
			continue
		}
		if ok, _ := path.Match(g, name); ok {
			return true
		}
	}
	return false
}

// placeFiles moves names from tmp into hostDir once none of them would
// replace a directory or, without force, an existing file. Without force
// each move is a no-replace rename, so a name that appears after the check
// still fails, and files already moved are removed again. With force an
// existing file or symlink is replaced, never followed.
func placeFiles(tmp, hostDir string, names []string, force bool) ([]string, error) {
	slices.Sort(names)
	var clashes []string
	for _, n := range names {
		fi, err := os.Lstat(filepath.Join(hostDir, n))
		switch {
		case errors.Is(err, fs.ErrNotExist):
		case err != nil:
			return nil, err
		case fi.IsDir():
			return nil, fmt.Errorf("%q %w", filepath.Join(hostDir, n), ErrIsDirectory)
		case !force:
			clashes = append(clashes, strconv.Quote(filepath.Join(hostDir, n)))
		}
	}
	if len(clashes) > 0 {
		return nil, fmt.Errorf("%s %w", strings.Join(clashes, ", "), ErrFileExists)
	}
	placed := make([]string, 0, len(names))
	for _, n := range names {
		from, to := filepath.Join(tmp, n), filepath.Join(hostDir, n)
		var err error
		if force {
			err = os.Rename(from, to)
		} else {
			err = renameNoReplace(from, to)
		}
		if err != nil {
			if !force {
				for _, p := range placed {
					_ = os.Remove(p)
				}
			}
			return nil, placeError(to, err)
		}
		placed = append(placed, to)
	}
	return placed, nil
}

// placeError explains a failed move, pointing at --force when the host
// filesystem can't rename without replacing.
func placeError(to string, err error) error {
	switch {
	case errors.Is(err, fs.ErrExist):
		return fmt.Errorf("%q %w", to, ErrFileExists)
	case errors.Is(err, errors.ErrUnsupported), errors.Is(err, syscall.EINVAL):
		return fmt.Errorf("%q: %w: the host filesystem may not support renaming without replacing; --force overwrites instead", to, err)
	}
	return err
}

// ParseSize parses a byte count with an optional k, m, g, or t suffix
// (powers of 1024), such as 512k or 1g.
func ParseSize(s string) (int64, error) {
	v := strings.ToLower(strings.TrimSpace(s))
	shift := 0
	if v != "" {
		switch v[len(v)-1] {
		case 'k':
			shift = 10
		case 'm':
			shift = 20
		case 'g':
			shift = 30
		case 't':
			shift = 40
		}
		if shift > 0 {
			v = v[:len(v)-1]
		}
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 || strings.HasPrefix(v, "+") {
		return 0, fmt.Errorf("invalid size %q: want a number of bytes with an optional k, m, g, or t suffix", s)
	}
	if n > math.MaxInt64>>shift {
		return 0, fmt.Errorf("invalid size %q: too large", s)
	}
	return n << shift, nil
}
