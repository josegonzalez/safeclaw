package expand

// Resuming.
//
// The manifest is also the state a later run on the same destination
// resumes from. A run that finds dest/manifest.json reads it and checks it
// before it changes anything, since the destination is written by code in
// the sandbox: checkState refuses a manifest that names a path outside the
// destination, that reaches a container through a link or anything that
// isn't a directory, whose packed containers aren't regular files of the
// kind recorded, with an outcome or flag it doesn't know, or whose records
// don't fit together as a run writes them. A refused manifest fails the
// run with nothing changed.
//
// A resumed run keeps the containers that were opened, rejected, skipped,
// or past the depth limit as they are, and opens again, in their order,
// the ones that needed a password, were too large, or failed, with its own
// password and size limit, and those taken off the skip list. Then it
// copies in and opens its new inputs. The size limit counts what is
// already in the destination: everything but the input copies and the
// manifest, measured on disk. The depth limit and whether emails are
// opened are the destination's, from its first run: a run with others is
// refused. A resumed run that fails removes what it added and leaves the
// manifest as it was.

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/josegonzalez/safeclaw/internal/unpack"
)

// state is a destination and its manifest, locked for a run.
type state struct {
	root string
	m    *Manifest
	// resumed is set when m was read from the destination.
	resumed bool
	// lockFile holds the lock on root.
	lockFile *os.File
}

// openState returns dest's state, locked, or nil when dest is missing or
// has no manifest. exclusive takes the lock for a run rather than for
// reading.
func openState(dest string) (*state, error) {
	return openStateLocked(dest, true)
}

func openStateLocked(dest string, exclusive bool) (*state, error) {
	abs, err := filepath.Abs(dest)
	if err != nil {
		return nil, err
	}
	fi, err := os.Lstat(abs)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, nil
	case err != nil:
		return nil, err
	case fi.Mode()&fs.ModeSymlink != 0:
		return nil, fmt.Errorf("%s is a symbolic link", dest)
	case !fi.IsDir():
		return nil, fmt.Errorf("%s is not a directory", dest)
	}
	if _, err := os.Lstat(filepath.Join(abs, ManifestFile)); errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	} else if err != nil {
		return nil, err
	}
	root, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return nil, err
	}
	st := &state{root: root, resumed: true}
	if err := st.lockAs(exclusive); err != nil {
		return nil, err
	}
	m, err := ReadManifest(root)
	if err == nil {
		err = checkState(root, m)
	}
	if err == nil {
		m.Size, err = usedSize(root, m)
	}
	if err != nil {
		st.close()
		return nil, fmt.Errorf("refusing to resume from %s: %w", filepath.Join(dest, ManifestFile), err)
	}
	st.m = m
	return st, nil
}

// lock takes the exclusive lock on root, if it isn't held yet, and for a
// first run checks root is still empty once it has it.
func (s *state) lock() error {
	if s.lockFile != nil {
		return nil
	}
	if err := s.lockAs(true); err != nil {
		return err
	}
	names, err := os.ReadDir(s.root)
	if err == nil && len(names) > 0 {
		err = fmt.Errorf("%s is not empty", s.root)
	}
	if err != nil {
		s.close()
	}
	return err
}

func (s *state) lockAs(exclusive bool) error {
	f, err := os.OpenFile(s.root, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	how := syscall.LOCK_SH
	if exclusive {
		how = syscall.LOCK_EX
	}
	if err := syscall.Flock(int(f.Fd()), how|syscall.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return fmt.Errorf("another run is using %s", s.root)
		}
		return err
	}
	s.lockFile = f
	return nil
}

func (s *state) close() {
	if s != nil && s.lockFile != nil {
		_ = s.lockFile.Close()
		s.lockFile = nil
	}
}

// usedSize is what counts toward the size limit in root: the size of every
// regular file in it, without following links, but the input copies and
// the manifest.
func usedSize(root string, m *Manifest) (int64, error) {
	n, err := unpack.TreeSize(root)
	if err != nil {
		return 0, err
	}
	for _, p := range append([]string{ManifestFile}, inputPaths(m)...) {
		if fi, err := os.Lstat(filepath.Join(root, p)); err == nil && fi.Mode().IsRegular() {
			n -= fi.Size()
		}
	}
	return max(n, 0), nil
}

func inputPaths(m *Manifest) []string {
	out := make([]string, 0, len(m.Inputs))
	for _, in := range m.Inputs {
		out = append(out, in.Path)
	}
	return out
}

var (
	sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// inputCopyName is an input copy's name, N-NAME.
	inputCopyName = regexp.MustCompile(`^[1-9][0-9]*-[^/]+$`)
	// maxCode is the highest exit code a container's own failure has.
	maxCode = int(unpack.NotArchive)
)

// checkState checks m, read from root, before a run resumes from it,
// beyond what Check checks: that its records fit together as Run writes
// them, and that every container left packed is still a regular file of
// its kind, reached only through directories.
func checkState(root string, m *Manifest) error {
	if m.Status != "ok" || m.Code != 0 {
		return fmt.Errorf("status %q, code %d: not a finished run", m.Status, m.Code)
	}
	if m.Options.Depth < 0 || m.Options.MaxSize <= 0 {
		return fmt.Errorf("bad options %+v", m.Options)
	}
	inputs := map[string]bool{}
	for _, in := range m.Inputs {
		switch {
		case !inputCopyName.MatchString(in.Path):
			return fmt.Errorf("input %q is not an input copy's name", in.Path)
		case inputs[in.Path]:
			return fmt.Errorf("input %q is listed twice", in.Path)
		case in.Size < 0:
			return fmt.Errorf("input %q has a negative size", in.Path)
		case in.SHA256 != "" && !sha256Hex.MatchString(in.SHA256):
			return fmt.Errorf("input %q has a bad sha256", in.Path)
		}
		inputs[in.Path] = true
	}
	skip := map[string]bool{}
	for _, p := range m.Skip {
		if skip[p] {
			return fmt.Errorf("skip %q is listed twice", p)
		}
		skip[p] = true
	}
	byPath := map[string]Container{}
	for _, c := range m.Containers {
		if err := checkContainer(c, byPath, inputs, skip); err != nil {
			return fmt.Errorf("container %q: %w", c.Path, err)
		}
		byPath[c.Path] = c
		if c.Outcome == OutcomeUnpacked {
			continue
		}
		if err := checkPacked(root, c, !m.Options.Mail); err != nil {
			return fmt.Errorf("container %q: %w", c.Path, err)
		}
	}
	return nil
}

// checkContainer checks c's record against the ones before it.
func checkContainer(c Container, before map[string]Container, inputs, skip map[string]bool) error {
	flag, ok := outcomeFlags[c.Outcome]
	if !ok {
		return fmt.Errorf("unknown outcome %q", c.Outcome)
	}
	if len(c.Flags) == 0 || c.Flags[0] != flag {
		return fmt.Errorf("flags %q don't start with %s", c.Flags, flag)
	}
	for _, f := range c.Flags[1:] {
		if c.Outcome != OutcomeUnpacked || c.Kind != KindEmail || !slices.Contains(emailProblems, f) {
			return fmt.Errorf("unknown flag %q", f)
		}
	}
	if c.Code < 0 || c.Code > maxCode {
		return fmt.Errorf("unknown code %d", c.Code)
	}
	if c.Outcome == OutcomeSkipped && !skip[c.Path] {
		return errors.New("skipped, but not on the skip list")
	}
	if c.Parent == "" {
		if !inputs[c.Path] || c.Depth != 0 {
			return errors.New("not an input at depth 0, but has no parent")
		}
	} else {
		p, ok := before[c.Parent]
		switch {
		case !ok:
			return fmt.Errorf("parent %q isn't listed before it", c.Parent)
		case p.Outcome != OutcomeUnpacked || !strings.HasPrefix(c.Path, p.Unpacked+"/"):
			return fmt.Errorf("not inside its parent's directory %q", p.Unpacked)
		case c.Depth <= p.Depth:
			return fmt.Errorf("depth %d, not below its parent's %d", c.Depth, p.Depth)
		}
	}
	if (c.Outcome == OutcomeUnpacked) != (c.Unpacked != "") {
		return fmt.Errorf("outcome %s with directory %q", c.Outcome, c.Unpacked)
	}
	if c.Unpacked != "" && !ownDir(c.Path, c.Unpacked) {
		return fmt.Errorf("directory %q is not its own", c.Unpacked)
	}
	for _, o := range c.Outputs {
		if c.Unpacked == "" || !strings.HasPrefix(o, c.Unpacked+"/") {
			return fmt.Errorf("output %q is not in its directory", o)
		}
	}
	return nil
}

// ownDir reports whether dir is a name Run opens the container p into:
// p.unpacked, or p.unpacked-N for N from 2, next to p.
func ownDir(p, dir string) bool {
	if path.Dir(p) != path.Dir(dir) {
		return false
	}
	rest, ok := strings.CutPrefix(path.Base(dir), path.Base(p)+unpack.UnpackedSuffix)
	if !ok {
		return false
	}
	if rest == "" {
		return true
	}
	n, err := strconv.Atoi(strings.TrimPrefix(rest, "-"))
	return err == nil && n >= 2 && rest == "-"+strconv.Itoa(n)
}

// checkPacked checks that the container c left packed is a regular file of
// its kind, reached from root only through directories, without following
// a link.
func checkPacked(root string, c Container, noMail bool) error {
	cur := root
	parts := strings.Split(c.Path, "/")
	for i, part := range parts {
		cur = filepath.Join(cur, part)
		fi, err := os.Lstat(cur)
		if err != nil {
			return err
		}
		if i < len(parts)-1 && !fi.IsDir() {
			return fmt.Errorf("%s is not a directory", path.Join(parts[:i+1]...))
		}
		if i == len(parts)-1 && !fi.Mode().IsRegular() {
			return errors.New("not a regular file")
		}
	}
	kind, err := detectKind(cur, noMail)
	if err != nil {
		return err
	}
	if kind != c.Kind {
		return fmt.Errorf("recorded as %q, but it is %q", c.Kind, kind)
	}
	return nil
}
