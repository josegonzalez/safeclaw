package unpack

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// Defaults for Options.
const (
	// DefaultMaxSize is the default limit on the total size of what is
	// extracted, nested archives included: 512 MiB.
	DefaultMaxSize = 512 << 20
	// DefaultDepth is the default number of levels of nested archives
	// unpacked below the archive given.
	DefaultDepth = 3
	// UnpackedSuffix names the directory a nested archive is unpacked into,
	// next to it.
	UnpackedSuffix = ".unpacked"
)

// Options configures Extract.
type Options struct {
	// Runner runs 7z.
	Runner Runner
	// Password is given to 7z for encrypted archives, nested ones included.
	Password *string
	// MaxSize limits the total size of the files in the destination. It is
	// checked against the listing before each archive is extracted, while
	// it extracts, and against the files written afterwards, for formats
	// that don't record sizes or that record them wrongly.
	MaxSize int64
	// Depth is how many levels of nested archives are unpacked; 0 unpacks
	// none.
	Depth int
	// DropBad leaves out links, special files, and entries with unsafe
	// paths instead of rejecting the archive.
	DropBad bool
	// KeepGoing leaves a nested archive that fails packed, flagged with its
	// Kind's Flag, and carries on, instead of failing the whole extraction.
	// What it extracted is removed, without following links, and the size
	// limit stays shared by the whole tree. The archive given to Extract
	// still fails the extraction for its own problems.
	KeepGoing bool
	// PollInterval is how often the size is checked while 7z extracts.
	PollInterval time.Duration
}

// Result is what Extract wrote.
type Result struct {
	// Entries are every path in the destination, relative to it, sorted.
	Entries []Entry
	// Dropped are the bad entries left out with Options.DropBad, with the
	// directory of the nested archive they came from in front.
	Dropped []Entry
	// Failed are the nested archives left packed with Options.KeepGoing,
	// one error each, in the order they were tried, with Archive set.
	Failed []*Error
}

// Extract extracts archive into dest, which must be missing or an empty
// directory, and not a symbolic link.
//
// The archive is listed first, and one with links, special files, or
// unsafe paths is rejected (or those entries are left out, with
// Options.DropBad), as is one whose listed size is over the limit or that
// is encrypted without a password. After 7z extracts it, any link or
// special file it made is deleted, which rejects the archive unless
// Options.DropBad is set since the listing didn't show it, files lose their
// setuid and setgid bits and become readable and writable by their owner,
// and every path must resolve inside dest. Then each file that starts like
// an archive is unpacked into NAME.unpacked next to it, the same way, up to
// Options.Depth levels. With Options.KeepGoing, a nested archive that
// fails is left packed and flagged instead. On any other error dest is
// emptied, without following links, and the error is an *Error. An archive
// 7z can't open is NotArchive, unless it starts like one Detect knows,
// which makes it corrupt and Failed; a nested file 7z can't open is left as
// it is.
func Extract(ctx context.Context, archive, dest string, o Options) (*Result, error) {
	if o.Runner == nil {
		return nil, &Error{Kind: Failed, Msg: "no 7z runner"}
	}
	if o.MaxSize <= 0 {
		return nil, &Error{Kind: Failed, Msg: "the size limit must be positive"}
	}
	if o.Depth < 0 {
		return nil, &Error{Kind: Failed, Msg: "the depth limit can't be negative"}
	}
	if o.PollInterval <= 0 {
		o.PollInterval = 200 * time.Millisecond
	}
	src, err := filepath.Abs(archive)
	if err != nil {
		return nil, &Error{Kind: Failed, Msg: err.Error()}
	}
	if fi, err := os.Stat(src); err != nil {
		return nil, &Error{Kind: Failed, Msg: err.Error()}
	} else if !fi.Mode().IsRegular() {
		return nil, &Error{Kind: Failed, Msg: fmt.Sprintf("%s is not a regular file", archive)}
	}
	root, err := prepareDest(dest)
	if err != nil {
		return nil, &Error{Kind: Failed, Msg: err.Error()}
	}
	x := &extractor{o: o, root: root, flags: map[string][]string{}, unpacked: map[string]string{}}
	if err := x.unpack(ctx, src, root, "", 0); err != nil {
		if cerr := emptyDir(root); cerr != nil {
			err = errors.Join(err, fmt.Errorf("emptying %s: %w", dest, cerr))
		}
		return &Result{Dropped: x.dropped}, err
	}
	entries, err := x.entries()
	if err != nil {
		_ = emptyDir(root)
		return nil, &Error{Kind: Failed, Msg: err.Error()}
	}
	return &Result{Entries: entries, Dropped: x.dropped, Failed: x.failed}, nil
}

// prepareDest makes dest if it is missing and returns its absolute path
// with links resolved. An existing dest must be an empty directory and not
// a symbolic link.
func prepareDest(dest string) (string, error) {
	abs, err := filepath.Abs(dest)
	if err != nil {
		return "", err
	}
	fi, err := os.Lstat(abs)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.Mkdir(abs, 0o755); err != nil {
			return "", err
		}
	case err != nil:
		return "", err
	case fi.Mode()&fs.ModeSymlink != 0:
		return "", fmt.Errorf("%s is a symbolic link", dest)
	case !fi.IsDir():
		return "", fmt.Errorf("%s is not a directory", dest)
	default:
		names, err := os.ReadDir(abs)
		if err != nil {
			return "", err
		}
		if len(names) > 0 {
			return "", fmt.Errorf("%s is not empty", dest)
		}
	}
	return filepath.EvalSymlinks(abs)
}

type extractor struct {
	o    Options
	root string
	// dropped are entries left out or deleted with DropBad.
	dropped []Entry
	// flags are extra flags by path relative to root.
	flags map[string][]string
	// unpacked maps a nested archive's path to its directory, both
	// relative to root.
	unpacked map[string]string
	// failed are the nested archives left packed with KeepGoing.
	failed []*Error
}

// unpack extracts archive into dir, rel being dir relative to the root
// ("" for the root) and depth the nesting level.
func (x *extractor) unpack(ctx context.Context, archive, dir, rel string, depth int) error {
	name := x.archiveName(archive, depth)
	fail := func(err error) error {
		var e *Error
		if !errors.As(err, &e) {
			e = &Error{Kind: Failed, Msg: err.Error()}
		}
		if e.Archive == "" {
			e.Archive = name
		}
		return e
	}

	l, err := x.o.Runner.List(ctx, archive, x.o.Password)
	if err != nil {
		if errors.Is(err, errNotArchive) {
			if depth > 0 {
				return err
			}
			err = notArchive(archive)
		}
		return fail(err)
	}
	var bad, good []Entry
	encrypted := false
	for _, e := range l.Entries {
		if e.Bad() {
			bad = append(bad, e)
			continue
		}
		good = append(good, e)
		encrypted = encrypted || e.Encrypted
	}
	if len(bad) > 0 && !x.o.DropBad {
		return fail(&Error{Kind: Rejected, Msg: fmt.Sprintf("%d %s with links, special files, or unsafe paths", len(bad), plural(len(bad), "entry", "entries")), Bad: prefixed(rel, bad)})
	}
	if encrypted && x.o.Password == nil {
		return fail(&Error{Kind: NeedsPassword, Msg: "the archive has encrypted entries and no password was given"})
	}
	var listed int64
	for _, e := range good {
		if e.Type == TypeFile && e.Size > 0 {
			listed += e.Size
		}
	}
	used, err := treeSize(x.root)
	if err != nil {
		return fail(err)
	}
	if listed > x.o.MaxSize-used {
		return fail(x.tooLarge(fmt.Sprintf("its listing adds up to %d bytes", listed)))
	}

	var include []string
	if len(bad) > 0 {
		include = []string{}
		for _, e := range good {
			if e.Type == TypeFile {
				include = append(include, e.Path)
			}
		}
	}
	if include == nil || len(include) > 0 {
		if err := x.extractWatched(ctx, archive, dir, include); err != nil {
			return fail(err)
		}
	}
	if len(bad) > 0 {
		// Left-out entries can take directories with them, so the safe
		// directories the listing has are made here.
		for _, e := range good {
			if e.Type != TypeDir {
				continue
			}
			p := filepath.Join(dir, filepath.FromSlash(e.Path))
			if !within(dir, p) {
				continue
			}
			if err := mkdirNoFollow(dir, p); err != nil {
				return fail(err)
			}
		}
		x.dropped = append(x.dropped, withFlag(prefixed(rel, bad), FlagDropped)...)
	}

	removed, err := sanitize(x.root, dir)
	if err != nil {
		return fail(err)
	}
	if len(removed) > 0 {
		if !x.o.DropBad {
			return fail(&Error{Kind: Rejected, Msg: fmt.Sprintf("7z made %d %s or special %s the listing didn't show", len(removed), plural(len(removed), "link", "links"), plural(len(removed), "file", "files")), Bad: removed})
		}
		x.dropped = append(x.dropped, withFlag(removed, FlagDropped)...)
	}
	if used, err = treeSize(x.root); err != nil {
		return fail(err)
	}
	if used > x.o.MaxSize {
		return fail(x.tooLarge(fmt.Sprintf("it extracted to %d bytes", used)))
	}

	nested, err := archivesIn(dir)
	if err != nil {
		return fail(err)
	}
	for _, p := range nested {
		prel := relTo(x.root, p)
		if depth >= x.o.Depth {
			x.flags[prel] = append(x.flags[prel], FlagDepthLimit)
			continue
		}
		sub, err := uniqueDir(p + UnpackedSuffix)
		if err != nil {
			return fail(err)
		}
		before := x.mark()
		err = x.unpack(ctx, p, sub, relTo(x.root, sub), depth+1)
		if errors.Is(err, errNotArchive) {
			// It only starts like an archive.
			if err := os.RemoveAll(sub); err != nil {
				return fail(err)
			}
			continue
		}
		if err != nil {
			var e *Error
			if !x.o.KeepGoing || ctx.Err() != nil || !errors.As(err, &e) {
				return err
			}
			if err := x.leavePacked(sub, before); err != nil {
				return fail(err)
			}
			// A deeper archive's failure is handled where it happens,
			// so this one is p's own and names it.
			x.flags[prel] = append(x.flags[prel], e.Kind.Flag())
			x.failed = append(x.failed, e)
			continue
		}
		x.unpacked[prel] = relTo(x.root, sub)
	}
	return nil
}

// mark is how much a nested archive's unpacking has recorded, so it can
// be taken back when the archive is left packed.
type mark struct{ dropped, failed int }

func (x *extractor) mark() mark {
	return mark{dropped: len(x.dropped), failed: len(x.failed)}
}

// leavePacked removes sub, a nested archive's directory, without following
// links, and forgets what was recorded for it since m.
func (x *extractor) leavePacked(sub string, m mark) error {
	if err := emptyDir(sub); err != nil {
		return err
	}
	if err := os.Remove(sub); err != nil {
		return err
	}
	x.dropped = x.dropped[:m.dropped]
	x.failed = x.failed[:m.failed]
	prefix := relTo(x.root, sub) + "/"
	for p := range x.flags {
		if strings.HasPrefix(p, prefix) {
			delete(x.flags, p)
		}
	}
	for p := range x.unpacked {
		if strings.HasPrefix(p, prefix) {
			delete(x.unpacked, p)
		}
	}
	return nil
}

func (x *extractor) archiveName(archive string, depth int) string {
	if depth == 0 {
		return ""
	}
	return relTo(x.root, archive)
}

func (x *extractor) tooLarge(why string) *Error {
	return &Error{Kind: TooLarge, Msg: fmt.Sprintf("%s, over the %d byte limit", why, x.o.MaxSize)}
}

// extractWatched runs 7z, stopping it once the files in the root add up to
// more than the size limit.
func (x *extractor) extractWatched(ctx context.Context, archive, dir string, include []string) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var over atomic.Bool
	done := make(chan struct{})
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		t := time.NewTicker(x.o.PollInterval)
		defer t.Stop()
		for {
			select {
			case <-done:
				return
			case <-t.C:
				// Files come and go while 7z runs, so a failed walk just
				// counts what it saw.
				if n, _ := treeSize(x.root); n > x.o.MaxSize {
					over.Store(true)
					cancel()
					return
				}
			}
		}
	}()
	err := x.o.Runner.Extract(ctx, archive, dir, include, x.o.Password)
	close(done)
	<-stopped
	if over.Load() {
		return x.tooLarge("it grew past the limit while extracting")
	}
	return err
}

// entries lists everything in the root.
func (x *extractor) entries() ([]Entry, error) {
	var out []Entry
	err := filepath.WalkDir(x.root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == x.root {
			return nil
		}
		rel := relTo(x.root, p)
		e := Entry{Path: rel, Type: TypeFile, Size: -1, Extra: x.flags[rel], Unpacked: x.unpacked[rel]}
		switch {
		case d.IsDir():
			e.Type = TypeDir
		case d.Type().IsRegular():
			fi, err := d.Info()
			if err != nil {
				return err
			}
			e.Size = fi.Size()
		default:
			return fmt.Errorf("%s is not a regular file or directory", rel)
		}
		if e.Unpacked != "" {
			e.Extra = append(e.Extra, FlagUnpacked)
		}
		out = append(out, e)
		return nil
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, err
}

// sanitize checks what 7z wrote into dir. It deletes links, special files,
// and files with more than one hard link, returning them with paths
// relative to root; makes directories usable by their owner and files
// readable and writable by it, without setuid, setgid, or sticky bits; and
// checks that every path left resolves inside root.
func sanitize(root, dir string) ([]Entry, error) {
	var removed []Entry
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := relTo(root, p)
		fi, err := os.Lstat(p)
		if err != nil {
			return err
		}
		mode := fi.Mode()
		switch {
		case mode&fs.ModeSymlink != 0:
			target, _ := os.Readlink(p)
			removed = append(removed, Entry{Path: rel, Type: TypeSymlink, Size: -1, Link: target})
			return os.Remove(p)
		case mode.IsDir():
			// WalkDir reads a directory after this returns, so it can be
			// one 7z made without read or search permission.
			return os.Chmod(p, mode.Perm()|0o700)
		case !mode.IsRegular():
			removed = append(removed, Entry{Path: rel, Type: TypeSpecial, Size: -1})
			return os.Remove(p)
		case linkCount(fi) > 1:
			removed = append(removed, Entry{Path: rel, Type: TypeHardlink, Size: fi.Size()})
			return os.Remove(p)
		}
		if mode&(fs.ModeSetuid|fs.ModeSetgid|fs.ModeSticky) != 0 || mode.Perm()&0o600 != 0o600 {
			return os.Chmod(p, mode.Perm()|0o600)
		}
		return nil
	})
	if err != nil {
		return removed, err
	}
	err = filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			return err
		}
		if !within(root, real) {
			return fmt.Errorf("%s resolves outside the destination", relTo(root, p))
		}
		return nil
	})
	return removed, err
}

// emptyDir removes everything in dir without following links. Directories
// are made writable first, since 7z can make them without permissions.
func emptyDir(dir string) error {
	_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err == nil && d.IsDir() {
			_ = os.Chmod(p, 0o700)
		}
		return nil
	})
	names, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var errs []error
	for _, n := range names {
		errs = append(errs, os.RemoveAll(filepath.Join(dir, n.Name())))
	}
	return errors.Join(errs...)
}

// treeSize adds up the sizes of the regular files under dir.
func treeSize(dir string) (int64, error) {
	var n int64
	err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			fi, err := d.Info()
			if err != nil {
				return err
			}
			n += fi.Size()
		}
		return nil
	})
	return n, err
}

// mkdirNoFollow makes the directory p and its parents below base, refusing
// to go through anything that isn't a directory.
func mkdirNoFollow(base, p string) error {
	rel, err := filepath.Rel(base, p)
	if err != nil {
		return err
	}
	cur := base
	for _, seg := range strings.Split(rel, string(filepath.Separator)) {
		if seg == "." || seg == "" {
			continue
		}
		cur = filepath.Join(cur, seg)
		fi, err := os.Lstat(cur)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			if err := os.Mkdir(cur, 0o755); err != nil {
				return err
			}
		case err != nil:
			return err
		case !fi.IsDir():
			return fmt.Errorf("%s is not a directory", cur)
		}
	}
	return nil
}

// uniqueDir makes a new directory named p, or p-2, p-3, and so on when
// that name is taken, so a nested archive is never unpacked into something
// the archive already had.
func uniqueDir(p string) (string, error) {
	for i := 1; i < 1000; i++ {
		name := p
		if i > 1 {
			name = p + "-" + strconv.Itoa(i)
		}
		err := os.Mkdir(name, 0o755)
		if err == nil {
			return name, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return "", err
		}
	}
	return "", fmt.Errorf("no free name for %s", p)
}

// within reports whether p is root or inside it. Both must be clean,
// absolute paths.
func within(root, p string) bool {
	rel, err := filepath.Rel(root, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func relTo(root, p string) string {
	rel, err := filepath.Rel(root, p)
	if err != nil {
		return p
	}
	return filepath.ToSlash(rel)
}

// prefixed returns entries with dir (relative to the root) in front of
// their paths. The paths are joined as they are, not cleaned, so an unsafe
// one still shows as it was in the archive.
func prefixed(dir string, entries []Entry) []Entry {
	out := make([]Entry, len(entries))
	for i, e := range entries {
		if dir != "" {
			e.Path = dir + "/" + e.Path
		}
		out[i] = e
	}
	return out
}

func withFlag(entries []Entry, flag string) []Entry {
	for i := range entries {
		entries[i].Extra = append(append([]string(nil), entries[i].Extra...), flag)
	}
	return entries
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// List lists archive's entries with r, without extracting anything. The
// error is an *Error, NotArchive or Failed for one 7z can't open as
// Extract decides.
func List(ctx context.Context, r Runner, archive string, pw *string) (*Listing, error) {
	src, err := filepath.Abs(archive)
	if err != nil {
		return nil, &Error{Kind: Failed, Msg: err.Error()}
	}
	if fi, err := os.Stat(src); err != nil {
		return nil, &Error{Kind: Failed, Msg: err.Error()}
	} else if !fi.Mode().IsRegular() {
		return nil, &Error{Kind: Failed, Msg: fmt.Sprintf("%s is not a regular file", archive)}
	}
	l, err := r.List(ctx, src, pw)
	if errors.Is(err, errNotArchive) {
		err = notArchive(src)
	}
	if err != nil {
		var e *Error
		if errors.As(err, &e) {
			return nil, e
		}
		return nil, &Error{Kind: Failed, Msg: err.Error()}
	}
	return l, nil
}
