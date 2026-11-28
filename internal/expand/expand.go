// Package expand opens a tree of untrusted emails and archives into one
// destination: each input is copied in, and every email and archive in
// the tree is opened next to itself into NAME.unpacked, emails as the mail
// package extracts them and archives as the unpack package does, with one
// depth and size limit for the whole tree. A container that fails is left
// packed and flagged, and everything else is kept. A manifest in the
// destination records every container, and a later run on the same
// destination resumes from it. It backs `safeclaw expand`,
// installed as safeclaw-expand in the sandbox image variant.
package expand

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/josegonzalez/safeclaw/internal/mail"
	"github.com/josegonzalez/safeclaw/internal/unpack"
)

// Defaults for Options, the same as safeclaw-unpack's and safeclaw-mail's.
const (
	DefaultMaxSize = unpack.DefaultMaxSize
	DefaultDepth   = unpack.DefaultDepth
)

// KindEmail is the kind of an email container; an archive's kind is its
// format as unpack.Detect names it.
const KindEmail = "email"

// Outcomes of a container.
const (
	// OutcomeUnpacked is a container opened into its Unpacked directory.
	OutcomeUnpacked = "unpacked"
	// OutcomeRejected is an archive with links, special files, or unsafe
	// paths, or an email over a limit on its structure.
	OutcomeRejected = "rejected"
	// OutcomeNeedsPassword is an encrypted archive with no password, or
	// the wrong one.
	OutcomeNeedsPassword = "needs-password"
	// OutcomeTooLarge is a container that would take the tree past
	// Options.MaxSize.
	OutcomeTooLarge = "too-large"
	// OutcomeFailed is a container that failed otherwise: a corrupt
	// archive, or 7z failing.
	OutcomeFailed = "failed"
	// OutcomeDepthLimit is a container deeper than Options.Depth.
	OutcomeDepthLimit = "depth-limit"
	// OutcomeSkipped is a container left packed because its path is in the
	// manifest's skip list.
	OutcomeSkipped = "skipped"
)

// FlagSkipped is OutcomeSkipped's flag.
const FlagSkipped = "SKIPPED"

// outcomeFlags are the flag each outcome gets, the same as
// safeclaw-unpack's.
var outcomeFlags = map[string]string{
	OutcomeUnpacked:      unpack.FlagUnpacked,
	OutcomeRejected:      unpack.FlagRejected,
	OutcomeNeedsPassword: unpack.FlagNeedsPassword,
	OutcomeTooLarge:      unpack.FlagTooLarge,
	OutcomeFailed:        unpack.FlagFailed,
	OutcomeDepthLimit:    unpack.FlagDepthLimit,
	OutcomeSkipped:       FlagSkipped,
}

// retried reports whether a later run tries a container with outcome
// again: one that needed a password, was too large, or failed otherwise.
func retried(outcome string) bool {
	return outcome == OutcomeNeedsPassword || outcome == OutcomeTooLarge || outcome == OutcomeFailed
}

// emailProblems are the part flags an opened email's record carries.
var emailProblems = []string{mail.FlagUnsafeName, mail.FlagBadEncoding, mail.FlagMalformed}

// Options configures Run.
type Options struct {
	// Runner runs 7z. Without one, every archive is left packed and
	// flagged FAILED.
	Runner unpack.Runner
	// Password is given to 7z for every encrypted archive.
	Password *string
	// MaxSize limits the total size of everything opened, across the whole
	// tree; the input copies don't count.
	MaxSize int64
	// Depth is how many levels of containers are opened below the inputs;
	// 0 opens only the inputs.
	Depth int
	// NoMail leaves emails as they are, as plain files.
	NoMail bool
	// PollInterval is how often the size is checked while 7z extracts.
	PollInterval time.Duration
	// Skip are containers to leave packed, flagged SKIPPED, by path in the
	// destination; they are added to the manifest's skip list, so later
	// runs leave them packed too.
	Skip []string
	// Unskip are paths to take off the skip list, so a container skipped
	// before is opened.
	Unskip []string
	// Ignore, when set, is called with each entry of an input directory
	// that is left out, a link, a directory, or anything else that isn't a
	// regular file, and why.
	Ignore func(path, why string)
}

// Run copies inputs into dest and opens every container in the tree,
// writing the manifest to dest/manifest.json and returning it. dest must
// not be a symbolic link. Without a manifest in it, dest must be missing
// or an empty directory; with one, Run resumes from it, as described in
// resume.go.
//
// An input that is a directory, or a link to one, stands for every regular
// file directly in it, in order of name; links, directories, and anything
// else in it are left out without being followed, and given to
// Options.Ignore. A directory with none is no inputs. An input directory
// must not be dest, hold dest, or be inside it. A run that names inputs but
// finds no files in them still writes the manifest, making dest if it's
// missing, so the same command line works on every run.
//
// Each input is copied in as N-NAME, so inputs never collide. Each file
// that starts like an archive unpack.Detect knows, or like an email
// mail.Detect knows, is a container, opened into NAME.unpacked next to it
// (NAME.unpacked-2 and so on when that name is taken), and then the files
// in that directory are looked at in turn, except the ones Run wrote
// itself, an email's body.txt and parts.txt. A container that fails, or is
// past Options.Depth, is left packed and recorded with its outcome, and
// what it extracted is removed without following links. A nested file that
// only starts like an archive, which 7z can't open, is left as it is and
// not recorded, as safeclaw-unpack leaves it; an input like that is
// corrupt, and FAILED.
//
// An input with the same name and content as one already copied in, by
// this run or an earlier one, isn't copied again. Paths in Options.Skip and
// Options.Unskip are changes to the manifest's skip list: a container at a
// path on the list is left packed, flagged SKIPPED, unless it is past
// Options.Depth.
//
// An input that is missing or not a regular file or a directory (a link to
// one is followed), or a usage error, fails the run before dest is touched. An
// I/O error outside a container, or ctx ending, fails it too: a first run
// empties dest, and a resumed one removes what it added, both without
// following links.
func Run(ctx context.Context, inputs []string, dest string, o Options) (*Manifest, error) {
	if o.MaxSize <= 0 {
		return nil, errors.New("the size limit must be positive")
	}
	sources, err := checkOptions(inputs, dest, o)
	if err != nil {
		return nil, err
	}
	st, err := openState(dest)
	if err != nil {
		return nil, err
	}
	if st == nil {
		if len(inputs) == 0 {
			return nil, errors.New("no inputs, and no manifest in the destination to resume from")
		}
		if len(o.Unskip) > 0 {
			return nil, fmt.Errorf("%s is not skipped", o.Unskip[0])
		}
		root, err := unpack.PrepareDest(dest)
		if err != nil {
			return nil, err
		}
		st = &state{root: root, m: &Manifest{
			Schema: SchemaVersion, Status: "ok",
			Inputs:     []Input{},
			Containers: []Container{},
		}}
	}
	defer st.close()
	if err := st.lock(); err != nil {
		return nil, err
	}
	x := &expander{ctx: ctx, o: o, root: st.root, m: st.m, resume: st.resumed}
	if err := x.prepare(); err != nil {
		return nil, err
	}
	if err := x.run(sources); err != nil {
		if ctx.Err() != nil {
			err = fmt.Errorf("interrupted: %w", err)
		}
		if !x.resume {
			if cerr := unpack.EmptyDir(x.root); cerr != nil {
				err = errors.Join(err, fmt.Errorf("emptying %s: %w", dest, cerr))
			}
		} else if cerr := x.rollback(); cerr != nil {
			err = errors.Join(err, fmt.Errorf("removing what the run added to %s: %w", dest, cerr))
		}
		return nil, err
	}
	return x.m, nil
}

// checkOptions checks what Run and Plan can check before looking at the
// destination's contents, returning the files the inputs name.
func checkOptions(inputs []string, dest string, o Options) ([]source, error) {
	if o.Depth < 0 {
		return nil, errors.New("the depth limit can't be negative")
	}
	for _, p := range append(slices.Clone(o.Skip), o.Unskip...) {
		if !fs.ValidPath(p) || p == "." {
			return nil, fmt.Errorf("%q is not a path inside the destination", p)
		}
	}
	for _, p := range o.Skip {
		if slices.Contains(o.Unskip, p) {
			return nil, fmt.Errorf("%s is both skipped and unskipped", p)
		}
	}
	return resolveInputs(inputs, dest, o.Ignore)
}

type expander struct {
	ctx  context.Context
	o    Options
	root string
	m    *Manifest
	// resume is set when the run resumes from a manifest.
	resume bool
	// skip is the skip list.
	skip map[string]bool
	// reopen are the indexes of the containers already recorded that the
	// run opens again.
	reopen []int
	// added are the files and directories the run made in root, removed
	// when a resumed run fails.
	added []string
}

// prepare checks the run's options against the manifest and applies
// Options.Skip and Options.Unskip to the skip list, changing nothing on
// disk.
func (x *expander) prepare() error {
	m := x.m
	if x.resume {
		if err := checkPolicy(m.Options, x.o); err != nil {
			return err
		}
	}
	byPath := map[string]*Container{}
	for i := range m.Containers {
		byPath[m.Containers[i].Path] = &m.Containers[i]
	}
	x.skip = map[string]bool{}
	for _, p := range m.Skip {
		x.skip[p] = true
	}
	for _, p := range x.o.Unskip {
		if !x.skip[p] {
			return fmt.Errorf("%s is not skipped", p)
		}
		delete(x.skip, p)
	}
	for _, p := range x.o.Skip {
		if c := byPath[p]; c != nil && c.Outcome == OutcomeUnpacked {
			return fmt.Errorf("%s is already opened, into %s", p, c.Unpacked)
		}
		x.skip[p] = true
	}
	m.Skip = nil
	for p := range x.skip {
		m.Skip = append(m.Skip, p)
	}
	sort.Strings(m.Skip)
	m.Options = ManifestOptions{Depth: x.o.Depth, MaxSize: x.o.MaxSize, Mail: !x.o.NoMail, Password: x.o.Password != nil}
	for i, c := range m.Containers {
		switch {
		case c.Outcome == OutcomeSkipped && !x.skip[c.Path], retried(c.Outcome) && !x.skip[c.Path]:
			x.reopen = append(x.reopen, i)
		case retried(c.Outcome):
			m.Containers[i] = Container{Path: c.Path, Kind: c.Kind, Depth: c.Depth, Parent: c.Parent}
			x.set(i, m.Containers[i], OutcomeSkipped)
		}
	}
	return nil
}

// checkPolicy refuses a run on a destination with options rec whose depth
// limit, or whether it opens emails, isn't the destination's.
func checkPolicy(rec ManifestOptions, o Options) error {
	if o.Depth != rec.Depth {
		return fmt.Errorf("the destination was opened with a depth limit of %d, not %d, and a later run keeps it (--depth %d)", rec.Depth, o.Depth, rec.Depth)
	}
	if o.NoMail == rec.Mail {
		if rec.Mail {
			return errors.New("the destination was opened with emails opened, and a later run keeps that (no --no-mail)")
		}
		return errors.New("the destination was opened with emails left as plain files, and a later run keeps that (--no-mail)")
	}
	return nil
}

func (x *expander) run(inputs []source) error {
	for _, i := range x.reopen {
		c := x.m.Containers[i]
		if err := x.ctx.Err(); err != nil {
			return err
		}
		if err := x.open(filepath.Join(x.root, filepath.FromSlash(c.Path)), c.Kind, c.Depth, c.Parent, i); err != nil {
			return err
		}
	}
	have := map[string]bool{}
	for _, in := range x.m.Inputs {
		if in.SHA256 != "" {
			have[inputKey(in.Path, in.SHA256)] = true
		}
	}
	for _, in := range inputs {
		p := filepath.Join(x.root, fmt.Sprintf("%d-%s", len(x.m.Inputs)+1, inputName(in.path)))
		n, sum, created, err := copyInput(in, p)
		if created {
			x.added = append(x.added, p)
		}
		if err != nil {
			return fmt.Errorf("copying %s: %w", in.path, err)
		}
		key := inputKey(x.rel(p), sum)
		if have[key] {
			// The same file is already in, from this run or an earlier one.
			x.added = x.added[:len(x.added)-1]
			if err := os.Remove(p); err != nil {
				return err
			}
			continue
		}
		have[key] = true
		x.m.Inputs = append(x.m.Inputs, Input{Path: x.rel(p), Size: n, SHA256: sum})
		kind, err := x.consider(p, 0, "")
		if err != nil {
			return err
		}
		x.m.Inputs[len(x.m.Inputs)-1].Kind = kind
	}
	return writeManifest(x.root, x.m)
}

// inputName is the NAME of the copy of the input in, N-NAME.
func inputName(in string) string {
	if name := mail.SafeName(filepath.Base(in)); name != "" {
		return name
	}
	return "input"
}

// inputKey identifies an input copy by its NAME and content, so the same
// file given again is found whatever its N.
func inputKey(copyPath, sum string) string {
	_, name, _ := strings.Cut(copyPath, "-")
	return name + "/" + sum
}

// consider opens p, a regular file at depth level, when it is a container,
// returning its kind, or "" when it isn't one.
func (x *expander) consider(p string, level int, parent string) (string, error) {
	if err := x.ctx.Err(); err != nil {
		return "", err
	}
	kind, err := x.detect(p)
	if err != nil || kind == "" {
		return "", err
	}
	return kind, x.open(p, kind, level, parent, -1)
}

// detect returns p's container kind, without following a link.
func (x *expander) detect(p string) (string, error) {
	return detectKind(p, x.o.NoMail)
}

// detectKind returns p's container kind, without following a link: an
// archive format, KindEmail unless noMail is set, or "" for neither.
func detectKind(p string, noMail bool) (string, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil {
		return "", err
	} else if !fi.Mode().IsRegular() {
		return "", nil
	}
	head := make([]byte, unpack.HeadSize)
	n, err := io.ReadFull(f, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return "", err
	}
	if format := unpack.Detect(head[:n]); format != "" {
		return format, nil
	}
	if noMail {
		return "", nil
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", err
	}
	ok, err := mail.Detect(f)
	if err != nil || !ok {
		return "", err
	}
	return KindEmail, nil
}

// child is a file found in an opened container.
type child struct {
	path  string
	level int
}

// open opens the container p into p.unpacked and then the containers in
// it. Its record is the one at index idx, or a new one for -1.
func (x *expander) open(p, kind string, level int, parent string, idx int) error {
	c := Container{Path: x.rel(p), Kind: kind, Depth: level, Parent: parent}
	if level > x.o.Depth {
		x.set(idx, c, OutcomeDepthLimit)
		return nil
	}
	if x.skip[c.Path] {
		x.set(idx, c, OutcomeSkipped)
		return nil
	}
	used := x.m.Size
	left := x.o.MaxSize - used
	if left <= 0 {
		c.Code = int(unpack.TooLarge)
		c.Error = (&unpack.Error{Kind: unpack.TooLarge, Msg: fmt.Sprintf("nothing is left of the %d byte limit", x.o.MaxSize)}).Error()
		x.set(idx, c, OutcomeTooLarge)
		return nil
	}
	dir, err := unpack.UniqueDir(p + unpack.UnpackedSuffix)
	if err != nil {
		return err
	}
	x.added = append(x.added, dir)
	var children []child
	var outputs []string
	var flags []string
	if kind == KindEmail {
		children, outputs, flags, err = x.openEmail(p, dir, level, left)
	} else {
		children, err = x.openArchive(p, dir, level, left)
	}
	if err == nil {
		var n int64
		if n, err = unpack.TreeSize(dir); err == nil && n > left {
			err = &unpack.Error{Kind: unpack.TooLarge, Msg: fmt.Sprintf("it opened to %d bytes, over the %d bytes left of the %d byte limit", n, left, x.o.MaxSize)}
		}
		x.m.Size = used + n
	}
	if err != nil {
		x.m.Size = used
		if cerr := x.ctx.Err(); cerr != nil {
			return cerr
		}
		if rerr := removeDir(dir); rerr != nil {
			return rerr
		}
		if level > 0 && idx < 0 && notContainer(err) {
			// It only started like one. One already recorded, which a
			// run without 7z left FAILED, stays FAILED.
			return nil
		}
		outcome := failure(&c, err)
		x.set(idx, c, outcome)
		return nil
	}
	c.Unpacked = x.rel(dir)
	for _, o := range outputs {
		c.Outputs = append(c.Outputs, x.rel(o))
	}
	x.set(idx, c, OutcomeUnpacked, flags...)
	for _, ch := range children {
		if _, err := x.consider(ch.path, ch.level, c.Path); err != nil {
			return err
		}
	}
	return nil
}

// openEmail extracts the email p into dir and writes its part listing,
// returning the attachments with their depths, the files it wrote itself,
// and the problems its parts had.
func (x *expander) openEmail(p, dir string, level int, left int64) ([]child, []string, []string, error) {
	res, err := mail.Extract(x.ctx, p, dir, mail.Options{Depth: x.o.Depth - level, MaxSize: left})
	if err != nil {
		return nil, nil, nil, err
	}
	partsFile := filepath.Join(dir, mail.PartsFile)
	f, err := os.OpenFile(partsFile, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return nil, nil, nil, err
	}
	err = mail.WriteParts(f, res.Parts, true)
	if err = errors.Join(err, f.Close()); err != nil {
		return nil, nil, nil, err
	}
	// An attachment is one level below the email, and one more for each
	// forwarded message around it, as mail counts them against its depth.
	var nested []string
	problems := map[string]bool{}
	for _, part := range res.Parts {
		if part.Has(mail.FlagNestedMessage) {
			nested = append(nested, part.ID+".")
		}
		for _, f := range emailProblems {
			problems[f] = problems[f] || part.Has(f)
		}
	}
	levels := map[string]int{}
	for _, part := range res.Parts {
		if part.File == "" || part.File == res.Body {
			continue
		}
		l := level + 1
		for _, n := range nested {
			if strings.HasPrefix(part.ID, n) {
				l++
			}
		}
		levels[filepath.Join(dir, filepath.FromSlash(part.File))] = l
	}
	outputs := []string{filepath.Join(dir, res.Body), partsFile}
	files, err := filesIn(dir)
	if err != nil {
		return nil, nil, nil, err
	}
	var children []child
	for _, f := range files {
		if f == outputs[0] || f == outputs[1] {
			continue
		}
		l, ok := levels[f]
		if !ok {
			l = level + 1
		}
		children = append(children, child{path: f, level: l})
	}
	var flags []string
	for _, f := range emailProblems {
		if problems[f] {
			flags = append(flags, f)
		}
	}
	return children, outputs, flags, nil
}

// openArchive extracts the archive p into dir, without unpacking the
// archives in it, which Run opens itself, returning the files it holds.
func (x *expander) openArchive(p, dir string, level int, left int64) ([]child, error) {
	if x.o.Runner == nil {
		return nil, &unpack.Error{Kind: unpack.Failed, Msg: "7z not found on PATH; it is in the sandbox image variant (the 7zip package)"}
	}
	_, err := unpack.Extract(x.ctx, p, dir, unpack.Options{Runner: x.o.Runner, Password: x.o.Password, MaxSize: left, Depth: 0, PollInterval: x.o.PollInterval})
	if err != nil {
		return nil, err
	}
	files, err := filesIn(dir)
	if err != nil {
		return nil, err
	}
	children := make([]child, 0, len(files))
	for _, f := range files {
		children = append(children, child{path: f, level: level + 1})
	}
	return children, nil
}

// set records c with outcome's flag, and flags after it, as the record at
// index idx, or as a new one for -1.
func (x *expander) set(idx int, c Container, outcome string, flags ...string) {
	c.Outcome = outcome
	c.Flags = append([]string{outcomeFlags[outcome]}, flags...)
	if idx < 0 {
		x.m.Containers = append(x.m.Containers, c)
		return
	}
	x.m.Containers[idx] = c
}

// rollback removes what a resumed run added, newest first, without
// following links, leaving the destination as it was before the run.
func (x *expander) rollback() error {
	var errs []error
	for i := len(x.added) - 1; i >= 0; i-- {
		p := x.added[i]
		fi, err := os.Lstat(p)
		switch {
		case errors.Is(err, fs.ErrNotExist):
			continue
		case err != nil:
			errs = append(errs, err)
		case fi.IsDir():
			errs = append(errs, removeDir(p))
		default:
			errs = append(errs, os.Remove(p))
		}
	}
	return errors.Join(errs...)
}

func (x *expander) rel(p string) string {
	rel, err := filepath.Rel(x.root, p)
	if err != nil {
		return p
	}
	return filepath.ToSlash(rel)
}

// failure fills in c's code, error, and rejected entries from err and
// returns its outcome.
func failure(c *Container, err error) string {
	c.Error = err.Error()
	var ue *unpack.Error
	var me *mail.Error
	switch {
	case errors.As(err, &ue):
		c.Code = int(ue.Kind)
		for _, e := range ue.Bad {
			c.Rejected = append(c.Rejected, entryOf(e))
		}
		switch ue.Kind {
		case unpack.Rejected:
			return OutcomeRejected
		case unpack.NeedsPassword:
			return OutcomeNeedsPassword
		case unpack.TooLarge:
			return OutcomeTooLarge
		}
	case errors.As(err, &me):
		c.Code = int(me.Kind)
		switch me.Kind {
		case mail.Rejected:
			return OutcomeRejected
		case mail.TooLarge:
			return OutcomeTooLarge
		}
	}
	// Anything else failed, including an input that started like an
	// archive or a message but isn't one, which is corrupt.
	c.Code = int(unpack.Failed)
	return OutcomeFailed
}

// notContainer reports whether err is a nested file's that only started
// like a container: 7z can't open it, or it has no message header.
func notContainer(err error) bool {
	return errors.Is(err, unpack.ErrNotArchive) || mail.KindOf(err) == mail.NotMessage
}

func entryOf(e unpack.Entry) Entry {
	j := Entry{Type: e.Type, Path: e.Path, Flags: e.Flags(), Link: e.Link}
	if j.Flags == nil {
		j.Flags = []string{}
	}
	if e.Size >= 0 {
		size := e.Size
		j.Size = &size
	}
	return j
}

// filesIn returns the regular files under dir, sorted, without following
// links.
func filesIn(dir string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			out = append(out, p)
		}
		return nil
	})
	sort.Strings(out)
	return out, err
}

// removeDir removes dir and everything in it without following links.
func removeDir(dir string) error {
	if err := unpack.EmptyDir(dir); err != nil {
		return err
	}
	return os.Remove(dir)
}

// copyInput copies the regular file in to the new file p, following a link
// to in unless it was found in an input directory, and never p, and returns
// its size and hex SHA-256, and whether it made p.
func copyInput(in source, p string) (int64, string, bool, error) {
	src, err := openSource(in)
	if err != nil {
		return 0, "", false, err
	}
	defer src.Close()
	dst, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return 0, "", false, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(dst, h), src)
	return n, hex.EncodeToString(h.Sum(nil)), true, errors.Join(err, dst.Close())
}

// hashFile returns the size and hex SHA-256 of the regular file in,
// following a link to it unless it was found in an input directory.
func hashFile(in source) (int64, string, error) {
	f, err := openSource(in)
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	return n, hex.EncodeToString(h.Sum(nil)), err
}

// openSource opens the regular file in for reading, following a link to it
// unless it was found in an input directory.
func openSource(in source) (*os.File, error) {
	flags := os.O_RDONLY | syscall.O_NONBLOCK
	if in.inDir {
		flags |= syscall.O_NOFOLLOW
	}
	f, err := os.OpenFile(in.path, flags, 0)
	if err != nil {
		return nil, err
	}
	if fi, err := f.Stat(); err != nil {
		_ = f.Close()
		return nil, err
	} else if !fi.Mode().IsRegular() {
		_ = f.Close()
		return nil, fmt.Errorf("%s is not a regular file", in.path)
	}
	return f, nil
}
