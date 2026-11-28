// Package expand opens a tree of untrusted emails and archives into one
// destination: each input is copied in, and every email and archive in
// the tree is opened next to itself into NAME.unpacked, emails as the mail
// package extracts them and archives as the unpack package does, with one
// depth and size limit for the whole tree. A container that fails is left
// packed and flagged, and everything else is kept. A manifest in the
// destination records every container. It backs `safeclaw expand`,
// installed as safeclaw-expand in the sandbox image variant.
package expand

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
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
)

// outcomeFlags are the flag each outcome gets, the same as
// safeclaw-unpack's.
var outcomeFlags = map[string]string{
	OutcomeUnpacked:      unpack.FlagUnpacked,
	OutcomeRejected:      unpack.FlagRejected,
	OutcomeNeedsPassword: unpack.FlagNeedsPassword,
	OutcomeTooLarge:      unpack.FlagTooLarge,
	OutcomeFailed:        unpack.FlagFailed,
	OutcomeDepthLimit:    unpack.FlagDepthLimit,
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
}

// Run copies inputs into dest, which must be missing or an empty directory,
// and not a symbolic link, and opens every container in the tree, writing
// the manifest to dest/manifest.json and returning it.
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
// An input that is missing or not a regular file (a link to one is
// followed) fails the run before dest is touched. An I/O error outside a
// container, or ctx ending, fails it too, emptying dest without following
// links.
func Run(ctx context.Context, inputs []string, dest string, o Options) (*Manifest, error) {
	if len(inputs) == 0 {
		return nil, errors.New("no inputs")
	}
	if o.MaxSize <= 0 {
		return nil, errors.New("the size limit must be positive")
	}
	if o.Depth < 0 {
		return nil, errors.New("the depth limit can't be negative")
	}
	for _, in := range inputs {
		if fi, err := os.Stat(in); err != nil {
			return nil, err
		} else if !fi.Mode().IsRegular() {
			return nil, fmt.Errorf("%s is not a regular file", in)
		}
	}
	root, err := unpack.PrepareDest(dest)
	if err != nil {
		return nil, err
	}
	x := &expander{ctx: ctx, o: o, root: root, m: &Manifest{
		Schema: SchemaVersion, Status: "ok",
		Options:    ManifestOptions{Depth: o.Depth, MaxSize: o.MaxSize, Mail: !o.NoMail, Password: o.Password != nil},
		Inputs:     []Input{},
		Containers: []Container{},
	}}
	if err := x.run(inputs); err != nil {
		if ctx.Err() != nil {
			err = fmt.Errorf("interrupted: %w", err)
		}
		if cerr := unpack.EmptyDir(root); cerr != nil {
			err = errors.Join(err, fmt.Errorf("emptying %s: %w", dest, cerr))
		}
		return nil, err
	}
	return x.m, nil
}

type expander struct {
	ctx  context.Context
	o    Options
	root string
	m    *Manifest
}

func (x *expander) run(inputs []string) error {
	var copies []string
	for i, in := range inputs {
		name := mail.SafeName(filepath.Base(in))
		if name == "" {
			name = "input"
		}
		p := filepath.Join(x.root, fmt.Sprintf("%d-%s", i+1, name))
		n, err := copyInput(in, p)
		if err != nil {
			return fmt.Errorf("copying %s: %w", in, err)
		}
		x.m.Inputs = append(x.m.Inputs, Input{Path: x.rel(p), Size: n})
		copies = append(copies, p)
	}
	for i, p := range copies {
		kind, err := x.consider(p, 0, "")
		if err != nil {
			return err
		}
		x.m.Inputs[i].Kind = kind
	}
	return writeManifest(x.root, x.m)
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
	return kind, x.open(p, kind, level, parent)
}

// detect returns p's container kind, without following a link.
func (x *expander) detect(p string) (string, error) {
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
	if x.o.NoMail {
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
// it.
func (x *expander) open(p, kind string, level int, parent string) error {
	c := Container{Path: x.rel(p), Kind: kind, Depth: level, Parent: parent}
	if level > x.o.Depth {
		x.record(c, OutcomeDepthLimit)
		return nil
	}
	used := x.m.Size
	left := x.o.MaxSize - used
	if left <= 0 {
		c.Code = int(unpack.TooLarge)
		c.Error = (&unpack.Error{Kind: unpack.TooLarge, Msg: fmt.Sprintf("nothing is left of the %d byte limit", x.o.MaxSize)}).Error()
		x.record(c, OutcomeTooLarge)
		return nil
	}
	dir, err := unpack.UniqueDir(p + unpack.UnpackedSuffix)
	if err != nil {
		return err
	}
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
		if level > 0 && notContainer(err) {
			// It only started like one.
			return nil
		}
		outcome := failure(&c, err)
		x.record(c, outcome)
		return nil
	}
	c.Unpacked = x.rel(dir)
	for _, o := range outputs {
		c.Outputs = append(c.Outputs, x.rel(o))
	}
	x.record(c, OutcomeUnpacked, flags...)
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

// record adds c with outcome's flag, and flags after it.
func (x *expander) record(c Container, outcome string, flags ...string) {
	c.Outcome = outcome
	c.Flags = append([]string{outcomeFlags[outcome]}, flags...)
	x.m.Containers = append(x.m.Containers, c)
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
// to in but never p, and returns its size.
func copyInput(in, p string) (int64, error) {
	src, err := os.OpenFile(in, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return 0, err
	}
	defer src.Close()
	if fi, err := src.Stat(); err != nil {
		return 0, err
	} else if !fi.Mode().IsRegular() {
		return 0, fmt.Errorf("%s is not a regular file", in)
	}
	dst, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return 0, err
	}
	n, err := io.Copy(dst, src)
	return n, errors.Join(err, dst.Close())
}
