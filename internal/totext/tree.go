package totext

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/josegonzalez/safeclaw/internal/expand"
	"github.com/josegonzalez/safeclaw/internal/mail"
	"github.com/josegonzalez/safeclaw/internal/termtext"
)

// Defaults for TreeOptions' limits.
const (
	DefaultMaxFiles  = 10000
	DefaultMaxOutput = 512 << 20
)

// ManifestText is the manifest ConvertTree writes into OUTDIR.
const ManifestText = "manifest.txt"

// StatusSkipped is a tree entry that wasn't converted: a link, a special
// file, a container safeclaw-expand opened, or one past a limit.
const StatusSkipped = "skipped"

// Reasons a tree entry was skipped, besides ReasonOutputLimit.
const (
	// ReasonFileLimit is a file past TreeOptions.MaxFiles.
	ReasonFileLimit = "file-limit"
	// ReasonLink is a symbolic link, which is never followed.
	ReasonLink = "link"
	// ReasonSpecial is something other than a regular file, a directory,
	// or a link: a FIFO, socket, or device.
	ReasonSpecial = "special"
	// ReasonUnpacked is an email or archive safeclaw-expand opened, whose
	// files are converted instead.
	ReasonUnpacked = "unpacked"
	// ReasonExpandManifest is safeclaw-expand's manifest.json, which is
	// folded into the report instead.
	ReasonExpandManifest = "expand-manifest"
	// ReasonMissing is a container safeclaw-expand's manifest lists that
	// isn't a file in SRC.
	ReasonMissing = "missing"
)

// What TreeReport.Expand says about SRC's safeclaw-expand manifest.
const (
	// ExpandNone is a SRC with no manifest.json.
	ExpandNone = "none"
	// ExpandFolded is a manifest that was read and folded in.
	ExpandFolded = "folded"
	// ExpandInvalid is a manifest.json that isn't a valid safeclaw-expand
	// manifest, so SRC was converted as a plain folder.
	ExpandInvalid = "invalid"
)

// TreeOptions configures ConvertTree: Options for every file, and limits
// for the whole tree.
type TreeOptions struct {
	Options
	// MaxFiles limits how many files are converted; the rest are skipped.
	MaxFiles int
	// MaxOutput limits the total size of the text files written; once a
	// write would pass it, the rest is skipped. The manifest doesn't
	// count.
	MaxOutput int64
	// Replace lets OUTDIR hold an earlier run's results, which are
	// replaced once the run succeeds.
	Replace bool
}

// DefaultTreeOptions returns the defaults, with the real tools.
func DefaultTreeOptions() TreeOptions {
	return TreeOptions{Options: DefaultOptions(), MaxFiles: DefaultMaxFiles, MaxOutput: DefaultMaxOutput}
}

func (o *TreeOptions) validate() error {
	if err := o.Options.validate(); err != nil {
		return err
	}
	if o.MaxFiles < 1 {
		return errors.New("the file limit must be at least 1")
	}
	if o.MaxOutput < 1 {
		return errors.New("the output limit must be positive")
	}
	return nil
}

// TreeReport is what ConvertTree did. It is printed by `safeclaw totext
// --recursive --json`, so its format is stable within a Schema version.
// Lists are never nil.
type TreeReport struct {
	Schema int `json:"schema"`
	// Status is "ok", "partial", or "failed", and Code its exit code.
	Status string `json:"status"`
	Code   int    `json:"code"`
	// Error says why the run failed.
	Error string `json:"error,omitempty"`
	// Warning says what went wrong after the run succeeded: earlier
	// results that TreeOptions.Replace swapped out but couldn't remove.
	Warning string `json:"warning,omitempty"`
	// Expand is ExpandNone, ExpandFolded, or ExpandInvalid, and
	// ExpandError why a manifest was invalid.
	Expand      string `json:"expand"`
	ExpandError string `json:"expand_error,omitempty"`
	// OutputSize is the total size of the text files written.
	OutputSize int64 `json:"output_size"`
	// Entries are every file under SRC, in the order they were walked,
	// then the containers safeclaw-expand's manifest lists that weren't
	// found. Empty for a failed run.
	Entries []Entry `json:"entries"`
}

// Kind returns the report's Kind: OK, Partial, or Failed.
func (r *TreeReport) Kind() Kind { return Kind(r.Code) }

// Entry is one file under SRC.
type Entry struct {
	// Index numbers the entries from 1. A file's outputs start with it,
	// zero-padded to Width.
	Index int `json:"index"`
	// Path is the file's path in SRC, with slashes.
	Path string `json:"path"`
	// Size is the file's size, from lstat.
	Size int64 `json:"size"`
	// Status is the conversion's Kind's name, such as "ok" or
	// "unsupported", or StatusSkipped.
	Status string `json:"status"`
	// Error says what went wrong, as Report's does.
	Error     string `json:"error,omitempty"`
	Type      string `json:"type"`
	Pages     int    `json:"pages"`
	Encrypted bool   `json:"encrypted"`
	// Files are the files written to OUTDIR, in page order.
	Files    []File `json:"files"`
	OCRPages []int  `json:"ocr_pages"`
	// Skipped is what was skipped and why; a skipped entry's reason is a
	// whole-file Skip.
	Skipped []Skip `json:"skipped"`
	// ExpandOutput is the container whose safeclaw-expand output this is,
	// such as an email's body.txt.
	ExpandOutput string `json:"expand_output,omitempty"`
	// Container is safeclaw-expand's record of this file, when it is an
	// email or archive.
	Container *expand.Container `json:"container,omitempty"`
}

// ok reports whether the entry counts as converted for the run's status:
// converted in full, or skipped only because its content is converted
// elsewhere, and not a container left packed.
func (e *Entry) ok() bool {
	if e.Container != nil && e.Container.Outcome != expand.OutcomeUnpacked {
		return false
	}
	switch e.Status {
	case OK.String():
		return true
	case StatusSkipped:
		return len(e.Skipped) == 1 && (e.Skipped[0].Reason == ReasonUnpacked || e.Skipped[0].Reason == ReasonExpandManifest)
	}
	return false
}

// treeFile is a file found under SRC.
type treeFile struct {
	abs  string
	mode fs.FileMode
}

type tree struct {
	o       TreeOptions
	root    string
	dest    string
	r       *TreeReport
	files   []treeFile
	dirs    map[string]bool
	width   int
	budget  *budget
	limited bool
	// prev is the earlier run's results being replaced, and dest then a
	// new directory beside them.
	prev *previous
}

// ConvertTree converts every regular file under src into outdir, flat,
// and writes ManifestText there.
//
// src must be a directory; a link to one is followed, but no link under
// it is. Its files are walked in lexical order, each directory's entries
// sorted by name. Each regular file is converted as Convert converts one,
// with its own per-tool timeouts, into files named NNN-NAME.pNNN.txt,
// NNN-NAME.ocr.txt, or NNN-NAME.text.txt, NNN being its Index and NAME
// its path made safe as mail.SafeName makes attachment names safe, so
// names never collide. Links and special files are listed and skipped.
//
// When src holds a safeclaw-expand manifest that expand.ReadManifest
// accepts, its containers are folded in: each email and archive's entry
// carries its record, one that was opened is skipped since its files are
// converted, manifest.json itself is skipped, and the files the helper
// wrote, an email's body.txt and parts.txt, are converted and marked. The
// manifest's paths are only matched against the files walked, never
// opened. A manifest.json that isn't valid is reported and converted as
// a plain file.
//
// outdir has Convert's rules: it must be missing or an empty directory,
// and not a symbolic link, and it can't be inside src. A file that fails
// leaves nothing in outdir. The run fails, emptying outdir without
// following links, for a usage or I/O error or ctx ending.
//
// With o.Replace, outdir may also hold an earlier run's results: a
// ManifestText that is exactly what WriteText writes for a run that ended
// ok or partial, and only the regular files it lists as outputs. The run
// then writes into a new directory beside outdir, which takes outdir's
// place once the run succeeds, in one step where the filesystem can swap
// directories; the earlier results are then removed without following
// links. A failed run leaves them as they were.
func ConvertTree(ctx context.Context, src, outdir string, o TreeOptions) *TreeReport {
	r := &TreeReport{Schema: Schema, Expand: ExpandNone, Entries: []Entry{}}
	t := &tree{o: o, r: r, dirs: map[string]bool{}}
	if err := t.run(ctx, src, outdir); err != nil {
		if ctx.Err() != nil {
			err = fmt.Errorf("interrupted: %w", err)
		}
		switch {
		case t.prev != nil && t.dest != "":
			// replace may have given it OUTDIR's permissions.
			_ = os.Chmod(t.dest, 0o700)
			if cerr := os.RemoveAll(t.dest); cerr != nil {
				err = errors.Join(err, fmt.Errorf("removing %s: %w", t.dest, cerr))
			}
		case t.dest != "":
			if cerr := emptyDir(t.dest); cerr != nil {
				err = errors.Join(err, fmt.Errorf("emptying %s: %w", outdir, cerr))
			}
		}
		r.Entries, r.OutputSize = []Entry{}, 0
		r.Status, r.Code, r.Error = Failed.String(), int(Failed), err.Error()
		return r
	}
	return r
}

func (t *tree) run(ctx context.Context, src, outdir string) error {
	if err := t.o.validate(); err != nil {
		return err
	}
	root, err := filepath.Abs(src)
	if err != nil {
		return err
	}
	if root, err = filepath.EvalSymlinks(root); err != nil {
		return err
	}
	if fi, err := os.Stat(root); err != nil {
		return err
	} else if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", src)
	}
	t.root = root
	if out, err := resolveOut(outdir); err != nil {
		return err
	} else if within(root, out) {
		return fmt.Errorf("%s is inside %s", outdir, src)
	}
	if t.o.Replace {
		if t.prev, err = checkPrevious(outdir); err != nil {
			return err
		}
	}
	if err := t.walk(ctx); err != nil {
		return err
	}
	m := t.readManifest()
	t.entries(m)
	if t.prev != nil {
		err = t.prepareReplace()
	} else {
		t.dest, err = prepareDest(outdir)
	}
	if err != nil {
		return err
	}
	if within(root, t.dest) {
		return fmt.Errorf("%s is inside %s", outdir, src)
	}
	t.budget = &budget{max: t.o.MaxOutput}
	converted := 0
	for i := range t.r.Entries {
		e := &t.r.Entries[i]
		if e.Status != "" {
			continue
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		switch {
		case t.limited:
			t.skipEntry(e, Skip{Reason: ReasonOutputLimit, Detail: fmt.Sprintf("over the %d byte output limit", t.o.MaxOutput)})
		case converted >= t.o.MaxFiles:
			t.skipEntry(e, Skip{Reason: ReasonFileLimit, Detail: fmt.Sprintf("over the %d file limit", t.o.MaxFiles)})
		default:
			converted++
			if err := t.convert(ctx, e, t.files[i].abs); err != nil {
				return err
			}
		}
	}
	t.r.OutputSize = t.budget.used
	kind := OK
	for i := range t.r.Entries {
		if !t.r.Entries[i].ok() {
			kind = Partial
		}
	}
	t.r.Status, t.r.Code = kind.String(), int(kind)
	if err := t.writeManifest(); err != nil {
		return err
	}
	if t.prev != nil {
		return t.replace(ctx, outdir)
	}
	return nil
}

// prepareReplace makes the directory the run writes into in place of the
// earlier results: beside them, so it can take their place in one rename
// on the same filesystem.
func (t *tree) prepareReplace() error {
	dest, err := os.MkdirTemp(filepath.Dir(t.prev.path), "."+filepath.Base(t.prev.path)+".totext-*")
	if err != nil {
		return err
	}
	t.dest = dest
	return nil
}

// replace puts the run's results in place of the earlier ones, checking
// first that outdir is still the directory checked at the start and still
// holds only earlier results, and then removes those. The new directory
// gets OUTDIR's permissions. Once they are swapped, nothing fails the run.
func (t *tree) replace(ctx context.Context, outdir string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Chmod(t.dest, t.prev.info.Mode().Perm()); err != nil {
		return err
	}
	if fi, err := os.Lstat(t.prev.path); err != nil {
		return err
	} else if !os.SameFile(fi, t.prev.info) {
		return fmt.Errorf("%s changed during the run", outdir)
	}
	if err := checkResults(t.prev.path); err != nil {
		return fmt.Errorf("%s changed during the run: %w", outdir, err)
	}
	old, err := replaceDir(t.dest, t.prev)
	if err != nil {
		return fmt.Errorf("replacing %s: %w", outdir, err)
	}
	t.dest = t.prev.path
	// OUTDIR's permissions may not let its files be removed.
	_ = os.Chmod(old, 0o700)
	if err := os.RemoveAll(old); err != nil {
		t.r.Warning = fmt.Sprintf("the earlier results couldn't all be removed from %s: %v", old, err)
	}
	return nil
}

// resolveOut returns outdir's absolute path with the links in it
// resolved, as far as they exist.
func resolveOut(outdir string) (string, error) {
	abs, err := filepath.Abs(outdir)
	if err != nil {
		return "", err
	}
	if _, err := os.Lstat(abs); err == nil {
		return filepath.EvalSymlinks(abs)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return "", err
	}
	return filepath.Join(parent, filepath.Base(abs)), nil
}

// within reports whether p is dir or inside it.
func within(dir, p string) bool {
	rel, err := filepath.Rel(dir, p)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// walk lists everything under the root without following links, in
// lexical order. A directory that can't be read gets a failed entry.
func (t *tree) walk(ctx context.Context) error {
	return filepath.WalkDir(t.root, func(p string, d fs.DirEntry, err error) error {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		if p == t.root {
			return err
		}
		rel, rerr := filepath.Rel(t.root, p)
		if rerr != nil {
			return rerr
		}
		rel = filepath.ToSlash(rel)
		if err != nil {
			t.add(treeFile{abs: p}, Entry{Path: rel, Status: Failed.String(), Error: err.Error()})
			if d != nil && d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.IsDir() {
			t.dirs[rel] = true
			return nil
		}
		e := Entry{Path: rel}
		info, err := d.Info()
		if err != nil {
			e.Status, e.Error = Failed.String(), err.Error()
		} else {
			e.Size = info.Size()
		}
		t.add(treeFile{abs: p, mode: d.Type()}, e)
		return nil
	})
}

func (t *tree) add(f treeFile, e Entry) {
	e.Index = len(t.r.Entries) + 1
	if e.Type == "" {
		e.Type = TypeUnknown
	}
	e.Files, e.OCRPages, e.Skipped = []File{}, []int{}, []Skip{}
	t.files = append(t.files, f)
	t.r.Entries = append(t.r.Entries, e)
}

// readManifest reads the root's safeclaw-expand manifest, or returns nil
// when there is none or it isn't valid.
func (t *tree) readManifest() *expand.Manifest {
	if _, err := os.Lstat(filepath.Join(t.root, expand.ManifestFile)); err != nil {
		return nil
	}
	m, err := expand.ReadManifest(t.root)
	if err != nil {
		t.r.Expand, t.r.ExpandError = ExpandInvalid, err.Error()
		return nil
	}
	t.r.Expand = ExpandFolded
	return m
}

// entries decides what happens to each entry before anything is
// converted, folding in m when there is one, and leaves the ones to
// convert with no status.
func (t *tree) entries(m *expand.Manifest) {
	containers := map[string]*expand.Container{}
	outputs := map[string]string{}
	if m != nil {
		for i := range m.Containers {
			c := &m.Containers[i]
			containers[c.Path] = c
			for _, o := range c.Outputs {
				outputs[o] = c.Path
			}
		}
	}
	seen := map[string]bool{}
	for i := range t.r.Entries {
		e := &t.r.Entries[i]
		mode := t.files[i].mode
		if c, ok := containers[e.Path]; ok {
			e.Container = c
			seen[e.Path] = true
		}
		e.ExpandOutput = outputs[e.Path]
		switch {
		case e.Status != "":
		case mode&fs.ModeSymlink != 0:
			t.skipEntry(e, Skip{Reason: ReasonLink, Detail: "links are not followed"})
		case !mode.IsRegular():
			t.skipEntry(e, Skip{Reason: ReasonSpecial, Detail: "not a regular file"})
		case m != nil && e.Path == expand.ManifestFile:
			t.skipEntry(e, Skip{Reason: ReasonExpandManifest, Detail: "folded into the report"})
		case e.Container != nil && e.Container.Outcome == expand.OutcomeUnpacked && t.dirs[e.Container.Unpacked]:
			// An outcome other than unpacked, including one this version
			// doesn't know, is a container left packed, converted like
			// any other file.
			t.skipEntry(e, Skip{Reason: ReasonUnpacked, Detail: "opened by safeclaw-expand into " + e.Container.Unpacked})
		}
	}
	if m != nil {
		for i := range m.Containers {
			c := &m.Containers[i]
			if seen[c.Path] {
				continue
			}
			t.add(treeFile{}, Entry{Path: c.Path, Container: c})
			t.skipEntry(&t.r.Entries[len(t.r.Entries)-1], Skip{Reason: ReasonMissing, Detail: "listed in the manifest but not a file in SRC"})
		}
	}
	t.width = max(3, len(strconv.Itoa(len(t.r.Entries))))
}

func (t *tree) skipEntry(e *Entry, s Skip) {
	e.Status = StatusSkipped
	e.Skipped = append(e.Skipped, s)
}

// id is an entry's index as its outputs start with it.
func (t *tree) id(e *Entry) string {
	return fmt.Sprintf("%0*d", t.width, e.Index)
}

// convert converts one entry's file. The error is for what fails the
// run: ctx ending, or a failed file's outputs that can't be removed.
func (t *tree) convert(ctx context.Context, e *Entry, abs string) error {
	// The walk saw a regular file; make sure it still is one, not a link.
	if fi, err := os.Lstat(abs); err != nil || !fi.Mode().IsRegular() {
		if err == nil {
			err = errors.New("it changed from a regular file during the run")
		}
		e.Status, e.Error = Failed.String(), err.Error()
		return nil
	}
	name := mail.SafeName(e.Path)
	if name == "" {
		name = "file"
	}
	r := &Report{Schema: Schema, Type: TypeUnknown, Files: []File{}, OCRPages: []int{}, Skipped: []Skip{}}
	c := &converter{o: t.o.Options, src: abs, root: t.dest, r: r, prefix: t.id(e) + "-" + name + ".", budget: t.budget}
	used := t.budget.used
	kind, err := c.run(ctx)
	if c.tmp != "" {
		_ = os.RemoveAll(c.tmp)
	}
	if cerr := ctx.Err(); cerr != nil {
		return cerr
	}
	if kind != OK && kind != Partial {
		if rerr := c.removeCreated(); rerr != nil {
			return fmt.Errorf("removing what %s wrote: %w", e.Path, rerr)
		}
		t.budget.used = used
		r.Files, r.OCRPages = []File{}, []int{}
	}
	r.end(kind, err)
	e.Status, e.Error, e.Type, e.Pages, e.Encrypted = r.Status, r.Error, r.Type, r.Pages, r.Encrypted
	e.Files, e.OCRPages, e.Skipped = r.Files, r.OCRPages, r.Skipped
	if c.limited {
		t.limited = true
		if len(e.Files) == 0 {
			e.Status = StatusSkipped
		}
	}
	return nil
}

// writeManifest writes ManifestText into OUTDIR, never over or through
// anything there.
func (t *tree) writeManifest() error {
	f, err := os.OpenFile(filepath.Join(t.dest, ManifestText), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644)
	if err != nil {
		return err
	}
	err = t.r.WriteText(f)
	return errors.Join(err, f.Close())
}

// WriteText writes the report as tab-separated lines, as ManifestText
// holds it: a tree line, then for each entry a file line, an error line
// when it has an error, a container line when safeclaw-expand recorded
// it, and its page and skipped lines. Paths, errors, and details are
// escaped as termtext.EscapeField escapes them.
func (r *TreeReport) WriteText(w io.Writer) error {
	var b strings.Builder
	width := max(3, len(strconv.Itoa(len(r.Entries))))
	fmt.Fprintf(&b, "tree\t%s\t%d\t%d\t%s\t%s\n", r.Status, len(r.Entries), r.OutputSize, r.Expand, dash(termtext.EscapeField(r.ExpandError)))
	for i := range r.Entries {
		e := &r.Entries[i]
		id := fmt.Sprintf("%0*d", width, e.Index)
		var flags []string
		if e.Encrypted {
			flags = append(flags, "ENCRYPTED")
		}
		if e.ExpandOutput != "" {
			flags = append(flags, "EXPAND-OUTPUT")
		}
		fmt.Fprintf(&b, "file\t%s\t%s\t%s\t%s\t%d\t%d\t%s\n", id, termtext.EscapeField(e.Path), e.Status, e.Type, e.Size, e.Pages, dash(strings.Join(flags, ",")))
		if e.Error != "" {
			fmt.Fprintf(&b, "error\t%s\t%s\n", id, termtext.EscapeField(e.Error))
		}
		if c := e.Container; c != nil {
			fmt.Fprintf(&b, "container\t%s\t%s\t%d\t%s\t%s\t%s\t%s\n", id, termtext.EscapeField(c.Kind), c.Depth, termtext.EscapeField(c.Outcome),
				dash(termtext.EscapeField(strings.Join(c.Flags, ","))), dash(termtext.EscapeField(c.Parent)), dash(termtext.EscapeField(c.Error)))
		}
		for _, f := range e.Files {
			ocr := "-"
			if f.OCR {
				ocr = "OCR"
			}
			fmt.Fprintf(&b, "page\t%s\t%d\t%d\t%s\t%s\n", id, f.Page, f.Chars, termtext.EscapeField(f.Path), ocr)
		}
		for _, s := range e.Skipped {
			fmt.Fprintf(&b, "skipped\t%s\t%d\t%d\t%s\t%s\t%s\n", id, s.FirstPage, s.LastPage, s.Reason, dash(s.Tool), dash(termtext.EscapeField(s.Detail)))
		}
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
