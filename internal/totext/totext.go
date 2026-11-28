// Package totext turns an untrusted PDF, image, or text file into text
// files that are safe to read, with poppler's pdfinfo, pdftotext, and
// pdftoppm and with tesseract. It is the logic behind `safeclaw totext`,
// which the sandbox image variant links as safeclaw-totext.
package totext

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"syscall"
	"time"
)

// Schema is the version of the Report format. Fields may be added within
// a version, but are never renamed, removed, or given a new meaning
// without a new one.
const Schema = 1

// Defaults for Options.
const (
	DefaultMaxPages     = 100
	DefaultOCRThreshold = 10
	DefaultOCRDPI       = 300
	DefaultOCRLang      = "eng"
	DefaultTimeout      = 60 * time.Second
	// DefaultMaxPixels is the default limit on the longer side of a page
	// rendered for OCR, so a crafted page size can't make pdftoppm render
	// an enormous image.
	DefaultMaxPixels = 10000
	// MaxOCRDPI is the highest --ocr-dpi accepted.
	MaxOCRDPI = 1200
)

// Output file names for an image's OCR and a text file's copy. A PDF's
// pages are p001.txt, p002.txt, and so on.
const (
	ImageOutput = "ocr.txt"
	TextOutput  = "text.txt"
)

// Kind is how a conversion ended. Its value is the exit code. The codes
// follow safeclaw-unpack's where the meaning is shared (1 failed, 3 needs a
// password, 5 not a file it handles), and leave unpack's 2 (rejected) and 4
// (too large) unused.
type Kind int

// Outcomes, and the exit codes `safeclaw totext` uses for them.
const (
	// OK is every page converted.
	OK Kind = 0
	// Failed is any other failure: a tool failed on the whole file, the
	// file is corrupt, or a usage or I/O error. OUTDIR is emptied.
	Failed Kind = 1
	// Unsupported is a file that is not a PDF, a supported image, or
	// text. OUTDIR is emptied.
	Unsupported Kind = 5
	// Encrypted is a PDF that can't be read without a password. OUTDIR is
	// emptied.
	Encrypted Kind = 3
	// Partial is text written for the file but something skipped: pages
	// over the page limit, or a page whose extraction or OCR timed out or
	// failed. OUTDIR keeps what was written.
	Partial Kind = 6
	// TimedOut is a tool that timed out on the whole file, pdfinfo or an
	// image's OCR, so nothing was written. OUTDIR is emptied.
	TimedOut Kind = 7
)

func (k Kind) String() string {
	switch k {
	case OK:
		return "ok"
	case Unsupported:
		return ReasonUnsupported
	case Encrypted:
		return ReasonEncrypted
	case Partial:
		return "partial"
	case TimedOut:
		return ReasonTimedOut
	}
	return ReasonFailed
}

// Reasons something was skipped.
const (
	ReasonEncrypted   = "encrypted"
	ReasonPageLimit   = "page-limit"
	ReasonTimedOut    = "timed-out"
	ReasonUnsupported = "unsupported"
	ReasonFailed      = "failed"
	// ReasonOutputLimit is what a tree's --max-output left unconverted.
	ReasonOutputLimit = "output-limit"
)

// Options configures Convert. Zero values take the defaults, except
// OCRThreshold, where 0 turns OCR of PDF pages off; use
// DefaultOptions for the defaults.
type Options struct {
	// Runner runs the tools.
	Runner Runner
	// MaxPages is how many of a PDF's pages are converted; the rest are
	// skipped.
	MaxPages int
	// OCRThreshold is the number of characters, not counting whitespace,
	// below which a PDF page is rendered and OCR'd. 0 turns it off.
	OCRThreshold int
	// OCRDPI is the resolution pages are rendered at for OCR.
	OCRDPI int
	// OCRLang is tesseract's -l: language names joined with +.
	OCRLang string
	// Timeout limits each run of each tool.
	Timeout time.Duration
	// MaxPixels limits the longer side of a rendered page, lowering the
	// resolution for a page too large for OCRDPI.
	MaxPixels int
}

// DefaultOptions returns the defaults, with the real tools.
func DefaultOptions() Options {
	return Options{
		Runner:       Exec{},
		MaxPages:     DefaultMaxPages,
		OCRThreshold: DefaultOCRThreshold,
		OCRDPI:       DefaultOCRDPI,
		OCRLang:      DefaultOCRLang,
		Timeout:      DefaultTimeout,
		MaxPixels:    DefaultMaxPixels,
	}
}

var langRe = regexp.MustCompile(`^[A-Za-z0-9_]+(\+[A-Za-z0-9_]+)*$`)

func (o *Options) validate() error {
	if o.Runner == nil {
		return errors.New("no tool runner")
	}
	if o.MaxPages < 1 {
		return errors.New("the page limit must be at least 1")
	}
	if o.OCRThreshold < 0 {
		return errors.New("the OCR threshold can't be negative")
	}
	if o.OCRDPI < 1 || o.OCRDPI > MaxOCRDPI {
		return fmt.Errorf("the OCR resolution must be between 1 and %d", MaxOCRDPI)
	}
	if !langRe.MatchString(o.OCRLang) {
		return fmt.Errorf("invalid OCR language %q: want tesseract language names such as eng or eng+deu", o.OCRLang)
	}
	if o.Timeout <= 0 {
		return errors.New("the timeout must be positive")
	}
	if o.MaxPixels <= 0 {
		o.MaxPixels = DefaultMaxPixels
	}
	return nil
}

// Report is what Convert did. It is printed by `safeclaw totext --json`,
// so its format is stable within a Schema version. Lists are never nil.
type Report struct {
	Schema int `json:"schema"`
	// Status is the Kind's name, such as "ok" or "partial".
	Status string `json:"status"`
	// Code is the Kind, the exit code.
	Code int `json:"code"`
	// Error says what went wrong, for every Kind but OK and Partial.
	Error string `json:"error,omitempty"`
	// Type is the type detected from the file's first bytes, such as
	// "pdf", "png", or "text", or "unknown".
	Type string `json:"type"`
	// Pages is a PDF's page count, 1 for an image or text file, and 0 when
	// it isn't known.
	Pages int `json:"pages"`
	// Encrypted is whether a PDF is encrypted, readable or not.
	Encrypted bool `json:"encrypted"`
	// Files are the files written, in page order.
	Files []File `json:"files"`
	// OCRPages are the pages whose file holds OCR text.
	OCRPages []int `json:"ocr_pages"`
	// Skipped is what was skipped, and why.
	Skipped []Skip `json:"skipped"`
}

// Kind returns the report's Kind.
func (r *Report) Kind() Kind { return Kind(r.Code) }

// File is one file written to OUTDIR.
type File struct {
	// Page is the PDF page, 1 for an image or text file.
	Page int `json:"page"`
	// Path is the file's name in OUTDIR.
	Path string `json:"path"`
	// Chars is the number of characters in the file, not counting
	// whitespace.
	Chars int `json:"chars"`
	// OCR is whether the text came from OCR.
	OCR bool `json:"ocr"`
}

// Skip is something skipped: a range of pages, or with pages 0 the whole
// file.
type Skip struct {
	FirstPage int `json:"first_page"`
	LastPage  int `json:"last_page"`
	// Reason is one of the Reason constants.
	Reason string `json:"reason"`
	// Tool is the tool that timed out or failed.
	Tool string `json:"tool,omitempty"`
	// Detail says more, for people rather than parsing.
	Detail string `json:"detail,omitempty"`
}

// Convert writes the text of file into outdir, which must be missing or an
// empty directory, and not a symbolic link.
//
// The file's type comes from its first bytes. A PDF's page count is read
// with pdfinfo, and each page up to Options.MaxPages is extracted with
// `pdftotext -layout` into its own file; a page with fewer than
// Options.OCRThreshold characters is rendered with pdftoppm and OCR'd with
// tesseract, and the OCR text replaces the page's unless it has fewer
// characters. An image is OCR'd into ImageOutput, and a text file copied
// into TextOutput. Control characters are removed from everything written.
// Each tool run is limited to Options.Timeout. When the result's Kind is
// anything but OK or Partial, outdir is emptied, without following links.
func Convert(ctx context.Context, file, outdir string, o Options) *Report {
	r := &Report{Schema: Schema, Type: TypeUnknown, Files: []File{}, OCRPages: []int{}, Skipped: []Skip{}}
	if err := o.validate(); err != nil {
		return r.end(Failed, err)
	}
	src, err := filepath.Abs(file)
	if err != nil {
		return r.end(Failed, err)
	}
	if fi, err := os.Stat(src); err != nil {
		return r.end(Failed, err)
	} else if !fi.Mode().IsRegular() {
		return r.end(Failed, fmt.Errorf("%s is not a regular file", file))
	}
	root, err := prepareDest(outdir)
	if err != nil {
		return r.end(Failed, err)
	}
	c := &converter{o: o, src: src, root: root, r: r}
	kind, err := c.run(ctx)
	if c.tmp != "" {
		_ = os.RemoveAll(c.tmp)
	}
	if kind != OK && kind != Partial {
		if cerr := emptyDir(root); cerr != nil {
			err = errors.Join(err, fmt.Errorf("emptying %s: %w", outdir, cerr))
		}
		r.Files, r.OCRPages = []File{}, []int{}
	}
	return r.end(kind, err)
}

func (r *Report) end(k Kind, err error) *Report {
	r.Status, r.Code = k.String(), int(k)
	if err != nil {
		r.Error = err.Error()
	}
	return r
}

type converter struct {
	o    Options
	src  string
	root string
	r    *Report
	// tmp holds rendered pages.
	tmp string
	// prefix starts the name of every file written, "" for one file's
	// OUTDIR, and NNN-NAME. in a tree's.
	prefix string
	// budget limits what a tree's files write; nil for no limit.
	budget *budget
	// created are the files created in root.
	created []string
	// limited is whether the budget ran out during the conversion.
	limited bool
}

// errOutputLimit is a write that would take a tree's output past its
// limit.
var errOutputLimit = errors.New("over the output limit")

// budget is what a tree's text files may still write.
type budget struct {
	max, used int64
}

// counted writes to w, counting what it writes against b when b is set.
type counted struct {
	w io.Writer
	b *budget
	n int64
}

func (w *counted) Write(p []byte) (int, error) {
	if w.b != nil {
		if w.b.used+int64(len(p)) > w.b.max {
			return 0, errOutputLimit
		}
		w.b.used += int64(len(p))
	}
	n, err := w.w.Write(p)
	w.n += int64(n)
	if w.b != nil {
		w.b.used -= int64(len(p) - n)
	}
	return n, err
}

// output counts what is written to f against the budget.
func (c *converter) output(f io.Writer) *counted {
	return &counted{w: f, b: c.budget}
}

// release gives n bytes back to the budget, for a file removed or
// replaced.
func (c *converter) release(n int64) {
	if c.budget != nil {
		c.budget.used -= n
	}
}

// drop removes the file name and gives its n bytes back.
func (c *converter) drop(name string, n int64) error {
	c.release(n)
	return os.Remove(filepath.Join(c.root, name))
}

// limit records that the budget ran out, skipping pages first to last
// when there are any.
func (c *converter) limit(first, last int, tool string) {
	c.limited = true
	if first <= last {
		c.skip(Skip{FirstPage: first, LastPage: last, Reason: ReasonOutputLimit, Tool: tool, Detail: fmt.Sprintf("over the %d byte output limit", c.budget.max)})
	}
}

// stopOnError passes writes to w, and stops the tool with the error when
// one fails, so a tool whose output can't be written isn't left waiting
// for its timeout.
type stopOnError struct {
	w    io.Writer
	stop context.CancelCauseFunc
}

func (s stopOnError) Write(p []byte) (int, error) {
	n, err := s.w.Write(p)
	if err != nil {
		s.stop(err)
	}
	return n, err
}

// errTimedOut is a tool that ran past its timeout.
type errTimedOut struct{ tool string }

func (e errTimedOut) Error() string { return e.tool + " timed out" }

func (c *converter) run(ctx context.Context) (Kind, error) {
	typ, err := DetectFile(c.src)
	if err != nil {
		return Failed, err
	}
	c.r.Type = typ
	switch {
	case typ == TypePDF:
		return c.pdf(ctx)
	case IsImage(typ):
		return c.image(ctx)
	case typ == TypeText:
		return c.text()
	}
	c.skip(Skip{Reason: ReasonUnsupported, Detail: "not a PDF, a supported image, or text"})
	return Unsupported, errors.New("not a PDF, a PNG, JPEG, GIF, TIFF, BMP, or WebP image, or UTF-8 text")
}

func (c *converter) skip(s Skip) {
	c.r.Skipped = append(c.r.Skipped, s)
}

// done is the Kind for a conversion that wrote what it could.
func (c *converter) done() (Kind, error) {
	if len(c.r.Skipped) > 0 {
		return Partial, nil
	}
	return OK, nil
}

// tool runs a tool under its timeout. It returns errTimedOut when the
// timeout ended it, ctx's error when ctx ended it, and the error writing
// its output when that ended it.
func (c *converter) tool(ctx context.Context, stdout io.Writer, name string, args ...string) error {
	wctx, stop := context.WithCancelCause(ctx)
	defer stop(nil)
	tctx, cancel := context.WithTimeout(wctx, c.o.Timeout)
	defer cancel()
	err := c.o.Runner.Run(tctx, stopOnError{w: stdout, stop: stop}, name, args...)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if cause := context.Cause(wctx); cause != nil {
		return cause
	}
	if err != nil && errors.Is(tctx.Err(), context.DeadlineExceeded) {
		return errTimedOut{name}
	}
	return err
}

// toolSkip describes a tool's failure as a Skip of pages first to last,
// or returns false when err isn't the tool's own failure, such as a
// missing tool or an interrupt, which ends the conversion.
func toolSkip(err error, tool string, first, last int) (Skip, bool) {
	var to errTimedOut
	if errors.As(err, &to) {
		return Skip{FirstPage: first, LastPage: last, Reason: ReasonTimedOut, Tool: tool, Detail: err.Error()}, true
	}
	var ee *ExitError
	if errors.As(err, &ee) {
		return Skip{FirstPage: first, LastPage: last, Reason: ReasonFailed, Tool: tool, Detail: err.Error()}, true
	}
	return Skip{}, false
}

// needsPassword reports whether a poppler tool failed for want of a
// password, or, with exit status 3, for the document's permissions.
func needsPassword(err error) bool {
	var ee *ExitError
	return errors.As(err, &ee) && (ee.Code == 3 || passwordRe.MatchString(ee.Stderr))
}

var passwordRe = regexp.MustCompile(`(?i)incorrect password`)

// create makes a new file in the output directory, refusing to follow or
// replace anything already there.
func (c *converter) create(name string) (*os.File, error) {
	f, err := os.OpenFile(filepath.Join(c.root, name), os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o644)
	if err == nil {
		c.created = append(c.created, name)
	}
	return f, err
}

// removeCreated removes every file the conversion created, for one that
// didn't end OK or Partial in a tree.
func (c *converter) removeCreated() error {
	var errs []error
	for _, name := range c.created {
		if err := os.Remove(filepath.Join(c.root, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

func (c *converter) add(f File) {
	c.r.Files = append(c.r.Files, f)
	if f.OCR {
		c.r.OCRPages = append(c.r.OCRPages, f.Page)
	}
}

func (c *converter) pdf(ctx context.Context) (Kind, error) {
	var out capped
	out.max = 1 << 20
	err := c.tool(ctx, &out, "pdfinfo", "-f", "1", "-l", strconv.Itoa(c.o.MaxPages), "--", c.src)
	if err != nil {
		var to errTimedOut
		switch {
		case needsPassword(err):
			c.r.Encrypted = true
			c.skip(Skip{Reason: ReasonEncrypted, Tool: "pdfinfo", Detail: "the PDF needs a password"})
			return Encrypted, errors.New("the PDF is encrypted and needs a password")
		case errors.As(err, &to):
			c.skip(Skip{Reason: ReasonTimedOut, Tool: "pdfinfo", Detail: err.Error()})
			return TimedOut, err
		}
		return Failed, err
	}
	info, err := parsePDFInfo(out.String())
	if err != nil {
		return Failed, err
	}
	c.r.Pages, c.r.Encrypted = info.pages, info.encrypted
	n := min(info.pages, c.o.MaxPages)
	width := max(3, len(strconv.Itoa(n)))
	for p := 1; p <= n; p++ {
		err := c.page(ctx, info, p, fmt.Sprintf("%sp%0*d.txt", c.prefix, width, p))
		if errors.Is(err, errOutputLimit) {
			// The pages after the one the output ran out on are skipped,
			// and that one too unless it has a file or a skip already.
			first := p
			if k := len(c.r.Files); k > 0 && c.r.Files[k-1].Page == p {
				first = p + 1
			} else if k := len(c.r.Skipped); k > 0 && c.r.Skipped[k-1].LastPage == p {
				first = p + 1
			}
			c.limit(first, n, "")
			break
		}
		if err != nil {
			if needsPassword(err) {
				c.skip(Skip{Reason: ReasonEncrypted, Tool: "pdftotext", Detail: "the PDF's permissions don't allow extracting its text"})
				return Encrypted, errors.New("the PDF is encrypted and doesn't allow extracting its text")
			}
			return Failed, err
		}
	}
	if info.pages > n {
		c.skip(Skip{FirstPage: n + 1, LastPage: info.pages, Reason: ReasonPageLimit, Detail: fmt.Sprintf("over the %d page limit", c.o.MaxPages)})
	}
	return c.done()
}

// page extracts page p into name. A tool timing out or failing on the
// page is recorded as a Skip; the error is for anything that ends the
// conversion, or errOutputLimit when a tree's output ran out, with the
// page's text kept when it was written in full.
func (c *converter) page(ctx context.Context, info *pdfInfo, p int, name string) error {
	f, err := c.create(name)
	if err != nil {
		return err
	}
	out := c.output(f)
	cw := newCleaner(out)
	pg := strconv.Itoa(p)
	err = c.tool(ctx, cw, "pdftotext", "-layout", "-enc", "UTF-8", "-f", pg, "-l", pg, "--", c.src, "-")
	if cerr := cw.Close(); err == nil {
		err = cerr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if errors.Is(err, errOutputLimit) {
		return errors.Join(err, c.drop(name, out.n))
	}
	textOK := err == nil
	chars := cw.Chars()
	if err != nil {
		if needsPassword(err) {
			return err
		}
		s, ok := toolSkip(err, "pdftotext", p, p)
		if !ok {
			return err
		}
		c.skip(s)
		chars = 0
	}
	ocr := false
	var limited error
	if c.o.OCRThreshold > 0 && chars < c.o.OCRThreshold {
		n, used, err := c.ocrPage(ctx, info, p, name, chars, !textOK, out.n)
		switch {
		case errors.Is(err, errOutputLimit):
			limited = err
		case err != nil:
			return err
		case used:
			ocr, chars, textOK = true, n, true
		}
	}
	if !textOK {
		return errors.Join(limited, c.drop(name, out.n))
	}
	c.add(File{Page: p, Path: name, Chars: chars, OCR: ocr})
	return limited
}

// ocrPage renders page p and OCRs it. When the OCR text has at least
// textChars characters, or replace is set, it replaces the page's file,
// which held textSize bytes, and used is true. It returns errOutputLimit,
// with the page skipped, when a tree's output ran out.
func (c *converter) ocrPage(ctx context.Context, info *pdfInfo, p int, name string, textChars int, replace bool, textSize int64) (chars int, used bool, err error) {
	if c.tmp == "" {
		if c.tmp, err = os.MkdirTemp("", "safeclaw-totext-*"); err != nil {
			return 0, false, err
		}
	}
	dpi := c.dpi(info, p)
	base := filepath.Join(c.tmp, "page")
	img := base + ".png"
	defer os.Remove(img)
	pg := strconv.Itoa(p)
	err = c.tool(ctx, io.Discard, "pdftoppm", "-f", pg, "-l", pg, "-r", strconv.Itoa(dpi), "-gray", "-png", "-singlefile", "--", c.src, base)
	if err != nil {
		s, ok := toolSkip(err, "pdftoppm", p, p)
		if !ok {
			return 0, false, err
		}
		c.skip(s)
		return 0, false, nil
	}
	tmpName := "." + name + ".ocr"
	f, err := c.create(tmpName)
	if err != nil {
		return 0, false, err
	}
	tmpPath := filepath.Join(c.root, tmpName)
	defer os.Remove(tmpPath)
	out := c.output(f)
	cw := newCleaner(out)
	err = c.tool(ctx, cw, "tesseract", img, "stdout", "-l", c.o.OCRLang, "--dpi", strconv.Itoa(dpi))
	if cerr := cw.Close(); err == nil {
		err = cerr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if errors.Is(err, errOutputLimit) {
		c.release(out.n)
		c.limit(p, p, "tesseract")
		return 0, false, err
	}
	if err != nil {
		c.release(out.n)
		s, ok := toolSkip(err, "tesseract", p, p)
		if !ok {
			return 0, false, err
		}
		c.skip(s)
		return 0, false, nil
	}
	if !replace && cw.Chars() < textChars {
		c.release(out.n)
		return 0, false, nil
	}
	if err := os.Rename(tmpPath, filepath.Join(c.root, name)); err != nil {
		c.release(out.n)
		return 0, false, err
	}
	c.release(textSize)
	return cw.Chars(), true, nil
}

// dpi is the resolution page p is rendered at: Options.OCRDPI, lowered
// when that would make the page's longer side more than
// Options.MaxPixels.
func (c *converter) dpi(info *pdfInfo, p int) int {
	dpi := c.o.OCRDPI
	size, ok := info.sizes[p]
	if !ok {
		return dpi
	}
	longest := max(size[0], size[1])
	if longest <= 0 {
		return dpi
	}
	if px := longest * float64(dpi) / 72; px > float64(c.o.MaxPixels) {
		dpi = max(1, int(float64(c.o.MaxPixels)*72/longest))
	}
	return dpi
}

func (c *converter) image(ctx context.Context) (Kind, error) {
	c.r.Pages = 1
	name := c.prefix + ImageOutput
	f, err := c.create(name)
	if err != nil {
		return Failed, err
	}
	out := c.output(f)
	cw := newCleaner(out)
	err = c.tool(ctx, cw, "tesseract", c.src, "stdout", "-l", c.o.OCRLang)
	if cerr := cw.Close(); err == nil {
		err = cerr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if errors.Is(err, errOutputLimit) {
		if err := c.drop(name, out.n); err != nil {
			return Failed, err
		}
		c.limit(0, 0, "tesseract")
		return c.done()
	}
	if err != nil {
		var to errTimedOut
		if errors.As(err, &to) {
			c.skip(Skip{Reason: ReasonTimedOut, Tool: "tesseract", Detail: err.Error()})
			return TimedOut, err
		}
		return Failed, err
	}
	c.add(File{Page: 1, Path: name, Chars: cw.Chars(), OCR: true})
	return c.done()
}

func (c *converter) text() (Kind, error) {
	c.r.Pages = 1
	in, err := os.Open(c.src)
	if err != nil {
		return Failed, err
	}
	defer in.Close()
	name := c.prefix + TextOutput
	f, err := c.create(name)
	if err != nil {
		return Failed, err
	}
	out := c.output(f)
	cw := newCleaner(out)
	_, err = io.Copy(cw, in)
	if cerr := cw.Close(); err == nil {
		err = cerr
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if errors.Is(err, errOutputLimit) {
		if err := c.drop(name, out.n); err != nil {
			return Failed, err
		}
		c.limit(0, 0, "")
		return c.done()
	}
	if err != nil {
		return Failed, err
	}
	c.add(File{Page: 1, Path: name, Chars: cw.Chars()})
	return c.done()
}

// prepareDest makes dest if it is missing and returns its absolute path
// with links resolved. An existing dest must be an empty directory and not
// a symbolic link. These are safeclaw-unpack's rules for DEST.
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

// emptyDir removes everything in dir without following links.
func emptyDir(dir string) error {
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
