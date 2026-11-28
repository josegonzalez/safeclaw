package totext

import (
	"bytes"
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
	"github.com/josegonzalez/safeclaw/internal/termtext"
)

// exchangeDirs is exchange, replaced in tests.
var exchangeDirs = exchange

// maxTreeManifestSize limits the size of an earlier run's manifest that
// TreeOptions.Replace reads.
const maxTreeManifestSize = 256 << 20

// previous is an OUTDIR holding an earlier run's results, which a run with
// TreeOptions.Replace replaces.
type previous struct {
	// path is OUTDIR's absolute path with the links above it resolved.
	path string
	info fs.FileInfo
}

// checkPrevious decides whether outdir holds an earlier run's results that
// a run with TreeOptions.Replace may replace. It returns nil for a missing
// or empty outdir, which is converted into as without Replace, and an
// error for anything else that isn't a directory, not a link, holding a
// manifest that checkResults accepts.
func checkPrevious(outdir string) (*previous, error) {
	abs, err := filepath.Abs(outdir)
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
		return nil, fmt.Errorf("%s is a symbolic link", outdir)
	case !fi.IsDir():
		return nil, fmt.Errorf("%s is not a directory", outdir)
	}
	names, err := os.ReadDir(abs)
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, nil
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(abs))
	if err != nil {
		return nil, err
	}
	p := &previous{path: filepath.Join(parent, filepath.Base(abs)), info: fi}
	if p.path == parent {
		return nil, fmt.Errorf("%s has no parent directory to replace it in", outdir)
	}
	if err := checkResults(p.path); err != nil {
		return nil, fmt.Errorf("%s is not empty and doesn't hold an earlier safeclaw-totext --recursive run's results, so --replace won't remove it: %w", outdir, err)
	}
	return p, nil
}

// checkResults checks that dir holds only an earlier run's results: a
// ManifestText that readTreeManifest accepts and the regular files it
// lists as outputs. A listed output may be missing, but nothing else may
// be there, since the manifest says nothing about it.
func checkResults(dir string) error {
	r, err := readTreeManifest(dir)
	if err != nil {
		return err
	}
	listed := map[string]bool{ManifestText: true}
	for i := range r.Entries {
		for _, f := range r.Entries[i].Files {
			listed[f.Path] = true
		}
	}
	names, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, n := range names {
		switch {
		case !listed[n.Name()]:
			return fmt.Errorf("%s isn't in %s", termtext.Escape(n.Name()), ManifestText)
		case !n.Type().IsRegular():
			return fmt.Errorf("%s is not a regular file", termtext.Escape(n.Name()))
		}
	}
	return nil
}

// readTreeManifest reads and checks dir's ManifestText: a regular file,
// not a link, of at most maxTreeManifestSize bytes, that is exactly what
// WriteText writes for a run that ended ok or partial, whose outputs are
// flat names in dir starting with their entry's index and ending in .txt,
// none listed twice.
func readTreeManifest(dir string) (*TreeReport, error) {
	f, err := os.OpenFile(filepath.Join(dir, ManifestText), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil {
		return nil, err
	} else if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", ManifestText)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxTreeManifestSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxTreeManifestSize {
		return nil, fmt.Errorf("%s is over %d bytes", ManifestText, maxTreeManifestSize)
	}
	r, err := parseTreeText(data)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", ManifestText, err)
	}
	var b bytes.Buffer
	if err := r.WriteText(&b); err != nil {
		return nil, err
	}
	if !bytes.Equal(b.Bytes(), data) {
		return nil, fmt.Errorf("%s is not as safeclaw-totext writes it", ManifestText)
	}
	if r.Status != OK.String() && r.Status != Partial.String() {
		return nil, fmt.Errorf("%s has the status %q", ManifestText, r.Status)
	}
	width := max(3, len(strconv.Itoa(len(r.Entries))))
	seen := map[string]bool{}
	for i := range r.Entries {
		e := &r.Entries[i]
		if e.Index != i+1 {
			return nil, fmt.Errorf("%s numbers entry %d as %d", ManifestText, i+1, e.Index)
		}
		prefix := fmt.Sprintf("%0*d-", width, e.Index)
		for _, out := range e.Files {
			n := out.Path
			if !strings.HasPrefix(n, prefix) || !strings.HasSuffix(n, ".txt") || strings.ContainsAny(n, "/\x00") || n != filepath.Base(n) {
				return nil, fmt.Errorf("%s lists an output that isn't a file it would write: %s", ManifestText, termtext.Escape(n))
			}
			if seen[n] {
				return nil, fmt.Errorf("%s lists %s twice", ManifestText, termtext.Escape(n))
			}
			seen[n] = true
		}
	}
	return r, nil
}

// treeFields is how many fields each kind of manifest line has.
var treeFields = map[string]int{"tree": 6, "file": 8, "error": 3, "container": 8, "page": 6, "skipped": 7}

// parseTreeText parses the lines WriteText writes into a report that
// WriteText writes the same way. It doesn't check that they are exactly
// what it would write; readTreeManifest does that by writing them again.
func parseTreeText(data []byte) (*TreeReport, error) {
	text, ok := strings.CutSuffix(string(data), "\n")
	if !ok {
		return nil, errors.New("it doesn't end in a newline")
	}
	r := &TreeReport{Schema: Schema, Entries: []Entry{}}
	var e *Entry
	for i, line := range strings.Split(text, "\n") {
		f := strings.Split(line, "\t")
		if n, ok := treeFields[f[0]]; !ok || len(f) != n {
			return nil, fmt.Errorf("line %d is not a manifest line", i+1)
		}
		if (i == 0) != (f[0] == "tree") {
			return nil, fmt.Errorf("line %d: the tree line must come first, and only once", i+1)
		}
		if f[0] != "tree" && f[0] != "file" && e == nil {
			return nil, fmt.Errorf("line %d comes before any file line", i+1)
		}
		var err error
		switch f[0] {
		case "tree":
			r.Status, r.Expand = f[1], f[4]
			if _, err = number(f[2]); err == nil {
				r.OutputSize, err = int64Field(f[3])
			}
			if err == nil {
				r.ExpandError, err = unescape(undash(f[5]))
			}
		case "file":
			r.Entries = append(r.Entries, Entry{Files: []File{}, OCRPages: []int{}, Skipped: []Skip{}})
			e = &r.Entries[len(r.Entries)-1]
			err = parseFileLine(e, f)
		case "error":
			e.Error, err = unescape(f[2])
		case "container":
			e.Container, err = parseContainerLine(f)
		case "page":
			err = parsePageLine(e, f)
		case "skipped":
			err = parseSkippedLine(e, f)
		}
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", i+1, err)
		}
	}
	return r, nil
}

func parseFileLine(e *Entry, f []string) error {
	var err error
	if e.Index, err = number(f[1]); err != nil {
		return err
	}
	if e.Path, err = unescape(f[2]); err != nil {
		return err
	}
	e.Status, e.Type = f[3], f[4]
	if e.Size, err = int64Field(f[5]); err != nil {
		return err
	}
	if e.Pages, err = number(f[6]); err != nil {
		return err
	}
	if f[7] == "-" {
		return nil
	}
	for flag := range strings.SplitSeq(f[7], ",") {
		switch flag {
		case "ENCRYPTED":
			e.Encrypted = true
		case "EXPAND-OUTPUT":
			// The manifest only flags it; the container isn't named.
			e.ExpandOutput = "-"
		default:
			return fmt.Errorf("unknown flag %q", flag)
		}
	}
	return nil
}

func parseContainerLine(f []string) (*expand.Container, error) {
	c := &expand.Container{}
	var err error
	if c.Kind, err = unescape(f[2]); err != nil {
		return nil, err
	}
	if c.Depth, err = number(f[3]); err != nil {
		return nil, err
	}
	if c.Outcome, err = unescape(f[4]); err != nil {
		return nil, err
	}
	flags, err := unescape(undash(f[5]))
	if err != nil {
		return nil, err
	}
	if flags != "" {
		c.Flags = strings.Split(flags, ",")
	}
	if c.Parent, err = unescape(undash(f[6])); err != nil {
		return nil, err
	}
	if c.Error, err = unescape(undash(f[7])); err != nil {
		return nil, err
	}
	return c, nil
}

func parsePageLine(e *Entry, f []string) error {
	var out File
	var err error
	if out.Page, err = number(f[2]); err != nil {
		return err
	}
	if out.Chars, err = number(f[3]); err != nil {
		return err
	}
	if out.Path, err = unescape(f[4]); err != nil {
		return err
	}
	switch f[5] {
	case "OCR":
		out.OCR = true
	case "-":
	default:
		return fmt.Errorf("%q is not OCR or -", f[5])
	}
	e.Files = append(e.Files, out)
	return nil
}

func parseSkippedLine(e *Entry, f []string) error {
	var s Skip
	var err error
	if s.FirstPage, err = number(f[2]); err != nil {
		return err
	}
	if s.LastPage, err = number(f[3]); err != nil {
		return err
	}
	s.Reason, s.Tool = f[4], undash(f[5])
	if s.Detail, err = unescape(undash(f[6])); err != nil {
		return err
	}
	e.Skipped = append(e.Skipped, s)
	return nil
}

// number parses a field that holds a count, which is never negative.
func number(s string) (int, error) {
	n, err := strconv.Atoi(s)
	if err == nil && n < 0 {
		err = fmt.Errorf("%q is negative", s)
	}
	return n, err
}

func int64Field(s string) (int64, error) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err == nil && n < 0 {
		err = fmt.Errorf("%q is negative", s)
	}
	return n, err
}

func unescape(s string) (string, error) { return termtext.UnescapeField(s) }

func undash(s string) string {
	if s == "-" {
		return ""
	}
	return s
}

// replaceDir puts the directory tmp, a sibling of p.path, in place of
// p.path, and returns the directory now holding the earlier results,
// which the caller removes. When it fails, p.path is as it was.
func replaceDir(tmp string, p *previous) (string, error) {
	err := exchangeDirs(tmp, p.path)
	if err == nil {
		return tmp, nil
	}
	if !errors.Is(err, errors.ErrUnsupported) && !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOTSUP) && !errors.Is(err, syscall.ENOSYS) {
		return "", err
	}
	return moveAside(tmp, p)
}

// moveAside replaces p.path with tmp where they can't be exchanged: it
// moves the earlier results to a new name beside them, then the new ones
// in, moving the earlier ones back if that fails. The earlier results
// stay in the same directory, since moving a directory to another needs
// write permission on it.
func moveAside(tmp string, p *previous) (string, error) {
	// The name is made unique by creating it; renaming a directory over
	// an empty one, should another take the name meanwhile, only replaces
	// that empty one.
	old, err := os.MkdirTemp(filepath.Dir(p.path), "."+filepath.Base(p.path)+".old-*")
	if err != nil {
		return "", err
	}
	if err := os.Remove(old); err != nil {
		return "", err
	}
	if err := os.Rename(p.path, old); err != nil {
		return "", err
	}
	if err := os.Rename(tmp, p.path); err != nil {
		if rerr := os.Rename(old, p.path); rerr != nil {
			return "", errors.Join(err, fmt.Errorf("the earlier results are in %s: %w", old, rerr))
		}
		return "", err
	}
	return old, nil
}
