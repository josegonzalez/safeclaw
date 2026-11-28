package totext

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestCleaner(t *testing.T) {
	for _, c := range []struct {
		in    []string
		want  string
		chars int
	}{
		{[]string{"plain text\n"}, "plain text\n", 9},
		{[]string{"tab\there\n"}, "tab\there\n", 7},
		{[]string{"esc\x1b[2Jcls\a\b\x7f"}, "esc[2Jcls", 9},
		{[]string{"page one\f", "page two\r\n"}, "page onepage two\n", 14},
		{[]string{"c1 \u0085\u009b31m"}, "c1 31m", 5},
		{[]string{"bidi \u202egnp.exe\u202c \u2066x\u2069\u200f\u061c"}, "bidi gnp.exe x", 12},
		{[]string{"bad\xff\xfe"}, "bad��", 5},
		{[]string{"r\xc3", "\xa9sum\xc3\xa9"}, "résumé", 6},
		{[]string{"\xe2\x82", "\xac"}, "€", 1},
		{[]string{"cut\xe2\x82"}, "cut�", 4},
		{[]string{"\u2028keep\u00a0nbsp"}, "\u2028keep\u00a0nbsp", 8},
	} {
		var b bytes.Buffer
		cw := newCleaner(&b)
		for _, s := range c.in {
			if n, err := cw.Write([]byte(s)); err != nil || n != len(s) {
				t.Fatalf("Write(%q) = %d, %v", s, n, err)
			}
		}
		if err := cw.Close(); err != nil {
			t.Fatal(err)
		}
		if b.String() != c.want || cw.Chars() != c.chars {
			t.Errorf("%q: got %q (%d chars), want %q (%d chars)", c.in, b.String(), cw.Chars(), c.want, c.chars)
		}
	}
}

func TestDetect(t *testing.T) {
	bmp := append([]byte("BM"), make([]byte, 16)...)
	bmp[14] = 40
	for name, c := range map[string]struct {
		head     string
		complete bool
		want     string
	}{
		"pdf":                {"%PDF-1.7\n", true, TypePDF},
		"pdf after junk":     {"\x00\x01junk\n%PDF-1.4\n", true, TypePDF},
		"text naming %PDF-":  {"a header looks like %PDF-1.4\n", true, TypeText},
		"png":                {"\x89PNG\r\n\x1a\n....", true, TypePNG},
		"jpeg":               {"\xff\xd8\xff\xe0", true, TypeJPEG},
		"gif":                {"GIF89a", true, TypeGIF},
		"tiff le":            {"II*\x00", true, TypeTIFF},
		"tiff be":            {"MM\x00*", true, TypeTIFF},
		"webp":               {"RIFF\x00\x00\x00\x00WEBPVP8 ", true, TypeWebP},
		"riff not webp":      {"RIFF\x00\x00\x00\x00WAVEfmt ", true, TypeUnknown},
		"bmp":                {string(bmp), true, TypeBMP},
		"text starting BM":   {"BMW and other cars\n", true, TypeText},
		"utf-8 text":         {"résumé\n", true, TypeText},
		"empty":              {"", true, TypeText},
		"latin-1":            {"r\xe9sum\xe9\n", true, TypeUnknown},
		"nul":                {"text\x00more", true, TypeUnknown},
		"cut rune, partial":  {"abc\xe2\x82", false, TypeText},
		"cut rune, complete": {"abc\xe2\x82", true, TypeUnknown},
		"zip":                {"PK\x03\x04\x14\x00\x00\x00", true, TypeUnknown},
		"named .pdf, is elf": {"\x7fELF\x02\x01\x01\x00", true, TypeUnknown},
	} {
		if got := Detect([]byte(c.head), c.complete); got != c.want {
			t.Errorf("%s: Detect = %q, want %q", name, got, c.want)
		}
	}
}

func TestParsePDFInfo(t *testing.T) {
	out := "Title:          evil\nPages:          9999\nEncrypted:      no\nAuthor:         x\n" +
		"Pages:          3\nEncrypted:      yes (print:yes copy:no change:no addNotes:no algorithm:AES-256)\n" +
		"Page    1 size: 612 x 792 pts (letter)\nPage    1 rot:  0\nPage    2 size: 14400 x 14400 pts\nFile size:      1234 bytes\n"
	info, err := parsePDFInfo(out)
	if err != nil {
		t.Fatal(err)
	}
	if info.pages != 3 || !info.encrypted || info.sizes[1] != [2]float64{612, 792} || info.sizes[2] != [2]float64{14400, 14400} {
		t.Errorf("info = %+v", info)
	}
	if _, err := parsePDFInfo("Title: x\n"); err == nil {
		t.Error("no page count was accepted")
	}
	if _, err := parsePDFInfo("Pages: 2\nEncrypted: no\nEncrypted: yes\n"); err == nil {
		t.Error("a repeated Encrypted line was accepted")
	}
}

// fake is a Runner that answers from per-tool functions and records each
// call.
type fake struct {
	mu    sync.Mutex
	calls [][]string
	tools map[string]func(ctx context.Context, w io.Writer, args []string) error
}

func (f *fake) Run(ctx context.Context, w io.Writer, tool string, args ...string) error {
	f.mu.Lock()
	f.calls = append(f.calls, append([]string{tool}, args...))
	f.mu.Unlock()
	fn, ok := f.tools[tool]
	if !ok {
		return fmt.Errorf("unexpected %s", tool)
	}
	return fn(ctx, w, args)
}

func (f *fake) called(tool string) [][]string {
	var out [][]string
	for _, c := range f.calls {
		if c[0] == tool {
			out = append(out, c[1:])
		}
	}
	return out
}

// hang blocks until ctx is done, like a tool stuck on a crafted file.
func hang(ctx context.Context, _ io.Writer, _ []string) error {
	<-ctx.Done()
	return ctx.Err()
}

// flagValue returns the value after flag in args.
func flagValue(args []string, flag string) string {
	i := slices.Index(args, flag)
	if i < 0 || i+1 >= len(args) {
		return ""
	}
	return args[i+1]
}

// pdfFake fakes a PDF of pages pages, where texts gives each page's text
// layer and ocr its OCR text.
func pdfFake(pages int, texts, ocr map[string]string) *fake {
	return &fake{tools: map[string]func(context.Context, io.Writer, []string) error{
		"pdfinfo": func(_ context.Context, w io.Writer, _ []string) error {
			fmt.Fprintf(w, "Producer: x\nPages:          %d\nEncrypted:      no\nPage    1 size: 612 x 792 pts\n", pages)
			return nil
		},
		"pdftotext": func(_ context.Context, w io.Writer, args []string) error {
			_, err := io.WriteString(w, texts[flagValue(args, "-f")]+"\f")
			return err
		},
		"pdftoppm": func(_ context.Context, _ io.Writer, args []string) error {
			return os.WriteFile(args[len(args)-1]+".png", []byte("\x89PNG\r\n\x1a\npage "+flagValue(args, "-f")), 0o644)
		},
		"tesseract": func(_ context.Context, w io.Writer, args []string) error {
			img, err := os.ReadFile(args[0])
			if err != nil {
				return err
			}
			page := strings.TrimPrefix(string(img), "\x89PNG\r\n\x1a\npage ")
			_, err = io.WriteString(w, ocr[page])
			return err
		},
	}}
}

func input(t *testing.T, name string, data []byte) (file, outdir string) {
	t.Helper()
	dir := t.TempDir()
	file = filepath.Join(dir, name)
	if err := os.WriteFile(file, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return file, filepath.Join(dir, "out")
}

func opts(r Runner) Options {
	o := DefaultOptions()
	o.Runner = r
	o.Timeout = 5 * time.Second
	return o
}

func readOut(t *testing.T, outdir string) map[string]string {
	t.Helper()
	names, err := os.ReadDir(outdir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, n := range names {
		b, err := os.ReadFile(filepath.Join(outdir, n.Name()))
		if err != nil {
			t.Fatal(err)
		}
		got[n.Name()] = string(b)
	}
	return got
}

func TestConvertPDF(t *testing.T) {
	f := pdfFake(3,
		map[string]string{"1": "First page \x1b[31mred\x1b[0m text", "2": "  3  ", "3": "Third"},
		map[string]string{"2": "Scanned words here", "3": "x"})
	file, outdir := input(t, "doc.txt", []byte("%PDF-1.7\n"))
	r := Convert(t.Context(), file, outdir, opts(f))
	if r.Kind() != OK || r.Status != "ok" || r.Type != TypePDF || r.Pages != 3 || r.Encrypted || r.Error != "" {
		t.Fatalf("report = %+v", r)
	}
	want := []File{
		{Page: 1, Path: "p001.txt", Chars: 23},
		{Page: 2, Path: "p002.txt", Chars: 16, OCR: true},
		{Page: 3, Path: "p003.txt", Chars: 5},
	}
	if !slices.Equal(r.Files, want) || !slices.Equal(r.OCRPages, []int{2}) || len(r.Skipped) != 0 {
		t.Errorf("files = %+v, ocr = %v, skipped = %+v", r.Files, r.OCRPages, r.Skipped)
	}
	got := readOut(t, outdir)
	if len(got) != 3 || got["p001.txt"] != "First page [31mred[0m text" || got["p002.txt"] != "Scanned words here" || got["p003.txt"] != "Third" {
		t.Errorf("files = %q", got)
	}
	abs, _ := filepath.Abs(file)
	for _, call := range f.calls {
		i := slices.Index(call, "--")
		if call[0] == "tesseract" {
			if call[1] == abs || !strings.HasPrefix(call[1], "/") || !slices.Contains(call, "--dpi") {
				t.Errorf("tesseract got %q", call)
			}
			continue
		}
		if i < 0 || call[i+1] != abs {
			t.Errorf("%s: the file isn't after --: %q", call[0], call)
		}
	}
	if info := f.called("pdfinfo"); len(info) != 1 || !slices.Equal(info[0][:4], []string{"-f", "1", "-l", "100"}) {
		t.Errorf("pdfinfo calls = %q", info)
	}
	// Page 3 has 5 characters, under the threshold, but OCR found fewer,
	// so its text layer is kept.
	if n := len(f.called("pdftoppm")); n != 2 {
		t.Errorf("rendered %d pages, want 2", n)
	}
}

func TestConvertPDFNoOCR(t *testing.T) {
	f := pdfFake(1, map[string]string{"1": ""}, nil)
	file, outdir := input(t, "doc.pdf", []byte("%PDF-1.7\n"))
	o := opts(f)
	o.OCRThreshold = 0
	r := Convert(t.Context(), file, outdir, o)
	if r.Kind() != OK || len(r.Files) != 1 || r.Files[0].Chars != 0 || len(f.called("pdftoppm")) != 0 {
		t.Errorf("report = %+v, calls = %q", r, f.calls)
	}
}

func TestConvertPageLimit(t *testing.T) {
	f := pdfFake(250, map[string]string{"1": "one two", "2": "three four"}, nil)
	file, outdir := input(t, "doc.pdf", []byte("%PDF-1.7\n"))
	o := opts(f)
	o.MaxPages = 2
	o.OCRThreshold = 0
	r := Convert(t.Context(), file, outdir, o)
	if r.Kind() != Partial || r.Status != "partial" || r.Pages != 250 || len(r.Files) != 2 {
		t.Fatalf("report = %+v", r)
	}
	if !slices.Equal(r.Skipped, []Skip{{FirstPage: 3, LastPage: 250, Reason: ReasonPageLimit, Detail: "over the 2 page limit"}}) {
		t.Errorf("skipped = %+v", r.Skipped)
	}
	if n := len(f.called("pdftotext")); n != 2 {
		t.Errorf("pdftotext ran %d times", n)
	}
	if info := f.called("pdfinfo"); flagValue(info[0], "-l") != "2" {
		t.Errorf("pdfinfo = %q", info)
	}
	if got := readOut(t, outdir); len(got) != 2 {
		t.Errorf("partial output was not kept: %q", got)
	}
}

func TestConvertPageNamesWiden(t *testing.T) {
	f := pdfFake(1000, map[string]string{}, nil)
	file, outdir := input(t, "doc.pdf", []byte("%PDF-1.7\n"))
	o := opts(f)
	o.MaxPages = 1000
	o.OCRThreshold = 0
	r := Convert(t.Context(), file, outdir, o)
	if r.Kind() != OK || r.Files[0].Path != "p0001.txt" || r.Files[999].Path != "p1000.txt" {
		t.Errorf("report = %v %+v %+v", r.Status, r.Files[0], r.Files[len(r.Files)-1])
	}
}

func TestConvertEncrypted(t *testing.T) {
	f := &fake{tools: map[string]func(context.Context, io.Writer, []string) error{
		"pdfinfo": func(context.Context, io.Writer, []string) error {
			return &ExitError{Tool: "pdfinfo", Code: 1, Stderr: "Command Line Error: Incorrect password\n"}
		},
	}}
	file, outdir := input(t, "doc.pdf", []byte("%PDF-1.7\n"))
	r := Convert(t.Context(), file, outdir, opts(f))
	if r.Kind() != Encrypted || r.Status != "encrypted" || r.Code != 3 || !r.Encrypted || r.Error == "" {
		t.Fatalf("report = %+v", r)
	}
	if len(r.Skipped) != 1 || r.Skipped[0].Reason != ReasonEncrypted || r.Skipped[0].FirstPage != 0 {
		t.Errorf("skipped = %+v", r.Skipped)
	}
	if got := readOut(t, outdir); len(got) != 0 {
		t.Errorf("outdir = %q", got)
	}
}

func TestConvertEncryptedPermissions(t *testing.T) {
	f := pdfFake(2, map[string]string{"1": "page one text"}, nil)
	f.tools["pdftotext"] = func(_ context.Context, w io.Writer, args []string) error {
		if flagValue(args, "-f") == "2" {
			return &ExitError{Tool: "pdftotext", Code: 3, Stderr: "Permission Error: Copying of text from this document is not allowed.\n"}
		}
		_, err := io.WriteString(w, "page one text")
		return err
	}
	file, outdir := input(t, "doc.pdf", []byte("%PDF-1.7\n"))
	r := Convert(t.Context(), file, outdir, opts(f))
	if r.Kind() != Encrypted || len(r.Files) != 0 {
		t.Fatalf("report = %+v", r)
	}
	if got := readOut(t, outdir); len(got) != 0 {
		t.Errorf("outdir was not emptied: %q", got)
	}
}

func TestConvertTimeouts(t *testing.T) {
	t.Run("pdfinfo", func(t *testing.T) {
		f := &fake{tools: map[string]func(context.Context, io.Writer, []string) error{"pdfinfo": hang}}
		file, outdir := input(t, "doc.pdf", []byte("%PDF-1.7\n"))
		o := opts(f)
		o.Timeout = 50 * time.Millisecond
		r := Convert(t.Context(), file, outdir, o)
		if r.Kind() != TimedOut || r.Status != "timed-out" || r.Code != 7 || len(r.Skipped) != 1 || r.Skipped[0].Tool != "pdfinfo" || r.Skipped[0].Reason != ReasonTimedOut {
			t.Errorf("report = %+v", r)
		}
	})
	t.Run("page", func(t *testing.T) {
		f := pdfFake(3, map[string]string{"1": "one page of text", "3": "third page text"}, map[string]string{"2": "ocr of two"})
		text := f.tools["pdftotext"]
		f.tools["pdftotext"] = func(ctx context.Context, w io.Writer, args []string) error {
			if flagValue(args, "-f") == "2" {
				_, _ = io.WriteString(w, "half a pa")
				return hang(ctx, w, args)
			}
			return text(ctx, w, args)
		}
		file, outdir := input(t, "doc.pdf", []byte("%PDF-1.7\n"))
		o := opts(f)
		o.Timeout = 50 * time.Millisecond
		r := Convert(t.Context(), file, outdir, o)
		if r.Kind() != Partial || len(r.Skipped) != 1 {
			t.Fatalf("report = %+v", r)
		}
		if s := r.Skipped[0]; s.FirstPage != 2 || s.LastPage != 2 || s.Reason != ReasonTimedOut || s.Tool != "pdftotext" {
			t.Errorf("skipped = %+v", s)
		}
		// The page's text timed out, so it was OCR'd instead.
		if !slices.Equal(r.OCRPages, []int{2}) || readOut(t, outdir)["p002.txt"] != "ocr of two" {
			t.Errorf("ocr = %v, files = %q", r.OCRPages, readOut(t, outdir))
		}
	})
	t.Run("page and its OCR", func(t *testing.T) {
		f := pdfFake(2, map[string]string{"1": "one page of text"}, nil)
		text := f.tools["pdftotext"]
		f.tools["pdftotext"] = func(ctx context.Context, w io.Writer, args []string) error {
			if flagValue(args, "-f") == "2" {
				return hang(ctx, w, args)
			}
			return text(ctx, w, args)
		}
		f.tools["tesseract"] = hang
		file, outdir := input(t, "doc.pdf", []byte("%PDF-1.7\n"))
		o := opts(f)
		o.Timeout = 50 * time.Millisecond
		r := Convert(t.Context(), file, outdir, o)
		if r.Kind() != Partial || len(r.Files) != 1 || len(r.Skipped) != 2 || r.Skipped[1].Tool != "tesseract" {
			t.Fatalf("report = %+v", r)
		}
		if got := readOut(t, outdir); len(got) != 1 || got["p001.txt"] == "" {
			t.Errorf("outdir = %q", got)
		}
	})
	t.Run("image", func(t *testing.T) {
		f := &fake{tools: map[string]func(context.Context, io.Writer, []string) error{"tesseract": hang}}
		file, outdir := input(t, "scan.pdf", []byte("\x89PNG\r\n\x1a\n"))
		o := opts(f)
		o.Timeout = 50 * time.Millisecond
		r := Convert(t.Context(), file, outdir, o)
		if r.Kind() != TimedOut || r.Type != TypePNG || len(r.Files) != 0 || r.Skipped[0].Tool != "tesseract" {
			t.Errorf("report = %+v", r)
		}
		if got := readOut(t, outdir); len(got) != 0 {
			t.Errorf("outdir = %q", got)
		}
	})
	t.Run("interrupted", func(t *testing.T) {
		f := pdfFake(2, nil, nil)
		ctx, cancel := context.WithCancel(t.Context())
		f.tools["pdftotext"] = func(c context.Context, w io.Writer, args []string) error {
			cancel()
			return hang(c, w, args)
		}
		file, outdir := input(t, "doc.pdf", []byte("%PDF-1.7\n"))
		r := Convert(ctx, file, outdir, opts(f))
		if r.Kind() != Failed || !strings.Contains(r.Error, "canceled") {
			t.Errorf("report = %+v", r)
		}
		if got := readOut(t, outdir); len(got) != 0 {
			t.Errorf("outdir = %q", got)
		}
	})
}

func TestConvertPageFailure(t *testing.T) {
	f := pdfFake(2, map[string]string{"1": "one page of text"}, nil)
	text := f.tools["pdftotext"]
	f.tools["pdftotext"] = func(ctx context.Context, w io.Writer, args []string) error {
		if flagValue(args, "-f") == "2" {
			return &ExitError{Tool: "pdftotext", Code: 1, Stderr: "Syntax Error: broken \x1b[2J\n"}
		}
		return text(ctx, w, args)
	}
	f.tools["pdftoppm"] = func(context.Context, io.Writer, []string) error {
		return &ExitError{Tool: "pdftoppm", Code: 99}
	}
	file, outdir := input(t, "doc.pdf", []byte("%PDF-1.7\n"))
	r := Convert(t.Context(), file, outdir, opts(f))
	if r.Kind() != Partial || len(r.Files) != 1 || len(r.Skipped) != 2 {
		t.Fatalf("report = %+v", r)
	}
	if s := r.Skipped[0]; s.Reason != ReasonFailed || s.Tool != "pdftotext" || !strings.Contains(s.Detail, "broken") {
		t.Errorf("skipped = %+v", s)
	}
	if s := r.Skipped[1]; s.Reason != ReasonFailed || s.Tool != "pdftoppm" {
		t.Errorf("skipped = %+v", s)
	}
}

func TestConvertPDFFailure(t *testing.T) {
	f := &fake{tools: map[string]func(context.Context, io.Writer, []string) error{
		"pdfinfo": func(context.Context, io.Writer, []string) error {
			return &ExitError{Tool: "pdfinfo", Code: 1, Stderr: "Syntax Error: Couldn't find trailer dictionary\n"}
		},
	}}
	file, outdir := input(t, "doc.pdf", []byte("%PDF-1.7\n"))
	r := Convert(t.Context(), file, outdir, opts(f))
	if r.Kind() != Failed || !strings.Contains(r.Error, "trailer") {
		t.Errorf("report = %+v", r)
	}
}

func TestConvertRenderResolution(t *testing.T) {
	f := pdfFake(2, nil, nil)
	f.tools["pdfinfo"] = func(_ context.Context, w io.Writer, _ []string) error {
		_, err := io.WriteString(w, "Pages: 2\nEncrypted: no\nPage    1 size: 612 x 792 pts\nPage    2 size: 14400 x 7200 pts\n")
		return err
	}
	file, outdir := input(t, "doc.pdf", []byte("%PDF-1.7\n"))
	r := Convert(t.Context(), file, outdir, opts(f))
	if r.Kind() != OK {
		t.Fatalf("report = %+v", r)
	}
	calls := f.called("pdftoppm")
	if len(calls) != 2 || flagValue(calls[0], "-r") != "300" || flagValue(calls[1], "-r") != "50" {
		t.Errorf("pdftoppm = %q", calls)
	}
	if tc := f.called("tesseract"); flagValue(tc[1], "--dpi") != "50" || flagValue(tc[1], "-l") != "eng" {
		t.Errorf("tesseract = %q", tc)
	}
}

func TestConvertImage(t *testing.T) {
	f := &fake{tools: map[string]func(context.Context, io.Writer, []string) error{
		"tesseract": func(_ context.Context, w io.Writer, args []string) error {
			_, err := io.WriteString(w, "Invoice \x1b]8;;http://x\x07total\n")
			return err
		},
	}}
	file, outdir := input(t, "photo.txt", []byte("\xff\xd8\xff\xe0rest"))
	o := opts(f)
	o.OCRLang = "eng+deu"
	r := Convert(t.Context(), file, outdir, o)
	if r.Kind() != OK || r.Type != TypeJPEG || r.Pages != 1 || !slices.Equal(r.Files, []File{{Page: 1, Path: ImageOutput, Chars: 24, OCR: true}}) || !slices.Equal(r.OCRPages, []int{1}) {
		t.Fatalf("report = %+v", r)
	}
	if got := readOut(t, outdir)[ImageOutput]; got != "Invoice ]8;;http://xtotal\n" {
		t.Errorf("ocr.txt = %q", got)
	}
	abs, _ := filepath.Abs(file)
	if c := f.calls[0]; !slices.Equal(c, []string{"tesseract", abs, "stdout", "-l", "eng+deu"}) {
		t.Errorf("tesseract = %q", c)
	}
}

func TestConvertText(t *testing.T) {
	file, outdir := input(t, "notes.pdf", []byte("line one\r\n\x1b[2Jline two\u202e\n"))
	r := Convert(t.Context(), file, outdir, opts(&fake{}))
	if r.Kind() != OK || r.Type != TypeText || !slices.Equal(r.Files, []File{{Page: 1, Path: TextOutput, Chars: 17}}) || len(r.OCRPages) != 0 {
		t.Fatalf("report = %+v", r)
	}
	if got := readOut(t, outdir)[TextOutput]; got != "line one\n[2Jline two\n" {
		t.Errorf("text.txt = %q", got)
	}
}

func TestConvertUnsupported(t *testing.T) {
	file, outdir := input(t, "report.pdf", []byte("PK\x03\x04\x14\x00\x00\x00\x08\x00"))
	f := &fake{}
	r := Convert(t.Context(), file, outdir, opts(f))
	if r.Kind() != Unsupported || r.Status != "unsupported" || r.Code != 5 || r.Type != TypeUnknown || len(f.calls) != 0 {
		t.Fatalf("report = %+v", r)
	}
	if !slices.Equal(r.Skipped, []Skip{{Reason: ReasonUnsupported, Detail: "not a PDF, a supported image, or text"}}) {
		t.Errorf("skipped = %+v", r.Skipped)
	}
}

func TestConvertOutdir(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(file, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	full := filepath.Join(dir, "full")
	if err := os.MkdirAll(filepath.Join(full, "x"), 0o755); err != nil {
		t.Fatal(err)
	}
	empty := filepath.Join(dir, "empty")
	if err := os.Mkdir(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(empty, link); err != nil {
		t.Fatal(err)
	}
	for outdir, want := range map[string]string{
		full:                        "not empty",
		link:                        "symbolic link",
		file:                        "not a directory",
		filepath.Join(dir, "a/b/c"): "no such file",
	} {
		r := Convert(t.Context(), file, outdir, opts(&fake{}))
		if r.Kind() != Failed || !strings.Contains(r.Error, want) {
			t.Errorf("%s: report = %+v", outdir, r)
		}
	}
	if r := Convert(t.Context(), file, empty, opts(&fake{})); r.Kind() != OK {
		t.Errorf("empty outdir: %+v", r)
	}
	if r := Convert(t.Context(), dir, filepath.Join(dir, "new"), opts(&fake{})); r.Kind() != Failed || !strings.Contains(r.Error, "not a regular file") {
		t.Errorf("directory input: %+v", r)
	}
}

func TestOptionsValidate(t *testing.T) {
	for name, edit := range map[string]func(*Options){
		"no runner":      func(o *Options) { o.Runner = nil },
		"max pages":      func(o *Options) { o.MaxPages = 0 },
		"threshold":      func(o *Options) { o.OCRThreshold = -1 },
		"dpi":            func(o *Options) { o.OCRDPI = 0 },
		"dpi too high":   func(o *Options) { o.OCRDPI = MaxOCRDPI + 1 },
		"lang option":    func(o *Options) { o.OCRLang = "-psm" },
		"lang path":      func(o *Options) { o.OCRLang = "../x" },
		"lang empty":     func(o *Options) { o.OCRLang = "" },
		"lang trailing+": func(o *Options) { o.OCRLang = "eng+" },
		"timeout":        func(o *Options) { o.Timeout = 0 },
	} {
		o := opts(&fake{})
		edit(&o)
		file, outdir := input(t, "a.txt", []byte("hi"))
		if r := Convert(t.Context(), file, outdir, o); r.Kind() != Failed {
			t.Errorf("%s: accepted: %+v", name, r)
		}
		if _, err := os.Stat(outdir); err == nil {
			t.Errorf("%s: outdir was made", name)
		}
	}
}

// TestExecKillsGroup checks that the real runner kills a tool and the
// processes it started when the timeout passes.
func TestExecKillsGroup(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "pid")
	ctx, cancel := context.WithTimeout(t.Context(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := Exec{WaitDelay: 500 * time.Millisecond}.Run(ctx, io.Discard, "sh", "-c", `sleep 60 & echo $! > "$1"; wait`, "sh", pidFile)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 5*time.Second {
		t.Fatalf("err = %v after %v", err, time.Since(start))
	}
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	var pid int
	if _, err := fmt.Sscan(string(b), &pid); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for syscall.Kill(pid, 0) == nil {
		if time.Now().After(deadline) {
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("the tool's child %d outlived its timeout", pid)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestExecErrors(t *testing.T) {
	err := Exec{}.Run(t.Context(), io.Discard, "sh", "-c", "echo oops >&2; exit 3")
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != 3 || ee.Stderr != "oops\n" || ee.Error() != "sh exited with status 3: oops" {
		t.Errorf("err = %v", err)
	}
	var b bytes.Buffer
	if err := (Exec{}).Run(t.Context(), &b, "sh", "-c", "printf hi; cat"); err != nil || b.String() != "hi" {
		t.Errorf("stdout = %q, %v (stdin must be empty)", b.String(), err)
	}
	if err := (Exec{}).Run(t.Context(), io.Discard, "safeclaw-no-such-tool"); err == nil || !strings.Contains(err.Error(), "not found on PATH") {
		t.Errorf("missing tool: %v", err)
	}
}
