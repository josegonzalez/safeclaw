package totext

import (
	"bytes"
	"image"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/josegonzalez/safeclaw/internal/totext/totexttest"
)

// These tests run the real poppler and tesseract on documents they
// generate. They are skipped when the tools aren't on PATH; the sandbox
// variant's integration test in internal/session runs the same kinds of
// documents through safeclaw-totext there.

func realTools(t *testing.T) Options {
	t.Helper()
	for _, tool := range []string{"pdfinfo", "pdftotext", "pdftoppm", "tesseract"} {
		if _, err := exec.LookPath(tool); err != nil {
			t.Skipf("%s not on PATH", tool)
		}
	}
	o := DefaultOptions()
	o.Timeout = 2 * time.Minute
	return o
}

// scan renders the first page of a text PDF the way a scanner would see
// it, as a grayscale image at dpi.
func scan(t *testing.T, pdf []byte, dpi int) *image.Gray {
	t.Helper()
	dir := t.TempDir()
	in := filepath.Join(dir, "in.pdf")
	if err := os.WriteFile(in, pdf, 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "page")
	if b, err := exec.Command("pdftoppm", "-r", "150", "-gray", "-singlefile", "-f", "1", "-l", "1", "--", in, out).CombinedOutput(); err != nil {
		t.Fatalf("pdftoppm: %v\n%s", err, b)
	}
	data, err := os.ReadFile(out + ".pgm")
	if err != nil {
		t.Fatal(err)
	}
	img, err := totexttest.ParsePGM(data)
	if err != nil {
		t.Fatal(err)
	}
	return img
}

func TestIntegrationPDF(t *testing.T) {
	o := realTools(t)
	file, outdir := input(t, "doc.bin", totexttest.TextPDF("Hello from page one", "", "Third (page) here"))
	r := Convert(t.Context(), file, outdir, o)
	if r.Kind() != OK || r.Type != TypePDF || r.Pages != 3 || len(r.Files) != 3 {
		t.Fatalf("report = %+v", r)
	}
	got := readOut(t, outdir)
	if !strings.Contains(got["p001.txt"], "Hello from page one") || !strings.Contains(got["p003.txt"], "Third (page) here") {
		t.Errorf("files = %q", got)
	}
	// The blank page has no text, so it was OCR'd, finding none.
	if !slices.Equal(r.OCRPages, []int{2}) || r.Files[1].Chars != 0 || r.Files[0].Chars != 16 {
		t.Errorf("files = %+v, ocr = %v", r.Files, r.OCRPages)
	}

	o.MaxPages = 2
	_, outdir2 := input(t, "x", nil)
	r = Convert(t.Context(), file, outdir2, o)
	if r.Kind() != Partial || len(r.Files) != 2 || !slices.Equal(r.Skipped, []Skip{{FirstPage: 3, LastPage: 3, Reason: ReasonPageLimit, Detail: "over the 2 page limit"}}) {
		t.Errorf("page limit report = %+v", r)
	}
}

func TestIntegrationScanned(t *testing.T) {
	o := realTools(t)
	img := scan(t, totexttest.TextPDF("SCANNED INVOICE NUMBER 4217"), 150)
	file, outdir := input(t, "scan.pdf", totexttest.ImagePDF(img, 150))
	r := Convert(t.Context(), file, outdir, o)
	if r.Kind() != OK || r.Pages != 1 || !slices.Equal(r.OCRPages, []int{1}) {
		t.Fatalf("report = %+v", r)
	}
	if got := readOut(t, outdir)["p001.txt"]; !strings.Contains(got, "INVOICE") || !strings.Contains(got, "4217") {
		t.Errorf("OCR text = %q", got)
	}

	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	file, outdir = input(t, "scan.pdf", b.Bytes())
	r = Convert(t.Context(), file, outdir, o)
	if r.Kind() != OK || r.Type != TypePNG || !slices.Equal(r.OCRPages, []int{1}) {
		t.Fatalf("image report = %+v", r)
	}
	if got := readOut(t, outdir)[ImageOutput]; !strings.Contains(got, "INVOICE") {
		t.Errorf("image OCR text = %q", got)
	}
}

func TestIntegrationEncrypted(t *testing.T) {
	o := realTools(t)
	data, err := totexttest.EncryptedPDF("secret", "hidden text")
	if err != nil {
		t.Fatal(err)
	}
	file, outdir := input(t, "enc.pdf", data)
	r := Convert(t.Context(), file, outdir, o)
	if r.Kind() != Encrypted || !r.Encrypted || len(r.Skipped) != 1 || r.Skipped[0].Reason != ReasonEncrypted {
		t.Errorf("report = %+v", r)
	}
	// The generated file really is a PDF that opens with its password.
	if b, err := exec.Command("pdftotext", "-upw", "secret", "--", file, "-").Output(); err != nil || !strings.Contains(string(b), "hidden text") {
		t.Errorf("with the password: %q, %v", b, err)
	}
}

func TestIntegrationTimeout(t *testing.T) {
	o := realTools(t)
	o.Timeout = time.Nanosecond
	file, outdir := input(t, "doc.pdf", totexttest.TextPDF("text"))
	r := Convert(t.Context(), file, outdir, o)
	if r.Kind() != TimedOut || r.Skipped[0].Tool != "pdfinfo" {
		t.Errorf("report = %+v", r)
	}
}
