package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/totext"
)

func TestWriteTotextReport(t *testing.T) {
	var b bytes.Buffer
	err := writeTotextReport(&b, &totext.Report{
		Type: totext.TypePDF, Pages: 9, Encrypted: true,
		Files: []totext.File{{Page: 1, Path: "p001.txt", Chars: 120}, {Page: 2, Path: "p002.txt", Chars: 40, OCR: true}},
		Skipped: []totext.Skip{
			{FirstPage: 3, LastPage: 3, Reason: totext.ReasonTimedOut, Tool: "pdftotext", Detail: "pdftotext timed out"},
			{FirstPage: 4, LastPage: 9, Reason: totext.ReasonPageLimit, Detail: "tab\there \x1b[2J"},
			{Reason: totext.ReasonFailed},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "type\tpdf\t9\tENCRYPTED\n" +
		"page\t1\t120\tp001.txt\t-\n" +
		"page\t2\t40\tp002.txt\tOCR\n" +
		"skipped\t3\t3\ttimed-out\tpdftotext\tpdftotext timed out\n" +
		"skipped\t4\t9\tpage-limit\t-\ttab\\there \\x1b[2J\n" +
		"skipped\t0\t0\tfailed\t-\t-\n"
	if b.String() != want {
		t.Errorf("got\n%q\nwant\n%q", b.String(), want)
	}
}

func TestTotextFlags(t *testing.T) {
	cmd := newTotextCommand("totext")
	for name, want := range map[string]string{"json": "false", "max-pages": "100", "ocr-threshold": "10", "ocr-dpi": "300", "ocr-lang": "eng", "timeout": "1m0s"} {
		if got := cmd.Flags().Lookup(name).DefValue; got != want {
			t.Errorf("--%s default = %q, want %q", name, got, want)
		}
	}
	for _, s := range []string{"Exit codes:", "0  ok", "1  failed", "3  encrypted", "5  unsupported", "6  partial", "7  timed out", "p001.txt", totext.ImageOutput, totext.TextOutput} {
		if !strings.Contains(cmd.Long, s) {
			t.Errorf("help lacks %q", s)
		}
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "a.txt")
	if err := os.WriteFile(file, []byte("hi"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"--max-pages", "0", file, filepath.Join(dir, "o1")},
		{"--ocr-threshold", "-1", file, filepath.Join(dir, "o2")},
		{"--ocr-dpi", "5000", file, filepath.Join(dir, "o3")},
		{"--ocr-lang", "-l", file, filepath.Join(dir, "o4")},
		{"--timeout", "0s", file, filepath.Join(dir, "o5")},
	} {
		if _, err := run(t, newTotextCommand("totext"), args...); !errors.Is(err, exitCodeError{1}) {
			t.Errorf("%q: %v", args, err)
		}
	}
}

// TestTotextCommand converts text files, which need no tools, through the
// command.
func TestTotextCommand(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "notes.pdf")
	if err := os.WriteFile(file, []byte("hello \x1b]0;title\x07world\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, newTotextCommand("totext"), file, filepath.Join(dir, "a"))
	if err != nil || out != "type\ttext\t1\t-\npage\t1\t18\ttext.txt\t-\n" {
		t.Errorf("text = %q, %v", out, err)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "a", totext.TextOutput)); err != nil || string(b) != "hello ]0;titleworld\n" {
		t.Errorf("text.txt = %q, %v", b, err)
	}
	out, err = run(t, newTotextCommand("totext"), "--json", file, filepath.Join(dir, "b"))
	var v map[string]any
	if err != nil || json.Unmarshal([]byte(out), &v) != nil || v["schema"] != float64(1) || v["status"] != "ok" || v["type"] != "text" {
		t.Errorf("--json = %q, %v", out, err)
	}
	for _, field := range []string{"files", "ocr_pages", "skipped"} {
		if _, ok := v[field].([]any); !ok {
			t.Errorf("--json %s is not a list: %q", field, out)
		}
	}

	zip := filepath.Join(dir, "x.pdf")
	if err := os.WriteFile(zip, []byte("PK\x03\x04\x00\x00"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err = run(t, newTotextCommand("totext"), "--json", zip, filepath.Join(dir, "c"))
	var r totext.Report
	if !errors.Is(err, exitCodeError{5}) || json.Unmarshal([]byte(out), &r) != nil || r.Status != "unsupported" || r.Code != 5 || r.Skipped[0].Reason != "unsupported" {
		t.Errorf("unsupported = %q, %v", out, err)
	}
	if _, err := run(t, newTotextCommand("totext"), file, filepath.Join(dir, "a")); !errors.Is(err, exitCodeError{1}) {
		t.Errorf("non-empty outdir: %v", err)
	}
}

// TestTotextProgramName checks that the binary run as safeclaw-totext is
// `safeclaw totext`.
func TestTotextProgramName(t *testing.T) {
	for arg0, want := range map[string]bool{
		"safeclaw-totext":                true,
		"/usr/local/bin/safeclaw-totext": true,
		"safeclaw":                       false,
		"safeclaw-unpack":                false,
		"safeclaw-totext-old":            false,
	} {
		if got := isTotextProgram(arg0); got != want {
			t.Errorf("isTotextProgram(%q) = %v", arg0, got)
		}
	}
	if code := executeTotext(t.Context(), []string{"--max-pages", "nope", "a", "b"}); code != 1 {
		t.Errorf("bad --max-pages exit = %d", code)
	}
	if code := executeTotext(t.Context(), []string{"a"}); code != 1 {
		t.Errorf("missing OUTDIR exit = %d", code)
	}
	if code := executeTotext(t.Context(), []string{"--help"}); code != 0 {
		t.Errorf("--help exit = %d", code)
	}
}

// TestTotextRecursive converts a folder of text files, which need no
// tools, through the command.
func TestTotextRecursive(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	if err := os.MkdirAll(filepath.Join(src, "a"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string]string{"a/one.txt": "one", "two.txt": "two \x1b[2J"} {
		if err := os.WriteFile(filepath.Join(src, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	out, err := run(t, newTotextCommand("totext"), "--recursive", src, filepath.Join(dir, "a"))
	want := "tree\tok\t2\t10\tnone\t-\n" +
		"file\t001\ta/one.txt\tok\ttext\t3\t1\t-\n" +
		"page\t001\t1\t3\t001-a_one.txt.text.txt\t-\n" +
		"file\t002\ttwo.txt\tok\ttext\t8\t1\t-\n" +
		"page\t002\t1\t6\t002-two.txt.text.txt\t-\n"
	if err != nil || out != want {
		t.Errorf("got %q, %v, want %q", out, err, want)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "a", totext.ManifestText)); err != nil || string(b) != want {
		t.Errorf("manifest.txt = %q, %v", b, err)
	}

	out, err = run(t, newTotextCommand("totext"), "--recursive", "--json", "--max-files", "1", src, filepath.Join(dir, "b"))
	var r totext.TreeReport
	if !errors.Is(err, exitCodeError{6}) || json.Unmarshal([]byte(out), &r) != nil || r.Status != "partial" || r.Code != 6 || len(r.Entries) != 2 ||
		r.Entries[1].Status != totext.StatusSkipped || r.Entries[1].Skipped[0].Reason != totext.ReasonFileLimit {
		t.Errorf("--max-files = %q, %v", out, err)
	}
	if _, err := run(t, newTotextCommand("totext"), "--recursive", "--max-output", "4", src, filepath.Join(dir, "c")); !errors.Is(err, exitCodeError{6}) {
		t.Errorf("--max-output: %v", err)
	}

	for _, args := range [][]string{
		{"--recursive", src, filepath.Join(src, "out")},
		{"--recursive", "--max-output", "0", src, filepath.Join(dir, "d")},
		{"--recursive", "--max-output", "lots", src, filepath.Join(dir, "d")},
		{"--recursive", "--max-files", "0", src, filepath.Join(dir, "d")},
		{"--max-files", "5", filepath.Join(src, "two.txt"), filepath.Join(dir, "d")},
		{"--max-output", "5m", filepath.Join(src, "two.txt"), filepath.Join(dir, "d")},
		{"--recursive", filepath.Join(src, "two.txt"), filepath.Join(dir, "d")},
	} {
		if _, err := run(t, newTotextCommand("totext"), args...); !errors.Is(err, exitCodeError{1}) {
			t.Errorf("%q: %v", args, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, "d")); err == nil {
		t.Error("a usage error created OUTDIR")
	}
	out, err = run(t, newTotextCommand("totext"), "--recursive", "--json", "--max-output", "x", src, filepath.Join(dir, "e"))
	if !errors.Is(err, exitCodeError{1}) || json.Unmarshal([]byte(out), &r) != nil || r.Status != "failed" || r.Error == "" || r.Entries == nil {
		t.Errorf("--json failure = %q, %v", out, err)
	}
}
