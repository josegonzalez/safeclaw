package totext

import (
	"context"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// snapshot records what is in dir, a link as "->target", without
// following links.
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	names, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, n := range names {
		p := filepath.Join(dir, n.Name())
		switch {
		case n.Type()&os.ModeSymlink != 0:
			target, err := os.Readlink(p)
			if err != nil {
				t.Fatal(err)
			}
			got[n.Name()] = "->" + target
		case n.IsDir():
			got[n.Name()] = "dir"
		default:
			b, err := os.ReadFile(p)
			if err != nil {
				t.Fatal(err)
			}
			got[n.Name()] = string(b)
		}
	}
	return got
}

func replaceOpts(r Runner) TreeOptions {
	o := treeOpts(r)
	o.Replace = true
	return o
}

// earlierRun converts a tree into a new OUTDIR, the only thing in its
// parent, and returns SRC and OUTDIR.
func earlierRun(t *testing.T) (src, outdir string) {
	t.Helper()
	src = writeTree(t, map[string]string{"a.txt": "one", "b/report.pdf": pdfData, "c.png": pngData})
	outdir = filepath.Join(t.TempDir(), "out")
	if r := ConvertTree(t.Context(), src, outdir, treeOpts(treeFake())); r.Kind() != OK {
		t.Fatalf("earlier run = %+v", r)
	}
	return src, outdir
}

// onlyOutdir checks that nothing but OUTDIR was left beside it.
func onlyOutdir(t *testing.T, outdir string) {
	t.Helper()
	names, err := os.ReadDir(filepath.Dir(outdir))
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != 1 || names[0].Name() != filepath.Base(outdir) {
		t.Errorf("beside OUTDIR: %v", names)
	}
}

func TestConvertTreeReplace(t *testing.T) {
	src, outdir := earlierRun(t)
	// A read-only OUTDIR is replaced by one with its permissions.
	if err := os.Chmod(outdir, 0o555); err != nil {
		t.Fatal(err)
	}
	readOnly := outdir
	t.Cleanup(func() { _ = os.Chmod(readOnly, 0o755) })
	// Without --replace, the earlier results are refused.
	if r := ConvertTree(t.Context(), src, outdir, treeOpts(treeFake())); r.Kind() != Failed || !strings.Contains(r.Error, "not empty") {
		t.Fatalf("without replace = %+v", r)
	}
	// The tree changes: a file goes, one changes, and one is added.
	if err := os.Remove(filepath.Join(src, "a.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "c.png"), []byte("now text"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "d.txt"), []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	r := ConvertTree(t.Context(), src, outdir, replaceOpts(treeFake()))
	if r.Kind() != OK || r.Error != "" || r.Warning != "" {
		t.Fatalf("replace = %+v", r)
	}
	want := map[string]string{
		"001-b_report.pdf.p001.txt": "page 1 of report.pdf",
		"001-b_report.pdf.p002.txt": "page 2 of report.pdf",
		"002-c.png.text.txt":        "now text",
		"003-d.txt.text.txt":        "new",
	}
	got := snapshot(t, outdir)
	manifest := got[ManifestText]
	delete(got, ManifestText)
	if !maps.Equal(got, want) {
		t.Errorf("outdir = %q, want %q", got, want)
	}
	if !strings.HasPrefix(manifest, "tree\tok\t3\t") || strings.Contains(manifest, "a.txt") {
		t.Errorf("manifest = %q", manifest)
	}
	if fi, err := os.Lstat(outdir); err != nil || fi.Mode().Perm() != 0o555 {
		t.Errorf("OUTDIR's mode = %v, %v", fi.Mode(), err)
	}
	onlyOutdir(t, outdir)

	// It can be replaced again, from what it wrote itself.
	if r := ConvertTree(t.Context(), src, outdir, replaceOpts(treeFake())); r.Kind() != OK {
		t.Errorf("second replace = %+v", r)
	}
	onlyOutdir(t, outdir)

	// A missing or empty OUTDIR is converted into as without --replace.
	for _, out := range []string{filepath.Join(t.TempDir(), "new"), t.TempDir()} {
		if r := ConvertTree(t.Context(), src, out, replaceOpts(treeFake())); r.Kind() != OK || len(snapshot(t, out)) != 5 {
			t.Errorf("%s: %+v", out, r)
		}
	}
}

// TestConvertTreeReplaceFallback replaces where directories can't be
// swapped in one step.
func TestConvertTreeReplaceFallback(t *testing.T) {
	orig := exchangeDirs
	t.Cleanup(func() { exchangeDirs = orig })
	exchangeDirs = func(_, _ string) error { return errors.ErrUnsupported }
	src, outdir := earlierRun(t)
	if err := os.Chmod(outdir, 0o555); err != nil {
		t.Fatal(err)
	}
	readOnly := outdir
	t.Cleanup(func() { _ = os.Chmod(readOnly, 0o755) })
	if err := os.WriteFile(filepath.Join(src, "a.txt"), []byte("changed"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := ConvertTree(t.Context(), src, outdir, replaceOpts(treeFake())); r.Kind() != OK {
		t.Fatalf("replace = %+v", r)
	}
	if got := snapshot(t, outdir)["001-a.txt.text.txt"]; got != "changed" {
		t.Errorf("a.txt's output = %q", got)
	}
	onlyOutdir(t, outdir)

	// When the new results can't be moved in, the earlier ones are moved
	// back.
	_, outdir = earlierRun(t)
	fi, err := os.Lstat(outdir)
	if err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, outdir)
	if _, err := replaceDir(filepath.Join(filepath.Dir(outdir), "gone"), &previous{path: outdir, info: fi}); err == nil {
		t.Error("replacing with a missing directory worked")
	}
	if got := snapshot(t, outdir); !maps.Equal(got, before) {
		t.Errorf("outdir = %q, want %q", got, before)
	}
	onlyOutdir(t, outdir)
}

// TestConvertTreeReplaceFails checks that a run that fails, however it
// fails, leaves the earlier results as they were.
func TestConvertTreeReplaceFails(t *testing.T) {
	orig := exchangeDirs
	t.Cleanup(func() { exchangeDirs = orig })
	for name, c := range map[string]struct {
		edit     func(src string) string
		tools    func(f *fake, cancel context.CancelFunc)
		exchange func(a, b string) error
		want     string
	}{
		"interrupted": {
			tools: func(f *fake, cancel context.CancelFunc) {
				f.tools["tesseract"] = func(ctx context.Context, w io.Writer, args []string) error {
					cancel()
					return hang(ctx, w, args)
				}
			},
			want: "interrupted",
		},
		"src missing": {
			edit: func(src string) string { return filepath.Join(src, "nope") },
			want: "no such file",
		},
		"swap fails": {
			exchange: func(_, _ string) error { return syscall.EIO },
			want:     "input/output error",
		},
		"outdir changes": {
			exchange: func(_, _ string) error { panic("not reached") },
			want:     "changed during the run",
		},
	} {
		t.Run(name, func(t *testing.T) {
			src, outdir := earlierRun(t)
			before := snapshot(t, outdir)
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			f := treeFake()
			if c.tools != nil {
				c.tools(f, cancel)
			}
			if c.edit != nil {
				src = c.edit(src)
			}
			exchangeDirs = orig
			if c.exchange != nil {
				exchangeDirs = c.exchange
			}
			if name == "outdir changes" {
				f.tools["tesseract"] = func(_ context.Context, w io.Writer, _ []string) error {
					if err := os.WriteFile(filepath.Join(outdir, "extra"), nil, 0o644); err != nil {
						return err
					}
					_, err := io.WriteString(w, "ocr")
					return err
				}
				before["extra"] = ""
			}
			r := ConvertTree(ctx, src, outdir, replaceOpts(f))
			if r.Kind() != Failed || !strings.Contains(r.Error, c.want) || len(r.Entries) != 0 {
				t.Errorf("report = %+v", r)
			}
			if got := snapshot(t, outdir); !maps.Equal(got, before) {
				t.Errorf("outdir = %q, want %q", got, before)
			}
			onlyOutdir(t, outdir)
		})
	}
}

func TestConvertTreeReplaceRefused(t *testing.T) {
	src, valid := earlierRun(t)
	manifest, err := os.ReadFile(filepath.Join(valid, ManifestText))
	if err != nil {
		t.Fatal(err)
	}
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "keep.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	m := string(manifest)
	for name, files := range map[string]map[string]string{
		"no manifest":       {"x": "x"},
		"manifest only dir": {ManifestText + "/x": "x"},
		"manifest a link":   {ManifestText: "->" + filepath.Join(valid, ManifestText)},
		"not a manifest":    {ManifestText: "hello\n"},
		"empty manifest":    {ManifestText: ""},
		"unlisted file":     {ManifestText: m, "notes.md": "mine"},
		"unlisted txt":      {ManifestText: m, "004-x.txt": "mine"},
		"listed is a dir":   {ManifestText: m, "001-a.txt.text.txt/x": "x"},
		"listed is a link":  {ManifestText: m, "001-a.txt.text.txt": "->" + filepath.Join(outside, "keep.txt")},
		"listed links out":  {ManifestText: m, "002-b_report.pdf.p001.txt": "->" + outside},
		"failed status":     {ManifestText: strings.Replace(m, "tree\tok", "tree\tfailed", 1)},
		"no newline":        {ManifestText: strings.TrimSuffix(m, "\n")},
		"crlf":              {ManifestText: strings.ReplaceAll(m, "\n", "\r\n")},
		"extra field":       {ManifestText: strings.Replace(m, "\t-\n", "\t-\tx\n", 1)},
		"wrong count":       {ManifestText: strings.Replace(m, "tree\tok\t3", "tree\tok\t4", 1)},
		"wrong index":       {ManifestText: strings.ReplaceAll(m, "\t003\t", "\t004\t")},
		"padded number":     {ManifestText: strings.Replace(m, "\t3\t1\t-\n", "\t03\t1\t-\n", 1)},
		"unknown flag":      {ManifestText: strings.Replace(m, "\t3\t1\t-\n", "\t3\t1\tNOPE\n", 1)},
		"blank line":        {ManifestText: m + "\n"},
		"page before file":  {ManifestText: strings.Replace(m, "file\t001", "page\t001\t1\t1\t001-x.txt\t-\nfile\t001", 1)},
		"output up":         {ManifestText: strings.Replace(m, "001-a.txt.text.txt", "../001-a.txt.text.txt", 1)},
		"output in a dir":   {ManifestText: strings.Replace(m, "001-a.txt.text.txt", "001-a/../keep.txt", 1)},
		"output not .txt":   {ManifestText: strings.Replace(m, "001-a.txt.text.txt", "001-a.txt.text", 1)},
		"output other id":   {ManifestText: strings.Replace(m, "001-a.txt.text.txt", "002-a.txt.text.txt", 1)},
		"output manifest":   {ManifestText: strings.Replace(m, "001-a.txt.text.txt", ManifestText, 1)},
		"output escaped":    {ManifestText: strings.Replace(m, "001-a.txt.text.txt", `001-a\x2ftxt.txt`, 1)},
		"output twice":      {ManifestText: strings.Replace(m, "002-b_report.pdf.p002.txt", "002-b_report.pdf.p001.txt", 1)},
	} {
		outdir := writeTree(t, files)
		before := snapshot(t, outdir)
		r := ConvertTree(t.Context(), src, outdir, replaceOpts(treeFake()))
		if r.Kind() != Failed || !strings.Contains(r.Error, "--replace won't remove it") {
			t.Errorf("%s: report = %+v", name, r)
		}
		if got := snapshot(t, outdir); !maps.Equal(got, before) {
			t.Errorf("%s: outdir = %q, want %q", name, got, before)
		}
	}
	if got := snapshot(t, outside); len(got) != 1 || got["keep.txt"] != "keep" {
		t.Errorf("outside = %q", got)
	}

	// OUTDIR itself can't be a link, even to earlier results.
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(valid, link); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, valid)
	if r := ConvertTree(t.Context(), src, link, replaceOpts(treeFake())); r.Kind() != Failed || !strings.Contains(r.Error, "symbolic link") {
		t.Errorf("a link: %+v", r)
	}
	if got := snapshot(t, valid); !maps.Equal(got, before) {
		t.Errorf("through a link: outdir = %q", got)
	}
	// Nor a file, or inside SRC.
	if r := ConvertTree(t.Context(), src, filepath.Join(valid, ManifestText), replaceOpts(treeFake())); r.Kind() != Failed || !strings.Contains(r.Error, "not a directory") {
		t.Errorf("a file: %+v", r)
	}
	if r := ConvertTree(t.Context(), src, src, replaceOpts(treeFake())); r.Kind() != Failed || !strings.Contains(r.Error, "inside") {
		t.Errorf("SRC itself: %+v", r)
	}
	// A link above OUTDIR is followed, as without --replace.
	parentLink := filepath.Join(t.TempDir(), "parent")
	if err := os.Symlink(filepath.Dir(valid), parentLink); err != nil {
		t.Fatal(err)
	}
	if r := ConvertTree(t.Context(), src, filepath.Join(parentLink, filepath.Base(valid)), replaceOpts(treeFake())); r.Kind() != OK {
		t.Errorf("through a parent link: %+v", r)
	}
	onlyOutdir(t, valid)
}

// TestConvertTreeReplaceLinks checks that removing the earlier results
// never follows a link, even one put there after they were checked.
func TestConvertTreeReplaceLinks(t *testing.T) {
	orig := exchangeDirs
	t.Cleanup(func() { exchangeDirs = orig })
	src, outdir := earlierRun(t)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "keep.txt"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	exchangeDirs = func(a, b string) error {
		if err := os.Symlink(outside, filepath.Join(b, "link")); err != nil {
			return err
		}
		return orig(a, b)
	}
	if r := ConvertTree(t.Context(), src, outdir, replaceOpts(treeFake())); r.Kind() != OK {
		t.Fatalf("replace = %+v", r)
	}
	if got := snapshot(t, outside); len(got) != 1 || got["keep.txt"] != "keep" {
		t.Errorf("outside = %q", got)
	}
	if _, err := os.Lstat(filepath.Join(outdir, "link")); err == nil {
		t.Error("the link is in the new results")
	}
	onlyOutdir(t, outdir)
}

// TestReadTreeManifest checks that a manifest with every kind of line,
// including a folded expand manifest, reads back as it was written.
func TestReadTreeManifest(t *testing.T) {
	src := expandTree(t, nil, map[string]string{"enc.pdf": pdfData, "link": "->/etc/passwd", "a\tb\x1b.txt": "esc"})
	outdir := filepath.Join(t.TempDir(), "out")
	r := ConvertTree(t.Context(), src, outdir, treeOpts(treeFake()))
	if r.Kind() != Partial {
		t.Fatalf("report = %+v", r)
	}
	got, err := readTreeManifest(outdir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Entries) != len(r.Entries) || got.Status != r.Status || got.OutputSize != r.OutputSize {
		t.Errorf("read %+v, wrote %+v", got, r)
	}
	if err := checkResults(outdir); err != nil {
		t.Error(err)
	}
	if r := ConvertTree(t.Context(), src, outdir, replaceOpts(treeFake())); r.Kind() != Partial {
		t.Errorf("replace = %+v", r)
	}
}
