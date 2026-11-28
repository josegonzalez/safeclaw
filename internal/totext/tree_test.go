package totext

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/josegonzalez/safeclaw/internal/expand"
)

// treeFake fakes the tools for a tree, by the base name of each file:
// enc.pdf needs a password, bad.pdf is corrupt, any other PDF has two
// pages whose text names the file and page, slow.png hangs tesseract, and
// any other image OCRs to its name.
func treeFake() *fake {
	return &fake{tools: map[string]func(context.Context, io.Writer, []string) error{
		"pdfinfo": func(_ context.Context, w io.Writer, args []string) error {
			switch filepath.Base(args[len(args)-1]) {
			case "enc.pdf":
				return &ExitError{Tool: "pdfinfo", Code: 1, Stderr: "Incorrect password"}
			case "bad.pdf":
				return &ExitError{Tool: "pdfinfo", Code: 1, Stderr: "Syntax Error: Couldn't find trailer dictionary"}
			}
			_, err := io.WriteString(w, "Pages:          2\nEncrypted:      no\n")
			return err
		},
		"pdftotext": func(_ context.Context, w io.Writer, args []string) error {
			_, err := fmt.Fprintf(w, "page %s of %s\f", flagValue(args, "-f"), filepath.Base(args[len(args)-2]))
			return err
		},
		"tesseract": func(ctx context.Context, w io.Writer, args []string) error {
			if filepath.Base(args[0]) == "slow.png" {
				return hang(ctx, w, args)
			}
			_, err := io.WriteString(w, "ocr of "+filepath.Base(args[0]))
			return err
		},
	}}
}

const (
	pdfData = "%PDF-1.7\n"
	pngData = "\x89PNG\r\n\x1a\n...."
)

// writeTree creates files under a new directory: each value is the file's
// content, or "->target" for a symbolic link.
func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for name, data := range files {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		var err error
		if target, ok := strings.CutPrefix(data, "->"); ok {
			err = os.Symlink(target, p)
		} else {
			err = os.WriteFile(p, []byte(data), 0o644)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func treeOpts(r Runner) TreeOptions {
	o := DefaultTreeOptions()
	o.Options = opts(r)
	return o
}

// entry returns the entry for path.
func entry(t *testing.T, r *TreeReport, path string) *Entry {
	t.Helper()
	for i := range r.Entries {
		if r.Entries[i].Path == path {
			return &r.Entries[i]
		}
	}
	t.Fatalf("no entry for %s in %+v", path, r.Entries)
	return nil
}

func reasons(e *Entry) []string {
	var out []string
	for _, s := range e.Skipped {
		out = append(out, s.Reason)
	}
	return out
}

func outputs(e *Entry) []string {
	var out []string
	for _, f := range e.Files {
		out = append(out, f.Path)
	}
	return out
}

func TestConvertTree(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := writeTree(t, map[string]string{
		"docs/report.pdf":  pdfData,
		"docs/enc.pdf":     pdfData,
		"docs/bad.pdf":     pdfData,
		"docs/scan.png":    pngData,
		"a/b.txt":          "one \x1b[2J",
		"a_b.txt":          "two",
		"bin/tool":         "\x7fELF\x02\x01\x01\x00",
		"link.txt":         "->" + outside,
		"linkdir":          "->" + filepath.Dir(outside),
		"..hidden/.. x\t":  "dots",
		"deep/" + "ü/é.md": "accents",
	})
	if err := syscall.Mkfifo(filepath.Join(src, "fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	outdir := filepath.Join(t.TempDir(), "out")
	r := ConvertTree(t.Context(), src, outdir, treeOpts(treeFake()))
	if r.Kind() != Partial || r.Status != "partial" || r.Error != "" || r.Expand != ExpandNone {
		t.Fatalf("report = %+v", r)
	}
	var paths []string
	for i, e := range r.Entries {
		paths = append(paths, e.Path)
		if e.Index != i+1 {
			t.Errorf("%s has index %d", e.Path, e.Index)
		}
	}
	want := []string{"..hidden/.. x\t", "a/b.txt", "a_b.txt", "bin/tool", "deep/ü/é.md", "docs/bad.pdf", "docs/enc.pdf", "docs/report.pdf", "docs/scan.png", "fifo", "link.txt", "linkdir"}
	if !slices.Equal(paths, want) {
		t.Errorf("entries = %q, want %q", paths, want)
	}
	for path, c := range map[string]struct {
		status  string
		outputs []string
		reasons []string
	}{
		"..hidden/.. x\t": {"ok", []string{"001-hidden_. x.text.txt"}, nil},
		"a/b.txt":         {"ok", []string{"002-a_b.txt.text.txt"}, nil},
		"a_b.txt":         {"ok", []string{"003-a_b.txt.text.txt"}, nil},
		"bin/tool":        {"unsupported", nil, []string{ReasonUnsupported}},
		"deep/ü/é.md":     {"ok", []string{"005-deep_ü_é.md.text.txt"}, nil},
		"docs/bad.pdf":    {"failed", nil, nil},
		"docs/enc.pdf":    {"encrypted", nil, []string{ReasonEncrypted}},
		"docs/report.pdf": {"ok", []string{"008-docs_report.pdf.p001.txt", "008-docs_report.pdf.p002.txt"}, nil},
		"docs/scan.png":   {"ok", []string{"009-docs_scan.png.ocr.txt"}, nil},
		"fifo":            {StatusSkipped, nil, []string{ReasonSpecial}},
		"link.txt":        {StatusSkipped, nil, []string{ReasonLink}},
		"linkdir":         {StatusSkipped, nil, []string{ReasonLink}},
	} {
		e := entry(t, r, path)
		if e.Status != c.status || !slices.Equal(outputs(e), c.outputs) || !slices.Equal(reasons(e), c.reasons) {
			t.Errorf("%q: status %s, outputs %q, skipped %+v, error %q", path, e.Status, outputs(e), e.Skipped, e.Error)
		}
	}
	if e := entry(t, r, "docs/bad.pdf"); !strings.Contains(e.Error, "trailer") || e.Type != TypePDF {
		t.Errorf("bad.pdf = %+v", e)
	}
	if e := entry(t, r, "docs/report.pdf"); e.Size != int64(len(pdfData)) || e.Pages != 2 || e.Files[1].Chars != 17 {
		t.Errorf("report.pdf = %+v", e)
	}
	got := readOut(t, outdir)
	if len(got) != 8 || got["002-a_b.txt.text.txt"] != "one [2J" || got["003-a_b.txt.text.txt"] != "two" || got["008-docs_report.pdf.p002.txt"] != "page 2 of report.pdf" {
		t.Errorf("outdir = %q", got)
	}
	for name := range got {
		if strings.Contains(name, "secret") || (name != ManifestText && !strings.HasSuffix(name, ".txt")) {
			t.Errorf("unexpected output %q", name)
		}
	}
	var b bytes.Buffer
	if err := r.WriteText(&b); err != nil || got[ManifestText] != b.String() {
		t.Errorf("manifest.txt = %q, want %q (%v)", got[ManifestText], b.String(), err)
	}
	if r.OutputSize != int64(len("dots")+len("one [2J")+len("two")+len("accents")+2*len("page 1 of report.pdf")+len("ocr of scan.png")) {
		t.Errorf("output size = %d", r.OutputSize)
	}
}

func TestConvertTreeOK(t *testing.T) {
	src := writeTree(t, map[string]string{"one.txt": "1", "sub/two.pdf": pdfData})
	outdir := filepath.Join(t.TempDir(), "out")
	r := ConvertTree(t.Context(), src, outdir, treeOpts(treeFake()))
	if r.Kind() != OK || r.Status != "ok" || len(r.Entries) != 2 {
		t.Fatalf("report = %+v", r)
	}
}

// TestConvertTreeTimeout checks that each file keeps its own per-tool
// timeout, so one hanging file doesn't hold up the rest.
func TestConvertTreeTimeout(t *testing.T) {
	src := writeTree(t, map[string]string{"a/slow.png": pngData, "b.txt": "after"})
	o := treeOpts(treeFake())
	o.Timeout = 50 * time.Millisecond
	r := ConvertTree(t.Context(), src, filepath.Join(t.TempDir(), "out"), o)
	if r.Kind() != Partial || entry(t, r, "a/slow.png").Status != ReasonTimedOut || entry(t, r, "b.txt").Status != "ok" {
		t.Errorf("report = %+v", r)
	}
}

func TestConvertTreeFileLimit(t *testing.T) {
	src := writeTree(t, map[string]string{"1.txt": "a", "2": "->1.txt", "3.txt": "b", "4.txt": "c"})
	o := treeOpts(treeFake())
	o.MaxFiles = 2
	r := ConvertTree(t.Context(), src, filepath.Join(t.TempDir(), "out"), o)
	if r.Kind() != Partial {
		t.Fatalf("report = %+v", r)
	}
	// The link isn't converted, so it doesn't count.
	for path, want := range map[string]string{"1.txt": "ok", "2": ReasonLink, "3.txt": "ok", "4.txt": ReasonFileLimit} {
		e := entry(t, r, path)
		if got := e.Status; got != want && (got != StatusSkipped || !slices.Equal(reasons(e), []string{want})) {
			t.Errorf("%s: %s %+v", path, got, e.Skipped)
		}
	}
}

func TestConvertTreeOutputLimit(t *testing.T) {
	// a.txt takes 10 bytes, and big.pdf's first page 21 of the 40 left
	// ("page 1 of big.pdf\n" after cleaning is 17 bytes: two pages don't
	// fit in 30).
	src := writeTree(t, map[string]string{"a.txt": "0123456789", "big.pdf": pdfData, "c.txt": "x"})
	o := treeOpts(treeFake())
	o.OCRThreshold = 0
	o.MaxOutput = 30
	outdir := filepath.Join(t.TempDir(), "out")
	r := ConvertTree(t.Context(), src, outdir, o)
	if r.Kind() != Partial || r.OutputSize != 27 {
		t.Fatalf("report = %+v", r)
	}
	big := entry(t, r, "big.pdf")
	if big.Status != "partial" || !slices.Equal(outputs(big), []string{"002-big.pdf.p001.txt"}) ||
		!slices.Equal(big.Skipped, []Skip{{FirstPage: 2, LastPage: 2, Reason: ReasonOutputLimit, Detail: "over the 30 byte output limit"}}) {
		t.Errorf("big.pdf = %+v", big)
	}
	if c := entry(t, r, "c.txt"); c.Status != StatusSkipped || !slices.Equal(reasons(c), []string{ReasonOutputLimit}) {
		t.Errorf("c.txt = %+v", c)
	}
	got := readOut(t, outdir)
	if len(got) != 3 || got["002-big.pdf.p001.txt"] != "page 1 of big.pdf" {
		t.Errorf("outdir = %q", got)
	}

	// A text file that doesn't fit leaves nothing and is skipped.
	src = writeTree(t, map[string]string{"a.txt": "0123456789"})
	o.MaxOutput = 5
	outdir = filepath.Join(t.TempDir(), "out")
	r = ConvertTree(t.Context(), src, outdir, o)
	if a := entry(t, r, "a.txt"); r.Kind() != Partial || a.Status != StatusSkipped || len(a.Files) != 0 || r.OutputSize != 0 {
		t.Errorf("report = %+v", r)
	}
	if got := readOut(t, outdir); len(got) != 1 {
		t.Errorf("outdir = %q", got)
	}
}

// TestConvertTreeOutputLimitStopsTool checks that a tool whose output
// runs past the limit is stopped rather than left to its timeout.
func TestConvertTreeOutputLimitStopsTool(t *testing.T) {
	f := &fake{tools: map[string]func(context.Context, io.Writer, []string) error{
		"tesseract": func(ctx context.Context, w io.Writer, _ []string) error {
			for ctx.Err() == nil {
				if _, err := io.WriteString(w, "more text "); err != nil {
					<-ctx.Done()
					return ctx.Err()
				}
			}
			return ctx.Err()
		},
	}}
	src := writeTree(t, map[string]string{"scan.png": pngData})
	o := treeOpts(f)
	o.MaxOutput = 1000
	o.Timeout = time.Minute
	start := time.Now()
	r := ConvertTree(t.Context(), src, filepath.Join(t.TempDir(), "out"), o)
	if e := entry(t, r, "scan.png"); e.Status != StatusSkipped || !slices.Equal(reasons(e), []string{ReasonOutputLimit}) || e.Skipped[0].Tool != "tesseract" {
		t.Errorf("scan.png = %+v", e)
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Errorf("took %v", d)
	}
}

func TestConvertTreeOutdir(t *testing.T) {
	src := writeTree(t, map[string]string{"a.txt": "a"})
	full := t.TempDir()
	if err := os.WriteFile(filepath.Join(full, "x"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(src, "a.txt")
	for name, c := range map[string]struct{ src, out string }{
		"inside src":    {src, filepath.Join(src, "out")},
		"src itself":    {src, src},
		"not empty":     {src, full},
		"a link":        {src, link},
		"src is a file": {file, filepath.Join(t.TempDir(), "out")},
		"src missing":   {filepath.Join(src, "nope"), filepath.Join(t.TempDir(), "out")},
	} {
		r := ConvertTree(t.Context(), c.src, c.out, treeOpts(treeFake()))
		if r.Kind() != Failed || r.Error == "" || len(r.Entries) != 0 {
			t.Errorf("%s: report = %+v", name, r)
		}
	}
	if _, err := os.Lstat(filepath.Join(src, "out")); err == nil {
		t.Error("an OUTDIR inside SRC was created")
	}
	o := treeOpts(treeFake())
	o.MaxFiles = 0
	if r := ConvertTree(t.Context(), src, filepath.Join(t.TempDir(), "o"), o); r.Kind() != Failed {
		t.Errorf("no file limit: %+v", r)
	}
	o = treeOpts(treeFake())
	o.MaxOutput = 0
	if r := ConvertTree(t.Context(), src, filepath.Join(t.TempDir(), "o"), o); r.Kind() != Failed {
		t.Errorf("no output limit: %+v", r)
	}
	// A link to SRC is followed.
	srcLink := filepath.Join(t.TempDir(), "src")
	if err := os.Symlink(src, srcLink); err != nil {
		t.Fatal(err)
	}
	if r := ConvertTree(t.Context(), srcLink, filepath.Join(t.TempDir(), "o"), treeOpts(treeFake())); r.Kind() != OK {
		t.Errorf("SRC through a link: %+v", r)
	}
}

func TestConvertTreeInterrupt(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	f := treeFake()
	f.tools["tesseract"] = func(ctx context.Context, w io.Writer, args []string) error {
		cancel()
		return hang(ctx, w, args)
	}
	src := writeTree(t, map[string]string{"a.txt": "a", "b.png": pngData, "c.txt": "c"})
	outdir := filepath.Join(t.TempDir(), "out")
	r := ConvertTree(ctx, src, outdir, treeOpts(f))
	if r.Kind() != Failed || !strings.Contains(r.Error, "interrupted") || len(r.Entries) != 0 || r.OutputSize != 0 {
		t.Errorf("report = %+v", r)
	}
	if got := readOut(t, outdir); len(got) != 0 {
		t.Errorf("outdir = %q", got)
	}
}

// expandTree lays out what safeclaw-expand writes for an email carrying a
// zip that holds a report, beside a rejected zip, with m as its manifest.
func expandTree(t *testing.T, edit func(m *expand.Manifest), extra map[string]string) string {
	t.Helper()
	files := map[string]string{
		"1-mail.eml":                                          "From: a@example.com\nSubject: hi\n\nbody",
		"1-mail.eml.unpacked/body.txt":                        "From: a@example.com\nSubject: hi\n\nbody",
		"1-mail.eml.unpacked/parts.txt":                       "1\ttext/plain\t4\t-\tBODY\tbody.txt\n",
		"1-mail.eml.unpacked/1-files.zip":                     "PK\x03\x04\x00\x00\x00\x00",
		"1-mail.eml.unpacked/1-files.zip.unpacked/report.pdf": pdfData,
		"2-bad.zip": "PK\x03\x04\x00\x00\x00\x00",
	}
	for k, v := range extra {
		files[k] = v
	}
	src := writeTree(t, files)
	m := &expand.Manifest{
		Schema: expand.SchemaVersion, Status: "ok",
		Inputs: []expand.Input{{Path: "1-mail.eml", Kind: expand.KindEmail}, {Path: "2-bad.zip", Kind: "zip"}},
		Containers: []expand.Container{
			{Path: "1-mail.eml", Kind: expand.KindEmail, Outcome: expand.OutcomeUnpacked, Flags: []string{"UNPACKED"}, Unpacked: "1-mail.eml.unpacked",
				Outputs: []string{"1-mail.eml.unpacked/body.txt", "1-mail.eml.unpacked/parts.txt"}},
			{Path: "1-mail.eml.unpacked/1-files.zip", Kind: "zip", Depth: 1, Parent: "1-mail.eml", Outcome: expand.OutcomeUnpacked, Flags: []string{"UNPACKED"}, Unpacked: "1-mail.eml.unpacked/1-files.zip.unpacked"},
			{Path: "2-bad.zip", Kind: "zip", Outcome: expand.OutcomeRejected, Flags: []string{"REJECTED"}, Code: 2, Error: "rejected: 1 entry with links"},
		},
	}
	if edit != nil {
		edit(m)
	}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, expand.ManifestFile), data, 0o644); err != nil {
		t.Fatal(err)
	}
	return src
}

func TestConvertTreeExpand(t *testing.T) {
	src := expandTree(t, func(m *expand.Manifest) {
		m.Containers = append(m.Containers,
			expand.Container{Path: "gone.zip", Kind: "zip", Outcome: expand.OutcomeFailed, Flags: []string{"FAILED"}},
			// An outcome this version doesn't know is a container left
			// packed.
			expand.Container{Path: "3-later.eml", Kind: expand.KindEmail, Outcome: "skipped-by-a-newer-version", Flags: []string{"SKIPPED"}})
	}, map[string]string{"3-later.eml": "From: b@example.com\n\nlater"})
	outdir := filepath.Join(t.TempDir(), "out")
	r := ConvertTree(t.Context(), src, outdir, treeOpts(treeFake()))
	if r.Kind() != Partial || r.Expand != ExpandFolded || r.ExpandError != "" {
		t.Fatalf("report = %+v", r)
	}
	for path, c := range map[string]struct {
		status, reason, output, outcome string
	}{
		"1-mail.eml":                                          {StatusSkipped, ReasonUnpacked, "", expand.OutcomeUnpacked},
		"1-mail.eml.unpacked/body.txt":                        {"ok", "", "1-mail.eml", ""},
		"1-mail.eml.unpacked/parts.txt":                       {"ok", "", "1-mail.eml", ""},
		"1-mail.eml.unpacked/1-files.zip":                     {StatusSkipped, ReasonUnpacked, "", expand.OutcomeUnpacked},
		"1-mail.eml.unpacked/1-files.zip.unpacked/report.pdf": {"ok", "", "", ""},
		"2-bad.zip":         {"unsupported", ReasonUnsupported, "", expand.OutcomeRejected},
		"3-later.eml":       {"ok", "", "", "skipped-by-a-newer-version"},
		expand.ManifestFile: {StatusSkipped, ReasonExpandManifest, "", ""},
		"gone.zip":          {StatusSkipped, ReasonMissing, "", expand.OutcomeFailed},
	} {
		e := entry(t, r, path)
		outcome := ""
		if e.Container != nil {
			outcome = e.Container.Outcome
		}
		reason := ""
		if len(e.Skipped) > 0 {
			reason = e.Skipped[0].Reason
		}
		if e.Status != c.status || reason != c.reason || e.ExpandOutput != c.output || outcome != c.outcome {
			t.Errorf("%s: status %s, skipped %+v, expand output %q, container %+v", path, e.Status, e.Skipped, e.ExpandOutput, e.Container)
		}
	}
	if last := r.Entries[len(r.Entries)-1]; last.Path != "gone.zip" {
		t.Errorf("the missing container isn't last: %+v", last)
	}
	var b bytes.Buffer
	if err := r.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"tree\tpartial\t9\t",
		"\tfolded\t-\n",
		"file\t001\t1-mail.eml\tskipped\tunknown\t",
		"container\t001\temail\t0\tunpacked\tUNPACKED\t-\t-\n",
		"skipped\t001\t0\t0\tunpacked\t-\topened by safeclaw-expand into 1-mail.eml.unpacked\n",
		"\tEXPAND-OUTPUT\n",
		"page\t004\t1\t",
		"\t004-1-mail.eml.unpacked_body.txt.text.txt\t-\n",
		"container\t002\tzip\t1\tunpacked\tUNPACKED\t1-mail.eml\t-\n",
		"container\t006\tzip\t0\trejected\tREJECTED\t-\trejected: 1 entry with links\n",
		"file\t009\tgone.zip\tskipped\t",
		"skipped\t009\t0\t0\tmissing\t",
	} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("manifest lacks %q:\n%s", want, b.String())
		}
	}

	// With every container opened, the run is ok.
	src = expandTree(t, func(m *expand.Manifest) { m.Containers = m.Containers[:2] }, nil)
	if err := os.Remove(filepath.Join(src, "2-bad.zip")); err != nil {
		t.Fatal(err)
	}
	if r := ConvertTree(t.Context(), src, filepath.Join(t.TempDir(), "out"), treeOpts(treeFake())); r.Kind() != OK {
		t.Errorf("report = %+v", r)
	}
}

// TestConvertTreeTamperedManifest checks that an expand manifest is only
// used when ReadManifest accepts it, and never makes ConvertTree read a
// path outside SRC or skip a file whose directory isn't there.
func TestConvertTreeTamperedManifest(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("outside-content"), 0o644); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(m *expand.Manifest){
		"outside":    func(m *expand.Manifest) { m.Containers[0].Path = "../" + filepath.Base(outside) + "/secret.txt" },
		"absolute":   func(m *expand.Manifest) { m.Containers[0].Outputs = []string{filepath.Join(outside, "secret.txt")} },
		"duplicated": func(m *expand.Manifest) { m.Containers[1].Path = m.Containers[0].Path },
		"schema":     func(m *expand.Manifest) { m.Schema = 99 },
	} {
		src := expandTree(t, edit, nil)
		outdir := filepath.Join(t.TempDir(), "out")
		r := ConvertTree(t.Context(), src, outdir, treeOpts(treeFake()))
		if r.Expand != ExpandInvalid || r.ExpandError == "" || r.Kind() == Failed {
			t.Errorf("%s: report = %+v", name, r)
			continue
		}
		// As a plain folder, the containers and manifest.json are
		// converted like any other file.
		if e := entry(t, r, expand.ManifestFile); e.Status != "ok" || e.Container != nil {
			t.Errorf("%s: manifest.json = %+v", name, e)
		}
		if e := entry(t, r, "1-mail.eml"); e.Status != "ok" || e.Container != nil {
			t.Errorf("%s: 1-mail.eml = %+v", name, e)
		}
		for out, text := range readOut(t, outdir) {
			if strings.Contains(text, "outside-content") {
				t.Errorf("%s: %s holds the file outside SRC", name, out)
			}
		}
	}

	// A manifest that is a link isn't read, and the link isn't followed.
	src := expandTree(t, nil, nil)
	data, err := os.ReadFile(filepath.Join(src, expand.ManifestFile))
	if err != nil {
		t.Fatal(err)
	}
	elsewhere := filepath.Join(outside, "manifest.json")
	if err := os.WriteFile(elsewhere, data, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(src, expand.ManifestFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, filepath.Join(src, expand.ManifestFile)); err != nil {
		t.Fatal(err)
	}
	r := ConvertTree(t.Context(), src, filepath.Join(t.TempDir(), "out"), treeOpts(treeFake()))
	if e := entry(t, r, expand.ManifestFile); r.Expand != ExpandInvalid || e.Status != StatusSkipped || !slices.Equal(reasons(e), []string{ReasonLink}) {
		t.Errorf("report = %+v", r)
	}

	// A valid manifest can't hide a file by calling it an opened container
	// whose directory isn't there.
	src = expandTree(t, func(m *expand.Manifest) {
		m.Containers[2].Outcome, m.Containers[2].Unpacked = expand.OutcomeUnpacked, "2-bad.zip.unpacked"
	}, nil)
	r = ConvertTree(t.Context(), src, filepath.Join(t.TempDir(), "out"), treeOpts(treeFake()))
	if e := entry(t, r, "2-bad.zip"); r.Expand != ExpandFolded || e.Status != "unsupported" {
		t.Errorf("2-bad.zip = %+v", e)
	}
}

func TestWriteTreeText(t *testing.T) {
	r := &TreeReport{Status: "partial", OutputSize: 12, Expand: ExpandInvalid, ExpandError: "bad\x1b[2J", Entries: []Entry{
		{Index: 1, Path: "a/\x1bb.pdf", Size: 9, Status: "partial", Type: TypePDF, Pages: 3, Encrypted: true,
			Files:   []File{{Page: 1, Path: "001-a_b.pdf.p001.txt", Chars: 12, OCR: true}},
			Skipped: []Skip{{FirstPage: 2, LastPage: 3, Reason: ReasonOutputLimit, Detail: "over"}}},
		{Index: 2, Path: "x", Status: "failed", Type: TypeUnknown, Error: "line\nbreak", ExpandOutput: "m.eml",
			Container: &expand.Container{Kind: "zip", Depth: 2, Parent: "p\tq", Outcome: "failed", Flags: []string{"FAILED"}, Error: "corrupt"}},
	}}
	var b bytes.Buffer
	if err := r.WriteText(&b); err != nil {
		t.Fatal(err)
	}
	want := "tree\tpartial\t2\t12\tinvalid\tbad\\x1b[2J\n" +
		"file\t001\ta/\\x1bb.pdf\tpartial\tpdf\t9\t3\tENCRYPTED\n" +
		"page\t001\t1\t12\t001-a_b.pdf.p001.txt\tOCR\n" +
		"skipped\t001\t2\t3\toutput-limit\t-\tover\n" +
		"file\t002\tx\tfailed\tunknown\t0\t0\tEXPAND-OUTPUT\n" +
		"error\t002\tline\\nbreak\n" +
		"container\t002\tzip\t2\tfailed\tFAILED\tp\\tq\tcorrupt\n"
	if b.String() != want {
		t.Errorf("got\n%s\nwant\n%s", b.String(), want)
	}
}
