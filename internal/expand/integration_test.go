package expand

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/unpack"
)

// These tests run the real 7z on trees they generate. They are skipped
// when there is no 7z on PATH, except under `make test-integration`, which
// sets SAFECLAW_REQUIRE_7Z.

func sevenZip(t *testing.T) unpack.SevenZip {
	t.Helper()
	z, err := unpack.Find()
	if err != nil {
		if os.Getenv("SAFECLAW_REQUIRE_7Z") != "" {
			t.Fatal(err)
		}
		t.Skip(err)
	}
	return z
}

type zipFile struct {
	name, body string
	mode       fs.FileMode
}

func makeZip(t *testing.T, files ...zipFile) string {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for _, f := range files {
		h := &zip.FileHeader{Name: f.name, Method: zip.Deflate}
		if f.mode != 0 {
			h.SetMode(f.mode)
		}
		fw, err := w.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(f.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func gz(t *testing.T, data []byte) string {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// TestIntegrationTree runs the real 7z on several generated inputs: an
// email carrying a zip that holds a forwarded .eml carrying another zip,
// a zip with a symlink, a password zip, a zip bomb, and a gzip bomb.
func TestIntegrationTree(t *testing.T) {
	z := sevenZip(t)
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(secret, []byte("s3cret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	encZip := filepath.Join(dir, "enc.zip")
	// The test's own password, for an archive it made, is fine in argv.
	if out, err := exec.Command(z.Path, "a", "-bd", "-tzip", "-ppw", encZip, secret).CombinedOutput(); err != nil {
		t.Fatalf("7z a: %v\n%s", err, out)
	}
	enc, err := os.ReadFile(encZip)
	if err != nil {
		t.Fatal(err)
	}

	inner := makeZip(t, zipFile{name: "deep/deep.txt", body: "deep\n"})
	fwd := email("inner", "the inner one", "inner.zip", inner)
	files := makeZip(t, zipFile{name: "fwd.eml", body: fwd}, zipFile{name: "good.pdf", body: "%PDF-1.7\n"}, zipFile{name: "enc.zip", body: string(enc)})
	report := email("report", "see attached", "files.zip", files)
	links := makeZip(t, zipFile{name: "fine.txt", body: "fine"}, zipFile{name: "l", body: "/etc/passwd", mode: fs.ModeSymlink | 0o777})
	bomb := makeZip(t, zipFile{name: "zeros", body: string(make([]byte, 4<<20))})
	gzBomb := gz(t, make([]byte, 4<<20))

	in := writeInputs(t, "report.eml", report, "links.zip", links, "bomb.zip", bomb, "zeros.gz", gzBomb)
	o := Options{Runner: z, MaxSize: 2 << 20, Depth: 3}
	dest, m := run(t, nil, o, in...)
	checkSummary(t, m, []string{
		"1-report.eml email 0 UNPACKED -> 1-report.eml.unpacked",
		"1-report.eml.unpacked/1-files.zip zip 1 UNPACKED -> 1-report.eml.unpacked/1-files.zip.unpacked",
		"1-report.eml.unpacked/1-files.zip.unpacked/enc.zip zip 2 NEEDS-PASSWORD",
		"1-report.eml.unpacked/1-files.zip.unpacked/fwd.eml email 2 UNPACKED -> 1-report.eml.unpacked/1-files.zip.unpacked/fwd.eml.unpacked",
		"1-report.eml.unpacked/1-files.zip.unpacked/fwd.eml.unpacked/1-inner.zip zip 3 UNPACKED -> 1-report.eml.unpacked/1-files.zip.unpacked/fwd.eml.unpacked/1-inner.zip.unpacked",
		"2-links.zip zip 0 REJECTED",
		"3-bomb.zip zip 0 TOO-LARGE",
		"4-zeros.gz gzip 0 TOO-LARGE",
	})
	if got := readFile(t, filepath.Join(dest, "1-report.eml.unpacked/1-files.zip.unpacked/fwd.eml.unpacked/1-inner.zip.unpacked/deep/deep.txt")); got != "deep\n" {
		t.Errorf("deep.txt = %q", got)
	}
	if l := m.Containers[5]; len(l.Rejected) != 1 || l.Rejected[0].Path != "l" || l.Code != 2 {
		t.Errorf("links = %+v", l)
	}
	for _, p := range []string{"2-links.zip.unpacked", "3-bomb.zip.unpacked", "4-zeros.gz.unpacked", "1-report.eml.unpacked/1-files.zip.unpacked/enc.zip.unpacked"} {
		if _, err := os.Lstat(filepath.Join(dest, p)); err == nil {
			t.Errorf("%s left behind", p)
		}
	}
	if m.Size > o.MaxSize {
		t.Errorf("size = %d", m.Size)
	}
	// Nothing got out of the destination.
	if names, _ := os.ReadDir(filepath.Dir(dest)); len(names) != 1 {
		t.Errorf("next to dest: %v", names)
	}

	// The password opens the nested password zip, and a larger limit the
	// bombs.
	pw := "pw"
	o.Password, o.MaxSize = &pw, 16<<20
	dest, m = run(t, nil, o, in[0], in[2], in[3])
	checkSummary(t, m, []string{
		"1-report.eml email 0 UNPACKED -> 1-report.eml.unpacked",
		"1-report.eml.unpacked/1-files.zip zip 1 UNPACKED -> 1-report.eml.unpacked/1-files.zip.unpacked",
		"1-report.eml.unpacked/1-files.zip.unpacked/enc.zip zip 2 UNPACKED -> 1-report.eml.unpacked/1-files.zip.unpacked/enc.zip.unpacked",
		"1-report.eml.unpacked/1-files.zip.unpacked/fwd.eml email 2 UNPACKED -> 1-report.eml.unpacked/1-files.zip.unpacked/fwd.eml.unpacked",
		"1-report.eml.unpacked/1-files.zip.unpacked/fwd.eml.unpacked/1-inner.zip zip 3 UNPACKED -> 1-report.eml.unpacked/1-files.zip.unpacked/fwd.eml.unpacked/1-inner.zip.unpacked",
		"2-bomb.zip zip 0 UNPACKED -> 2-bomb.zip.unpacked",
		"3-zeros.gz gzip 0 UNPACKED -> 3-zeros.gz.unpacked",
	})
	if got := readFile(t, filepath.Join(dest, "1-report.eml.unpacked/1-files.zip.unpacked/enc.zip.unpacked/secret.txt")); got != "s3cret\n" {
		t.Errorf("secret.txt = %q", got)
	}
}

// TestIntegrationResume runs the real 7z over three runs on one
// destination: an email carrying a password zip, a 7z archive with
// encrypted headers, and a zip to skip, planned, opened without the
// password, and opened again with it.
func TestIntegrationResume(t *testing.T) {
	z := sevenZip(t)
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(secret, []byte("s3cret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	encZip, enc7z := filepath.Join(dir, "enc.zip"), filepath.Join(dir, "enc.7z")
	// The test's own password, for archives it made, is fine in argv.
	for _, args := range [][]string{{"a", "-bd", "-tzip", "-ppw", encZip, secret}, {"a", "-bd", "-t7z", "-ppw", "-mhe=on", enc7z, secret}} {
		if out, err := exec.Command(z.Path, args...).CombinedOutput(); err != nil {
			t.Fatalf("7z %v: %v\n%s", args, err, out)
		}
	}
	report := email("report", "the password is pw", "enc.zip", readFile(t, encZip))
	in := writeInputs(t, "report.eml", report, "enc.7z", readFile(t, enc7z), "skip.zip", makeZip(t, zipFile{name: "x.txt", body: "x"}))
	o := Options{Runner: z, MaxSize: 1 << 20, Depth: 3, Skip: []string{"3-skip.zip"}}
	dest, m := run(t, nil, o, in...)
	checkSummary(t, m, []string{
		"1-report.eml email 0 UNPACKED -> 1-report.eml.unpacked",
		"1-report.eml.unpacked/1-enc.zip zip 1 NEEDS-PASSWORD",
		"2-enc.7z 7z 0 NEEDS-PASSWORD",
		"3-skip.zip zip 0 SKIPPED",
	})

	// The plan lists the zip's entries, encrypted, and the skipped zip's,
	// and can't list the 7z without the password.
	o.Skip = nil
	items, err := Plan(t.Context(), nil, dest, o)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 3 || len(items[0].Entries) != 1 || !items[0].Entries[0].Encrypted || items[1].ListError == "" || len(items[2].Entries) != 1 || items[2].Entries[0].Path != "x.txt" {
		t.Errorf("plan = %+v", items)
	}
	pw := "pw"
	o.Password = &pw
	if items, err := Plan(t.Context(), nil, dest, o); err != nil || items[1].ListError != "" || len(items[1].Entries) != 1 {
		t.Errorf("plan with the password = %+v, %v", items, err)
	}

	// The password opens both, and the skipped zip stays packed.
	m = rerun(t, nil, dest, o, in...)
	checkSummary(t, m, []string{
		"1-report.eml email 0 UNPACKED -> 1-report.eml.unpacked",
		"1-report.eml.unpacked/1-enc.zip zip 1 UNPACKED -> 1-report.eml.unpacked/1-enc.zip.unpacked",
		"2-enc.7z 7z 0 UNPACKED -> 2-enc.7z.unpacked",
		"3-skip.zip zip 0 SKIPPED",
	})
	for _, p := range []string{"1-report.eml.unpacked/1-enc.zip.unpacked/secret.txt", "2-enc.7z.unpacked/secret.txt"} {
		if got := readFile(t, filepath.Join(dest, p)); got != "s3cret\n" {
			t.Errorf("%s = %q", p, got)
		}
	}
	if len(m.Inputs) != 3 {
		t.Errorf("inputs = %+v", m.Inputs)
	}
	o.Unskip = []string{"3-skip.zip"}
	m = rerun(t, nil, dest, o)
	if c := m.Containers[3]; c.Outcome != OutcomeUnpacked {
		t.Errorf("unskipped = %+v", c)
	}
}

// TestIntegrationHold runs the real 7z with --hold mail-archives on an
// email carrying a zip that holds another zip, and a message forwarding an
// email that carries a zip: both zips that came out of emails are held,
// listed by the plan, and opened only once released, the zip in the
// released one as usual. A file that only starts like a zip isn't held.
func TestIntegrationHold(t *testing.T) {
	z := sevenZip(t)
	inner := makeZip(t, zipFile{name: "deep.txt", body: "deep\n"})
	files := makeZip(t, zipFile{name: "inner.zip", body: inner}, zipFile{name: "notes.txt", body: "notes\n"})
	fwd := forwarding(email("inner", "the inner one", "fwd.zip", makeZip(t, zipFile{name: "f.txt", body: "f\n"})))
	in := writeInputs(t, "report.eml", email("report", "see attached", "files.zip", files, "fake.zip", zipHead+"not really"), "fwd.eml", fwd)
	o := Options{Runner: z, MaxSize: 1 << 20, Depth: 3, Hold: []string{HoldMailArchives}}
	dest, m := run(t, nil, o, in...)
	checkSummary(t, m, []string{
		"1-report.eml email 0 UNPACKED -> 1-report.eml.unpacked",
		"1-report.eml.unpacked/1-files.zip zip 1 HELD",
		"2-fwd.eml email 0 UNPACKED -> 2-fwd.eml.unpacked",
		"2-fwd.eml.unpacked/1-fwd.zip zip 2 HELD",
	})

	items, err := Plan(t.Context(), nil, dest, o)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || len(items[0].Entries) != 2 || items[0].Entries[0].Path != "inner.zip" || len(items[1].Entries) != 1 || items[1].Entries[0].Path != "f.txt" {
		t.Errorf("plan = %+v", items)
	}

	o.Release = []string{"1-report.eml.unpacked/1-files.zip"}
	m = rerun(t, nil, dest, o)
	checkSummary(t, m, []string{
		"1-report.eml email 0 UNPACKED -> 1-report.eml.unpacked",
		"1-report.eml.unpacked/1-files.zip zip 1 UNPACKED -> 1-report.eml.unpacked/1-files.zip.unpacked",
		"2-fwd.eml email 0 UNPACKED -> 2-fwd.eml.unpacked",
		"2-fwd.eml.unpacked/1-fwd.zip zip 2 HELD",
		"1-report.eml.unpacked/1-files.zip.unpacked/inner.zip zip 2 UNPACKED -> 1-report.eml.unpacked/1-files.zip.unpacked/inner.zip.unpacked",
	})
	if got := readFile(t, filepath.Join(dest, "1-report.eml.unpacked/1-files.zip.unpacked/inner.zip.unpacked/deep.txt")); got != "deep\n" {
		t.Errorf("deep.txt = %q", got)
	}
	o.Release, o.ReleaseAll = nil, true
	m = rerun(t, nil, dest, o)
	if c := m.Containers[3]; c.Outcome != OutcomeUnpacked {
		t.Errorf("released forwarded zip = %+v", c)
	}
	if got := readFile(t, filepath.Join(dest, "2-fwd.eml.unpacked/1-fwd.zip.unpacked/f.txt")); got != "f\n" {
		t.Errorf("f.txt = %q", got)
	}
}
