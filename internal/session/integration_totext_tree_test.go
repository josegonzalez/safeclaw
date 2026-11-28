//go:build integration

package session

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/expand"
	"github.com/josegonzalez/safeclaw/internal/totext"
	"github.com/josegonzalez/safeclaw/internal/totext/totexttest"
	"github.com/josegonzalez/safeclaw/internal/variant"
)

// TestIntegrationSandboxTotextTree runs safeclaw-expand in the sandbox
// variant on an email carrying a zip of PDFs, beside a zip with a
// symlink, then safeclaw-totext --recursive on what it opened.
func TestIntegrationSandboxTotextTree(t *testing.T) {
	d := docker.New()
	if id, err := d.ImageID(context.Background(), variant.Image(variant.Sandbox)); err != nil || id == "" {
		t.Skip("sandbox variant not built; run `safeclaw build --variant sandbox` first")
	}
	makeZip := func(files ...string) string {
		var b bytes.Buffer
		w := zip.NewWriter(&b)
		for i := 0; i+1 < len(files); i += 2 {
			h := &zip.FileHeader{Name: files[i], Method: zip.Deflate}
			if files[i] == "link" {
				h.SetMode(fs.ModeSymlink | 0o777)
			}
			fw, err := w.CreateHeader(h)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := fw.Write([]byte(files[i+1])); err != nil {
				t.Fatal(err)
			}
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		return b.String()
	}
	enc, err := totexttest.EncryptedPDF("secret", "hidden text")
	if err != nil {
		t.Fatal(err)
	}
	files := makeZip(
		"docs/report.pdf", string(totexttest.TextPDF("Quarterly report page one", "Page two words")),
		"docs/locked.pdf", string(enc),
		"notes ü (1).txt", "plain \x1b[2Jnotes\n",
	)
	email := "From: Eve <eve@example.com>\r\nSubject: report\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: text/plain\r\n\r\nPlease see the attached files\r\n" +
		"--b\r\nContent-Type: application/zip\r\nContent-Disposition: attachment; filename=\"files.zip\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString([]byte(files)) + "\r\n" +
		"--b--\r\n"
	in := t.TempDir()
	for name, data := range map[string]string{
		"report.eml": email,
		"links.zip":  makeZip("fine.txt", "fine", "link", "/etc/passwd"),
	} {
		if err := os.WriteFile(filepath.Join(in, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	out := runEphemeral(t, d, in, `
safeclaw-expand /in/report.eml /in/links.zip /sandbox/tree >/dev/null; echo "expand=$?"
safeclaw-totext --recursive --json /sandbox/tree /sandbox/text > /sandbox/report.json; echo "totext=$?"
echo "--- manifest"
cat /sandbox/text/manifest.txt
echo "--- files"
ls -1 /sandbox/text
echo "--- body"
cat /sandbox/text/*body.txt.text.txt
echo "--- page"
cat /sandbox/text/*report.pdf.p001.txt
echo "--- inside"
safeclaw-totext --recursive /sandbox/tree /sandbox/tree/text; echo "inside=$?"
test -e /sandbox/tree/text && echo created
echo "--- json"
cat /sandbox/report.json
`)
	got, report, _ := strings.Cut(string(out), "--- json\n")
	var r totext.TreeReport
	if err := json.Unmarshal([]byte(report), &r); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, want := range []string{
		"expand=0\ntotext=6\n",
		"tree\tpartial\t",
		"\tfolded\t-\n",
		"container\t001\temail\t0\tunpacked\tUNPACKED\t-\t-\n",
		"skipped\t001\t0\t0\tunpacked\t",
		"/docs/locked.pdf\tencrypted\tpdf\t",
		"\t1-report.eml.unpacked/body.txt\tok\ttext\t",
		"\tEXPAND-OUTPUT\n",
		"\t2-links.zip\tunsupported\t",
		"\tzip\t0\trejected\tREJECTED\t-\t",
		"\tmanifest.json\tskipped\t",
		"Please see the attached files",
		"Quarterly report page one",
		"_notes ü (1).txt.text.txt\n",
		"inside=1\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "\x1b") || strings.Contains(got, "created\n") {
		t.Errorf("output has an escape or an OUTDIR inside SRC:\n%q", got)
	}
	if r.Code != 6 || r.Expand != totext.ExpandFolded || len(r.Entries) == 0 {
		t.Fatalf("report = %+v", r)
	}
	_, list, _ := strings.Cut(got, "--- files\n")
	list, _, _ = strings.Cut(list, "--- body\n")
	written := map[string]bool{}
	for _, name := range strings.Split(strings.TrimSuffix(list, "\n"), "\n") {
		written[name] = true
	}
	outputs := 0
	for _, e := range r.Entries {
		for _, f := range e.Files {
			outputs++
			if !written[f.Path] || !strings.HasSuffix(f.Path, ".txt") || strings.ContainsAny(f.Path, "/\x1b") {
				t.Errorf("output %q of %s is not in OUTDIR as a safe name: %q", f.Path, e.Path, list)
			}
		}
		if e.Path == expand.ManifestFile && e.Status != totext.StatusSkipped {
			t.Errorf("manifest.json = %+v", e)
		}
	}
	if len(written) != outputs+1 {
		t.Errorf("OUTDIR has %d files for %d outputs: %q", len(written), outputs, list)
	}
}
