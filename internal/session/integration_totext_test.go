//go:build integration

package session

import (
	"bytes"
	"context"
	"encoding/json"
	"image/png"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/totext"
	"github.com/josegonzalez/safeclaw/internal/totext/totexttest"
	"github.com/josegonzalez/safeclaw/internal/variant"
)

// runEphemeral runs script in a one-off sandbox on the sandbox variant
// with in mounted at /in, and returns its stdout.
func runEphemeral(t *testing.T, d *docker.Client, in, script string) []byte {
	t.Helper()
	ctx := context.Background()
	m := &Manager{Docker: d}
	argv, name, err := m.PrepareEphemeral(ctx, SandboxOptions{Volumes: []string{in + ":/in"}}, ExecOptions{}, []string{"sh", "-c", script})
	if err != nil {
		t.Fatal(err)
	}
	container := config.ContainerName(name)
	t.Cleanup(func() { _ = d.Remove(ctx, container, true) })
	out, err := d.R.Output(ctx, nil, argv[1:]...)
	waitGone(t, d, container)
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return out
}

// TestIntegrationSandboxTotext runs safeclaw-totext in the sandbox
// variant on generated documents: a text PDF, a scanned PDF and image made
// by rendering a text PDF with the sandbox's own pdftoppm, an encrypted
// PDF, a text file with escape sequences, and a file of no supported type.
func TestIntegrationSandboxTotext(t *testing.T) {
	d := docker.New()
	if id, err := d.ImageID(context.Background(), variant.Image(variant.Sandbox)); err != nil || id == "" {
		t.Skip("sandbox variant not built; run `safeclaw build --variant sandbox` first")
	}
	in := t.TempDir()
	enc, err := totexttest.EncryptedPDF("secret", "hidden text")
	if err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{
		"text.pdf":    totexttest.TextPDF("Hello from page one", "", "Third page here"),
		"scansrc.pdf": totexttest.TextPDF("SCANNED INVOICE NUMBER 4217"),
		"enc.pdf":     enc,
		"notes.pdf":   []byte("plain \x1b[31mred\x1b[0m notes\r\n\u202eevil\n"),
		"archive.pdf": []byte("PK\x03\x04\x14\x00\x00\x00\x08\x00"),
	} {
		if err := os.WriteFile(filepath.Join(in, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	// Render the scan in the sandbox, then wrap it in a PDF and a PNG with
	// no text layer.
	pgm := runEphemeral(t, d, in, `pdftoppm -r 150 -gray -singlefile -- /in/scansrc.pdf /sandbox/page && cat /sandbox/page.pgm`)
	img, err := totexttest.ParsePGM(pgm)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := png.Encode(&b, img); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(in, "scan.pdf"), totexttest.ImagePDF(img, 150), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(in, "photo.txt"), b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	out := runEphemeral(t, d, in, `
for f in text scan enc notes archive; do
  safeclaw-totext --json /in/$f.pdf /sandbox/$f; echo "$f=$?"
done
safeclaw-totext --json /in/photo.txt /sandbox/photo; echo "photo=$?"
safeclaw-totext --json --max-pages 2 /in/text.pdf /sandbox/limited; echo "limited=$?"
safeclaw-totext --json --timeout 1ns /in/text.pdf /sandbox/timeout; echo "timeout=$?"
safeclaw-totext /in/text.pdf /sandbox/text; echo "nonempty=$?"
echo "---text"; cat /sandbox/text/p001.txt
echo "---scan"; cat /sandbox/scan/p001.txt
echo "---photo"; cat /sandbox/photo/ocr.txt
echo "---notes"; od -c /sandbox/notes/text.txt
echo "---left"; find /sandbox/enc /sandbox/archive /sandbox/timeout -mindepth 1 | wc -l
ls /sandbox/limited
readlink /usr/local/bin/safeclaw-totext
`)
	got := string(out)
	reports := map[string]totext.Report{}
	for _, line := range strings.Split(got, "\n") {
		if !strings.HasPrefix(line, "{") {
			continue
		}
		var r totext.Report
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("%v: %s", err, line)
		}
		key := r.Type
		switch {
		case r.Type == totext.TypePDF && r.Status == "partial":
			key = "limited"
		case r.Type == totext.TypePDF && r.Status == "timed-out":
			key = "timeout"
		case r.Type == totext.TypePDF && r.Encrypted:
			key = "enc"
		case r.Type == totext.TypePDF && r.Pages == 1:
			key = "scan"
		}
		reports[key] = r
	}
	for _, want := range []string{"text=0\n", "scan=0\n", "enc=3\n", "notes=0\n", "archive=5\n", "photo=0\n", "limited=6\n", "timeout=7\n", "nonempty=1\n", "---left\n0\n", "p001.txt\np002.txt\nsafeclaw\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
	if r := reports["pdf"]; r.Schema != 1 || r.Pages != 3 || len(r.Files) != 3 || !slices.Equal(r.OCRPages, []int{2}) {
		t.Errorf("text.pdf report = %+v", r)
	}
	if r := reports["scan"]; !slices.Equal(r.OCRPages, []int{1}) || r.Files[0].Chars == 0 {
		t.Errorf("scan.pdf report = %+v", r)
	}
	if r := reports["png"]; len(r.Files) != 1 || r.Files[0].Path != totext.ImageOutput || !r.Files[0].OCR {
		t.Errorf("photo.txt report = %+v", r)
	}
	if r := reports["limited"]; len(r.Skipped) != 1 || r.Skipped[0].Reason != totext.ReasonPageLimit || r.Skipped[0].FirstPage != 3 {
		t.Errorf("--max-pages report = %+v", r)
	}
	if r := reports["timeout"]; len(r.Skipped) != 1 || r.Skipped[0].Reason != totext.ReasonTimedOut || r.Skipped[0].Tool != "pdfinfo" {
		t.Errorf("--timeout report = %+v", r)
	}
	if r := reports["unknown"]; r.Code != 5 || r.Skipped[0].Reason != totext.ReasonUnsupported {
		t.Errorf("archive.pdf report = %+v", r)
	}
	section := func(name string) string {
		s := got[strings.Index(got, "---"+name+"\n")+len(name)+4:]
		return s[:strings.Index(s, "\n---")]
	}
	if s := section("text"); !strings.Contains(s, "Hello from page one") {
		t.Errorf("p001.txt = %q", s)
	}
	for _, name := range []string{"scan", "photo"} {
		if s := section(name); !strings.Contains(s, "INVOICE") || !strings.Contains(s, "4217") {
			t.Errorf("%s OCR = %q", name, s)
		}
	}
	if s := section("notes"); strings.Contains(s, "033") || strings.Contains(s, `\r`) || strings.Contains(s, "342 200 256") || !strings.Contains(s, "[   3   1   m   r   e   d") {
		t.Errorf("notes kept control characters:\n%s", s)
	}
}
