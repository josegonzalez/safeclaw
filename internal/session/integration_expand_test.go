//go:build integration

package session

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/variant"
)

// TestIntegrationSandboxExpand runs safeclaw-expand in the sandbox variant
// on generated inputs: an email carrying a zip that holds a forwarded .eml
// carrying another zip, and a zip with a symlink.
func TestIntegrationSandboxExpand(t *testing.T) {
	d := docker.New()
	ctx := context.Background()
	if id, err := d.ImageID(ctx, variant.Image(variant.Sandbox)); err != nil || id == "" {
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
	email := func(subject, name, data string) string {
		return "From: Eve <eve@example.com>\r\nSubject: " + subject + "\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" +
			"--b\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n" +
			"--b\r\nContent-Type: application/zip\r\nContent-Disposition: attachment; filename=\"" + name + "\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" + base64.StdEncoding.EncodeToString([]byte(data)) + "\r\n" +
			"--b--\r\n"
	}
	inner := makeZip("deep.txt", "deep\n")
	files := makeZip("fwd.eml", email("inner", "inner.zip", inner))
	in := t.TempDir()
	for name, data := range map[string]string{
		"report.eml": email("report", "files.zip", files),
		"links.zip":  makeZip("fine.txt", "fine", "link", "/etc/passwd"),
	} {
		if err := os.WriteFile(filepath.Join(in, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	m := &Manager{Docker: d}
	argv, name, err := m.PrepareEphemeral(ctx, SandboxOptions{Volumes: []string{in + ":/in"}}, ExecOptions{}, []string{"sh", "-c", `
safeclaw-expand /in/report.eml /in/links.zip /sandbox/out; echo "expand=$?"
cat /sandbox/out/1-report.eml.unpacked/1-files.zip.unpacked/fwd.eml.unpacked/1-inner.zip.unpacked/deep.txt
test -e /sandbox/out/2-links.zip.unpacked && echo leftover
test -e /sandbox/out/1-report.eml.unpacked/body.txt.unpacked && echo body-opened
grep -c '"path"' /sandbox/out/manifest.json
safeclaw-expand --json /in/report.eml /sandbox/out; echo "notempty=$?"
safeclaw-expand --json --no-mail /in/report.eml /sandbox/nomail; echo "nomail=$?"
readlink /usr/local/bin/safeclaw-expand
`})
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
	got := string(out)
	for _, want := range []string{
		"email\t1-report.eml\tUNPACKED\t1-report.eml.unpacked\n",
		"zip\t1-report.eml.unpacked/1-files.zip\tUNPACKED\t1-report.eml.unpacked/1-files.zip.unpacked\n",
		"email\t1-report.eml.unpacked/1-files.zip.unpacked/fwd.eml\tUNPACKED\t1-report.eml.unpacked/1-files.zip.unpacked/fwd.eml.unpacked\n",
		"zip\t1-report.eml.unpacked/1-files.zip.unpacked/fwd.eml.unpacked/1-inner.zip\tUNPACKED\t",
		"zip\t2-links.zip\tREJECTED\t-\nentry\tsymlink\tlink\tLINK\n",
		"expand=0\ndeep\n",
		`"status":"failed","code":1`,
		"notempty=1\n",
		`"mail":false`,
		`"containers":[]`,
		"nomail=0\n",
		"safeclaw\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
	for _, bad := range []string{"leftover", "body-opened"} {
		if strings.Contains(got, bad) {
			t.Errorf("output has %q:\n%s", bad, got)
		}
	}
}
