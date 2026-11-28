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
safeclaw-expand /in/report.eml /sandbox/out >/dev/null; echo "rerun=$?"
test -e /sandbox/out/3-report.eml && echo copied-again
mkdir /sandbox/full && touch /sandbox/full/x
safeclaw-expand --json /in/report.eml /sandbox/full; echo "notempty=$?"
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
		"rerun=0\n",
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
	for _, bad := range []string{"leftover", "body-opened", "copied-again"} {
		if strings.Contains(got, bad) {
			t.Errorf("output has %q:\n%s", bad, got)
		}
	}
}

// TestIntegrationSandboxExpandResume runs safeclaw-expand in a sandbox of
// the sandbox variant over two exec calls: the first leaves a password zip
// it generates packed, and plans, and the second opens it with the
// password. A manifest changed to name a path outside DEST is then
// refused.
func TestIntegrationSandboxExpandResume(t *testing.T) {
	d := docker.New()
	ctx := context.Background()
	if id, err := d.ImageID(ctx, variant.Image(variant.Sandbox)); err != nil || id == "" {
		t.Skip("sandbox variant not built; run `safeclaw build --variant sandbox` first")
	}
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	h := &zip.FileHeader{Name: "link"}
	h.SetMode(fs.ModeSymlink | 0o777)
	if fw, err := w.CreateHeader(h); err != nil {
		t.Fatal(err)
	} else if _, err := fw.Write([]byte("/etc/passwd")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	in := t.TempDir()
	if err := os.WriteFile(filepath.Join(in, "links.zip"), b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}

	m := &Manager{Docker: d}
	name := "itest-expand-resume"
	container := config.ContainerName(name)
	_ = d.Remove(ctx, container, true)
	t.Cleanup(func() { _ = d.Remove(context.Background(), container, true) })
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: name, Volumes: []string{in + ":/in"}}); err != nil {
		t.Fatal(err)
	}
	run := func(script string) string {
		t.Helper()
		out, err := d.Exec(ctx, container, copyExec, SandboxCommand([]string{"sh", "-c", script})...)
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return string(out)
	}
	// The test's own password, for an archive it made, is fine in argv.
	first := run(`
printf 's3cret\n' > secret.txt && 7z a -bd -tzip -ppw enc.zip secret.txt >/dev/null || exit
safeclaw-expand /sandbox/enc.zip /in/links.zip /sandbox/out; echo "first=$?"
echo ---
safeclaw-expand --plan /sandbox/out; echo "plan=$?"
`)
	second := run(`
SAFECLAW_UNPACK_PASSWORD=pw safeclaw-expand /sandbox/enc.zip /sandbox/out; echo "second=$?"
cat /sandbox/out/1-enc.zip.unpacked/secret.txt
grep -c '"path": "1-enc.zip"' /sandbox/out/manifest.json
sed -i 's/"path": "2-links.zip"/"path": "..\/x"/' /sandbox/out/manifest.json
cp /sandbox/out/manifest.json /sandbox/before.json
SAFECLAW_UNPACK_PASSWORD=pw safeclaw-expand /sandbox/out; echo "tampered=$?"
cmp -s /sandbox/out/manifest.json /sandbox/before.json && echo unchanged
`)
	for _, c := range []struct{ out, want string }{
		{first, "zip\t1-enc.zip\tNEEDS-PASSWORD\t-\nzip\t2-links.zip\tREJECTED\t-\nentry\tsymlink\tlink\tLINK\nfirst=0\n---\n"},
		{first, "---\nzip\t1-enc.zip\tNEEDS-PASSWORD\t-\nentry\tfile\t7\tsecret.txt\tENCRYPTED\nzip\t2-links.zip\tREJECTED\t-\nplan=0\n"},
		{second, "zip\t1-enc.zip\tUNPACKED\t1-enc.zip.unpacked\nzip\t2-links.zip\tREJECTED\t-\nentry\tsymlink\tlink\tLINK\nsecond=0\ns3cret\n2\n"},
		{second, "tampered=1\nunchanged\n"},
	} {
		if !strings.Contains(c.out, c.want) {
			t.Errorf("output lacks %q:\n%s", c.want, c.out)
		}
	}
}

// TestIntegrationSandboxExpandDir runs `safeclaw-expand /sandbox/in DEST`
// in a sandbox of the sandbox variant, without a shell, after cp-in: on an
// empty /sandbox/in, after copying a zip and a text file in, and after
// copying one more in, each time the same command line. A link and a
// directory in /sandbox/in are left out, and noted on stderr.
func TestIntegrationSandboxExpandDir(t *testing.T) {
	d := docker.New()
	ctx := context.Background()
	if id, err := d.ImageID(ctx, variant.Image(variant.Sandbox)); err != nil || id == "" {
		t.Skip("sandbox variant not built; run `safeclaw build --variant sandbox` first")
	}
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	if fw, err := w.Create("inside.txt"); err != nil {
		t.Fatal(err)
	} else if _, err := fw.Write([]byte("inside\n")); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	host := t.TempDir()
	files := map[string]string{"logs.zip": b.String(), "notes.txt": "notes\n", "later.txt": "later\n"}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(host, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	m := &Manager{Docker: d}
	name := "itest-expand-dir"
	container := config.ContainerName(name)
	_ = d.Remove(ctx, container, true)
	t.Cleanup(func() { _ = d.Remove(context.Background(), container, true) })
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: name}); err != nil {
		t.Fatal(err)
	}
	exec := func(cmd ...string) string {
		t.Helper()
		out, err := d.Exec(ctx, container, copyExec, SandboxCommand(cmd)...)
		if err != nil {
			t.Fatalf("%v: %v\n%s", cmd, err, out)
		}
		return string(out)
	}
	expand := []string{"safeclaw-expand", "/sandbox/in", "/sandbox/tree"}

	// An empty /sandbox/in is no inputs, and the run still writes the
	// manifest.
	exec("mkdir", "-p", "/sandbox/in")
	if out := exec(expand...); out != "" {
		t.Errorf("empty run = %q", out)
	}
	if out := exec("grep", "-c", `"inputs": \[\]`, "/sandbox/tree/manifest.json"); out != "1\n" {
		t.Errorf("empty manifest: %q", out)
	}

	if _, err := m.CopyIn(ctx, name, []string{filepath.Join(host, "logs.zip"), filepath.Join(host, "notes.txt")}, ""); err != nil {
		t.Fatal(err)
	}
	exec("ln", "-s", "/etc/passwd", "/sandbox/in/0-link")
	exec("mkdir", "/sandbox/in/0-sub")
	if out := exec(expand...); out != "zip\t1-1-logs.zip\tUNPACKED\t1-1-logs.zip.unpacked\n" {
		t.Errorf("first run = %q", out)
	}
	if out := exec("cat", "/sandbox/tree/1-1-logs.zip.unpacked/inside.txt", "/sandbox/tree/2-2-notes.txt"); out != "inside\nnotes\n" {
		t.Errorf("copies = %q", out)
	}

	// The same command line copies in only what is new, and notes what it
	// leaves out.
	if _, err := m.CopyIn(ctx, name, []string{filepath.Join(host, "later.txt")}, ""); err != nil {
		t.Fatal(err)
	}
	out := exec("sh", "-c", `safeclaw-expand /sandbox/in /sandbox/tree 2>&1; echo "second=$?"; ls /sandbox/tree`)
	for _, want := range []string{
		"zip\t1-1-logs.zip\tUNPACKED\t1-1-logs.zip.unpacked\n",
		"safeclaw-expand: ignoring /sandbox/in/0-link: a symbolic link\n",
		"safeclaw-expand: ignoring /sandbox/in/0-sub: a directory\n",
		"second=0\n1-1-logs.zip\n1-1-logs.zip.unpacked\n2-2-notes.txt\n3-3-later.txt\nmanifest.json\n",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("second run lacks %q:\n%s", want, out)
		}
	}
}

// TestIntegrationSandboxExpandHold runs safeclaw-expand --hold
// mail-archives in a sandbox of the sandbox variant over two exec calls:
// the first holds a zip attached to an email and one attached to a
// forwarded message, and plans, and the second releases the first zip,
// whose own zip is opened as usual, while the other stays held.
func TestIntegrationSandboxExpandHold(t *testing.T) {
	d := docker.New()
	ctx := context.Background()
	if id, err := d.ImageID(ctx, variant.Image(variant.Sandbox)); err != nil || id == "" {
		t.Skip("sandbox variant not built; run `safeclaw build --variant sandbox` first")
	}
	makeZip := func(name, data string) string {
		var b bytes.Buffer
		w := zip.NewWriter(&b)
		if fw, err := w.Create(name); err != nil {
			t.Fatal(err)
		} else if _, err := fw.Write([]byte(data)); err != nil {
			t.Fatal(err)
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
	forwarded := "From: Bob <bob@example.com>\r\nSubject: fwd\r\nContent-Type: multipart/mixed; boundary=f\r\n\r\n" +
		"--f\r\nContent-Type: text/plain\r\n\r\nsee below\r\n" +
		"--f\r\nContent-Type: message/rfc822\r\n\r\n" + email("inner", "fwd.zip", makeZip("f.txt", "f\n")) + "\r\n--f--\r\n"
	in := t.TempDir()
	for name, data := range map[string]string{
		"report.eml": email("report", "files.zip", makeZip("inner.zip", makeZip("deep.txt", "deep\n"))),
		"fwd.eml":    forwarded,
	} {
		if err := os.WriteFile(filepath.Join(in, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	m := &Manager{Docker: d}
	name := "itest-expand-hold"
	container := config.ContainerName(name)
	_ = d.Remove(ctx, container, true)
	t.Cleanup(func() { _ = d.Remove(context.Background(), container, true) })
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: name, Volumes: []string{in + ":/in"}}); err != nil {
		t.Fatal(err)
	}
	run := func(script string) string {
		t.Helper()
		out, err := d.Exec(ctx, container, copyExec, SandboxCommand([]string{"sh", "-c", script})...)
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return string(out)
	}
	first := run(`
safeclaw-expand --hold mail-archives /in/report.eml /in/fwd.eml /sandbox/out; echo "first=$?"
test -e /sandbox/out/1-report.eml.unpacked/1-files.zip.unpacked && echo opened
echo ---
safeclaw-expand --plan --hold mail-archives /sandbox/out; echo "plan=$?"
safeclaw-expand /sandbox/out >/dev/null 2>/dev/null; echo "nohold=$?"
`)
	second := run(`
safeclaw-expand --hold mail-archives --release 1-report.eml.unpacked/1-files.zip /in/report.eml /in/fwd.eml /sandbox/out; echo "second=$?"
cat /sandbox/out/1-report.eml.unpacked/1-files.zip.unpacked/inner.zip.unpacked/deep.txt
grep -c '"outcome": "held"' /sandbox/out/manifest.json
`)
	for _, c := range []struct{ out, want string }{
		{first, "email\t1-report.eml\tUNPACKED\t1-report.eml.unpacked\nzip\t1-report.eml.unpacked/1-files.zip\tHELD\t-\nemail\t2-fwd.eml\tUNPACKED\t2-fwd.eml.unpacked\nzip\t2-fwd.eml.unpacked/1-fwd.zip\tHELD\t-\nfirst=0\n---\n"},
		{first, "---\nzip\t1-report.eml.unpacked/1-files.zip\tHELD\t-\nentry\tfile\t"},
		{first, "\tinner.zip\t-\nzip\t2-fwd.eml.unpacked/1-fwd.zip\tHELD\t-\nentry\tfile\t2\tf.txt\t-\nplan=0\nnohold=1\n"},
		{second, "zip\t1-report.eml.unpacked/1-files.zip\tUNPACKED\t1-report.eml.unpacked/1-files.zip.unpacked\nemail\t2-fwd.eml\tUNPACKED\t2-fwd.eml.unpacked\nzip\t2-fwd.eml.unpacked/1-fwd.zip\tHELD\t-\nzip\t1-report.eml.unpacked/1-files.zip.unpacked/inner.zip\tUNPACKED\t"},
		{second, "second=0\ndeep\n1\n"},
	} {
		if !strings.Contains(c.out, c.want) {
			t.Errorf("output lacks %q:\n%s", c.want, c.out)
		}
	}
	if strings.Contains(first, "opened") {
		t.Errorf("held zip opened:\n%s", first)
	}
}
