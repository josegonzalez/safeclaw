//go:build integration

package session

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/variant"
)

// TestIntegrationSandboxMail runs safeclaw-mail in the sandbox variant on
// generated messages: one with a hostile attachment name, an HTML
// alternative with a script, and a forwarded message, and one that isn't a
// message.
func TestIntegrationSandboxMail(t *testing.T) {
	d := docker.New()
	ctx := context.Background()
	if id, err := d.ImageID(ctx, variant.Image(variant.Sandbox)); err != nil || id == "" {
		t.Skip("sandbox variant not built; run `safeclaw build --variant sandbox` first")
	}
	in := t.TempDir()
	b64 := base64.StdEncoding.EncodeToString
	msg := "From: Eve <eve@example.com>\r\nSubject: =?utf-8?q?Invoice_=E2=9C=93?=\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: multipart/alternative; boundary=a\r\n\r\n" +
		"--a\r\nContent-Type: text/plain\r\n\r\nPlease pay.\r\n" +
		"--a\r\nContent-Type: text/html\r\n\r\n<p>Please pay<script>steal()</script></p>\r\n" +
		"--a--\r\n" +
		"--b\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"../../evil\x1b.pdf\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" + b64([]byte("%PDF-1.4")) + "\r\n" +
		"--b\r\nContent-Type: message/rfc822\r\n\r\nFrom: Mallory <m@example.com>\r\nSubject: original\r\n\r\nforwarded text\r\n" +
		"--b--\r\n"
	for name, data := range map[string]string{"invoice.eml": msg, "notes.txt": "just text\n"} {
		if err := os.WriteFile(filepath.Join(in, name), []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	m := &Manager{Docker: d}
	argv, name, err := m.PrepareEphemeral(ctx, SandboxOptions{Volumes: []string{in + ":/in"}}, ExecOptions{}, []string{"sh", "-c", `
safeclaw-mail list /in/invoice.eml; echo "list=$?"
safeclaw-mail extract /in/invoice.eml /sandbox/out; echo "extract=$?"
ls -A /sandbox/out
cat /sandbox/out/body.txt
cat /sandbox/out/1-_._evil.pdf; echo
test -e /sandbox/evil.pdf && echo escaped
safeclaw-mail extract --json /in/notes.txt /sandbox/notes; echo "notes=$?"
echo "left=$(ls -A /sandbox/notes | wc -l)"
readlink /usr/local/bin/safeclaw-mail
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
		"From: Eve <eve@example.com>\nSubject: Invoice ✓\n\n",
		"1.1.1\ttext/plain\t11\t-\tBODY\n",
		"1.1.2\ttext/html\t",
		"\tSKIPPED\n",
		"1.2\tapplication/pdf\t8\t../../evil\\x1b.pdf\tATTACHMENT,UNSAFE-NAME\n",
		"1.3\tmessage/rfc822\t",
		"\tNESTED-MESSAGE\n",
		"list=0\n",
		"extract=0\n1-_._evil.pdf\nbody.txt\n",
		"Please pay.\n\n---------- Forwarded message (part 1.3) ----------\nFrom: Mallory <m@example.com>\nSubject: original\n\nforwarded text\n",
		"%PDF-1.4\n",
		`"status":"not a message","code":5`,
		"notes=5\nleft=0\n",
		"safeclaw\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
	for _, bad := range []string{"escaped", "steal", "\x1b"} {
		if strings.Contains(got, bad) {
			t.Errorf("output has %q:\n%s", bad, got)
		}
	}
}
