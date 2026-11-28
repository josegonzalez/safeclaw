//go:build integration

package cli

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/secrets"
	"github.com/josegonzalez/safeclaw/internal/session"
	"github.com/josegonzalez/safeclaw/internal/variant"
)

// zipCrypto returns a zip holding name, stored and encrypted with
// password using traditional PKWARE encryption, which 7z reads.
func zipCrypto(t *testing.T, name, data, password string) []byte {
	t.Helper()
	keys := [3]uint32{0x12345678, 0x23456789, 0x34567890}
	update := func(c byte) {
		keys[0] = crc32.IEEETable[byte(keys[0])^c] ^ keys[0]>>8
		keys[1] = (keys[1]+keys[0]&0xff)*134775813 + 1
		keys[2] = crc32.IEEETable[byte(keys[2])^byte(keys[1]>>24)] ^ keys[2]>>8
	}
	for _, c := range []byte(password) {
		update(c)
	}
	crc := crc32.ChecksumIEEE([]byte(data))
	plain := append([]byte("0123456789a"), byte(crc>>24))
	plain = append(plain, data...)
	enc := make([]byte, len(plain))
	for i, c := range plain {
		k := keys[2] | 2
		enc[i] = c ^ byte(k*(k^1)>>8)
		update(c)
	}
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	fw, err := w.CreateRaw(&zip.FileHeader{Name: name, Method: zip.Store, Flags: 0x1, CRC32: crc,
		CompressedSize64: uint64(len(enc)), UncompressedSize64: uint64(len(data))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(enc); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// TestIntegrationSandboxOpen runs `sandbox open` on a sandbox of the
// sandbox variant: it plans with nothing copied in, then copies in an
// email carrying a password zip and plans it, opens it, which leaves the
// zip packed, retries with --password-env unset and then set, converts
// the tree with --text, copies the text out, and plans a file copied in
// after that.
func TestIntegrationSandboxOpen(t *testing.T) {
	d := docker.New()
	ctx := context.Background()
	if id, err := d.ImageID(ctx, variant.Image(variant.Sandbox)); err != nil || id == "" {
		t.Skip("sandbox variant not built; run `safeclaw build --variant sandbox` first")
	}
	dir := t.TempDir()
	m := &session.Manager{Docker: d, Secrets: secrets.FileStore{Dir: filepath.Join(dir, ".secrets")}, CopyDir: filepath.Join(dir, "copy")}
	orig := newManager
	t.Cleanup(func() { newManager = orig })
	newManager = func() *session.Manager { return m }

	name := "itest-open"
	container := config.ContainerName(name)
	_ = d.Remove(ctx, container, true)
	t.Cleanup(func() { _ = d.Remove(context.Background(), container, true) })
	if _, err := m.EnsureSandbox(ctx, session.SandboxOptions{Name: name}); err != nil {
		t.Fatal(err)
	}

	enc := zipCrypto(t, "secret.txt", "s3cret \x1b[2J\n", "pw")
	email := "From: Eve <eve@example.com>\r\nSubject: report\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: text/plain\r\n\r\nthe password is pw\r\n" +
		"--b\r\nContent-Type: application/zip\r\nContent-Disposition: attachment; filename=\"files.zip\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
		base64.StdEncoding.EncodeToString(enc) + "\r\n--b--\r\n"
	host := filepath.Join(dir, "report.eml")
	if err := os.WriteFile(host, []byte(email), 0o644); err != nil {
		t.Fatal(err)
	}
	openErr := func(code int, args ...string) (string, string) {
		t.Helper()
		out, stderr, err := runStderr(append([]string{"sandbox", "open", name}, args...)...)
		if code == 0 && err != nil || code != 0 && !errors.Is(err, exitCodeError{code}) {
			t.Fatalf("open %q: err = %v, want exit %d\n%s%s", args, err, code, out, stderr)
		}
		return out, stderr
	}
	open := func(code int, args ...string) string {
		t.Helper()
		out, _ := openErr(code, args...)
		return out
	}
	sh := func(script string) {
		t.Helper()
		if out, err := d.Exec(ctx, container, docker.ExecOptions{User: config.SandboxUser, Workdir: config.SandboxDir}, "sh", "-c", script); err != nil {
			t.Fatalf("exec %q: %v\n%s", script, err, out)
		}
	}

	// Before anything is copied in there is nothing to plan, and with an
	// empty /sandbox/in nothing to open.
	if out, stderr := openErr(0, "--plan"); out != "" || !strings.Contains(stderr, "Nothing to plan: nothing has been copied into /sandbox/in") {
		t.Errorf("plan before cp-in: out = %q, stderr = %q", out, stderr)
	}
	sh("mkdir /sandbox/in")
	if out, stderr := openErr(0, "--plan"); out != "" || !strings.Contains(stderr, "Nothing to open: no archive or email in /sandbox/in is new") {
		t.Errorf("plan of an empty /sandbox/in: out = %q, stderr = %q", out, stderr)
	}

	if _, err := m.CopyIn(ctx, name, []string{host}, ""); err != nil {
		t.Fatal(err)
	}
	// Before the first open, the plan lists the new input and its parts,
	// and changes nothing.
	if out := open(0, "--plan"); !strings.HasPrefix(out, "email\t1-1-report.eml\tNEW\t-\npart\t") || !strings.Contains(out, "files.zip") {
		t.Errorf("plan before the first open:\n%s", out)
	}
	sh("test ! -e /sandbox/tree")

	packed := "zip\t1-1-report.eml.unpacked/1-files.zip\tNEEDS-PASSWORD\t-\n"
	if out := open(openLeftPacked); !strings.Contains(out, "email\t1-1-report.eml\tUNPACKED\t1-1-report.eml.unpacked\n") || !strings.Contains(out, packed) {
		t.Errorf("first open:\n%s", out)
	}
	if out := open(0, "--plan"); !strings.Contains(out, packed+"entry\tfile\t") {
		t.Errorf("plan:\n%s", out)
	}
	if out := open(openLeftPacked, "--password-env", "OPEN_TEST_PASSWORD"); !strings.Contains(out, packed) {
		t.Errorf("open without the variable:\n%s", out)
	}
	t.Setenv("OPEN_TEST_PASSWORD", "pw")
	if out := open(0, "--password-env", "OPEN_TEST_PASSWORD"); !strings.Contains(out, "zip\t1-1-report.eml.unpacked/1-files.zip\tUNPACKED\t") {
		t.Errorf("open with the password:\n%s", out)
	}
	out := open(0, "--text", "--max-pages", "10")
	if !strings.HasPrefix(out, "email\t1-1-report.eml\tUNPACKED\t") || !strings.Contains(out, "\ntree\tok\t") {
		t.Errorf("open --text:\n%s", out)
	}
	if strings.Contains(out, "\x1b") {
		t.Errorf("output has an escape:\n%q", out)
	}

	res, err := m.CopyOutReport(ctx, name, session.OpenOutDir, filepath.Join(dir, "text"), session.CopyOutOptions{Only: []string{"*.txt"}, NoScan: true, Mkdir: true})
	if err != nil {
		t.Fatal(err)
	}
	var all strings.Builder
	for _, p := range res.Paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		all.Write(b)
	}
	if got := all.String(); !strings.Contains(got, "s3cret [2J\n") || !strings.Contains(got, "the password is pw") || strings.Contains(got, "\x1b") {
		t.Errorf("copied out %d files:\n%q", len(res.Paths), got)
	}

	// A file copied in after the opens is planned as NEW, with what is
	// already opened left out.
	notes := filepath.Join(dir, "notes.eml")
	if err := os.WriteFile(notes, []byte("From: Eve <eve@example.com>\r\nSubject: notes\r\nContent-Type: text/plain\r\n\r\nmore notes\r\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CopyIn(ctx, name, []string{notes}, ""); err != nil {
		t.Fatal(err)
	}
	if out := open(0, "--plan"); !strings.HasPrefix(out, "email\t2-2-notes.eml\tNEW\t-\npart\t") || strings.Contains(out, "report.eml") {
		t.Errorf("plan after a new cp-in:\n%s", out)
	}
}
