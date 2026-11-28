//go:build integration

package session

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/variant"
)

// TestIntegrationSandboxUnpack runs safeclaw-unpack in the sandbox variant
// on generated archives: a tar with links and unsafe paths, and a zip
// holding a tar.gz.
func TestIntegrationSandboxUnpack(t *testing.T) {
	d := docker.New()
	ctx := context.Background()
	if id, err := d.ImageID(ctx, variant.Image(variant.Sandbox)); err != nil || id == "" {
		t.Skip("sandbox variant not built; run `safeclaw build --variant sandbox` first")
	}
	in := t.TempDir()

	var evil bytes.Buffer
	tw := tar.NewWriter(&evil)
	for _, h := range []*tar.Header{
		{Name: "ok.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 3},
		{Name: "../up.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 3},
		{Name: "sym", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"},
	} {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			_, _ = tw.Write([]byte("hi\n"))
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var inner bytes.Buffer
	gw := gzip.NewWriter(&inner)
	itw := tar.NewWriter(gw)
	if err := itw.WriteHeader(&tar.Header{Name: "deep.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 5}); err != nil {
		t.Fatal(err)
	}
	_, _ = itw.Write([]byte("deep\n"))
	if err := itw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	var outer bytes.Buffer
	zw := zip.NewWriter(&outer)
	f, err := zw.Create("inner.tar.gz")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write(inner.Bytes())
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	for name, data := range map[string][]byte{"evil.tar": evil.Bytes(), "outer.zip": outer.Bytes()} {
		if err := os.WriteFile(filepath.Join(in, name), data, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	m := &Manager{Docker: d}
	argv, name, err := m.PrepareEphemeral(ctx, SandboxOptions{Volumes: []string{in + ":/in"}}, ExecOptions{}, []string{"sh", "-c", `
safeclaw-unpack list /in/evil.tar; echo "list=$?"
safeclaw-unpack extract /in/evil.tar /sandbox/rejected; echo "rejected=$?"
echo "left=$(ls -A /sandbox/rejected | wc -l)"
test -e /sandbox/up.txt && echo escaped
safeclaw-unpack extract --drop-bad /in/evil.tar /sandbox/dropped; echo "dropped=$?"
safeclaw-unpack extract --json /in/outer.zip /sandbox/nested; echo "nested=$?"
cat /sandbox/nested/inner.tar.gz.unpacked/inner.tar.unpacked/deep.txt
readlink /usr/local/bin/safeclaw-unpack
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
		"file\t3\tok.txt\t-\n",
		"file\t3\t../up.txt\tUNSAFE-PATH\n",
		"symlink\t11\tsym\tLINK\n",
		"list=0\n",
		"rejected=2\n",
		"left=0\n",
		"file\t3\tok.txt\t-\nfile\t3\t../up.txt\tUNSAFE-PATH,DROPPED\nsymlink\t11\tsym\tLINK,DROPPED\ndropped=0\n",
		`"status":"ok"`,
		`"path":"inner.tar.gz.unpacked/inner.tar","flags":["UNPACKED"]`,
		"nested=0\ndeep\n",
		"safeclaw\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%s", want, got)
		}
	}
	if strings.Contains(got, "escaped") {
		t.Errorf("a file got out of the destination:\n%s", got)
	}
}
