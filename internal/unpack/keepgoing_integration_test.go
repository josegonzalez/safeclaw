package unpack

import (
	"archive/tar"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

// TestIntegrationKeepGoing runs the real 7z on a generated zip holding a
// good PDF beside a nested zip with a symlink, a nested encrypted 7z, a
// nested gzip bomb, and a nested tar.gz bomb, with --nested keep-going.
func TestIntegrationKeepGoing(t *testing.T) {
	z := sevenZip(t)
	dir := t.TempDir()
	secret := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(secret, []byte("s3cret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	enc := filepath.Join(dir, "enc.7z")
	// The test's own password, for an archive it made, is fine in argv.
	if out, err := exec.Command(z.Path, "a", "-bd", "-ppw", "-mhe=on", enc, secret).CombinedOutput(); err != nil {
		t.Fatalf("7z a: %v\n%s", err, out)
	}
	encData, err := os.ReadFile(enc)
	if err != nil {
		t.Fatal(err)
	}
	pdf := "%PDF-1.7\n%\xe2\xe3\xcf\xd3\n"
	links := makeZip(t, zipEntry{name: "fine.txt", body: "fine"}, zipEntry{name: "l", body: "/etc/passwd", mode: fs.ModeSymlink | 0o777})
	inner := gz(t, makeTar(t, tarEntry{name: "deep.txt", body: "deep\n"}))
	outer := makeZip(t,
		zipEntry{name: "good.pdf", body: pdf},
		zipEntry{name: "links.zip", body: string(links)},
		zipEntry{name: "enc.7z", body: string(encData)},
		// The gzip listing records the size, so this is refused up front.
		zipEntry{name: "zeros.gz", body: string(gz(t, make([]byte, 4<<20)))},
		// A tar inside a gzip is only measured once extracted.
		zipEntry{name: "zeros.tgz", body: string(gz(t, makeTar(t, tarEntry{name: "zeros", body: string(make([]byte, 3<<20))})))},
		zipEntry{name: "inner.tgz", body: string(inner)},
	)

	dest, res, err := extractReal(t, "outer.zip", outer, Options{MaxSize: 2 << 20, Depth: 2, KeepGoing: true})
	if err != nil {
		t.Fatal(err)
	}
	// What failed is left packed, flagged, and nothing it extracted is
	// left behind.
	want := []string{
		"enc.7z NEEDS-PASSWORD",
		"good.pdf ",
		"inner.tgz UNPACKED",
		"inner.tgz.unpacked ",
		"inner.tgz.unpacked/inner.tar UNPACKED",
		"inner.tgz.unpacked/inner.tar.unpacked ",
		"inner.tgz.unpacked/inner.tar.unpacked/deep.txt ",
		"links.zip REJECTED",
		"zeros.gz TOO-LARGE",
		"zeros.tgz TOO-LARGE",
	}
	if got := paths(res.Entries); !slices.Equal(got, want) {
		t.Errorf("entries =\n%q\nwant\n%q", got, want)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "good.pdf")); err != nil || string(b) != pdf {
		t.Errorf("good.pdf = %q, %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(dest, "links.zip")); err != nil {
		t.Errorf("links.zip wasn't kept packed: %v", err)
	}
	var rejected *Error
	for _, e := range res.Failed {
		if e.Archive == "links.zip" {
			rejected = e
		}
	}
	if rejected == nil || rejected.Kind != Rejected || len(rejected.Bad) != 1 || rejected.Bad[0].Path != "links.zip.unpacked/l" {
		t.Errorf("links.zip failure = %+v", rejected)
	}
	if n, err := treeSize(dest); err != nil || n > 2<<20 {
		t.Errorf("tree size = %d, %v", n, err)
	}
	noEscape(t, dest, "outer.zip")

	// Without keep-going the same archive fails as a whole.
	dest, _, err = extractReal(t, "outer.zip", outer, Options{MaxSize: 2 << 20, Depth: 2})
	if e := wantKind(t, err, NeedsPassword); e.Archive != "enc.7z" {
		t.Errorf("fail mode archive = %q", e.Archive)
	}
	wantEmpty(t, dest)

	// The outer archive's own problems still fail the run.
	evil := makeTar(t, tarEntry{name: "ok.txt", body: "ok\n"}, tarEntry{name: "sym", typ: tar.TypeSymlink, link: "/etc/passwd"})
	dest, _, err = extractReal(t, "evil.tar", evil, Options{KeepGoing: true})
	wantKind(t, err, Rejected)
	wantEmpty(t, dest)
	noEscape(t, dest, "evil.tar")
}
