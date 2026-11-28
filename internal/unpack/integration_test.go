package unpack

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// These tests run the real 7z on archives they generate. They are skipped
// when there is no 7z on PATH, except under `make test-integration`, which
// sets SAFECLAW_REQUIRE_7Z.

func sevenZip(t *testing.T) SevenZip {
	t.Helper()
	z, err := Find()
	if err != nil {
		if os.Getenv("SAFECLAW_REQUIRE_7Z") != "" {
			t.Fatal(err)
		}
		t.Skip(err)
	}
	return z
}

type tarEntry struct {
	name, body, link string
	typ              byte
}

func makeTar(t *testing.T, entries ...tarEntry) []byte {
	t.Helper()
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Linkname: e.link, Mode: 0o644, Size: int64(len(e.body)), Format: tar.FormatPAX}
		if e.typ == 0 {
			h.Typeflag = tar.TypeReg
		}
		if h.Typeflag != tar.TypeReg {
			h.Size = 0
		}
		if h.Typeflag == tar.TypeDir {
			h.Mode = 0o755
		}
		if err := w.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Size > 0 {
			if _, err := w.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

type zipEntry struct {
	name, body string
	mode       fs.FileMode
}

func makeZip(t *testing.T, entries ...zipEntry) []byte {
	t.Helper()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate}
		if e.mode != 0 {
			h.SetMode(e.mode)
		}
		f, err := w.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.Write([]byte(e.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func gz(t *testing.T, data []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	w := gzip.NewWriter(&b)
	if _, err := w.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

// workdir returns a directory for one archive and its destination. The
// archives are hostile, so the destination is two levels down: a path that
// got out of it would still land in the test's own directory.
func workdir(t *testing.T, name string, data []byte) (archive, dest string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "a", "b")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	archive = filepath.Join(dir, name)
	if err := os.WriteFile(archive, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return archive, filepath.Join(dir, "out")
}

func extractReal(t *testing.T, name string, data []byte, o Options) (string, *Result, error) {
	t.Helper()
	o.Runner = sevenZip(t)
	if o.MaxSize == 0 {
		o.MaxSize = 10 << 20
	}
	archive, dest := workdir(t, name, data)
	res, err := Extract(t.Context(), archive, dest, o)
	return dest, res, err
}

// noEscape checks that nothing landed next to the destination or above it.
func noEscape(t *testing.T, dest, archive string) {
	t.Helper()
	for _, dir := range []string{filepath.Dir(dest), filepath.Dir(filepath.Dir(dest)), filepath.Dir(filepath.Dir(filepath.Dir(dest)))} {
		names, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range names {
			switch n.Name() {
			case "out", "a", "b", archive:
			default:
				t.Errorf("%s escaped into %s", n.Name(), dir)
			}
		}
	}
}

func evilTar(t *testing.T) []byte {
	return makeTar(t,
		tarEntry{name: "ok.txt", body: "ok\n"},
		tarEntry{name: "../up.txt", body: "up\n"},
		tarEntry{name: "/abs.txt", body: "abs\n"},
		tarEntry{name: "sym", typ: tar.TypeSymlink, link: "/etc/passwd"},
		tarEntry{name: "hard", typ: tar.TypeLink, link: "ok.txt"},
		tarEntry{name: "fifo", typ: tar.TypeFifo},
		tarEntry{name: "dir", typ: tar.TypeDir},
		tarEntry{name: "dir/in.txt", body: "in\n"},
	)
}

func TestIntegrationList(t *testing.T) {
	z := sevenZip(t)
	archive, _ := workdir(t, "evil.tar", evilTar(t))
	l, err := List(t.Context(), z, archive, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, e := range l.Entries {
		got[e.Path] = e.Type + " " + strings.Join(e.Flags(), ",")
	}
	want := map[string]string{
		"ok.txt":     "file ",
		"up.txt":     "file UNSAFE-PATH",
		"abs.txt":    "file UNSAFE-PATH",
		"sym":        "symlink LINK",
		"hard":       "hardlink LINK",
		"fifo":       "special SPECIAL",
		"dir":        "dir ",
		"dir/in.txt": "file ",
	}
	for p, w := range want {
		g, ok := got[p]
		if !ok {
			// 7z may show the unsafe paths as stored or as it would
			// extract them; either way they must be flagged.
			for gp, gv := range got {
				if strings.HasSuffix(gp, p) && gp != p {
					g, ok = gv, true
				}
			}
		}
		if !ok || g != w {
			t.Errorf("%s = %q, want %q (listing %v)", p, g, w, got)
		}
	}
}

func TestIntegrationRejects(t *testing.T) {
	dest, _, err := extractReal(t, "evil.tar", evilTar(t), Options{})
	e := wantKind(t, err, Rejected)
	if len(e.Bad) != 5 {
		t.Errorf("bad = %v", paths(e.Bad))
	}
	wantEmpty(t, dest)
	noEscape(t, dest, "evil.tar")

	zipLink := makeZip(t, zipEntry{name: "ok.txt", body: "ok"}, zipEntry{name: "l", body: "/etc/passwd", mode: fs.ModeSymlink | 0o777})
	dest, _, err = extractReal(t, "links.zip", zipLink, Options{})
	wantKind(t, err, Rejected)
	wantEmpty(t, dest)
}

func TestIntegrationDropBad(t *testing.T) {
	dest, res, err := extractReal(t, "evil.tar", evilTar(t), Options{DropBad: true})
	if err != nil {
		t.Fatal(err)
	}
	if got := paths(res.Entries); !slices.Equal(got, []string{"dir ", "dir/in.txt ", "ok.txt "}) {
		t.Errorf("entries = %v", got)
	}
	if len(res.Dropped) != 5 {
		t.Errorf("dropped = %v", paths(res.Dropped))
	}
	if b, err := os.ReadFile(filepath.Join(dest, "ok.txt")); err != nil || string(b) != "ok\n" {
		t.Errorf("ok.txt = %q, %v", b, err)
	}
	noEscape(t, dest, "evil.tar")

	// Names are matched literally, not as wildcards.
	wild := makeZip(t, zipEntry{name: "a*", body: "1"}, zipEntry{name: "ab", body: "2"}, zipEntry{name: "../x", body: "3"})
	_, res, err = extractReal(t, "evil.zip", wild, Options{DropBad: true})
	if err != nil || !slices.Equal(paths(res.Entries), []string{"a* ", "ab "}) {
		t.Errorf("wildcards = %v, %v", paths(res.Entries), err)
	}
}

func TestIntegrationNested(t *testing.T) {
	inner := gz(t, makeTar(t, tarEntry{name: "deep.txt", body: "deep\n"}))
	outer := makeZip(t, zipEntry{name: "inner.tar.gz", body: string(inner)}, zipEntry{name: "readme.txt", body: "hi"}, zipEntry{name: "fake.gz", body: "\x1f\x8bnot really"})
	dest, res, err := extractReal(t, "outer.zip", outer, Options{Depth: 2})
	if err != nil {
		t.Fatal(err)
	}
	got := paths(res.Entries)
	for _, p := range []string{"inner.tar.gz UNPACKED", "inner.tar.gz.unpacked/inner.tar UNPACKED", "inner.tar.gz.unpacked/inner.tar.unpacked/deep.txt ", "readme.txt "} {
		if !slices.Contains(got, p) {
			t.Errorf("no %q in %v", p, got)
		}
	}
	if b, err := os.ReadFile(filepath.Join(dest, "inner.tar.gz.unpacked", "inner.tar.unpacked", "deep.txt")); err != nil || string(b) != "deep\n" {
		t.Errorf("deep.txt = %q, %v", b, err)
	}

	// A nested archive with a link rejects the whole thing.
	inner = gz(t, makeTar(t, tarEntry{name: "l", typ: tar.TypeSymlink, link: "/"}))
	outer = makeZip(t, zipEntry{name: "inner.tgz", body: string(inner)})
	dest, _, err = extractReal(t, "outer.zip", outer, Options{Depth: 2})
	if e := wantKind(t, err, Rejected); !strings.HasPrefix(e.Archive, "inner.tgz.unpacked/") {
		t.Errorf("archive = %q", e.Archive)
	}
	wantEmpty(t, dest)

	// Depth 0 leaves it packed.
	_, res, err = extractReal(t, "outer.zip", outer, Options{})
	if err != nil || !slices.Equal(paths(res.Entries), []string{"inner.tgz DEPTH-LIMIT"}) {
		t.Errorf("depth 0 = %v, %v", paths(res.Entries), err)
	}
}

func TestIntegrationTooLarge(t *testing.T) {
	// The gzip listing records the size, so this is refused up front.
	bomb := gz(t, make([]byte, 4<<20))
	dest, _, err := extractReal(t, "zeros.gz", bomb, Options{MaxSize: 1 << 20})
	wantKind(t, err, TooLarge)
	wantEmpty(t, dest)

	// A tar inside it is only measured once extracted.
	bomb = gz(t, makeTar(t, tarEntry{name: "zeros", body: string(make([]byte, 3<<20))}))
	dest, _, err = extractReal(t, "zeros.tgz", bomb, Options{MaxSize: 4 << 20, Depth: 1})
	wantKind(t, err, TooLarge)
	wantEmpty(t, dest)
}

func TestIntegrationPassword(t *testing.T) {
	z := sevenZip(t)
	dir := t.TempDir()
	plain := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(plain, []byte("s3cret\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"enc.7z"}, {"ench.7z", "-mhe=on"}, {"enc.zip", "-tzip"}} {
		archive := filepath.Join(dir, args[0])
		// The test's own password, for an archive it made, is fine in argv.
		cmd := exec.Command(z.Path, append([]string{"a", "-bd", "-ppw"}, append(args[1:], archive, plain)...)...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("7z a: %v\n%s", err, out)
		}
		t.Run(args[0], func(t *testing.T) {
			o := Options{Runner: z, MaxSize: 1 << 20, Depth: 1}
			_, err := Extract(t.Context(), archive, filepath.Join(t.TempDir(), "none"), o)
			wantKind(t, err, NeedsPassword)
			wrong := "nope"
			o.Password = &wrong
			_, err = Extract(t.Context(), archive, filepath.Join(t.TempDir(), "wrong"), o)
			wantKind(t, err, NeedsPassword)
			right := "pw"
			o.Password = &right
			dest := filepath.Join(t.TempDir(), "right")
			if _, err := Extract(t.Context(), archive, dest, o); err != nil {
				t.Fatal(err)
			}
			if b, err := os.ReadFile(filepath.Join(dest, "secret.txt")); err != nil || string(b) != "s3cret\n" {
				t.Errorf("secret.txt = %q, %v", b, err)
			}
		})
	}
}

func TestIntegrationNotArchive(t *testing.T) {
	z := sevenZip(t)
	archive, dest := workdir(t, "x*?.txt", []byte("just text\n"))
	_, err := List(t.Context(), z, archive, nil)
	wantKind(t, err, Failed)
	_, err = Extract(t.Context(), archive, dest, Options{Runner: z, MaxSize: 1 << 20})
	wantKind(t, err, Failed)

	// A wildcard in the archive's name is taken literally.
	archive, _ = workdir(t, "a*.zip", makeZip(t, zipEntry{name: "in.txt", body: "1"}))
	if err := os.WriteFile(filepath.Join(filepath.Dir(archive), "ab.zip"), makeZip(t, zipEntry{name: "other.txt", body: "2"}), 0o644); err != nil {
		t.Fatal(err)
	}
	l, err := List(t.Context(), z, archive, nil)
	if err != nil || len(l.Entries) != 1 || l.Entries[0].Path != "in.txt" {
		t.Errorf("wildcard name: %+v, %v", l, err)
	}
}
