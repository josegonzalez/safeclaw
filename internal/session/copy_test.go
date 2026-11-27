package session

import (
	"archive/tar"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
)

// copyFake is a sandbox world whose copy commands answer with listing (for
// ls) and tarOut and tarErr (for tar -c).
type copyFake struct {
	listing string
	tarOut  []byte
	tarErr  error
}

func newCopyManager(t *testing.T, f *copyFake) (*Manager, *dockertest.Runner) {
	t.Helper()
	w := &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-box":  {Running: true, Image: "img", Labels: sandboxLabels, NetworkMode: "none", Offline: true},
		"safeclaw-off":  {Image: "img", Labels: sandboxLabels, NetworkMode: "none", Offline: true},
		"safeclaw-chat": {Running: true, Image: "img"},
	}}
	m, r := newTestManager(t, w)
	r.Handler = func(args []string, stdin string) ([]byte, error) {
		if args[0] == "exec" {
			switch {
			case slices.Contains(args, lsBin):
				return []byte(f.listing), nil
			case slices.Contains(args, tarBin) && slices.Contains(args, "-c"):
				return f.tarOut, f.tarErr
			}
		}
		return w.handle(args, stdin)
	}
	return m, r
}

func writeFile(t *testing.T, p, content string) string {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func hasExec(r *dockertest.Runner) bool {
	return hasCall(r, "exec ")
}

func TestCopyInRefusesBadSources(t *testing.T) {
	dir := t.TempDir()
	file := writeFile(t, filepath.Join(dir, "ok.txt"), "ok")
	link := filepath.Join(dir, "link.txt")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		path string
		want error
	}{
		{link, ErrSymlink},
		{dir, ErrNotRegular},
		{fifo, ErrNotRegular},
		{filepath.Join(dir, "missing"), fs.ErrNotExist},
	}
	for _, tc := range cases {
		m, r := newCopyManager(t, &copyFake{})
		// A good file first: nothing is sent unless every file passes.
		_, err := m.CopyIn(context.Background(), "box", []string{file, tc.path}, "")
		if !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.path, err, tc.want)
		}
		if hasExec(r) {
			t.Errorf("%s: ran %v before every file was checked", tc.path, r.Commands())
		}
	}
}

func TestCopyIn(t *testing.T) {
	dir := t.TempDir()
	a := writeFile(t, filepath.Join(dir, "a", "report.pdf"), "first")
	b := writeFile(t, filepath.Join(dir, "b", "report.pdf"), "second!")
	m, r := newCopyManager(t, &copyFake{listing: "1-old.pdf\n7-report.pdf\nnotes\n12abc-x\n-3\n"})

	paths, err := m.CopyIn(context.Background(), "box", []string{a, b}, "")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"/sandbox/in/8-report.pdf", "/sandbox/in/9-report.pdf"}
	if !reflect.DeepEqual(paths, want) {
		t.Errorf("paths = %v, want %v", paths, want)
	}
	for _, prefix := range []string{
		"exec --user sandbox --workdir /sandbox safeclaw-box /usr/bin/mkdir -p -- /sandbox/in",
		"exec --user sandbox --workdir /sandbox safeclaw-box /usr/bin/ls -1A -- /sandbox/in",
	} {
		if !hasCall(r, prefix) {
			t.Errorf("missing %q in %v", prefix, r.Commands())
		}
	}
	call, ok := r.Find("exec -i --user sandbox --workdir /sandbox safeclaw-box /usr/bin/tar -x -f - -k -C /sandbox/in")
	if !ok {
		t.Fatalf("no tar -x in %v", r.Commands())
	}
	tr := tar.NewReader(strings.NewReader(call.Stdin))
	got := map[string]string{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if hdr.Typeflag != tar.TypeReg || hdr.Mode != 0o644 {
			t.Errorf("%s: type %c mode %o", hdr.Name, hdr.Typeflag, hdr.Mode)
		}
		body, _ := io.ReadAll(tr)
		got[hdr.Name] = string(body)
	}
	if want := map[string]string{"8-report.pdf": "first", "9-report.pdf": "second!"}; !reflect.DeepEqual(got, want) {
		t.Errorf("tar = %v, want %v", got, want)
	}
}

func TestCopyInDest(t *testing.T) {
	file := writeFile(t, filepath.Join(t.TempDir(), "x.txt"), "x")
	for dest, want := range map[string]string{
		"out":             "/sandbox/out/1-x.txt",
		"/sandbox":        "/sandbox/1-x.txt",
		"/sandbox/a/../b": "/sandbox/b/1-x.txt",
	} {
		m, _ := newCopyManager(t, &copyFake{})
		paths, err := m.CopyIn(context.Background(), "box", []string{file}, dest)
		if err != nil || len(paths) != 1 || paths[0] != want {
			t.Errorf("--to %s: paths = %v, err = %v, want %s", dest, paths, err, want)
		}
	}
	for _, dest := range []string{"/tmp", "../etc", "/sandboxes", "/"} {
		m, r := newCopyManager(t, &copyFake{})
		if _, err := m.CopyIn(context.Background(), "box", []string{file}, dest); !errors.Is(err, ErrCopyDest) {
			t.Errorf("--to %s: err = %v, want ErrCopyDest", dest, err)
		}
		if hasExec(r) {
			t.Errorf("--to %s ran %v", dest, r.Commands())
		}
	}
}

func TestCopyInExecError(t *testing.T) {
	file := writeFile(t, filepath.Join(t.TempDir(), "x.txt"), "x")
	m, r := newCopyManager(t, &copyFake{})
	failed := errors.New("tar: 1-x.txt: Cannot open: File exists")
	inner := r.Handler
	r.Handler = func(args []string, stdin string) ([]byte, error) {
		if slices.Contains(args, "-x") {
			return nil, failed
		}
		return inner(args, stdin)
	}
	if _, err := m.CopyIn(context.Background(), "box", []string{file}, ""); !errors.Is(err, failed) {
		t.Errorf("err = %v, want the tar error", err)
	}
}

func TestCopyTarget(t *testing.T) {
	file := writeFile(t, filepath.Join(t.TempDir(), "x.txt"), "x")
	host := t.TempDir()
	for name, want := range map[string]error{
		"chat":    ErrNotSandbox,
		"off":     ErrNotRunning,
		"missing": ErrNotFound,
	} {
		m, r := newCopyManager(t, &copyFake{})
		if _, err := m.CopyIn(context.Background(), name, []string{file}, ""); !errors.Is(err, want) {
			t.Errorf("cp-in %s: err = %v, want %v", name, err, want)
		}
		if _, err := m.CopyOut(context.Background(), name, "/sandbox/out", host, CopyOutOptions{Only: []string{"*"}}); !errors.Is(err, want) {
			t.Errorf("cp-out %s: err = %v, want %v", name, err, want)
		}
		if hasExec(r) {
			t.Errorf("%s ran %v", name, r.Commands())
		}
	}
	m, _ := newCopyManager(t, &copyFake{})
	_, err := m.CopyIn(context.Background(), "off", []string{file}, "")
	if err == nil || !strings.Contains(err.Error(), "safeclaw sandbox run -s off") {
		t.Errorf("stopped sandbox error should say how to start it: %v", err)
	}
}

func TestNextIndex(t *testing.T) {
	cases := map[string]int{
		"":                          1,
		"notes\nreport.pdf\n":       1,
		"1-a\n2-b\n":                3,
		"10-a\n9-b\n":               11,
		"007-a":                     8,
		"x-1\n-2\n3x-a\n4":          1,
		"99999999999999999999999-a": 1,
	}
	for listing, want := range cases {
		if got := nextIndex([]byte(listing)); got != want {
			t.Errorf("nextIndex(%q) = %d, want %d", listing, got, want)
		}
	}
}

func TestWriteTarShrink(t *testing.T) {
	p := writeFile(t, filepath.Join(t.TempDir(), "x"), "abc")
	s, err := openSource(p)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.f.Close() }()
	if err := os.Truncate(p, 1); err != nil {
		t.Fatal(err)
	}
	err = writeTar(io.Discard, []*source{s}, []string{"1-x"})
	if err == nil || !strings.Contains(err.Error(), "shrank") {
		t.Errorf("err = %v, want a shrank error", err)
	}
}

type entry struct {
	name     string
	typeflag byte
	body     string
	mode     int64
}

func makeTar(t *testing.T, entries ...entry) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		hdr := &tar.Header{Name: e.name, Typeflag: e.typeflag, Mode: e.mode, Size: int64(len(e.body))}
		if hdr.Mode == 0 {
			hdr.Mode = 0o644
		}
		switch e.typeflag {
		case tar.TypeReg:
		case tar.TypeSymlink, tar.TypeLink:
			hdr.Linkname, hdr.Size = e.body, 0
		default:
			hdr.Size = 0
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if hdr.Size > 0 {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// dirContents returns the names and contents of the entries in dir.
func dirContents(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, e := range entries {
		b, _ := os.ReadFile(filepath.Join(dir, e.Name()))
		out[e.Name()] = string(b)
	}
	return out
}

var resultsTar = []entry{
	{"./", tar.TypeDir, "", 0o755},
	{"./a.txt", tar.TypeReg, "alpha", 0o4755},
	{"./b.log", tar.TypeReg, "log", 0},
	{"./link.txt", tar.TypeSymlink, "/etc/passwd", 0},
	{"./hard.txt", tar.TypeLink, "./a.txt", 0},
	{"./fifo.txt", tar.TypeFifo, "", 0},
	{"./dir.txt/", tar.TypeDir, "", 0o755},
	{"./sub/", tar.TypeDir, "", 0o755},
	{"./sub/c.txt", tar.TypeReg, "nested", 0},
	{"./c.txt", tar.TypeReg, "gamma", 0},
	{"../up.txt", tar.TypeReg, "up", 0},
}

func TestCopyOut(t *testing.T) {
	host := t.TempDir()
	m, r := newCopyManager(t, &copyFake{tarOut: makeTar(t, resultsTar...)})
	paths, err := m.CopyOut(context.Background(), "box", "/sandbox/out", host, CopyOutOptions{Only: []string{"*.txt"}})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{filepath.Join(host, "a.txt"), filepath.Join(host, "c.txt")}
	if !reflect.DeepEqual(paths, want) {
		t.Errorf("paths = %v, want %v", paths, want)
	}
	if got := dirContents(t, host); !reflect.DeepEqual(got, map[string]string{"a.txt": "alpha", "c.txt": "gamma"}) {
		t.Errorf("host dir = %v", got)
	}
	fi, err := os.Stat(filepath.Join(host, "a.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode()&^0o644 != 0 {
		t.Errorf("a.txt mode = %v, want no more than 0644", fi.Mode())
	}
	want0 := "exec --user sandbox --workdir /sandbox safeclaw-box /usr/bin/tar -c -f - --exclude=./*/* -C /sandbox/out ."
	if !hasCall(r, want0) {
		t.Errorf("missing %q in %v", want0, r.Commands())
	}

	// Several globs keep a file matching any of them.
	host = t.TempDir()
	m, _ = newCopyManager(t, &copyFake{tarOut: makeTar(t, resultsTar...)})
	if _, err := m.CopyOut(context.Background(), "box", "out", host, CopyOutOptions{Only: []string{"a.*", "*.log"}}); err != nil {
		t.Fatal(err)
	}
	if got := dirContents(t, host); !reflect.DeepEqual(got, map[string]string{"a.txt": "alpha", "b.log": "log"}) {
		t.Errorf("host dir = %v", got)
	}
}

func TestCopyOutRefusesStreams(t *testing.T) {
	cases := []struct {
		name    string
		tar     []byte
		tarErr  error
		maxSize int64
		want    string
	}{
		{"duplicate", makeTar(t, entry{"./a.txt", tar.TypeReg, "1", 0}, entry{"a.txt", tar.TypeReg, "2", 0}), nil, 0, "more than once"},
		{"too large", makeTar(t, entry{"./a.txt", tar.TypeReg, "12345", 0}, entry{"./b.txt", tar.TypeReg, "678", 0}), nil, 6, ErrTooLarge.Error()},
		{"tar failed", makeTar(t, entry{"./a.txt", tar.TypeReg, "1", 0}), errors.New("tar: out: Cannot open: No such file or directory"), 0, "No such file"},
		{"truncated", makeTar(t, entry{"./a.txt", tar.TypeReg, "12345", 0})[:514], nil, 0, "unexpected EOF"},
	}
	for _, tc := range cases {
		host := t.TempDir()
		m, _ := newCopyManager(t, &copyFake{tarOut: tc.tar, tarErr: tc.tarErr})
		_, err := m.CopyOut(context.Background(), "box", "/sandbox/out", host, CopyOutOptions{Only: []string{"*"}, MaxSize: tc.maxSize})
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
		if got := dirContents(t, host); len(got) != 0 {
			t.Errorf("%s: left %v in the host dir", tc.name, got)
		}
	}
}

// TestExtractTopHugeSize checks that a declared size near math.MaxInt64, as
// GNU tar writes for a sparse file in base-256, is refused by the size limit
// instead of wrapping the running total.
func TestExtractTopHugeSize(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "./a.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1, Format: tar.FormatGNU}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Flush(); err != nil {
		t.Fatal(err)
	}
	hdrAt := buf.Len()
	if err := tw.WriteHeader(&tar.Header{Name: "./b.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: math.MaxInt64, Format: tar.FormatGNU}); err != nil {
		t.Fatal(err)
	}
	wantField := []byte{0x80, 0, 0, 0, 0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
	if got := buf.Bytes()[hdrAt+124 : hdrAt+136]; !bytes.Equal(got, wantField) {
		t.Fatalf("size field = % x, want % x", got, wantField)
	}
	if _, err := tw.Write(make([]byte, 65536)); err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	_, err := extractTop(bytes.NewReader(buf.Bytes()), dir, CopyOutOptions{Only: []string{"*"}, MaxSize: 1024})
	if !errors.Is(err, ErrTooLarge) {
		t.Errorf("err = %v, want %v", err, ErrTooLarge)
	}
	if _, err := os.Lstat(filepath.Join(dir, "b.txt")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("b.txt was created: %v", err)
	}
}

func TestCopyOutExisting(t *testing.T) {
	stream := makeTar(t, entry{"./a.txt", tar.TypeReg, "new a", 0}, entry{"./b.txt", tar.TypeReg, "new b", 0})
	only := []string{"*.txt"}

	host := t.TempDir()
	writeFile(t, filepath.Join(host, "a.txt"), "old a")
	m, _ := newCopyManager(t, &copyFake{tarOut: stream})
	if _, err := m.CopyOut(context.Background(), "box", "out", host, CopyOutOptions{Only: only}); !errors.Is(err, ErrFileExists) {
		t.Errorf("err = %v, want ErrFileExists", err)
	}
	if got := dirContents(t, host); !reflect.DeepEqual(got, map[string]string{"a.txt": "old a"}) {
		t.Errorf("a clash wrote files: %v", got)
	}

	// --force replaces files, and a symlink itself rather than its target.
	outside := writeFile(t, filepath.Join(t.TempDir(), "target"), "untouched")
	if err := os.Symlink(outside, filepath.Join(host, "b.txt")); err != nil {
		t.Fatal(err)
	}
	m, _ = newCopyManager(t, &copyFake{tarOut: stream})
	if _, err := m.CopyOut(context.Background(), "box", "out", host, CopyOutOptions{Only: only, Force: true}); err != nil {
		t.Fatal(err)
	}
	if got := dirContents(t, host); !reflect.DeepEqual(got, map[string]string{"a.txt": "new a", "b.txt": "new b"}) {
		t.Errorf("host dir = %v", got)
	}
	if fi, _ := os.Lstat(filepath.Join(host, "b.txt")); fi.Mode()&fs.ModeSymlink != 0 {
		t.Error("b.txt is still a symlink")
	}
	if b, _ := os.ReadFile(outside); string(b) != "untouched" {
		t.Errorf("symlink target = %q", b)
	}

	// A directory is never replaced.
	host = t.TempDir()
	if err := os.Mkdir(filepath.Join(host, "a.txt"), 0o755); err != nil {
		t.Fatal(err)
	}
	m, _ = newCopyManager(t, &copyFake{tarOut: stream})
	if _, err := m.CopyOut(context.Background(), "box", "out", host, CopyOutOptions{Only: only, Force: true}); !errors.Is(err, ErrIsDirectory) {
		t.Errorf("err = %v, want ErrIsDirectory", err)
	}
	if got := dirContents(t, host); len(got) != 1 {
		t.Errorf("host dir = %v", got)
	}
}

func TestCopyOutMaxFiles(t *testing.T) {
	// Empty files are free against --max-size, so only the count limits them.
	var entries []entry
	for i := range 5 {
		entries = append(entries, entry{fmt.Sprintf("./%d.txt", i), tar.TypeReg, "", 0})
	}
	entries = append(entries, entry{"./skip.log", tar.TypeReg, "", 0})
	stream := makeTar(t, entries...)

	host := t.TempDir()
	m, _ := newCopyManager(t, &copyFake{tarOut: stream})
	_, err := m.CopyOut(context.Background(), "box", "/sandbox/out", host, CopyOutOptions{Only: []string{"*.txt"}, MaxFiles: 4})
	if !errors.Is(err, ErrTooManyFiles) || !strings.Contains(err.Error(), "(4 files)") {
		t.Errorf("over the limit: err = %v, want ErrTooManyFiles", err)
	}
	if got := dirContents(t, host); len(got) != 0 {
		t.Errorf("over the limit left %v in the host dir", got)
	}

	// Exactly at the limit, and files --only drops don't count.
	for _, limit := range []int{5, 0} {
		host = t.TempDir()
		m, _ = newCopyManager(t, &copyFake{tarOut: stream})
		paths, err := m.CopyOut(context.Background(), "box", "/sandbox/out", host, CopyOutOptions{Only: []string{"*.txt"}, MaxFiles: limit})
		if err != nil || len(paths) != 5 {
			t.Errorf("MaxFiles %d: got %d files, err = %v", limit, len(paths), err)
		}
	}
}

// paxRecord formats one PAX record, whose length counts itself.
func paxRecord(k, v string) string {
	body := " " + k + "=" + v + "\n"
	n := len(body) + 1
	for len(strconv.Itoa(n))+len(body) != n {
		n++
	}
	return strconv.Itoa(n) + body
}

// setTypeflag rewrites a tar header block's type flag and checksum.
func setTypeflag(block []byte, flag byte) {
	block[156] = flag
	copy(block[148:156], "        ")
	sum := 0
	for _, c := range block {
		sum += int(c)
	}
	copy(block[148:156], fmt.Sprintf("%06o\x00 ", sum))
}

// TestCopyOutDropsSparse checks that a GNU sparse entry, which the tar
// reader would expand to its logical size, is dropped even without a size
// limit.
func TestCopyOutDropsSparse(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	// A PAX GNU sparse 0.1 entry: one byte of data at the end of a 1 GiB
	// file, so the stream stays tiny while the logical size is huge. Go's
	// writer won't write GNU.sparse records, so the extended header is
	// written as a plain entry whose type flag is then patched to x.
	var records string
	for _, kv := range [][2]string{
		{"GNU.sparse.major", "0"}, {"GNU.sparse.minor", "1"},
		{"GNU.sparse.size", "1073741824"}, {"GNU.sparse.numblocks", "1"},
		{"GNU.sparse.map", "1073741823,1"},
	} {
		records += paxRecord(kv[0], kv[1])
	}
	if err := tw.WriteHeader(&tar.Header{Name: "PaxHeaders/sparse.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(records)), Format: tar.FormatUSTAR}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(records)); err != nil {
		t.Fatal(err)
	}
	setTypeflag(buf.Bytes()[:512], tar.TypeXHeader)
	if err := tw.WriteHeader(&tar.Header{Name: "./sparse.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1, Format: tar.FormatUSTAR}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "./plain.txt", Typeflag: tar.TypeReg, Mode: 0o644, Size: 2}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("ok")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	// The reader does see it as a 1 GiB regular file.
	tr := tar.NewReader(bytes.NewReader(buf.Bytes()))
	got, err := tr.Next()
	if err != nil || got.Typeflag != tar.TypeReg || got.Size != 1<<30 || !sparse(got) {
		t.Fatalf("sparse header = %+v, %v", got, err)
	}

	host := t.TempDir()
	m, _ := newCopyManager(t, &copyFake{tarOut: buf.Bytes()})
	paths, err := m.CopyOut(context.Background(), "box", "/sandbox/out", host, CopyOutOptions{Only: []string{"*"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || !reflect.DeepEqual(dirContents(t, host), map[string]string{"plain.txt": "ok"}) {
		t.Errorf("paths = %v, host dir = %v", paths, dirContents(t, host))
	}
}

func TestCopyOutArgs(t *testing.T) {
	host := t.TempDir()
	file := writeFile(t, filepath.Join(t.TempDir(), "file"), "x")
	cases := []struct {
		name    string
		src     string
		hostDir string
		opts    CopyOutOptions
		want    string
	}{
		{"no glob", "out", host, CopyOutOptions{}, ErrNoGlob.Error()},
		{"bad glob", "out", host, CopyOutOptions{Only: []string{"["}}, "syntax error"},
		{"negative", "out", host, CopyOutOptions{Only: []string{"*"}, MaxSize: -1}, "negative"},
		{"negative files", "out", host, CopyOutOptions{Only: []string{"*"}, MaxFiles: -1}, "--max-files must not be negative"},
		{"no src", "", host, CopyOutOptions{Only: []string{"*"}}, "sandbox directory is required"},
		{"missing host dir", "out", filepath.Join(host, "missing"), CopyOutOptions{Only: []string{"*"}}, "no such file"},
		{"host file", "out", file, CopyOutOptions{Only: []string{"*"}}, "not a directory"},
	}
	for _, tc := range cases {
		m, r := newCopyManager(t, &copyFake{})
		_, err := m.CopyOut(context.Background(), "box", tc.src, tc.hostDir, tc.opts)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want %q", tc.name, err, tc.want)
		}
		if hasExec(r) {
			t.Errorf("%s ran %v", tc.name, r.Commands())
		}
	}
}

func TestTopLevel(t *testing.T) {
	for name, want := range map[string]string{
		"./a.txt": "a.txt",
		"a.txt":   "a.txt",
		"./.env":  ".env",
		"./":      "",
		".":       "",
		"./..":    "",
		"../a":    "",
		"./sub/a": "",
		"/a":      "",
		"a/":      "",
	} {
		got, ok := topLevel(name)
		if got != want || ok != (want != "") {
			t.Errorf("topLevel(%q) = %q, %v, want %q", name, got, ok, want)
		}
	}
}

func TestRenameNoReplace(t *testing.T) {
	dir := t.TempDir()
	from := writeFile(t, filepath.Join(dir, "from"), "new")
	to := writeFile(t, filepath.Join(dir, "to"), "old")
	if err := renameNoReplace(from, to); !errors.Is(err, fs.ErrExist) {
		t.Errorf("err = %v, want ErrExist", err)
	}
	if b, _ := os.ReadFile(to); string(b) != "old" {
		t.Errorf("to = %q", b)
	}
	if err := renameNoReplace(from, filepath.Join(dir, "fresh")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "fresh")); string(b) != "new" {
		t.Errorf("fresh = %q", b)
	}
}

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"0": 0, "512": 512, "4k": 4096, "1M": 1 << 20, "1g": 1 << 30, "2t": 2 << 40} {
		got, err := ParseSize(in)
		if err != nil || got != want {
			t.Errorf("ParseSize(%q) = %d, %v, want %d", in, got, err, want)
		}
	}
	for _, in := range []string{"", "g", "-1", "+1", "1.5g", "1gb", "9999999999t"} {
		if _, err := ParseSize(in); err == nil {
			t.Errorf("ParseSize(%q) should fail", in)
		}
	}
}

func TestCopyOutRefusesUnsafeNames(t *testing.T) {
	for _, name := range []string{
		"a\nb.txt",            // newline
		"a\tb.txt",            // tab
		"\x1b[31mred.txt",     // terminal escape
		"bell\a.txt",          // other C0 control
		"del\x7f.txt",         // DEL
		"csi\u009b31m.txt",    // C1 control
		"evil\u202etxt.exe",   // bidi override (format)
		"zero\u200bwidth.txt", // zero-width space (format)
		"nb\u00a0sp.txt",      // non-ASCII space
		"bad\xff.txt",         // not UTF-8
		"-rf.txt",             // looks like an option
	} {
		host := t.TempDir()
		stream := makeTar(t, entry{"./ok.txt", tar.TypeReg, "ok", 0}, entry{"./" + name, tar.TypeReg, "x", 0})
		m, _ := newCopyManager(t, &copyFake{tarOut: stream})
		_, err := m.CopyOut(context.Background(), "box", "out", host, CopyOutOptions{Only: []string{"*"}})
		if !errors.Is(err, ErrUnsafeName) {
			t.Errorf("%q: err = %v, want ErrUnsafeName", name, err)
			continue
		}
		if want := strconv.Quote(name); !strings.Contains(err.Error(), want) {
			t.Errorf("%q: err = %v, want it to name %s", name, err, want)
		}
		if got := dirContents(t, host); len(got) != 0 {
			t.Errorf("%q: left %v in the host dir", name, got)
		}
	}
}

func TestCopyOutIgnoresUnsafeNamesNotKept(t *testing.T) {
	// Entries that would be dropped anyway don't stop the copy.
	stream := makeTar(t,
		entry{"./ok.txt", tar.TypeReg, "ok", 0},
		entry{"./a\nb.log", tar.TypeReg, "x", 0},
		entry{"./c\nd.txt", tar.TypeSymlink, "/etc/passwd", 0},
		entry{"./e\nf.txt/", tar.TypeDir, "", 0o755},
	)
	host := t.TempDir()
	m, _ := newCopyManager(t, &copyFake{tarOut: stream})
	if _, err := m.CopyOut(context.Background(), "box", "out", host, CopyOutOptions{Only: []string{"*.txt"}}); err != nil {
		t.Fatal(err)
	}
	if got := dirContents(t, host); !reflect.DeepEqual(got, map[string]string{"ok.txt": "ok"}) {
		t.Errorf("host dir = %v", got)
	}
}

func TestCopyOutHiddenFiles(t *testing.T) {
	stream := makeTar(t,
		entry{"./a.txt", tar.TypeReg, "a", 0},
		entry{"./.envrc", tar.TypeReg, "evil", 0},
		entry{"./.hidden.txt", tar.TypeReg, "h", 0},
	)
	for _, tc := range []struct {
		only []string
		want map[string]string
	}{
		{[]string{"*"}, map[string]string{"a.txt": "a"}},
		{[]string{"*.txt"}, map[string]string{"a.txt": "a"}},
		{[]string{"?*"}, map[string]string{"a.txt": "a"}},
		{[]string{"[.a]*"}, map[string]string{"a.txt": "a"}},
		{[]string{".*.txt"}, map[string]string{".hidden.txt": "h"}},
		{[]string{"*", ".envrc"}, map[string]string{"a.txt": "a", ".envrc": "evil"}},
	} {
		host := t.TempDir()
		m, _ := newCopyManager(t, &copyFake{tarOut: stream})
		if _, err := m.CopyOut(context.Background(), "box", "out", host, CopyOutOptions{Only: tc.only}); err != nil {
			t.Fatalf("%v: %v", tc.only, err)
		}
		if got := dirContents(t, host); !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%v: host dir = %v, want %v", tc.only, got, tc.want)
		}
	}
}

func TestCopyOutQuotesNames(t *testing.T) {
	// Errors name files with %q, so a host directory with odd characters
	// still prints on one line.
	host := filepath.Join(t.TempDir(), "res\nults")
	if err := os.Mkdir(host, 0o755); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(host, "a.txt"), "old")
	m, _ := newCopyManager(t, &copyFake{tarOut: makeTar(t, entry{"./a.txt", tar.TypeReg, "new", 0})})
	_, err := m.CopyOut(context.Background(), "box", "out", host, CopyOutOptions{Only: []string{"*"}})
	if want := strconv.Quote(filepath.Join(host, "a.txt")) + " " + ErrFileExists.Error(); err == nil || err.Error() != want {
		t.Errorf("err = %v, want %s", err, want)
	}
	if err := os.Mkdir(filepath.Join(host, "d.txt"), 0o755); err != nil {
		t.Fatal(err)
	}
	m, _ = newCopyManager(t, &copyFake{tarOut: makeTar(t, entry{"./d.txt", tar.TypeReg, "new", 0})})
	_, err = m.CopyOut(context.Background(), "box", "out", host, CopyOutOptions{Only: []string{"*"}, Force: true})
	if want := strconv.Quote(filepath.Join(host, "d.txt")) + " " + ErrIsDirectory.Error(); err == nil || err.Error() != want {
		t.Errorf("err = %v, want %s", err, want)
	}

	if err := placeError("/h/a\x1b.txt", fs.ErrExist); err.Error() != `"/h/a\x1b.txt" `+ErrFileExists.Error() {
		t.Errorf("placeError = %v", err)
	}
	if err := placeError("/h/a\x1b.txt", syscall.EINVAL); !strings.HasPrefix(err.Error(), `"/h/a\x1b.txt": `) {
		t.Errorf("placeError = %v", err)
	}
	dup := makeTar(t, entry{"./a.txt", tar.TypeReg, "1", 0}, entry{"a.txt", tar.TypeReg, "2", 0})
	if _, err := extractTop(bytes.NewReader(dup), t.TempDir(), CopyOutOptions{Only: []string{"*"}}); err == nil || err.Error() != `"a.txt" appears more than once` {
		t.Errorf("duplicate err = %v", err)
	}
	short := makeTar(t, entry{"./a.txt", tar.TypeReg, "12345", 0})[:514]
	if _, err := extractTop(bytes.NewReader(short), t.TempDir(), CopyOutOptions{Only: []string{"*"}}); err == nil || !strings.HasPrefix(err.Error(), `"a.txt": `) {
		t.Errorf("short read err = %v", err)
	}
}

func TestQuotePath(t *testing.T) {
	for in, want := range map[string]string{
		"/sandbox/in/1-a b.txt": "/sandbox/in/1-a b.txt",
		"/h/résumé.pdf":         "/h/résumé.pdf",
		"/h/a\nb":               `"/h/a\nb"`,
		"/h/\x1b]0;x\a":         `"/h/\x1b]0;x\a"`,
		"/h/\xff":               `"/h/\xff"`,
	} {
		if got := QuotePath(in); got != want {
			t.Errorf("QuotePath(%q) = %s, want %s", in, got, want)
		}
	}
}
