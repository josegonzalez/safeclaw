package unpack

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// zipHead makes a file look like a zip to Detect.
const zipHead = "PK\x03\x04"

// fakeArchive is what a fakeRunner lists and extracts for one archive.
type fakeArchive struct {
	entries []Entry
	// files are written on extract, by path: "symlink:TARGET" makes a
	// link, "fifo:" a fifo, "hardlink:OTHER" a hard link to OTHER, and
	// anything else a file with that content.
	files   map[string]string
	listErr error
	xErr    error
}

// fakeRunner stands in for 7z, keyed by the archive's base name.
type fakeRunner struct {
	archives map[string]fakeArchive
	includes [][]string
	pws      []*string
	// during runs while extracting.
	during func(dir string)
}

func (f *fakeRunner) List(_ context.Context, archive string, pw *string) (*Listing, error) {
	f.pws = append(f.pws, pw)
	a, ok := f.archives[filepath.Base(archive)]
	if !ok {
		return nil, ErrNotArchive
	}
	if a.listErr != nil {
		return nil, a.listErr
	}
	entries := make([]Entry, len(a.entries))
	for i, e := range a.entries {
		e.UnsafePath = UnsafePath(e.Path)
		entries[i] = e
	}
	return &Listing{Type: "fake", Entries: entries}, nil
}

func (f *fakeRunner) Extract(ctx context.Context, archive, dir string, include []string, _ *string) error {
	f.includes = append(f.includes, include)
	a := f.archives[filepath.Base(archive)]
	if a.xErr != nil {
		return a.xErr
	}
	names := make([]string, 0, len(a.files))
	for name := range a.files {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if include != nil && !slices.Contains(include, name) {
			continue
		}
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		content := a.files[name]
		var err error
		switch {
		case strings.HasPrefix(content, "symlink:"):
			err = os.Symlink(strings.TrimPrefix(content, "symlink:"), p)
		case content == "fifo:":
			err = syscall.Mkfifo(p, 0o644)
		case strings.HasPrefix(content, "hardlink:"):
			err = os.Link(filepath.Join(dir, strings.TrimPrefix(content, "hardlink:")), p)
		case strings.HasPrefix(content, "mode0:"):
			err = os.WriteFile(p, []byte(content), 0o644)
			if err == nil {
				err = os.Chmod(p, os.ModeSetuid|0o100)
			}
		default:
			err = os.WriteFile(p, []byte(content), 0o644)
		}
		if err != nil {
			return err
		}
	}
	if f.during != nil {
		f.during(dir)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
	return nil
}

func file(p string, size int64) Entry { return Entry{Path: p, Type: TypeFile, Size: size} }

func paths(entries []Entry) []string {
	out := make([]string, len(entries))
	for i, e := range entries {
		out[i] = e.Path + " " + strings.Join(e.Flags(), ",")
	}
	return out
}

func extract(t *testing.T, f *fakeRunner, o Options) (string, *Result, error) {
	t.Helper()
	dir := t.TempDir()
	archive := filepath.Join(dir, "top.zip")
	if err := os.WriteFile(archive, []byte(zipHead), 0o644); err != nil {
		t.Fatal(err)
	}
	dest := filepath.Join(dir, "out")
	o.Runner = f
	if o.MaxSize == 0 {
		o.MaxSize = 1 << 20
	}
	if o.Depth == 0 {
		o.Depth = DefaultDepth
	}
	o.PollInterval = 5 * time.Millisecond
	res, err := Extract(t.Context(), archive, dest, o)
	return dest, res, err
}

// wantKind checks err's kind and returns a copy of it, which is not an
// error, so callers can drop it.
func wantKind(t *testing.T, err error, kind Kind) Error {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Kind != kind {
		t.Fatalf("err = %v, want kind %s", err, kind)
	}
	return *e
}

func wantEmpty(t *testing.T, dest string) {
	t.Helper()
	names, err := os.ReadDir(dest)
	if err != nil || len(names) != 0 {
		t.Errorf("dest has %v, %v; want it emptied", names, err)
	}
}

func TestExtract(t *testing.T) {
	f := &fakeRunner{archives: map[string]fakeArchive{"top.zip": {
		entries: []Entry{{Path: "d", Type: TypeDir}, file("d/a.txt", 2), file("b.txt", 1)},
		files:   map[string]string{"d/a.txt": "hi", "b.txt": "x", "s": "mode0:"},
	}}}
	dest, res, err := extract(t, f, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if got := paths(res.Entries); !slices.Equal(got, []string{"b.txt ", "d ", "d/a.txt ", "s "}) {
		t.Errorf("entries = %v", got)
	}
	if res.Entries[0].Size != 1 || res.Entries[1].Type != TypeDir || len(res.Dropped) != 0 {
		t.Errorf("result = %+v", res)
	}
	if f.includes[0] != nil {
		t.Errorf("include = %v, want everything", f.includes[0])
	}
	fi, err := os.Stat(filepath.Join(dest, "s"))
	if err != nil || fi.Mode()&os.ModeSetuid != 0 || fi.Mode().Perm()&0o600 != 0o600 {
		t.Errorf("setuid file mode = %v, %v", fi.Mode(), err)
	}
}

func TestExtractRejects(t *testing.T) {
	for name, entries := range map[string][]Entry{
		"dotdot":   {file("ok", 1), file("../x", 1)},
		"absolute": {file("/etc/x", 1)},
		"drive":    {file("C:\\x", 1)},
		"symlink":  {{Path: "l", Type: TypeSymlink, Link: "/etc"}},
		"hardlink": {{Path: "h", Type: TypeHardlink, Link: "ok"}},
		"special":  {{Path: "p", Type: TypeSpecial}},
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeRunner{archives: map[string]fakeArchive{"top.zip": {entries: entries, files: map[string]string{"ok": "1"}}}}
			dest, _, err := extract(t, f, Options{})
			e := wantKind(t, err, Rejected)
			if len(e.Bad) == 0 || !e.Bad[len(e.Bad)-1].Bad() {
				t.Errorf("bad = %+v", e.Bad)
			}
			if len(f.includes) != 0 {
				t.Error("a rejected archive was extracted")
			}
			wantEmpty(t, dest)
		})
	}
}

func TestExtractDropBad(t *testing.T) {
	f := &fakeRunner{archives: map[string]fakeArchive{"top.zip": {
		entries: []Entry{file("ok", 1), {Path: "empty", Type: TypeDir}, file("../x", 1), {Path: "l", Type: TypeSymlink}},
		files:   map[string]string{"ok": "1", "../x": "escaped", "l": "symlink:/etc"},
	}}}
	dest, res, err := extract(t, f, Options{DropBad: true})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(f.includes[0], []string{"ok"}) {
		t.Errorf("include = %v", f.includes[0])
	}
	if got := paths(res.Entries); !slices.Equal(got, []string{"empty ", "ok "}) {
		t.Errorf("entries = %v", got)
	}
	if got := paths(res.Dropped); !slices.Equal(got, []string{"../x UNSAFE-PATH,DROPPED", "l LINK,DROPPED"}) {
		t.Errorf("dropped = %v", got)
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(dest), "x")); err == nil {
		t.Error("a dropped entry was extracted")
	}

	// With nothing but bad files left, 7z isn't run.
	f = &fakeRunner{archives: map[string]fakeArchive{"top.zip": {entries: []Entry{file("/x", 1)}}}}
	if _, res, err := extract(t, f, Options{DropBad: true}); err != nil || len(f.includes) != 0 || len(res.Dropped) != 1 || len(res.Entries) != 0 {
		t.Errorf("all bad: %+v, %v, includes %v", res, err, f.includes)
	}
}

// TestExtractAfterChecks covers what 7z made that its listing didn't show.
func TestExtractAfterChecks(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"symlink":  {"ok": "1", "l": "symlink:../../etc"},
		"fifo":     {"ok": "1", "p": "fifo:"},
		"hardlink": {"ok": "1", "z": "hardlink:ok"},
	} {
		t.Run(name, func(t *testing.T) {
			f := &fakeRunner{archives: map[string]fakeArchive{"top.zip": {entries: []Entry{file("ok", 1)}, files: files}}}
			dest, _, err := extract(t, f, Options{})
			e := wantKind(t, err, Rejected)
			if len(e.Bad) != 1 || !e.Bad[0].Bad() {
				t.Errorf("bad = %+v", e.Bad)
			}
			wantEmpty(t, dest)

			f.includes = nil
			_, res, err := extract(t, f, Options{DropBad: true})
			if err != nil || len(res.Dropped) != 1 || !slices.Contains(res.Dropped[0].Flags(), FlagDropped) {
				t.Fatalf("drop: %+v, %v", res, err)
			}
			for _, e := range res.Entries {
				if e.Type != TypeFile || e.Path == res.Dropped[0].Path {
					t.Errorf("left %+v", e)
				}
			}
		})
	}
}

func TestExtractSize(t *testing.T) {
	// Refused from the listing, before extracting.
	f := &fakeRunner{archives: map[string]fakeArchive{"top.zip": {entries: []Entry{file("big", 2000)}, files: map[string]string{"big": "x"}}}}
	_, _, err := extract(t, f, Options{MaxSize: 1000})
	wantKind(t, err, TooLarge)
	if len(f.includes) != 0 {
		t.Error("extracted an archive whose listing is too large")
	}

	// Checked after extracting, for a size the listing doesn't have.
	f = &fakeRunner{archives: map[string]fakeArchive{"top.zip": {entries: []Entry{file("big", -1)}, files: map[string]string{"big": strings.Repeat("x", 2000)}}}}
	dest, _, err := extract(t, f, Options{MaxSize: 1000})
	wantKind(t, err, TooLarge)
	wantEmpty(t, dest)

	// Stopped while extracting.
	f.during = func(string) {}
	start := time.Now()
	dest, _, err = extract(t, f, Options{MaxSize: 1000})
	wantKind(t, err, TooLarge)
	if took := time.Since(start); took > 3*time.Second {
		t.Errorf("took %s to stop", took)
	}
	wantEmpty(t, dest)
}

func TestExtractPassword(t *testing.T) {
	f := &fakeRunner{archives: map[string]fakeArchive{"top.zip": {entries: []Entry{{Path: "a", Type: TypeFile, Size: 1, Encrypted: true}}, files: map[string]string{"a": "1"}}}}
	_, _, err := extract(t, f, Options{})
	wantKind(t, err, NeedsPassword)
	pw := "secret"
	if _, _, err := extract(t, f, Options{Password: &pw}); err != nil {
		t.Fatal(err)
	}
	if got := f.pws[len(f.pws)-1]; got == nil || *got != pw {
		t.Errorf("password = %v", got)
	}

	f.archives["top.zip"] = fakeArchive{listErr: &Error{Kind: NeedsPassword, Msg: "wrong password"}}
	_, _, err = extract(t, f, Options{Password: &pw})
	wantKind(t, err, NeedsPassword)
}

func TestExtractFailures(t *testing.T) {
	f := &fakeRunner{archives: map[string]fakeArchive{}}
	_, _, err := extract(t, f, Options{})
	if e := wantKind(t, err, Failed); !strings.Contains(e.Msg, "corrupt") {
		t.Errorf("a zip 7z can't open: %v", e)
	}
	f.archives["top.zip"] = fakeArchive{entries: []Entry{file("a", 1)}, files: map[string]string{"a": "1"}, xErr: &Error{Kind: Failed, Msg: "7z: Data Error"}}
	_, _, err = extract(t, f, Options{})
	wantKind(t, err, Failed)
}

func TestExtractNested(t *testing.T) {
	f := &fakeRunner{archives: map[string]fakeArchive{
		"top.zip": {
			entries: []Entry{file("inner.zip", 4), file("notes.txt", 1), file("fake.zip", 4), file("taken.zip", 4), {Path: "taken.zip.unpacked", Type: TypeDir}},
			files:   map[string]string{"inner.zip": zipHead, "notes.txt": "n", "fake.zip": zipHead, "taken.zip": zipHead, "taken.zip.unpacked/planted": "p"},
		},
		"inner.zip": {
			entries: []Entry{file("deep.zip", 4), file("x.txt", 1)},
			files:   map[string]string{"deep.zip": zipHead, "x.txt": "x"},
		},
		"deep.zip":  {entries: []Entry{file("y.txt", 1)}, files: map[string]string{"y.txt": "y"}},
		"taken.zip": {entries: []Entry{file("t.txt", 1)}, files: map[string]string{"t.txt": "t"}},
	}}
	_, res, err := extract(t, f, Options{Depth: 1})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"fake.zip ",
		"inner.zip UNPACKED",
		"inner.zip.unpacked ",
		"inner.zip.unpacked/deep.zip DEPTH-LIMIT",
		"inner.zip.unpacked/x.txt ",
		"notes.txt ",
		"taken.zip UNPACKED",
		"taken.zip.unpacked ",
		"taken.zip.unpacked-2 ",
		"taken.zip.unpacked-2/t.txt ",
		"taken.zip.unpacked/planted ",
	}
	if got := paths(res.Entries); !slices.Equal(got, want) {
		t.Errorf("entries =\n%v\nwant\n%v", got, want)
	}
	for _, e := range res.Entries {
		if e.Path == "taken.zip" && e.Unpacked != "taken.zip.unpacked-2" {
			t.Errorf("unpacked = %q", e.Unpacked)
		}
	}

	// Depth 2 reaches deep.zip.
	_, res, err = extract(t, f, Options{Depth: 2})
	if err != nil || !slices.Contains(paths(res.Entries), "inner.zip.unpacked/deep.zip.unpacked/y.txt ") {
		t.Errorf("depth 2: %v, %v", paths(res.Entries), err)
	}

	// A nested archive's bad entries reject everything, naming it.
	f.archives["deep.zip"] = fakeArchive{entries: []Entry{file("../../y", 1)}}
	dest, _, err := extract(t, f, Options{Depth: 2})
	e := wantKind(t, err, Rejected)
	if e.Archive != "inner.zip.unpacked/deep.zip" || len(e.Bad) != 1 || e.Bad[0].Path != "inner.zip.unpacked/deep.zip.unpacked/../../y" || !e.Bad[0].Bad() {
		t.Errorf("nested rejection = %+v", e)
	}
	wantEmpty(t, dest)

	// Or are dropped.
	_, res, err = extract(t, f, Options{Depth: 2, DropBad: true})
	if err != nil || !slices.Equal(paths(res.Dropped), []string{"inner.zip.unpacked/deep.zip.unpacked/../../y UNSAFE-PATH,DROPPED"}) {
		t.Errorf("nested drop: %v, %v", paths(res.Dropped), err)
	}
}

func TestExtractDest(t *testing.T) {
	f := &fakeRunner{archives: map[string]fakeArchive{"top.zip": {entries: []Entry{file("a", 1)}, files: map[string]string{"a": "1"}}}}
	dir := t.TempDir()
	archive := filepath.Join(dir, "top.zip")
	if err := os.WriteFile(archive, []byte(zipHead), 0o644); err != nil {
		t.Fatal(err)
	}
	o := Options{Runner: f, MaxSize: 100, Depth: 1}

	// An existing empty directory is fine.
	empty := filepath.Join(dir, "empty")
	if err := os.Mkdir(empty, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := Extract(t.Context(), archive, empty, o); err != nil {
		t.Errorf("empty dest: %v", err)
	}
	// One with files, a file, a link, and a missing parent are refused.
	link := filepath.Join(dir, "link")
	if err := os.Symlink(filepath.Join(dir, "target"), link); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "target"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, dest := range map[string]string{"not empty": empty, "file": archive, "link": link, "missing parent": filepath.Join(dir, "no", "such")} {
		if _, err := Extract(t.Context(), archive, dest, o); KindOf(err) != Failed {
			t.Errorf("%s: err = %v", name, err)
		}
	}
	if names, _ := os.ReadDir(filepath.Join(dir, "target")); len(names) != 0 {
		t.Errorf("extracted through a link: %v", names)
	}
	// The archive must be a regular file.
	if _, err := Extract(t.Context(), dir, filepath.Join(dir, "x"), o); KindOf(err) != Failed {
		t.Errorf("directory archive: %v", err)
	}
	for _, bad := range []Options{{Runner: f, MaxSize: 0}, {Runner: f, MaxSize: 1, Depth: -1}, {MaxSize: 1}} {
		if _, err := Extract(t.Context(), archive, filepath.Join(dir, "y"), bad); KindOf(err) != Failed {
			t.Errorf("options %+v: %v", bad, err)
		}
	}
}

func TestEmptyDirNoFollow(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "root")
	outside := filepath.Join(dir, "outside")
	for _, d := range []string{root, outside, filepath.Join(root, "locked")} {
		if err := os.Mkdir(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(outside, "keep"), []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "locked", "f"), []byte("f"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, "locked"), 0); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if err := EmptyDir(root); err != nil {
		t.Fatal(err)
	}
	wantEmpty(t, root)
	if _, err := os.Stat(filepath.Join(outside, "keep")); err != nil {
		t.Errorf("followed a link: %v", err)
	}
}

func TestDetect(t *testing.T) {
	tar := make([]byte, 512)
	copy(tar[257:], "ustar\x0000")
	for format, head := range map[string][]byte{
		"zip": []byte("PK\x03\x04rest"), "7z": []byte("7z\xbc\xaf\x27\x1c"), "rar": []byte("Rar!\x1a\x07\x01"),
		"gzip": []byte("\x1f\x8b\x08"), "bzip2": []byte("BZh91AY"), "xz": []byte("\xfd7zXZ\x00"), "zstd": []byte("\x28\xb5\x2f\xfd"), "tar": tar,
	} {
		if got := Detect(head); got != format {
			t.Errorf("Detect(%s) = %q", format, got)
		}
	}
	for _, head := range [][]byte{nil, []byte("PK"), []byte("%PDF-1.7"), []byte("hello"), make([]byte, 512), tar[:260]} {
		if got := Detect(head); got != "" {
			t.Errorf("Detect(%q) = %q", head, got)
		}
	}
}

func TestDetectFile(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		return p
	}
	zip, text, empty := write("a.zip", zipHead+"rest"), write("a.txt", "just text\n"), write("empty", "")
	link := filepath.Join(dir, "link")
	if err := os.Symlink(zip, link); err != nil {
		t.Fatal(err)
	}
	for p, want := range map[string]string{zip: "zip", text: "", empty: "", link: "zip"} {
		if got, err := DetectFile(p); got != want || err != nil {
			t.Errorf("DetectFile(%s) = %q, %v; want %q", filepath.Base(p), got, err, want)
		}
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{dir, fifo, filepath.Join(dir, "missing")} {
		_, err := DetectFile(p)
		wantKind(t, err, Failed)
	}
	// The nested walk doesn't follow links, so it never detects one.
	if _, err := detectPath(link, syscall.O_NOFOLLOW); err == nil {
		t.Error("detectPath followed a link with O_NOFOLLOW")
	}
	got, err := archivesIn(dir)
	if err != nil || !slices.Equal(got, []string{zip}) {
		t.Errorf("archivesIn = %v, %v", got, err)
	}
}

// TestNotArchive checks that a top-level file 7z can't open is NotArchive
// when it doesn't start like an archive, and Failed, as corrupt, when it
// does.
func TestNotArchive(t *testing.T) {
	dir := t.TempDir()
	f := &fakeRunner{archives: map[string]fakeArchive{}}
	for name, kind := range map[string]Kind{"notes.txt": NotArchive, "empty": NotArchive, "bad.zip": Failed} {
		p := filepath.Join(dir, name)
		content := "just text\n"
		switch name {
		case "empty":
			content = ""
		case "bad.zip":
			content = zipHead + "truncated"
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := List(t.Context(), f, p, nil)
		e := wantKind(t, err, kind)
		if kind == Failed && !strings.Contains(e.Msg, "starts like a zip archive") {
			t.Errorf("%s: %v", name, e)
		}
		dest := filepath.Join(dir, name+".out")
		_, err = Extract(t.Context(), p, dest, Options{Runner: f, MaxSize: 1 << 20})
		if e := wantKind(t, err, kind); e.Archive != "" {
			t.Errorf("%s: archive = %q", name, e.Archive)
		}
		// Either way the error says 7z couldn't open it.
		if !errors.Is(err, ErrNotArchive) {
			t.Errorf("%s: %v doesn't wrap ErrNotArchive", name, err)
		}
		wantEmpty(t, dest)
	}
	if err := (&Error{Kind: Failed, Msg: "7z: data error"}); errors.Is(err, ErrNotArchive) {
		t.Error("a plain failure wraps ErrNotArchive")
	}
	if NotArchive.String() != "not an archive" || int(NotArchive) != 5 {
		t.Errorf("NotArchive = %d %q", NotArchive, NotArchive)
	}
}
