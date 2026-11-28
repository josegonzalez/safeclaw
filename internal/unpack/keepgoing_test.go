package unpack

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestExtractKeepGoing(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "keep"), []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	f := &fakeRunner{archives: map[string]fakeArchive{
		"top.zip": {
			entries: []Entry{file("a.pdf", 4), file("links.zip", 4), file("listed.zip", 4), file("enc.zip", 4), file("big.zip", 4), file("broken.zip", 4), file("ok.zip", 4)},
			files:   map[string]string{"a.pdf": "%PDF", "links.zip": zipHead, "listed.zip": zipHead, "enc.zip": zipHead, "big.zip": zipHead, "broken.zip": zipHead, "ok.zip": zipHead},
		},
		// Its listing is clean, but 7z makes a link to outside next to
		// files, so the files must go too, without following the link.
		"links.zip": {
			entries: []Entry{file("x.txt", 1), {Path: "d", Type: TypeDir}},
			files:   map[string]string{"x.txt": "x", "d/f": "f", "d/out": "symlink:" + outside},
		},
		"listed.zip": {entries: []Entry{file("ok", 1), {Path: "l", Type: TypeSymlink, Link: "/etc"}}},
		"enc.zip":    {entries: []Entry{{Path: "s", Type: TypeFile, Size: 1, Encrypted: true}}},
		// No size in the listing, and too large once extracted.
		"big.zip":    {entries: []Entry{file("zeros", -1)}, files: map[string]string{"zeros": strings.Repeat("0", 2000)}},
		"broken.zip": {entries: []Entry{file("b", 1)}, files: map[string]string{"b": "b"}, xErr: &Error{Kind: Failed, Msg: "7z: Data Error"}},
		"ok.zip": {
			entries: []Entry{file("y.txt", 1), file("deep.zip", 4)},
			files:   map[string]string{"y.txt": "y", "deep.zip": zipHead},
		},
		"deep.zip": {entries: []Entry{file("../../z", 1)}},
	}}
	dest, res, err := extract(t, f, Options{MaxSize: 1000, KeepGoing: true})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"a.pdf ",
		"big.zip TOO-LARGE",
		"broken.zip FAILED",
		"enc.zip NEEDS-PASSWORD",
		"links.zip REJECTED",
		"listed.zip REJECTED",
		"ok.zip UNPACKED",
		"ok.zip.unpacked ",
		"ok.zip.unpacked/deep.zip REJECTED",
		"ok.zip.unpacked/y.txt ",
	}
	if got := paths(res.Entries); !slices.Equal(got, want) {
		t.Errorf("entries =\n%v\nwant\n%v", got, want)
	}
	var failed []string
	for _, e := range res.Failed {
		failed = append(failed, e.Kind.Flag()+" "+e.Archive+" "+strings.Join(paths(e.Bad), ";"))
	}
	wantFailed := []string{
		"TOO-LARGE big.zip ",
		"FAILED broken.zip ",
		"NEEDS-PASSWORD enc.zip ",
		"REJECTED links.zip links.zip.unpacked/d/out LINK",
		"REJECTED listed.zip listed.zip.unpacked/l LINK",
		"REJECTED ok.zip.unpacked/deep.zip ok.zip.unpacked/deep.zip.unpacked/../../z UNSAFE-PATH",
	}
	if !slices.Equal(failed, wantFailed) {
		t.Errorf("failed =\n%v\nwant\n%v", failed, wantFailed)
	}
	if _, err := os.Stat(filepath.Join(outside, "keep")); err != nil {
		t.Errorf("followed a link: %v", err)
	}
	for _, name := range []string{"a.pdf", "big.zip", "links.zip"} {
		if _, err := os.Stat(filepath.Join(dest, name)); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	// The archive given still fails the run for its own problems.
	f.archives["top.zip"] = fakeArchive{entries: []Entry{file("ok", 1), {Path: "l", Type: TypeSymlink}}}
	dest, _, err = extract(t, f, Options{KeepGoing: true})
	wantKind(t, err, Rejected)
	wantEmpty(t, dest)
}

// TestExtractKeepGoingBudget checks that the size limit is shared by the
// whole tree: a nested archive past what is left of it is left packed, and
// the space it took while extracting is given back to the ones after it.
func TestExtractKeepGoingBudget(t *testing.T) {
	f := &fakeRunner{archives: map[string]fakeArchive{
		"top.zip": {
			entries: []Entry{file("a.zip", 4), file("b.zip", 4), file("c.zip", 4), file("d.zip", 4)},
			files:   map[string]string{"a.zip": zipHead, "b.zip": zipHead, "c.zip": zipHead, "d.zip": zipHead},
		},
		"a.zip": {entries: []Entry{file("a", 400)}, files: map[string]string{"a": strings.Repeat("a", 400)}},
		// Fits alone, but not after a.zip, so it is refused from its
		// listing.
		"b.zip": {entries: []Entry{file("b", 600)}, files: map[string]string{"b": strings.Repeat("b", 600)}},
		// Grows past the limit once extracted, after a bad entry was
		// dropped.
		"c.zip": {entries: []Entry{file("c", -1), file("/bad", 1)}, files: map[string]string{"c": strings.Repeat("c", 700)}},
		// Fits in what c.zip gave back.
		"d.zip": {entries: []Entry{file("d", 500)}, files: map[string]string{"d": strings.Repeat("d", 500)}},
	}}
	dest, res, err := extract(t, f, Options{MaxSize: 1000, KeepGoing: true, DropBad: true})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"a.zip UNPACKED", "a.zip.unpacked ", "a.zip.unpacked/a ", "b.zip TOO-LARGE", "c.zip TOO-LARGE", "d.zip UNPACKED", "d.zip.unpacked ", "d.zip.unpacked/d "}
	if got := paths(res.Entries); !slices.Equal(got, want) {
		t.Errorf("entries = %v, want %v", got, want)
	}
	if len(res.Dropped) != 0 {
		t.Errorf("dropped from an archive left packed: %v", paths(res.Dropped))
	}
	if n, err := treeSize(dest); err != nil || n > 1000 {
		t.Errorf("tree size = %d, %v", n, err)
	}
}

// TestExtractKeepGoingDeep checks that a failure deep in the tree leaves
// only that archive packed, and that without keep-going it fails the run.
func TestExtractKeepGoingDeep(t *testing.T) {
	f := &fakeRunner{archives: map[string]fakeArchive{
		"top.zip": {entries: []Entry{file("mid.zip", 4)}, files: map[string]string{"mid.zip": zipHead}},
		"mid.zip": {entries: []Entry{file("bad.zip", 4), file("m", 1)}, files: map[string]string{"bad.zip": zipHead, "m": "m"}},
		"bad.zip": {entries: []Entry{{Path: "s", Type: TypeFile, Size: 1, Encrypted: true}}},
	}}
	_, res, err := extract(t, f, Options{KeepGoing: true})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"mid.zip UNPACKED", "mid.zip.unpacked ", "mid.zip.unpacked/bad.zip NEEDS-PASSWORD", "mid.zip.unpacked/m "}
	if got := paths(res.Entries); !slices.Equal(got, want) {
		t.Errorf("entries = %v, want %v", got, want)
	}

	dest, _, err := extract(t, f, Options{})
	if e := wantKind(t, err, NeedsPassword); e.Archive != "mid.zip.unpacked/bad.zip" {
		t.Errorf("archive = %q", e.Archive)
	}
	wantEmpty(t, dest)
}

// TestLeavePacked checks that a nested archive left packed takes what was
// recorded below it with it, and removes its directory without following
// links.
func TestLeavePacked(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "keep"), []byte("k"), 0o644); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(root, "a.zip.unpacked")
	if err := os.MkdirAll(filepath.Join(sub, "locked"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(sub, "link")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(sub, "locked"), 0); err != nil {
		t.Fatal(err)
	}
	x := &extractor{root: root, flags: map[string][]string{"a.zip": {FlagUnpacked}, "a.zip.unpacked/b.zip": {FlagDepthLimit}}, unpacked: map[string]string{"a.zip.unpacked/c.zip": "a.zip.unpacked/c.zip.unpacked"}}
	x.dropped = []Entry{file("before", 1)}
	m := x.mark()
	x.dropped = append(x.dropped, file("a.zip.unpacked/x", 1))
	x.failed = append(x.failed, &Error{Kind: Rejected, Archive: "a.zip.unpacked/d.zip"})
	if err := x.leavePacked(sub, m); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(sub); err == nil {
		t.Error("the directory is still there")
	}
	if _, err := os.Stat(filepath.Join(outside, "keep")); err != nil {
		t.Errorf("followed a link: %v", err)
	}
	if len(x.dropped) != 1 || len(x.failed) != 0 || len(x.unpacked) != 0 || len(x.flags) != 1 || x.flags["a.zip"] == nil {
		t.Errorf("left %+v", x)
	}
}

func TestKindFlag(t *testing.T) {
	for k, want := range map[Kind]string{Rejected: FlagRejected, NeedsPassword: FlagNeedsPassword, TooLarge: FlagTooLarge, Failed: FlagFailed, NotArchive: FlagFailed} {
		if got := k.Flag(); got != want {
			t.Errorf("%s.Flag() = %q, want %q", k, got, want)
		}
	}
}
