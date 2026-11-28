package unpack

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestUnsafePath(t *testing.T) {
	for p, want := range map[string]bool{
		"a.txt":             false,
		"dir/a.txt":         false,
		"./a":               false,
		"a..b":              false,
		"..a/b":             false,
		"dir/":              false,
		"x*y?.txt":          false,
		"résumé.pdf":        false,
		"ab:c":              false,
		"":                  true,
		"/etc/passwd":       true,
		"\\windows":         true,
		"\\\\server\\share": true,
		"C:/x":              true,
		"c:x":               true,
		"..":                true,
		"../a":              true,
		"a/../../b":         true,
		"a\\..\\b":          true,
		"a/..":              true,
		"tab\there":         true,
		"new\nline":         true,
		"esc\x1b[31m":       true,
		"del\x7f":           true,
		"c1\u0085":          true,
		"bad\xff":           true,
	} {
		if got := UnsafePath(p); got != want {
			t.Errorf("UnsafePath(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestEntryFlags(t *testing.T) {
	e := Entry{Path: "../x", Type: TypeSymlink, Encrypted: true, UnsafePath: true, Extra: []string{FlagDropped}}
	if got := e.Flags(); !slices.Equal(got, []string{FlagEncrypted, FlagLink, FlagUnsafePath, FlagDropped}) || !e.Bad() {
		t.Errorf("flags = %v, bad = %v", got, e.Bad())
	}
	for _, e := range []Entry{{Type: TypeHardlink}, {Type: TypeSpecial}, {Type: TypeFile, UnsafePath: true}} {
		if !e.Bad() {
			t.Errorf("%+v should be bad", e)
		}
	}
	if e := (Entry{Path: "a", Type: TypeFile, Encrypted: true}); e.Bad() || !slices.Equal(e.Flags(), []string{FlagEncrypted}) {
		t.Errorf("an encrypted file is not bad: %+v %v", e, e.Flags())
	}
	if f := (Entry{Path: "a", Type: TypeDir}).Flags(); f != nil {
		t.Errorf("flags = %v", f)
	}
}

func readFixture(t *testing.T, name string) *Listing {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	l, err := ParseListing(string(data))
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return l
}

type want struct {
	path, typ string
	size      int64
	flags     string
}

func checkEntries(t *testing.T, name string, l *Listing, wants []want) {
	t.Helper()
	if len(l.Entries) != len(wants) {
		t.Fatalf("%s: %d entries, want %d: %+v", name, len(l.Entries), len(wants), l.Entries)
	}
	for i, w := range wants {
		e := l.Entries[i]
		if e.Path != w.path || e.Type != w.typ || e.Size != w.size || strings.Join(e.Flags(), ",") != w.flags {
			t.Errorf("%s entry %d = %q %s %d %v, want %+v", name, i, e.Path, e.Type, e.Size, e.Flags(), w)
		}
	}
}

func TestParseListingTar(t *testing.T) {
	l := readFixture(t, "tar.slt")
	if l.Type != "tar" {
		t.Errorf("type = %q", l.Type)
	}
	checkEntries(t, "tar", l, []want{
		{"ok.txt", TypeFile, 5, ""},
		{"../up.txt", TypeFile, 5, FlagUnsafePath},
		{"/abs.txt", TypeFile, 5, FlagUnsafePath},
		{"sym", TypeSymlink, 11, FlagLink},
		{"hard", TypeHardlink, 0, FlagLink},
		{"fifo", TypeSpecial, 0, FlagSpecial},
		{"ctl\x1bname", TypeFile, 5, FlagUnsafePath},
	})
	if l.Entries[3].Link != "/etc/passwd" || l.Entries[4].Link != "ok.txt" {
		t.Errorf("links = %q, %q", l.Entries[3].Link, l.Entries[4].Link)
	}
}

func TestParseListingZip(t *testing.T) {
	l := readFixture(t, "zip.slt")
	if l.Type != "zip" {
		t.Errorf("type = %q", l.Type)
	}
	checkEntries(t, "zip", l, []want{
		{"ok.txt", TypeFile, 2, ""},
		{"C:/drive.txt", TypeFile, 1, FlagUnsafePath},
		{"..\\back.txt", TypeFile, 1, FlagUnsafePath},
		{"zsym", TypeSymlink, 11, FlagLink},
	})

	// p7zip writes the attributes differently.
	l = readFixture(t, "p7zip-zip.slt")
	checkEntries(t, "p7zip zip", l, []want{
		{"d", TypeDir, 0, ""},
		{"d/a.txt", TypeFile, 3, ""},
		{"d/l", TypeSymlink, 5, FlagLink},
	})
}

func TestParseListing7z(t *testing.T) {
	l := readFixture(t, "7z-links.slt")
	if l.Type != "7z" {
		t.Errorf("type = %q", l.Type)
	}
	checkEntries(t, "7z", l, []want{
		{"d", TypeDir, 0, ""},
		{"a.txt", TypeFile, 6, ""},
		{"d/b c*.txt", TypeFile, 2, ""},
		{"link", TypeSymlink, 11, FlagLink},
	})
	checkEntries(t, "encrypted 7z", readFixture(t, "7z-encrypted.slt"), []want{
		{"a.txt", TypeFile, 6, FlagEncrypted},
	})
}

func TestParseListingGzip(t *testing.T) {
	l := readFixture(t, "gzip.slt")
	if l.Type != "gzip" {
		t.Errorf("type = %q", l.Type)
	}
	checkEntries(t, "gzip", l, []want{{"t.tar", TypeFile, 10240, ""}})
}

func TestParseListingShapes(t *testing.T) {
	const head = "--\nPath = x\nType = tar\n\n----------\n"
	l, err := ParseListing(head + "Path = a\nSize = \nAttributes = D....\n\nPath = b\nSize = 3\nMode = crw-r--r--\n\nPath = c\nAttributes = L\n\nPath = d\nAttributes = d\n\nErrors: 1\n\nPath = after\n")
	if err != nil {
		t.Fatal(err)
	}
	checkEntries(t, "shapes", l, []want{
		{"a", TypeDir, -1, ""},
		{"b", TypeSpecial, 3, FlagSpecial},
		{"c", TypeSymlink, -1, FlagLink},
		{"d", TypeSpecial, -1, FlagSpecial},
	})

	// "Key =" with its trailing space trimmed, and CRLF line ends.
	l, err = ParseListing(strings.ReplaceAll(head+"Path = a\nSymbolic Link =\nSize = 1\n", "\n", "\r\n"))
	if err != nil || len(l.Entries) != 1 || l.Entries[0].Type != TypeFile || l.Entries[0].Size != 1 {
		t.Errorf("trimmed = %+v, %v", l, err)
	}
	if l, err := ParseListing(head); err != nil || len(l.Entries) != 0 {
		t.Errorf("empty archive = %+v, %v", l, err)
	}

	for name, out := range map[string]string{
		"no separator":  "Path = a\n",
		"repeated key":  head + "Path = a\nPath = b\n",
		"no path first": head + "Size = 1\nPath = a\n",
		"stray line":    head + "Path = a\nnot a property\n",
		"bad size":      head + "Path = a\nSize = -1\n",
		"size not int":  head + "Path = a\nSize = lots\n",
	} {
		if _, err := ParseListing(out); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestSplitAttributes(t *testing.T) {
	for v, want := range map[string][2]string{
		"D drwxr-xr-x":          {"D", "drwxr-xr-x"},
		"A -rw-r--r--":          {"A", "-rw-r--r--"},
		"V 01800000 0rw-------": {"V", "0rw-------"},
		" lrwxrwxrwx":           {"", "lrwxrwxrwx"},
		"_ lrwxr-xr-x":          {"_", "lrwxr-xr-x"},
		"D....":                 {"D....", ""},
		"RHA":                   {"RHA", ""},
		"":                      {"", ""},
		"weird value":           {"", ""},
	} {
		win, mode := splitAttributes(v)
		if win != want[0] || mode != want[1] {
			t.Errorf("splitAttributes(%q) = %q, %q, want %q", v, win, mode, want)
		}
	}
}
