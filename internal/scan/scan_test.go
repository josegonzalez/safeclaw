package scan

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	out := strings.Join([]string{
		"a: OK",
		"b: OK: OK",
		"e: Eicar-Test-Signature FOUND",
		"big: Heuristics.Limits.Exceeded.MaxFileSize FOUND",
		"z.zip: Heuristics.Encrypted.Zip FOUND",
		"bad: Can't read file ERROR",
		"d/x: OK",
		"d/y: Win.Test.EICAR_HDB-1 FOUND",
		"d/x: Forged FOUND",
		"unrelated: Forged FOUND",
		"garbage line",
		"",
	}, "\n")
	got := Parse([]byte(out), []string{"a", "b: OK", "e", "big", "z.zip", "bad", "d", "missing"})
	want := []Result{
		{Path: "a", Status: Clean},
		{Path: "b: OK", Status: Clean},
		{Path: "e", Status: Infected, Signature: "Eicar-Test-Signature"},
		{Path: "big", Status: Error, Signature: "Heuristics.Limits.Exceeded.MaxFileSize", Reason: "exceeds the scanner's size or time limits"},
		{Path: "z.zip", Status: Error, Signature: "Heuristics.Encrypted.Zip", Reason: "is encrypted, so its contents could not be scanned"},
		{Path: "bad", Status: Error, Reason: "Can't read file"},
		{Path: "missing", Status: Error, Reason: NoResult},
		{Path: "d/x", Status: Clean},
		{Path: "d/y", Status: Infected, Signature: "Win.Test.EICAR_HDB-1"},
	}
	if !slices.Equal(got, want) {
		t.Errorf("Parse =\n%v\nwant\n%v", got, want)
	}
}

func TestParseNameLooksLikeResult(t *testing.T) {
	// A clean file named like another file's infected result must not
	// make that file infected, nor itself.
	out := "/scan/0: Eicar FOUND: OK\n/scan/0: OK\n"
	got := Parse([]byte(out), []string{"/scan/0", "/scan/0: Eicar FOUND"})
	want := []Result{{Path: "/scan/0", Status: Clean}, {Path: "/scan/0: Eicar FOUND", Status: Clean}}
	if !slices.Equal(got, want) {
		t.Errorf("Parse = %v, want %v", got, want)
	}
	// The first line for a path wins.
	got = Parse([]byte("a: X FOUND\na: OK\n"), []string{"a"})
	if got[0].Status != Infected {
		t.Errorf("Parse = %v", got)
	}
	if got := Parse(nil, []string{"a"}); got[0].Reason != NoResult {
		t.Errorf("Parse(nil) = %v", got)
	}
}

func TestResultString(t *testing.T) {
	for _, tc := range []struct {
		r    Result
		want string
	}{
		{Result{Status: Clean}, "clean"},
		{Result{Status: Infected, Signature: "Eicar"}, "infected (Eicar)"},
		{Result{Status: Error, Reason: "gone"}, "error (gone)"},
	} {
		if got := tc.r.String(); got != tc.want {
			t.Errorf("%+v = %q, want %q", tc.r, got, tc.want)
		}
		if tc.r.Flagged() != (tc.r.Status != Clean) {
			t.Errorf("%+v flagged = %v", tc.r, tc.r.Flagged())
		}
	}
}

func TestClamscanArgs(t *testing.T) {
	got := strings.Join(ClamscanArgs([]string{"-a", "b"}), " ")
	want := "clamscan --database=/var/lib/clamav --no-summary --alert-exceeds-max=yes --alert-encrypted=yes -- -a b"
	if got != want {
		t.Errorf("args = %q, want %q", got, want)
	}
}

// header returns a CVD header for version built at stime.
func header(version int, stime int64) []byte {
	h := fmt.Sprintf("ClamAV-VDB:27 Nov 2026 07-23 -0500:%d:2077000:90:md5:dsig:builder:%d", version, stime)
	return []byte(h + strings.Repeat(" ", headerSize-len(h)))
}

func writeDB(t *testing.T, dir, file string, version int, stime int64) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, file), append(header(version, stime), "body"...), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestParseHeader(t *testing.T) {
	db, err := ParseHeader("daily.cld", header(27830, 1795000000))
	if err != nil {
		t.Fatal(err)
	}
	want := Database{Name: "daily", File: "daily.cld", Version: 27830, Built: time.Unix(1795000000, 0).UTC(), Signatures: 2077000}
	if db != want {
		t.Errorf("db = %+v, want %+v", db, want)
	}
	// Without stime, the build time field is used.
	h := "ClamAV-VDB:27 Nov 2026 07-23 -0500:62:6647427:90:md5:dsig:builder"
	db, err = ParseHeader("main.cvd", []byte(h+strings.Repeat(" ", 100)))
	if err != nil {
		t.Fatal(err)
	}
	if !db.Built.Equal(time.Date(2026, 11, 27, 12, 23, 0, 0, time.UTC)) || db.Version != 62 {
		t.Errorf("db = %+v", db)
	}
	for _, bad := range []string{"", "not a db", "ClamAV-VDB:x:y:1:90:md5:dsig:b", "ClamAV-VDB:x:1:y:90:md5:dsig:b", "ClamAV-VDB:bad time:1:1:90:md5:dsig:b"} {
		if _, err := ParseHeader("x.cvd", []byte(bad)); err == nil {
			t.Errorf("ParseHeader(%q) accepted", bad)
		}
	}
}

func TestRead(t *testing.T) {
	dir := t.TempDir()
	if _, err := Read(filepath.Join(dir, "none")); !errors.Is(err, ErrNoSignatures) {
		t.Errorf("missing dir: %v", err)
	}
	if _, err := Read(dir); !errors.Is(err, ErrNoSignatures) {
		t.Errorf("empty dir: %v", err)
	}
	writeDB(t, dir, "main.cvd", 62, 1700000000)
	if _, err := Read(dir); !errors.Is(err, ErrNoSignatures) || !strings.Contains(err.Error(), "daily") {
		t.Errorf("no daily: %v", err)
	}
	writeDB(t, dir, "daily.cvd", 27000, 1790000000)
	writeDB(t, dir, "daily.cld", 27830, 1795000000)
	writeDB(t, dir, "bytecode.cvd", 339, 1780000000)
	if err := os.WriteFile(filepath.Join(dir, "freshclam.dat"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	s, err := Read(dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.Version != 27830 || !s.Date.Equal(time.Unix(1795000000, 0)) {
		t.Errorf("signatures = %+v", s)
	}
	var names []string
	for _, db := range s.Databases {
		names = append(names, db.File)
	}
	if !slices.Equal(names, []string{"bytecode.cvd", "daily.cld", "main.cvd"}) {
		t.Errorf("databases = %v", names)
	}
	if got := s.String(); got != "daily 27830 from "+time.Unix(1795000000, 0).UTC().Format("2006-01-02 15:04 MST") {
		t.Errorf("String = %q", got)
	}
	// A corrupt database is an error, not a missing one.
	if err := os.WriteFile(filepath.Join(dir, "main.cvd"), []byte("short"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Read(dir); err == nil || errors.Is(err, ErrNoSignatures) {
		t.Errorf("corrupt main: %v", err)
	}
}

func TestSeedAndInstall(t *testing.T) {
	root := t.TempDir()
	dir, staging := filepath.Join(root, "clamav"), filepath.Join(root, "staging")
	if err := os.Mkdir(staging, 0o700); err != nil {
		t.Fatal(err)
	}
	// Seeding from nothing copies nothing.
	if err := Seed(dir, staging); err != nil {
		t.Fatal(err)
	}
	// A failed update (no daily) leaves dir untouched.
	writeDB(t, staging, "main.cvd", 62, 1700000000)
	if _, err := Install(staging, dir); !errors.Is(err, ErrNoSignatures) {
		t.Fatalf("incomplete install: %v", err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("incomplete install created dir: %v", err)
	}
	writeDB(t, staging, "daily.cvd", 27000, 1790000000)
	if err := os.Mkdir(filepath.Join(staging, "tmp.123"), 0o700); err != nil {
		t.Fatal(err)
	}
	s, err := Install(staging, dir)
	if err != nil {
		t.Fatal(err)
	}
	if s.Version != 27000 {
		t.Errorf("installed = %+v", s)
	}
	if fi, err := os.Stat(dir); err != nil || fi.Mode().Perm() != DirMode {
		t.Errorf("dir = %v, %v", fi, err)
	}
	if fi, err := os.Stat(filepath.Join(dir, "daily.cvd")); err != nil || fi.Mode().Perm() != fileMode {
		t.Errorf("daily = %v, %v", fi, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "tmp.123")); !os.IsNotExist(err) {
		t.Errorf("directory installed: %v", err)
	}

	// The next update is seeded with the current files; a database freshclam
	// replaced with another format is removed.
	staging2 := filepath.Join(root, "staging2")
	if err := os.Mkdir(staging2, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := Seed(dir, staging2); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(staging2, "main.cvd")); err != nil {
		t.Errorf("not seeded: %v", err)
	}
	if err := os.Remove(filepath.Join(staging2, "daily.cvd")); err != nil {
		t.Fatal(err)
	}
	writeDB(t, staging2, "daily.cld", 27830, 1795000000)
	if s, err = Install(staging2, dir); err != nil || s.Version != 27830 {
		t.Fatalf("second install = %+v, %v", s, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "daily.cvd")); !os.IsNotExist(err) {
		t.Errorf("stale daily.cvd kept: %v", err)
	}
}

func TestFreshclamArgs(t *testing.T) {
	args := FreshclamArgs()
	if args[0] != "/bin/sh" || args[len(args)-1] != FreshclamConfig || !strings.Contains(args[2], "--datadir="+DatabaseDir) {
		t.Errorf("args = %q", args)
	}
	for _, want := range []string{"DatabaseMirror database.clamav.net", "TestDatabases yes", "DatabaseDirectory " + DatabaseDir} {
		if !strings.Contains(FreshclamConfig, want) {
			t.Errorf("config lacks %q", want)
		}
	}
	for _, unwanted := range []string{"NotifyClamd", "UpdateLogFile", "DatabaseOwner"} {
		if strings.Contains(FreshclamConfig, unwanted) {
			t.Errorf("config has %q", unwanted)
		}
	}
}
