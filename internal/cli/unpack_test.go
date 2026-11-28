package cli

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/unpack"
)

func TestEscapeField(t *testing.T) {
	for in, want := range map[string]string{
		"plain.txt":      "plain.txt",
		"a b/c.txt":      "a b/c.txt",
		"tab\there":      `tab\there`,
		"new\nline":      `new\nline`,
		"esc\x1b[2J":     `esc\x1b[2J`,
		`back\slash`:     `back\\slash`,
		`fake\x1b`:       `fake\\x1b`,
		"bidi\u202ename": "bidi\\u202ename",
		"bad\xff":        `bad\xff`,
		"résumé":         "résumé",
	} {
		if got := escapeField(in); got != want {
			t.Errorf("escapeField(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestWriteEntries(t *testing.T) {
	var b bytes.Buffer
	err := writeEntries(&b, []unpack.Entry{
		{Path: "a.txt", Type: unpack.TypeFile, Size: 3},
		{Path: "d", Type: unpack.TypeDir, Size: -1},
		{Path: "../x\ty", Type: unpack.TypeSymlink, Size: -1, UnsafePath: true, Extra: []string{unpack.FlagDropped}},
		{Path: "s.zip", Type: unpack.TypeFile, Size: 9, Encrypted: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "file\t3\ta.txt\t-\n" +
		"dir\t-\td\t-\n" +
		"symlink\t-\t../x\\ty\tLINK,UNSAFE-PATH,DROPPED\n" +
		"file\t9\ts.zip\tENCRYPTED\n"
	if b.String() != want {
		t.Errorf("got\n%q\nwant\n%q", b.String(), want)
	}
}

func TestUnpackFailure(t *testing.T) {
	bad := []unpack.Entry{{Path: "/etc/x", Type: unpack.TypeFile, Size: 1, UnsafePath: true}}
	for _, c := range []struct {
		err  error
		code int
	}{
		{&unpack.Error{Kind: unpack.Rejected, Msg: "1 entry", Bad: bad}, 2},
		{&unpack.Error{Kind: unpack.NeedsPassword, Msg: "no password"}, 3},
		{&unpack.Error{Kind: unpack.TooLarge, Msg: "big"}, 4},
		{&unpack.Error{Kind: unpack.Failed, Msg: "7z"}, 1},
		{errors.New("other"), 1},
	} {
		cmd := newUnpackCommand("unpack")
		var out, errOut bytes.Buffer
		cmd.SetOut(&out)
		cmd.SetErr(&errOut)
		err := unpackFailure(cmd, false, c.err, nil)
		if !errors.Is(err, exitCodeError{c.code}) || !strings.Contains(errOut.String(), c.err.Error()) {
			t.Errorf("%v: err = %v, stderr = %q", c.err, err, errOut.String())
		}
		if c.code == 2 && out.String() != "file\t1\t/etc/x\tUNSAFE-PATH\n" {
			t.Errorf("rejected stdout = %q", out.String())
		}

		out.Reset()
		errOut.Reset()
		_ = unpackFailure(cmd, true, c.err, nil)
		var v unpackJSON
		if err := json.Unmarshal(out.Bytes(), &v); err != nil || v.Code != c.code || v.Error != c.err.Error() || errOut.Len() != 0 {
			t.Errorf("%v: json = %s, %v", c.err, out.String(), err)
		}
		if c.code == 2 && (len(v.Rejected) != 1 || v.Rejected[0].Path != "/etc/x" || v.Status != "rejected") {
			t.Errorf("rejected json = %s", out.String())
		}
	}
}

func TestUnpackPassword(t *testing.T) {
	f := unpackFlags{passwordEnv: "SAFECLAW_TEST_UNPACK_PW"}
	t.Setenv(f.passwordEnv, "")
	if pw, err := f.password(); pw != nil || err != nil {
		t.Errorf("empty = %v, %v", pw, err)
	}
	t.Setenv(f.passwordEnv, "s3 cret")
	pw, err := f.password()
	if err != nil || pw == nil || *pw != "s3 cret" {
		t.Errorf("password = %v, %v", pw, err)
	}
	if _, ok := os.LookupEnv(f.passwordEnv); ok {
		t.Error("the password stayed in the environment")
	}
	t.Setenv(f.passwordEnv, "two\nlines")
	if _, err := f.password(); err == nil {
		t.Error("a password with a line break was accepted")
	}
}

func TestUnpackFlags(t *testing.T) {
	cmd := newUnpackExtractCommand()
	for name, want := range map[string]string{"max-size": "512m", "depth": "3", "drop-bad": "false", "json": "false", "password-env": unpackPasswordEnv} {
		if got := cmd.Flags().Lookup(name).DefValue; got != want {
			t.Errorf("--%s default = %q, want %q", name, got, want)
		}
	}
	for _, help := range []string{newUnpackCommand("unpack").Long, cmd.Long, newUnpackListCommand().Long} {
		for _, s := range []string{"Exit codes:", "2  rejected", "3  needs password", "4  too large", unpackPasswordEnv} {
			if !strings.Contains(help, s) {
				t.Errorf("help lacks %q", s)
			}
		}
	}
	if !strings.Contains(cmd.Long, "512m") && !strings.Contains(cmd.Flags().FlagUsages(), "512m") {
		t.Error("the --max-size default is not documented")
	}
	if _, err := run(t, newUnpackExtractCommand(), "--max-size", "lots", "a", "b"); !errors.Is(err, exitCodeError{1}) {
		t.Errorf("bad --max-size: %v", err)
	}
	if _, err := run(t, newUnpackExtractCommand(), "--depth", "-1", "a", "b"); !errors.Is(err, exitCodeError{1}) {
		t.Errorf("bad --depth: %v", err)
	}
}

// TestUnpackCommand runs list and extract with the real 7z on a generated
// archive, when there is one.
func TestUnpackCommand(t *testing.T) {
	if _, err := unpack.Find(); err != nil {
		t.Skip(err)
	}
	dir := t.TempDir()
	var b bytes.Buffer
	w := zip.NewWriter(&b)
	for _, name := range []string{"a.txt", "sub/b.txt"} {
		f, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = f.Write([]byte("hi"))
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(dir, "x.zip")
	if err := os.WriteFile(archive, b.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := run(t, newUnpackCommand("unpack"), "list", archive)
	if err != nil || out != "file\t2\ta.txt\t-\nfile\t2\tsub/b.txt\t-\n" {
		t.Errorf("list = %q, %v", out, err)
	}
	out, err = run(t, newUnpackCommand("unpack"), "list", "--json", archive)
	var v unpackJSON
	if err != nil || json.Unmarshal([]byte(out), &v) != nil || v.Status != "ok" || v.Type != "zip" || len(v.Entries) != 2 || *v.Entries[0].Size != 2 {
		t.Errorf("list --json = %q, %v", out, err)
	}
	dest := filepath.Join(dir, "out")
	out, err = run(t, newUnpackCommand("unpack"), "extract", archive, dest)
	if err != nil || out != "file\t2\ta.txt\t-\ndir\t-\tsub\t-\nfile\t2\tsub/b.txt\t-\n" {
		t.Errorf("extract = %q, %v", out, err)
	}
	if _, err := run(t, newUnpackCommand("unpack"), "extract", archive, dest); !errors.Is(err, exitCodeError{1}) {
		t.Errorf("extract into a non-empty dest: %v", err)
	}
}

// TestUnpackProgramName checks that the binary run as safeclaw-unpack is
// `safeclaw unpack`.
func TestUnpackProgramName(t *testing.T) {
	for arg0, want := range map[string]bool{
		"safeclaw-unpack":                true,
		"/usr/local/bin/safeclaw-unpack": true,
		"safeclaw":                       false,
		"/usr/local/bin/safeclaw":        false,
		"safeclaw-unpack-old":            false,
	} {
		if got := isUnpackProgram(arg0); got != want {
			t.Errorf("isUnpackProgram(%q) = %v", arg0, got)
		}
	}
	if code := executeUnpack(t.Context(), []string{"extract", "--max-size", "nope", "a", "b"}); code != 1 {
		t.Errorf("bad --max-size exit = %d", code)
	}
	if code := executeUnpack(t.Context(), []string{"list"}); code != 1 {
		t.Errorf("missing archive exit = %d", code)
	}
	if code := executeUnpack(t.Context(), []string{"--help"}); code != 0 {
		t.Errorf("--help exit = %d", code)
	}
}
