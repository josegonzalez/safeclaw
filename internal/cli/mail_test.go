package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

const testMail = "From: =?utf-8?q?Eve_=1B[2J?= <eve@example.com>\r\nSubject: Invoice\x1b]0;x\x07\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" +
	"--b\r\nContent-Type: text/plain\r\n\r\nPlease pay.\r\n" +
	"--b\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"../in\tv\x1b.pdf\"\r\n\r\n%PDF\r\n" +
	"--b--\r\n"

func runMail(t *testing.T, args ...string) (string, string, error) {
	t.Helper()
	cmd := newMailCommand("mail")
	var out, errOut bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&errOut)
	cmd.SetArgs(args)
	err := cmd.ExecuteContext(t.Context())
	return out.String(), errOut.String(), err
}

func writeTestMail(t *testing.T, data string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "m.eml")
	if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestMailList(t *testing.T) {
	file := writeTestMail(t, testMail)
	out, _, err := runMail(t, "list", file)
	if err != nil {
		t.Fatal(err)
	}
	want := "From: Eve [2J <eve@example.com>\nSubject: Invoice]0;x\n\n" +
		"1\tmultipart/mixed\t-\t-\t-\n" +
		"1.1\ttext/plain\t11\t-\tBODY\n" +
		"1.2\tapplication/pdf\t4\t../in\\tv\\x1b.pdf\tATTACHMENT,UNSAFE-NAME\n"
	if out != want {
		t.Errorf("got\n%q\nwant\n%q", out, want)
	}

	out, _, err = runMail(t, "list", "--json", file)
	if err != nil {
		t.Fatal(err)
	}
	var v mailJSON
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatal(err)
	}
	if v.Status != "ok" || len(v.Parts) != 3 || v.Parts[0].Size != nil || v.Parts[2].Name != "../in\tv\x1b.pdf" || v.Headers[1].Value != "Invoice]0;x" {
		t.Errorf("json = %+v", v)
	}
	if strings.ContainsAny(out, "\x1b\x07") {
		t.Errorf("json has raw control characters: %q", out)
	}
}

func TestMailExtract(t *testing.T) {
	file := writeTestMail(t, testMail)
	dest := filepath.Join(t.TempDir(), "out")
	out, _, err := runMail(t, "extract", file, dest)
	if err != nil {
		t.Fatal(err)
	}
	want := "1\tmultipart/mixed\t-\t-\t-\t-\n" +
		"1.1\ttext/plain\t11\t-\tBODY\tbody.txt\n" +
		"1.2\tapplication/pdf\t4\t../in\\tv\\x1b.pdf\tATTACHMENT,UNSAFE-NAME\t1-_in v.pdf\n"
	if out != want {
		t.Errorf("got\n%q\nwant\n%q", out, want)
	}
	if b, err := os.ReadFile(filepath.Join(dest, "1-_in v.pdf")); err != nil || string(b) != "%PDF" {
		t.Errorf("attachment = %q, %v", b, err)
	}

	out, _, err = runMail(t, "extract", "--json", file, filepath.Join(t.TempDir(), "j"))
	var v mailJSON
	if err != nil || json.Unmarshal([]byte(out), &v) != nil || v.Body != "body.txt" || v.Parts[2].File != "1-_in v.pdf" {
		t.Errorf("json = %q, %v", out, err)
	}
}

func TestMailFailure(t *testing.T) {
	for _, c := range []struct {
		name string
		data string
		args []string
		code int
	}{
		{"not a message", "plain text\n", nil, 5},
		{"rejected", "Subject: x\r\n" + strings.Repeat("X: y\r\n", 1001) + "\r\n", nil, 2},
		{"too large", "Subject: x\r\n\r\n" + strings.Repeat("x", 5000), []string{"--max-size", "1k"}, 4},
		{"bad size", "Subject: x\r\n\r\nx", []string{"--max-size", "nope"}, 1},
		{"bad depth", "Subject: x\r\n\r\nx", []string{"--depth", "-1"}, 1},
	} {
		file := writeTestMail(t, c.data)
		dest := filepath.Join(t.TempDir(), "out")
		args := append(append([]string{"extract"}, c.args...), file, dest)
		_, errOut, err := runMail(t, args...)
		if !errors.Is(err, exitCodeError{c.code}) || !strings.HasPrefix(errOut, "mail: ") {
			t.Errorf("%s: err = %v, stderr = %q", c.name, err, errOut)
		}
		args = append(append([]string{"extract", "--json"}, c.args...), file, filepath.Join(t.TempDir(), "out"))
		out, _, _ := runMail(t, args...)
		var v mailJSON
		if json.Unmarshal([]byte(out), &v) != nil || v.Code != c.code || v.Status == "ok" || v.Error == "" {
			t.Errorf("%s: json = %q", c.name, out)
		}
		if names, _ := os.ReadDir(dest); len(names) > 0 {
			t.Errorf("%s: dest not emptied", c.name)
		}
	}
}

// TestMailProgramName checks that the binary run as safeclaw-mail is
// `safeclaw mail`, and that `safeclaw mail` is registered.
func TestMailProgramName(t *testing.T) {
	for arg0, want := range map[string]bool{
		"safeclaw-mail":                true,
		"/usr/local/bin/safeclaw-mail": true,
		"safeclaw":                     false,
		"safeclaw-unpack":              false,
		"safeclaw-mail-old":            false,
	} {
		if got := isMailProgram(arg0); got != want {
			t.Errorf("isMailProgram(%q) = %v", arg0, got)
		}
	}
	if code := executeMail(t.Context(), []string{"list"}); code != 1 {
		t.Errorf("missing file exit = %d", code)
	}
	if code := executeMail(t.Context(), []string{"--help"}); code != 0 {
		t.Errorf("--help exit = %d", code)
	}
	if code := executeMail(t.Context(), []string{"list", writeTestMail(t, "nope")}); code != 5 {
		t.Errorf("not a message exit = %d", code)
	}
	var found *cobra.Command
	for _, c := range NewRootCommand().Commands() {
		if c.Name() == "mail" {
			found = c
		}
	}
	if found == nil {
		t.Error("safeclaw has no mail command")
	}
}
