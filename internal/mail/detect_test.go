package mail

import (
	"errors"
	"io"
	"strings"
	"testing"
)

func TestDetect(t *testing.T) {
	for name, c := range map[string]struct {
		in   string
		want bool
	}{
		"message":          {"From: a@example.com\r\nSubject: x\r\n\r\nbody", true},
		"header only":      {"Subject: x\n", true},
		"mbox line":        {"From a@example.com Mon Jan  1 00:00:00 2024\nTo: b@example.com\n\nx", true},
		"lowercase field":  {"message-id: <x@y>\n\n", true},
		"body.txt":         {"From: Eve <eve@example.com>\nSubject: report\n\nsee attached\n", true},
		"no message field": {"Name: value\nOther: x\n\nbody", false},
		"plain text":       {"just some text\nand more\n", false},
		"empty":            {"", false},
		"mbox line only":   {"From a@example.com Mon Jan  1 00:00:00 2024", false},
		"binary":           {"\x00\x01\x02PK\x03\x04", false},
		"too many fields":  {"Subject: x\n" + strings.Repeat("X: y\n", MaxHeaderFields+1) + "\n", false},
		"long line":        {"Subject: " + strings.Repeat("x", MaxHeaderLine+1) + "\n\n", false},
		"part listing":     {"1\ttext/plain\t5\t-\tBODY\tbody.txt\n", false},
	} {
		got, err := Detect(strings.NewReader(c.in))
		if err != nil || got != c.want {
			t.Errorf("%s: Detect = %v, %v, want %v", name, got, err, c.want)
		}
	}
	boom := errors.New("boom")
	if _, err := Detect(io.MultiReader(strings.NewReader("Subject: x\n"), &errReader{boom})); !errors.Is(err, boom) {
		t.Errorf("read error = %v", err)
	}
}

type errReader struct{ err error }

func (e *errReader) Read([]byte) (int, error) { return 0, e.err }

func TestWriteParts(t *testing.T) {
	var b strings.Builder
	parts := []Part{{ID: "1", Type: "multipart/mixed", Size: -1}, {ID: "1.1", Type: "text/plain", Size: 3, File: BodyFile}, {ID: "1.2", Type: "application/pdf", Size: 4, Name: "a\tb\\c\x1b.pdf", File: "1-ab_c.pdf"}}
	parts[1].set(FlagBody)
	parts[2].set(FlagAttachment)
	parts[2].set(FlagUnsafeName)
	if err := WriteParts(&b, parts, true); err != nil {
		t.Fatal(err)
	}
	want := "1\tmultipart/mixed\t-\t-\t-\t-\n1.1\ttext/plain\t3\t-\tBODY\tbody.txt\n1.2\tapplication/pdf\t4\ta\\tb\\\\c\\x1b.pdf\tATTACHMENT,UNSAFE-NAME\t1-ab_c.pdf\n"
	if b.String() != want {
		t.Errorf("WriteParts =\n%q\nwant\n%q", b.String(), want)
	}
}
