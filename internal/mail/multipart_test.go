package mail

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func split(t *testing.T, body, boundary string) ([]string, error) {
	t.Helper()
	s := newSplitter(strings.NewReader(body), boundary)
	var parts []string
	for {
		r, err := s.next()
		if err == io.EOF {
			return parts, nil
		}
		if err != nil {
			return parts, err
		}
		b, err := io.ReadAll(r)
		parts = append(parts, string(b))
		if err != nil {
			return parts, err
		}
	}
}

func TestSplitter(t *testing.T) {
	for _, c := range []struct {
		name, body string
		want       []string
		err        bool
	}{
		{"crlf", "--b\r\nA\r\n--b\r\nB\r\n--b--\r\n", []string{"A", "B"}, false},
		{"lf", "--b\nA\n--b\nB\n--b--\n", []string{"A", "B"}, false},
		{"preamble and epilogue", "pre\r\n--b\r\nA\r\n--b--\r\nepilogue\r\n--b\r\nignored\r\n", []string{"A"}, false},
		{"transport padding", "--b \t\r\nA\r\n--b  \r\nB\r\n--b-- \r\n", []string{"A", "B"}, false},
		{"not at line start", "--b\r\nA --b\r\n--b--", []string{"A --b"}, false},
		{"longer boundary", "--b\r\nA\r\n--bc\r\n--b--", []string{"A\r\n--bc"}, false},
		{"keeps line breaks", "--b\r\n\r\nA\r\n\r\n\r\n--b--", []string{"\r\nA\r\n\r\n"}, false},
		{"empty part", "--b\r\n--b--", []string{""}, false},
		{"close at end of input", "--b\r\nA\r\n--b--", []string{"A"}, false},
		{"no close", "--b\r\nA\r\n", []string{"A\r\n"}, true},
		{"no delimiter", "just text\r\n", nil, true},
		{"empty", "", nil, true},
		{"long line", "--b\r\n" + strings.Repeat("x", 3*readBuffer) + "\r\n--b--", []string{strings.Repeat("x", 3*readBuffer)}, false},
	} {
		got, err := split(t, c.body, "b")
		if !slices.Equal(got, c.want) || (err != nil) != c.err {
			t.Errorf("%s: %.60q, %v; want %.60q, err %v", c.name, got, err, c.want, c.err)
		}
		if err != nil && !errors.Is(err, errNoDelimiter) {
			t.Errorf("%s: err = %v", c.name, err)
		}
	}
}

// TestBadPartHeader checks that a part header net/mail can't parse, or one
// mime/multipart's stricter parser would refuse, doesn't hide the parts
// after it.
func TestBadPartHeader(t *testing.T) {
	msg := head + "Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: text/plain\r\n\r\nfirst\r\n" +
		"--b\r\nno colon on this line\r\n\r\nraw part\r\n" +
		"--b\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=\"ctl\x1b\x01.pdf\"\r\nBad Key: spaces\r\n\r\n%PDF\r\n" +
		"--b\r\n continuation first\r\n\r\nalso raw\r\n" +
		"--b\r\nContent-Type: text/plain\r\n\r\nlast\r\n" +
		"--b--\r\n"
	dest, res, err := extract(t, msg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	wantParts(t, res.Parts,
		"1 multipart/mixed",
		"1.1 text/plain BODY body.txt",
		"1.2 application/octet-stream ATTACHMENT,MALFORMED 1-attachment",
		"1.3 application/pdf ATTACHMENT,UNSAFE-NAME 2-ctl.pdf",
		"1.4 application/octet-stream ATTACHMENT,MALFORMED 3-attachment",
		"1.5 text/plain BODY body.txt",
	)
	if got := readFile(t, dest, "1-attachment"); got != "no colon on this line\r\n\r\nraw part" {
		t.Errorf("raw part = %q", got)
	}
	if body := readFile(t, dest, BodyFile); !strings.HasSuffix(body, "\n\nfirst\n\nlast\n") {
		t.Errorf("body.txt = %q", body)
	}
}

// FuzzList runs List and Extract on arbitrary input: neither may panic,
// fail other than with an *Error, or write outside the destination, and
// everything List reports must be printable as given.
func FuzzList(f *testing.F) {
	f.Add(head + "\r\nbody\r\n")
	f.Add(forwarded(3))
	f.Add(head + nestedMultipart(5))
	f.Add(head + "Content-Type: multipart/alternative; boundary=b\r\n\r\n--b\r\nContent-Type: text/html\r\n\r\n<p>x<script>y</script>\r\n--b\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\na=3Db=\r\n\r\n--b--\r\n")
	f.Add(head + "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Disposition: attachment; filename=\"=?utf-8?q?..=2F..=2Fx?=\"\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8\r\n--b")
	f.Add("From x\nSubject: =?iso-8859-1?b?Y2Fm6Q==?=\n\n")
	f.Add("Subject: x\r\nContent-Type: message/rfc822\r\n\r\nSubject: y\r\nContent-Type: multipart/digest; boundary=d\r\n\r\n--d\r\n\r\nSubject: z\r\n\r\n--d--")
	f.Fuzz(func(t *testing.T, msg string) {
		dir := t.TempDir()
		file := filepath.Join(dir, "m.eml")
		if err := os.WriteFile(file, []byte(msg), 0o644); err != nil {
			t.Fatal(err)
		}
		o := Options{Depth: 2, MaxSize: 1 << 20}
		res, err := List(t.Context(), file, o)
		var e *Error
		if err != nil && !errors.As(err, &e) {
			t.Fatalf("List: %T %v", err, err)
		}
		if err == nil {
			for _, h := range res.Headers {
				if h.Value != CleanLine(h.Value) {
					t.Errorf("header %q not clean", h.Value)
				}
			}
			for _, p := range res.Parts {
				if p.Type != CleanLine(p.Type) {
					t.Errorf("type %q not clean", p.Type)
				}
			}
		}
		dest := filepath.Join(dir, "out")
		xres, xerr := Extract(t.Context(), file, dest, o)
		if xerr != nil && !errors.As(xerr, &e) {
			t.Fatalf("Extract: %T %v", xerr, xerr)
		}
		if (err == nil) != (xerr == nil) && KindOf(xerr) != TooLarge {
			t.Errorf("List err %v, Extract err %v", err, xerr)
		}
		names, _ := os.ReadDir(dir)
		if len(names) != 2 {
			t.Errorf("dir has %d entries", len(names))
		}
		if xerr != nil {
			wantEmpty(t, dest)
			return
		}
		for _, p := range xres.Parts {
			if p.File == "" || p.File == BodyFile {
				continue
			}
			if p.File != SafeName(p.File) || filepath.Base(p.File) != p.File {
				t.Errorf("unsafe file %q", p.File)
			}
		}
	})
}
