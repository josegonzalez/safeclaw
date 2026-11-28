package mail

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The messages here are generated, hostile ones included. Each is
// extracted two directories down, so a file that got out of the
// destination would land in the test's own directory, which noEscape
// checks.

func workdir(t *testing.T, msg string) (file, dest string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "a", "b")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	file = filepath.Join(dir, "msg.eml")
	if err := os.WriteFile(file, []byte(msg), 0o644); err != nil {
		t.Fatal(err)
	}
	return file, filepath.Join(dir, "out")
}

func noEscape(t *testing.T, dest string) {
	t.Helper()
	for _, dir := range []string{filepath.Dir(dest), filepath.Dir(filepath.Dir(dest))} {
		names, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, n := range names {
			switch n.Name() {
			case "out", "b", "msg.eml":
			default:
				t.Errorf("%s escaped into %s", n.Name(), dir)
			}
		}
	}
}

func extract(t *testing.T, msg string, o Options) (string, *Result, error) {
	t.Helper()
	if o.MaxSize == 0 {
		o.MaxSize = 10 << 20
	}
	file, dest := workdir(t, msg)
	res, err := Extract(t.Context(), file, dest, o)
	noEscape(t, dest)
	return dest, res, err
}

func list(t *testing.T, msg string, o Options) (*Result, error) {
	t.Helper()
	file, _ := workdir(t, msg)
	return List(t.Context(), file, o)
}

func wantKind(t *testing.T, err error, k Kind) *Error {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Kind != k {
		t.Fatalf("err = %v, want kind %v", err, k)
	}
	return e
}

func wantEmpty(t *testing.T, dir string) {
	t.Helper()
	names, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) > 0 {
		t.Errorf("%s has %d entries", dir, len(names))
	}
}

func readFile(t *testing.T, dir, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// summary is each part as "ID TYPE FLAGS FILE".
func summary(parts []Part) []string {
	var out []string
	for _, p := range parts {
		out = append(out, strings.TrimSpace(fmt.Sprintf("%s %s %s %s", p.ID, p.Type, strings.Join(p.Flags(), ","), p.File)))
	}
	return out
}

func wantParts(t *testing.T, parts []Part, want ...string) {
	t.Helper()
	if got := summary(parts); !slices.Equal(got, want) {
		t.Errorf("parts =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func b64(s string) string {
	return base64.StdEncoding.EncodeToString([]byte(s))
}

const head = "From: Alice <alice@example.com>\r\nTo: bob@example.com\r\nSubject: Hello\r\nDate: Mon, 2 Nov 2026 10:00:00 +0000\r\nMIME-Version: 1.0\r\n"

func TestPlain(t *testing.T) {
	msg := head + "Content-Type: text/plain; charset=utf-8\r\n\r\nHi Bob,\r\nsee you.\r\n"
	dest, res, err := extract(t, msg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	wantParts(t, res.Parts, "1 text/plain BODY body.txt")
	want := "From: Alice <alice@example.com>\nTo: bob@example.com\nDate: Mon, 2 Nov 2026 10:00:00 +0000\nSubject: Hello\n\nHi Bob,\nsee you.\n"
	if got := readFile(t, dest, BodyFile); got != want {
		t.Errorf("body.txt =\n%q\nwant\n%q", got, want)
	}
	if res.Parts[0].Size != 19 {
		t.Errorf("size = %d", res.Parts[0].Size)
	}

	// No Content-Type is text/plain, and an mbox From line is skipped.
	dest, res, err = extract(t, "From alice@example.com Mon Nov  2 10:00:00 2026\nSubject: x\n\nbody\n", Options{})
	if err != nil {
		t.Fatal(err)
	}
	wantParts(t, res.Parts, "1 text/plain BODY body.txt")
	if got := readFile(t, dest, BodyFile); got != "Subject: x\n\nbody\n" {
		t.Errorf("body.txt = %q", got)
	}
}

func TestHeadersDecodedAndStripped(t *testing.T) {
	msg := "From: =?utf-8?b?" + b64("Mallory \x1b[2J") + "?= <m@example.com>\r\n" +
		"Subject: =?iso-8859-1?q?caf=E9?= \x1b]0;title\x07 and\r\n more\u202e\r\n" +
		"Subject: second\r\n" +
		"To: =?x-unknown?q?raw?=\r\n" +
		"\r\nbody\r\n"
	res, err := list(t, msg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	want := []Header{
		{"From", "Mallory [2J <m@example.com>"},
		{"To", "=?x-unknown?q?raw?="},
		{"Subject", "café ]0;title and more"},
		{"Subject", "second"},
	}
	if !slices.Equal(res.Headers, want) {
		t.Errorf("headers = %q", res.Headers)
	}
}

func TestAlternative(t *testing.T) {
	msg := head + "Content-Type: multipart/alternative; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: text/html\r\n\r\n<p>html version</p>\r\n" +
		"--b\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nplain =\r\nversion=21\r\n" +
		"--b--\r\n"
	dest, res, err := extract(t, msg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	wantParts(t, res.Parts, "1 multipart/alternative", "1.1 text/html SKIPPED", "1.2 text/plain BODY body.txt")
	body := readFile(t, dest, BodyFile)
	if !strings.HasSuffix(body, "\n\nplain version!\n") || strings.Contains(body, "html") {
		t.Errorf("body.txt = %q", body)
	}

	// Without text/plain the HTML is used, without its scripts.
	msg = head + "Content-Type: multipart/alternative; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: text/calendar\r\n\r\nBEGIN:VCALENDAR\r\n" +
		"--b\r\nContent-Type: multipart/related; boundary=r\r\n\r\n" +
		"--r\r\nContent-Type: text/html; charset=iso-8859-1\r\nContent-Transfer-Encoding: base64\r\n\r\n" + b64("<script>steal()</script><p>Caf\xe9 <b>menu</b></p><style>x{}</style>") + "\r\n" +
		"--r\r\nContent-Type: image/png\r\nContent-ID: <logo>\r\nContent-Transfer-Encoding: base64\r\n\r\n" + b64("\x89PNG") + "\r\n" +
		"--r--\r\n" +
		"--b--\r\n"
	dest, res, err = extract(t, msg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	wantParts(t, res.Parts, "1 multipart/alternative", "1.1 text/calendar ATTACHMENT 1-attachment", "1.2 multipart/related", "1.2.1 text/html BODY body.txt", "1.2.2 image/png ATTACHMENT 2-attachment")
	body = readFile(t, dest, BodyFile)
	if !strings.HasSuffix(body, "\n\nCafé menu\n") || strings.Contains(body, "steal") {
		t.Errorf("body.txt = %q", body)
	}
	if got := readFile(t, dest, "2-attachment"); got != "\x89PNG" {
		t.Errorf("png = %q", got)
	}
}

func TestAttachmentNames(t *testing.T) {
	names := []string{
		`filename="../../etc/passwd"`,
		`filename="..\\..\\boot.ini"`,
		`filename=".bashrc"`,
		`filename="-rf"`,
		"filename=\"esc\x1b[2J.txt\"",
		`filename="=?utf-8?b?` + b64("../../enc\u202etxt.exe") + `?="`,
		`filename*=utf-8''%2e%2e%2Fpct%0a.txt`,
		`filename="report.pdf"`,
		`filename="report.pdf"`,
		`filename="` + strings.Repeat("x", 300) + `.pdf"`,
	}
	var b strings.Builder
	b.WriteString(head + "Content-Type: multipart/mixed; boundary=\"=_b\"\r\n\r\npreamble\r\n")
	b.WriteString("--=_b\r\nContent-Type: text/plain\r\n\r\nsee attached\r\n")
	for i, n := range names {
		fmt.Fprintf(&b, "--=_b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; %s\r\nContent-Transfer-Encoding: base64\r\n\r\n%s\r\n", n, b64(fmt.Sprintf("file %d", i)))
	}
	b.WriteString("--=_b--\r\nepilogue\r\n")
	dest, res, err := extract(t, b.String(), Options{})
	if err != nil {
		t.Fatal(err)
	}
	wantFiles := []string{
		"1-_._etc_passwd", "2-_._boot.ini", "3-bashrc", "4-rf", "5-esc[2J.txt", "6-_._enctxt.exe", "7-_pct .txt",
		"8-report.pdf", "9-report.pdf", "10-" + strings.Repeat("x", 96) + ".pdf",
	}
	origNames := []string{"../../etc/passwd", `..\..\boot.ini`, ".bashrc", "-rf", "esc\x1b[2J.txt", "../../enc\u202etxt.exe", "../pct\n.txt", "report.pdf", "report.pdf", strings.Repeat("x", 300) + ".pdf"}
	if len(res.Parts) != 2+len(names) {
		t.Fatalf("parts = %v", summary(res.Parts))
	}
	for i, p := range res.Parts[2:] {
		if p.File != wantFiles[i] || p.Name != origNames[i] {
			t.Errorf("part %s: file %q name %q, want %q %q", p.ID, p.File, p.Name, wantFiles[i], origNames[i])
		}
		if unsafe := i != 7 && i != 8; p.Has(FlagUnsafeName) != unsafe || !p.Has(FlagAttachment) {
			t.Errorf("part %s flags = %v", p.ID, p.Flags())
		}
		if got := readFile(t, dest, p.File); got != fmt.Sprintf("file %d", i) {
			t.Errorf("%s = %q", p.File, got)
		}
	}
	entries, _ := os.ReadDir(dest)
	if len(entries) != 1+len(names) {
		t.Errorf("dest has %d entries", len(entries))
	}
}

func forwarded(depth int) string {
	msg := "From: level0@example.com\r\nSubject: level 0\r\n\r\ninnermost\r\n"
	for i := 1; i <= depth; i++ {
		msg = fmt.Sprintf("From: level%d@example.com\r\nSubject: level %d\r\nContent-Type: multipart/mixed; boundary=b%d\r\n\r\n--b%d\r\nContent-Type: text/plain\r\n\r\ntext %d\r\n--b%d\r\nContent-Type: message/rfc822\r\nContent-Disposition: attachment\r\n\r\n%s\r\n--b%d--\r\n", i, i, i, i, i, i, msg, i)
	}
	return msg
}

func TestNested(t *testing.T) {
	dest, res, err := extract(t, forwarded(2), Options{Depth: 3})
	if err != nil {
		t.Fatal(err)
	}
	wantParts(t, res.Parts,
		"1 multipart/mixed",
		"1.1 text/plain BODY body.txt",
		"1.2 message/rfc822 NESTED-MESSAGE",
		"1.2.1 multipart/mixed",
		"1.2.1.1 text/plain BODY body.txt",
		"1.2.1.2 message/rfc822 NESTED-MESSAGE",
		"1.2.1.2.1 text/plain BODY body.txt",
	)
	want := "From: level2@example.com\nSubject: level 2\n\ntext 2\n\n" +
		"---------- Forwarded message (part 1.2) ----------\nFrom: level1@example.com\nSubject: level 1\n\ntext 1\n\n" +
		"---------- Forwarded message (part 1.2.1.2) ----------\nFrom: level0@example.com\nSubject: level 0\n\ninnermost\n"
	if got := readFile(t, dest, BodyFile); got != want {
		t.Errorf("body.txt =\n%q\nwant\n%q", got, want)
	}
	if h := res.Parts[2].Headers; len(h) != 2 || h[1].Value != "level 1" {
		t.Errorf("nested headers = %v", h)
	}

	// Past --depth, a nested message is written as it is.
	dest, res, err = extract(t, forwarded(2), Options{Depth: 1})
	if err != nil {
		t.Fatal(err)
	}
	last := res.Parts[len(res.Parts)-1]
	if last.ID != "1.2.1.2" || !last.Has(FlagDepthLimit) || !last.Has(FlagAttachment) || last.File != "1-message.eml" {
		t.Errorf("depth limit part = %+v", last)
	}
	if got := readFile(t, dest, "1-message.eml"); !strings.HasPrefix(got, "From: level0@example.com\r\n") {
		t.Errorf("message.eml = %q", got)
	}

	// Deep nesting stops at the depth limit without being rejected.
	res, err = list(t, forwarded(40), Options{Depth: DefaultDepth})
	if err != nil {
		t.Fatal(err)
	}
	if n := len(res.Parts); n != 3*DefaultDepth+3 {
		t.Errorf("%d parts: %v", n, summary(res.Parts))
	}

	// A nested message that isn't one is written as an attachment.
	msg := head + "Content-Type: message/rfc822\r\n\r\n no header here\r\n"
	dest, res, err = extract(t, msg, Options{Depth: 1})
	if err != nil {
		t.Fatal(err)
	}
	wantParts(t, res.Parts, "1 message/rfc822 ATTACHMENT,MALFORMED 1-message.eml")
	if got := readFile(t, dest, "1-message.eml"); got != " no header here\r\n" {
		t.Errorf("message.eml = %q", got)
	}
}

func TestLimits(t *testing.T) {
	for name, msg := range map[string]string{
		"header bytes":  head + strings.Repeat("X-Pad: "+strings.Repeat("p", 1000)+"\r\n", 300) + "\r\nbody",
		"header fields": head + strings.Repeat("X: y\r\n", MaxHeaderFields+1) + "\r\nbody",
		"header line":   head + "X-Long: " + strings.Repeat("l", MaxHeaderLine+1) + "\r\n\r\nbody",
		"part header":   head + "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nX-Long: " + strings.Repeat("l", MaxHeaderLine+1) + "\r\n\r\nx\r\n--b--\r\n",
		"part fields":   head + "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n" + strings.Repeat("X: y\r\n", MaxHeaderFields+1) + "\r\nx\r\n--b--\r\n",
		"parts":         head + "Content-Type: multipart/mixed; boundary=b\r\n\r\n" + strings.Repeat("--b\r\n\r\nx\r\n", MaxParts) + "--b--\r\n",
		"nesting":       head + nestedMultipart(MaxNesting+1),
		"nested header": head + "Content-Type: message/rfc822\r\n\r\n" + strings.Repeat("X: y\r\n", MaxHeaderFields+1) + "\r\nbody",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := list(t, msg, Options{Depth: 1})
			_ = wantKind(t, err, Rejected)
			dest, _, err := extract(t, msg, Options{Depth: 1})
			_ = wantKind(t, err, Rejected)
			wantEmpty(t, dest)
		})
	}

	// Just under the limits is fine.
	if _, err := list(t, head+nestedMultipart(MaxNesting-1), Options{}); err != nil {
		t.Errorf("nesting under the limit: %v", err)
	}
	if _, err := list(t, head+"Content-Type: multipart/mixed; boundary=b\r\n\r\n"+strings.Repeat("--b\r\n\r\nx\r\n", MaxParts-1)+"--b--\r\n", Options{}); err != nil {
		t.Errorf("parts under the limit: %v", err)
	}
}

// nestedMultipart is a header and body of multiparts nested n levels deep.
func nestedMultipart(n int) string {
	body := "Content-Type: text/plain\r\n\r\ndeep\r\n"
	for i := n - 1; i >= 1; i-- {
		body = fmt.Sprintf("Content-Type: multipart/mixed; boundary=n%d\r\n\r\n--n%d\r\n%s\r\n--n%d--\r\n", i, i, body, i)
	}
	return body
}

func TestBadEncodings(t *testing.T) {
	msg := head + "Content-Type: multipart/mixed; boundary=b\r\n\r\n" +
		"--b\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\n" + b64("first") + b64("second") + "\r\n" +
		"--b\r\nContent-Type: text/plain\r\nContent-Transfer-Encoding: x-uuencode\r\n\r\nraw text\r\n" +
		"--b\r\nContent-Type: text/plain; charset=x-klingon\r\n\r\nunknown charset\r\n" +
		"--b\r\nContent-Type: text/plain; charset=windows-1252\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nsmart =93quotes=94 =ZZ\r\n" +
		"--b\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nbad \xff\xfe utf8 \x1b[31mred\r\n" +
		"--b\r\nContent-Type: text/plain; charset=\"unterminated\r\n\r\nbad params\r\n" +
		"--b\r\nContent-Type: ???\r\n\r\nbad type\r\n" +
		"--b--\r\n"
	dest, res, err := extract(t, msg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	wantParts(t, res.Parts,
		"1 multipart/mixed",
		"1.1 text/plain BODY,BAD-ENCODING body.txt",
		"1.2 text/plain BODY,BAD-ENCODING body.txt",
		"1.3 text/plain BODY,BAD-ENCODING body.txt",
		"1.4 text/plain BODY,BAD-ENCODING body.txt",
		"1.5 text/plain BODY body.txt",
		"1.6 text/plain BODY,MALFORMED body.txt",
		"1.7 application/octet-stream ATTACHMENT,MALFORMED 1-attachment",
	)
	body := readFile(t, dest, BodyFile)
	for _, want := range []string{"\n\nfirst\n\n", "\n\nraw text\n\n", "\n\nunknown charset\n\n", "\n\nsmart \u201cquotes\u201d =ZZ\n\n", "\n\nbad \uFFFD\uFFFD utf8 [31mred\n\n", "bad params\n"} {
		if !strings.Contains(body, want) {
			t.Errorf("body.txt lacks %q:\n%q", want, body)
		}
	}
	if strings.Contains(body, "\x1b") || strings.Contains(body, "\r") {
		t.Errorf("body.txt has control characters: %q", body)
	}
}

func TestMalformedMultipart(t *testing.T) {
	// Cut short: the parts before the cut are kept.
	msg := head + "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\nContent-Type: text/plain\r\n\r\nkept\r\n--b\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=a.pdf\r\n\r\n%PDF-cut"
	dest, res, err := extract(t, msg, Options{})
	if err != nil {
		t.Fatal(err)
	}
	wantParts(t, res.Parts, "1 multipart/mixed MALFORMED", "1.1 text/plain BODY body.txt", "1.2 application/pdf ATTACHMENT,MALFORMED 1-a.pdf")
	if !strings.Contains(readFile(t, dest, BodyFile), "kept") || readFile(t, dest, "1-a.pdf") != "%PDF-cut" {
		t.Errorf("files lost")
	}

	// No boundary, or one that never shows.
	for _, ct := range []string{"multipart/mixed", "multipart/mixed; boundary=missing"} {
		res, err = list(t, head+"Content-Type: "+ct+"\r\n\r\n--other\r\n\r\nx\r\n", Options{})
		if err != nil || !res.Parts[0].Has(FlagMalformed) {
			t.Errorf("%s: %v, %v", ct, summary(res.Parts), err)
		}
	}
}

func TestTooLarge(t *testing.T) {
	big := strings.Repeat("0123456789", 2000)
	msg := head + "Content-Type: multipart/mixed; boundary=b\r\n\r\n--b\r\n\r\nbody\r\n--b\r\nContent-Disposition: attachment; filename=big\r\n\r\n" + big + "\r\n--b--\r\n"
	dest, _, err := extract(t, msg, Options{MaxSize: 10000})
	_ = wantKind(t, err, TooLarge)
	wantEmpty(t, dest)

	// The body text counts too, held alternatives included.
	msg = head + "Content-Type: multipart/alternative; boundary=b\r\n\r\n--b\r\nContent-Type: text/html\r\n\r\n" + big + "\r\n--b\r\nContent-Type: text/plain\r\n\r\nshort\r\n--b--\r\n"
	dest, _, err = extract(t, msg, Options{MaxSize: 10000})
	_ = wantKind(t, err, TooLarge)
	wantEmpty(t, dest)
	if _, _, err = extract(t, msg, Options{MaxSize: 30000}); err != nil {
		t.Errorf("under the limit: %v", err)
	}
}

func TestNotMessage(t *testing.T) {
	for name, data := range map[string]string{
		"empty":       "",
		"binary":      "\x89PNG\r\n\x1a\n",
		"text":        "just some text\n",
		"not mail":    "key: value\nother: thing\n\nbody",
		"blank first": "\r\nSubject: x\r\n",
	} {
		_, err := list(t, data, Options{})
		_ = wantKind(t, err, NotMessage)
		dest, _, err := extract(t, data, Options{})
		_ = wantKind(t, err, NotMessage)
		if names, _ := os.ReadDir(dest); len(names) > 0 {
			t.Errorf("%s: dest not emptied", name)
		}
	}
}

func TestDest(t *testing.T) {
	msg := head + "\r\nbody\r\n"
	file, dest := workdir(t, msg)
	o := Options{MaxSize: 1 << 20}

	// Not empty.
	if err := os.Mkdir(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dest, "keep"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Extract(t.Context(), file, dest, o)
	_ = wantKind(t, err, Failed)
	if _, err := os.Stat(filepath.Join(dest, "keep")); err != nil {
		t.Errorf("a non-empty dest was changed: %v", err)
	}

	// A symbolic link, even to an empty directory.
	target := t.TempDir()
	link := filepath.Join(filepath.Dir(dest), "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	_, err = Extract(t.Context(), file, link, o)
	_ = wantKind(t, err, Failed)
	wantEmpty(t, target)

	// A file.
	_, err = Extract(t.Context(), file, file, o)
	_ = wantKind(t, err, Failed)

	// An empty directory is fine, and the message must be a regular file.
	empty := t.TempDir()
	if _, err := Extract(t.Context(), file, empty, o); err != nil {
		t.Error(err)
	}
	_, err = Extract(t.Context(), filepath.Dir(file), filepath.Join(t.TempDir(), "x"), o)
	_ = wantKind(t, err, Failed)
	_, err = List(t.Context(), filepath.Join(t.TempDir(), "missing.eml"), Options{})
	_ = wantKind(t, err, Failed)

	// On failure the destination is emptied without following links: a
	// link left in it is removed, not its target.
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(dir, "l")); err != nil {
		t.Fatal(err)
	}
	if err := emptyDir(dir); err != nil {
		t.Fatal(err)
	}
	wantEmpty(t, dir)
	if b, err := os.ReadFile(outside); err != nil || string(b) != "keep" {
		t.Errorf("link target = %q, %v", b, err)
	}
}

func TestCancel(t *testing.T) {
	file, dest := workdir(t, head+"\r\n"+strings.Repeat("line\r\n", 100000))
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := Extract(ctx, file, dest, Options{MaxSize: 1 << 30})
	if err == nil {
		t.Fatal("no error after cancel")
	}
	wantEmpty(t, dest)
}

func TestDigestDefault(t *testing.T) {
	msg := head + "Content-Type: multipart/digest; boundary=d\r\n\r\n--d\r\n\r\nSubject: digested\r\n\r\ninner\r\n--d--\r\n"
	res, err := list(t, msg, Options{Depth: 1})
	if err != nil {
		t.Fatal(err)
	}
	wantParts(t, res.Parts, "1 multipart/digest", "1.1 message/rfc822 NESTED-MESSAGE", "1.1.1 text/plain BODY")
	if res.Parts[1].Size != int64(len("Subject: digested\r\n\r\ninner")) {
		t.Errorf("size = %d", res.Parts[1].Size)
	}
}
