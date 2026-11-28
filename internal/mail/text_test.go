package mail

import (
	"bytes"
	"io"
	"strings"
	"testing"
	"unicode/utf8"
)

func TestCleanLine(t *testing.T) {
	for in, want := range map[string]string{
		"plain":                    "plain",
		"  tab\there\r\nfold  ":    "tab here  fold",
		"esc\x1b[2Jcsi\u009b2J":    "esc[2Jcsi2J",
		"bidi\u202egnp.exe":        "bidignp.exe",
		"zero\u200bwidth":          "zerowidth",
		"bad\xffbyte":              "bad�byte",
		"nbsp space":               "nbsp space",
		"résumé ✓":                 "résumé ✓",
		"bell\x07 del\x7f nul\x00": "bell del nul",
	} {
		if got := CleanLine(in); got != want {
			t.Errorf("CleanLine(%q) = %q, want %q", in, got, want)
		}
	}
}

func filterText(t *testing.T, in string) string {
	t.Helper()
	var whole string
	// Split at every offset, so runes and CRLF cut across writes come out
	// the same.
	for split := 0; split <= len(in); split++ {
		var b bytes.Buffer
		f := newTextFilter(&b)
		for _, part := range []string{in[:split], in[split:]} {
			if n, err := f.Write([]byte(part)); err != nil || n != len(part) {
				t.Fatalf("Write = %d, %v", n, err)
			}
		}
		if err := f.Flush(); err != nil {
			t.Fatal(err)
		}
		if split == 0 {
			whole = b.String()
		} else if b.String() != whole {
			t.Fatalf("split %d: %q, unsplit %q", split, b.String(), whole)
		}
	}
	return whole
}

func TestTextFilter(t *testing.T) {
	for in, want := range map[string]string{
		"line\r\nnext\rcr\n":       "line\nnext\ncr\n",
		"tab\tkept\n":              "tab\tkept\n",
		"esc\x1b]52;c;QQ==\x07end": "esc]52;c;QQ==end",
		"c1\u009b2J raw\x9b2J":     "c12J raw�2J",
		"bidi\u202e\u2066\u200fx":  "bidix",
		"emoji 👍🏽 zwj 👩\u200d💻":    "emoji 👍🏽 zwj 👩\u200d💻",
		"cut\xe2\x9c":              "cut�",
		"del\x7f nul\x00":          "del nul",
	} {
		got := filterText(t, in)
		if got != want {
			t.Errorf("filter(%q) = %q, want %q", in, got, want)
		}
		if !utf8.ValidString(got) {
			t.Errorf("filter(%q) is not valid UTF-8", in)
		}
	}
}

func TestSafeName(t *testing.T) {
	long := strings.Repeat("a", 300)
	for in, want := range map[string]string{
		"report.pdf":                "report.pdf",
		"../../etc/passwd":          "_._etc_passwd",
		`..\..\win.ini`:             "_._win.ini",
		"a..b...c":                  "a.b.c",
		".hidden":                   "hidden",
		"-rf":                       "rf",
		"--.-x":                     "x",
		"...":                       "",
		"esc\x1b[2Jname.txt":        "esc[2Jname.txt",
		"new\nline.txt":             "new line.txt",
		"bidi\u202etxt.exe":         "biditxt.exe",
		"bad\xff.txt":               "bad_.txt",
		"trailing  ":                "trailing",
		"résumé.pdf":                "résumé.pdf",
		long + ".pdf":               strings.Repeat("a", 96) + ".pdf",
		long:                        strings.Repeat("a", 100),
		long + ".verylongextension": strings.Repeat("a", 100),
		strings.Repeat("é", 80):     strings.Repeat("é", 50),
	} {
		got := SafeName(in)
		if got != want {
			t.Errorf("SafeName(%q) = %q, want %q", in, got, want)
		}
		if len(got) > maxNameBytes || strings.ContainsAny(got, "/\\") || strings.Contains(got, "..") || strings.HasPrefix(got, ".") || strings.HasPrefix(got, "-") || !utf8.ValidString(got) {
			t.Errorf("SafeName(%q) = %q is unsafe", in, got)
		}
	}
}

func TestBase64Reader(t *testing.T) {
	for _, c := range []struct {
		in, want string
		bad      bool
	}{
		{"aGVs\r\nbG8=\r\n", "hello", false},
		{"aGVs bG8\n", "hello", false}, // missing padding
		{"aGVsbA\n", "hell", false},    // missing ==
		{"aGVsbG8=\n\n=\n", "hello", false},
		{"aGVs!!bG8=", "hello", false}, // junk outside the alphabet
		{"aGVsbG8=aGVsbG8=", "hello", true},
		{"aGVsb", "hel", true}, // a final group of one
		{"aGVsbG8", "hello", false},
		{"", "", false},
	} {
		got, err := io.ReadAll(newBase64Reader(strings.NewReader(c.in)))
		if string(got) != c.want || (err != nil) != c.bad {
			t.Errorf("base64 %q = %q, %v; want %q, bad %v", c.in, got, err, c.want, c.bad)
		}
		if err != nil && err != errBadEncoding {
			t.Errorf("base64 %q: err = %v", c.in, err)
		}
	}
}

func TestQPReader(t *testing.T) {
	long := strings.Repeat("x=3D", 5000)
	for _, c := range []struct {
		in, want string
		bad      bool
	}{
		{"caf=C3=A9\r\n", "café\r\n", false},
		{"soft=\r\nbreak\n", "softbreak\n", false},
		{"soft=  \nbreak", "softbreak", false},
		{"trailing   \nspace", "trailing\nspace", false},
		{"lower=c3=a9", "loweré", false},
		{"bad=ZZ", "bad=ZZ", true},
		{"end=", "end", false},
		{long, strings.Repeat("x=", 5000), false},
	} {
		got, err := io.ReadAll(newQPReader(strings.NewReader(c.in)))
		if string(got) != c.want || (err != nil) != c.bad {
			t.Errorf("qp %.40q = %.40q, %v; want %.40q, bad %v", c.in, got, err, c.want, c.bad)
		}
	}
}

func TestHTMLToText(t *testing.T) {
	in := `<html><head><title>Hidden title</title><style>p { color: red }</style>
<script>alert("x")</script></head><body>
<h1>Invoice</h1><p>Dear   customer,<br>please
pay <a href="https://evil.example/pay">https://bank.example</a> or
<a href="https://ok.example/">ok.example</a>.</p>
<ul><li>one</li><li>two &amp; three</li></ul>
<noscript>enable js</noscript><svg><text>icon</text></svg>
<pre>  keep
   this</pre><img src="x.png" alt="logo"><div>last</div>
<script>document.write("<p>injected</p>")</script>
</body></html>`
	var b strings.Builder
	if err := htmlToText(strings.NewReader(in), &b); err != nil {
		t.Fatal(err)
	}
	want := "Invoice\n\nDear customer,\nplease pay https://bank.example <https://evil.example/pay> or ok.example.\n\n- one\n- two & three\n\n  keep\n   this\n\n[logo]\nlast\n"
	if b.String() != want {
		t.Errorf("got\n%q\nwant\n%q", b.String(), want)
	}
	for _, bad := range []string{"alert", "color", "Hidden", "enable js", "icon", "injected"} {
		if strings.Contains(b.String(), bad) {
			t.Errorf("text has %q", bad)
		}
	}

	// A token over the limit is an error, after the text before it.
	b.Reset()
	err := htmlToText(strings.NewReader("<p>ok</p><a title=\""+strings.Repeat("x", maxHTMLToken+10)+"\">"), &b)
	if err == nil || !strings.Contains(b.String(), "ok") {
		t.Errorf("huge token: %q, %v", b.String(), err)
	}
}
