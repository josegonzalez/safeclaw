package termtext

import (
	"strings"
	"testing"
)

func TestEscape(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"plain", "tar: out: Cannot open", "tar: out: Cannot open"},
		{"newline and tab kept", "line 1\n\tline 2", "line 1\n\tline 2"},
		{"unicode kept", "café ✓", "café ✓"},
		{"esc", "a\x1b]0;pwned\x07b", `a\x1b]0;pwned\x07b`},
		{"carriage return", "ok\rfake", `ok\x0dfake`},
		{"del", "a\x7fb", `a\x7fb`},
		{"c1 as utf-8", "a\u009b31mb", `a\u009b31mb`},
		{"raw 8-bit c1", "a\x9b31mb", `a\x9b31mb`},
		{"invalid utf-8", "a\xff\xfeb", `a\xff\xfeb`},
		{"bidi override", "a\u202eb", "a\\u202eb"},
		{"nul", "a\x00b", `a\x00b`},
		{"empty", "", ""},
	}
	for _, tc := range cases {
		if got := Escape(tc.in); got != tc.want {
			t.Errorf("%s: Escape(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

func TestWriter(t *testing.T) {
	in := "ok \x1b[31mred\x1b[0m\ncafé ✓ \u009b2J\r\xff end\t\U0001F600\n"
	// Every split point, including ones inside a multi-byte rune, must give
	// the same output as escaping the whole stream at once.
	for split := 0; split <= len(in); split++ {
		var b strings.Builder
		w := NewWriter(&b)
		for _, part := range []string{in[:split], in[split:]} {
			n, err := w.Write([]byte(part))
			if err != nil || n != len(part) {
				t.Fatalf("split %d: Write = %d, %v", split, n, err)
			}
		}
		if err := w.Flush(); err != nil {
			t.Fatal(err)
		}
		if got, want := b.String(), Escape(in); got != want {
			t.Errorf("split %d: got %q, want %q", split, got, want)
		}
	}
}

func TestWriterByteAtATime(t *testing.T) {
	in := "a\u202eb é \U0001F600 \x1b]0;x\x07"
	var b strings.Builder
	w := NewWriter(&b)
	for i := range len(in) {
		if _, err := w.Write([]byte{in[i]}); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if got, want := b.String(), Escape(in); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestWriterFlushIncomplete(t *testing.T) {
	var b strings.Builder
	w := NewWriter(&b)
	// The first two bytes of a three-byte rune are held back until Flush.
	if _, err := w.Write([]byte("x\xe2\x9c")); err != nil {
		t.Fatal(err)
	}
	if got := b.String(); got != "x" {
		t.Errorf("before Flush: %q", got)
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	if got, want := b.String(), `x\xe2\x9c`; got != want {
		t.Errorf("after Flush: %q, want %q", got, want)
	}
}

func TestUnescapeField(t *testing.T) {
	for _, s := range []string{"plain/path.zip", "a\tb\nc", `back\slash`, "a\u202eb", "a\xff\x1bb", "emoji \U0001F600", "\U000e0001", ""} {
		got, err := UnescapeField(EscapeField(s))
		if err != nil || got != s {
			t.Errorf("UnescapeField(EscapeField(%q)) = %q, %v", s, got, err)
		}
	}
	for _, bad := range []string{`a\`, `a\q`, `a\x1`, `a\xzz`, "raw\ttab", `\x41`, "\\u0041", `a\x2b`, `\u202`} {
		if got, err := UnescapeField(bad); err == nil {
			t.Errorf("UnescapeField(%q) = %q, want an error", bad, got)
		}
	}
}
