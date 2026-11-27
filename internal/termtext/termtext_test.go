package termtext

import "testing"

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
