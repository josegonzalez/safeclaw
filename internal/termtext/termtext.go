// Package termtext makes untrusted text safe to print to a terminal.
package termtext

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Escape returns s with every rune unicode.IsPrint rejects, other than
// newline and tab, written as a Go escape: C0 and C1 controls such as ESC
// and CSI, DEL, carriage return, format characters such as bidi overrides,
// and non-ASCII spaces. Bytes that are not valid UTF-8 are escaped as \xNN,
// so a raw 8-bit C1 byte never reaches the terminal either. Newlines and
// tabs are kept so multi-line messages still read as they were written.
func Escape(s string) string {
	if safe(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 16)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size <= 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case keep(r):
			b.WriteRune(r)
		case r < 0x80:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r <= 0xffff:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			fmt.Fprintf(&b, `\U%08x`, r)
		}
		i += size
	}
	return b.String()
}

func keep(r rune) bool {
	return r == '\n' || r == '\t' || unicode.IsPrint(r)
}

func safe(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if !keep(r) {
			return false
		}
	}
	return true
}
