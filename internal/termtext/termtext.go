// Package termtext makes untrusted text safe to print to a terminal.
package termtext

import (
	"fmt"
	"io"
	"strconv"
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

// Writer escapes everything written to it with Escape's rules before
// passing it on, for streams such as a command's output. A UTF-8 sequence
// split across writes is held back until the rest of it arrives, so it is
// kept whole rather than escaped byte by byte. Call Flush when the stream
// ends to write out a held-back sequence that never completed.
type Writer struct {
	w       io.Writer
	pending []byte
}

// NewWriter returns a Writer that writes escaped text to w.
func NewWriter(w io.Writer) *Writer {
	return &Writer{w: w}
}

// Write escapes p and writes it to the underlying writer. It returns
// len(p) when the escaped text was written, since escaping changes how
// many bytes reach the underlying writer.
func (e *Writer) Write(p []byte) (int, error) {
	e.pending = append(e.pending, p...)
	buf := e.pending
	n := len(buf) - incompleteTail(buf)
	if _, err := io.WriteString(e.w, Escape(string(buf[:n]))); err != nil {
		e.pending = nil
		return 0, err
	}
	e.pending = append([]byte(nil), buf[n:]...)
	return len(p), nil
}

// Flush writes out a held-back incomplete UTF-8 sequence, escaped as the
// invalid bytes it now is.
func (e *Writer) Flush() error {
	if len(e.pending) == 0 {
		return nil
	}
	_, err := io.WriteString(e.w, Escape(string(e.pending)))
	e.pending = nil
	return err
}

// incompleteTail returns the length of the UTF-8 sequence at the end of b
// that has started but not finished, or 0 when b ends on a whole rune or
// on bytes that can't start one.
func incompleteTail(b []byte) int {
	for i := len(b) - 1; i >= 0 && len(b)-i < utf8.UTFMax; i-- {
		if utf8.RuneStart(b[i]) {
			if utf8.FullRune(b[i:]) {
				return 0
			}
			return len(b) - i
		}
	}
	return 0
}

// EscapeField escapes s for one field of a tab-separated line: backslashes
// are doubled, then everything Escape escapes, then tabs and newlines, so
// the result is unambiguous and has no control characters.
func EscapeField(s string) string {
	s = Escape(strings.ReplaceAll(s, `\`, `\\`))
	return strings.NewReplacer("\t", `\t`, "\n", `\n`).Replace(s)
}

// UnescapeField reverses EscapeField. It refuses s when it isn't exactly
// what EscapeField writes for some string, such as an unknown escape, a
// raw control character, or a character written as an escape that
// EscapeField would have kept, so each string has one written form.
func UnescapeField(s string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] != '\\' {
			b.WriteByte(s[i])
			i++
			continue
		}
		if i+1 >= len(s) {
			return "", fmt.Errorf("%q ends in a backslash", s)
		}
		n := 0
		switch s[i+1] {
		case '\\':
			b.WriteByte('\\')
		case 't':
			b.WriteByte('\t')
		case 'n':
			b.WriteByte('\n')
		case 'x':
			n = 2
		case 'u':
			n = 4
		case 'U':
			n = 8
		default:
			return "", fmt.Errorf("%q has an unknown escape \\%c", s, s[i+1])
		}
		if n == 0 {
			i += 2
			continue
		}
		if i+2+n > len(s) {
			return "", fmt.Errorf("%q has a short escape", s)
		}
		v, err := strconv.ParseUint(s[i+2:i+2+n], 16, 32)
		if err != nil {
			return "", fmt.Errorf("%q has a bad escape: %w", s, err)
		}
		if n == 2 {
			b.WriteByte(byte(v))
		} else {
			b.WriteRune(rune(v))
		}
		i += 2 + n
	}
	out := b.String()
	if EscapeField(out) != s {
		return "", fmt.Errorf("%q is not written as EscapeField writes it", s)
	}
	return out, nil
}
