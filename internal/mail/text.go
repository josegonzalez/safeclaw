package mail

import (
	"io"
	"path/filepath"
	"strings"
	"unicode"
	"unicode/utf8"
)

// CleanLine makes s safe to print on one line: invalid UTF-8 becomes
// U+FFFD, tabs, line breaks, and other spaces become a plain space, and
// every other rune unicode.IsPrint rejects is dropped, such as control
// characters, bidi overrides, and zero-width characters. Leading and
// trailing spaces are trimmed.
func CleanLine(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range strings.ToValidUTF8(s, "�") {
		switch {
		case unicode.IsSpace(r):
			b.WriteByte(' ')
		case unicode.IsPrint(r):
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// keepInText reports whether body text keeps r: line breaks and tabs, and
// everything but control characters and the characters that reorder text
// (bidi marks, embeddings, overrides, and isolates).
func keepInText(r rune) bool {
	switch {
	case r == '\n' || r == '\t':
		return true
	case unicode.IsControl(r):
		return false
	case r == '\u061c', r == '\u200e', r == '\u200f', r >= '\u202a' && r <= '\u202e', r >= '\u2066' && r <= '\u2069':
		return false
	}
	return true
}

// textFilter strips body text as it is written: CRLF and lone CR become
// LF, invalid UTF-8 becomes U+FFFD, and every rune keepInText rejects is
// dropped. Flush writes what is left of an incomplete UTF-8 sequence.
type textFilter struct {
	w       io.Writer
	pending []byte
	lastCR  bool
	out     []byte
}

func newTextFilter(w io.Writer) *textFilter {
	return &textFilter{w: w}
}

func (f *textFilter) Write(p []byte) (int, error) {
	f.pending = append(f.pending, p...)
	buf := f.pending
	f.pending = nil
	f.out = f.out[:0]
	for len(buf) > 0 {
		r, size := utf8.DecodeRune(buf)
		if r == utf8.RuneError && size <= 1 && !utf8.FullRune(buf) {
			// The rest of the sequence may come in the next write.
			f.pending = append([]byte(nil), buf...)
			break
		}
		buf = buf[size:]
		f.rune(r)
	}
	if len(f.out) > 0 {
		if _, err := f.w.Write(f.out); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (f *textFilter) rune(r rune) {
	wasCR := f.lastCR
	f.lastCR = r == '\r'
	switch {
	case r == '\r':
		f.out = append(f.out, '\n')
	case r == '\n' && wasCR:
	case keepInText(r):
		f.out = utf8.AppendRune(f.out, r)
	}
}

// Flush writes U+FFFD for an incomplete UTF-8 sequence left at the end.
func (f *textFilter) Flush() error {
	if len(f.pending) == 0 {
		return nil
	}
	f.pending = nil
	_, err := f.w.Write([]byte("�"))
	return err
}

// SafeName turns an attachment's original name into one that is safe to
// create in a directory and to print: slashes and backslashes become _,
// invalid UTF-8 becomes _, other spaces become a plain space, runes
// unicode.IsPrint rejects are dropped, runs of dots are shortened until no
// ".." is left, leading dots, dashes, and spaces and trailing spaces are
// trimmed, and the result is cut to 100 bytes, keeping a short extension.
// It returns "" when nothing is left.
func SafeName(name string) string {
	var b strings.Builder
	for _, r := range strings.ToValidUTF8(name, "_") {
		switch {
		case r == '/' || r == '\\':
			b.WriteByte('_')
		case unicode.IsSpace(r):
			b.WriteByte(' ')
		case unicode.IsPrint(r):
			b.WriteRune(r)
		}
	}
	s := b.String()
	for strings.Contains(s, "..") {
		s = strings.ReplaceAll(s, "..", ".")
	}
	s = trimName(s)
	if len(s) > maxNameBytes {
		ext := filepath.Ext(s)
		if len(ext) > 16 || len(ext) == len(s) {
			ext = ""
		}
		stem := s[:len(s)-len(ext)]
		stem = cutUTF8(stem, maxNameBytes-len(ext))
		s = trimName(strings.TrimRight(stem, ".")) + ext
		if s == ext {
			s = trimName(ext)
		}
	}
	return s
}

func trimName(s string) string {
	return strings.TrimRight(strings.TrimLeft(s, ".- "), " ")
}

// cutUTF8 cuts s to at most n bytes without splitting a rune.
func cutUTF8(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}
