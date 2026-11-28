package totext

import (
	"io"
	"unicode"
	"unicode/utf8"
)

// cleaner removes control characters from what is written through it
// before passing it on, and counts the characters it passes that aren't
// whitespace. It keeps newlines and tabs and drops every other C0 and C1
// control, DEL, and the bidirectional formatting characters that can make
// text read differently from how it is stored. Bytes that are not valid
// UTF-8 become U+FFFD, so the output is always valid UTF-8. A UTF-8
// sequence split across writes is held until the rest arrives; Close
// flushes an incomplete one as U+FFFD.
type cleaner struct {
	w       io.Writer
	pending []byte
	chars   int
	buf     []byte
}

func newCleaner(w io.Writer) *cleaner {
	return &cleaner{w: w}
}

// dropped reports whether r is removed from the text.
func dropped(r rune) bool {
	switch r {
	case '\n', '\t':
		return false
	case '\u061c', '\u200e', '\u200f':
		return true
	}
	return unicode.IsControl(r) || (r >= '\u202a' && r <= '\u202e') || (r >= '\u2066' && r <= '\u2069')
}

func (c *cleaner) Write(p []byte) (int, error) {
	data := p
	if len(c.pending) > 0 {
		data = append(append([]byte{}, c.pending...), p...)
	}
	c.buf = c.buf[:0]
	i := 0
	for i < len(data) {
		if !utf8.FullRune(data[i:]) {
			break
		}
		r, size := utf8.DecodeRune(data[i:])
		i += size
		c.add(r)
	}
	c.pending = append(c.pending[:0:0], data[i:]...)
	if _, err := c.w.Write(c.buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *cleaner) add(r rune) {
	if dropped(r) {
		return
	}
	if !unicode.IsSpace(r) {
		c.chars++
	}
	c.buf = utf8.AppendRune(c.buf, r)
}

// Close writes out an incomplete UTF-8 sequence left at the end as U+FFFD.
func (c *cleaner) Close() error {
	if len(c.pending) == 0 {
		return nil
	}
	c.pending = nil
	c.buf = c.buf[:0]
	c.add(utf8.RuneError)
	_, err := c.w.Write(c.buf)
	return err
}

// Chars is the number of characters written that aren't whitespace.
func (c *cleaner) Chars() int {
	return c.chars
}
