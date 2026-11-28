package mail

import (
	"bufio"
	"encoding/base64"
	"errors"
	"io"
	"mime"
	"strings"

	"golang.org/x/net/html/charset"
)

// errBadEncoding is returned by the decoders when their input can't be
// decoded in full.
var errBadEncoding = errors.New("bad encoding")

// transferDecoder returns a reader that decodes r's Content-Transfer-Encoding
// cte, and whether the encoding is one it knows. Unknown encodings are read
// as they are.
func transferDecoder(cte string, r io.Reader) (io.Reader, bool) {
	switch strings.ToLower(strings.TrimSpace(cte)) {
	case "base64":
		return newBase64Reader(r), true
	case "quoted-printable":
		return newQPReader(r), true
	case "", "7bit", "8bit", "binary":
		return r, true
	}
	return r, false
}

// base64Reader decodes base64 leniently, the way mail readers do: anything
// outside the alphabet, such as line breaks and spaces, is skipped, and
// missing padding at the end is added. Data after the padding, or a final
// group of a single character, is an errBadEncoding.
type base64Reader struct {
	dec io.Reader
}

func newBase64Reader(r io.Reader) io.Reader {
	return &base64Reader{dec: base64.NewDecoder(base64.StdEncoding, &base64Filter{src: bufio.NewReader(r)})}
}

func (b *base64Reader) Read(p []byte) (int, error) {
	n, err := b.dec.Read(p)
	var ce base64.CorruptInputError
	if errors.As(err, &ce) {
		err = errBadEncoding
	}
	return n, err
}

// base64Filter passes on only base64 characters and padding, adding the
// padding a message left out.
type base64Filter struct {
	src *bufio.Reader
	// q is how many characters of the current group of four were passed.
	q int
	// inPad is set after the first = of a group that needs two.
	inPad bool
	// done is set once a group with padding ends: nothing more is decoded.
	done bool
	tail []byte
	err  error
}

func (f *base64Filter) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if len(f.tail) > 0 {
			c := copy(p[n:], f.tail)
			f.tail = f.tail[c:]
			n += c
			continue
		}
		if f.err != nil {
			break
		}
		c, err := f.src.ReadByte()
		if err != nil {
			f.err = err
			if err == io.EOF && !f.done {
				switch {
				case f.inPad:
					f.tail = []byte("=")
				case f.q == 1:
					f.err = errBadEncoding
				case f.q == 2:
					f.tail = []byte("==")
				case f.q == 3:
					f.tail = []byte("=")
				}
			}
			continue
		}
		switch {
		case f.done:
			if isBase64(c) {
				f.err = errBadEncoding
			}
		case c == '=':
			switch {
			case f.inPad || f.q == 3:
				p[n] = c
				n++
				f.done = true
			case f.q == 2:
				p[n] = c
				n++
				f.inPad = true
			}
			// An = anywhere else is stray, and skipped.
		case isBase64(c):
			if f.inPad {
				f.err = errBadEncoding
				continue
			}
			p[n] = c
			n++
			f.q = (f.q + 1) % 4
		}
	}
	if n > 0 {
		return n, nil
	}
	return 0, f.err
}

func isBase64(c byte) bool {
	return c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '+' || c == '/'
}

// qpReader decodes quoted-printable leniently and without buffering lines:
// =XX is the byte XX, = before a line break is a soft break, and an = that
// is neither is kept as it is. Spaces and tabs at the end of a line are
// dropped.
type qpReader struct {
	src *bufio.Reader
	// spaces are spaces and tabs not yet known to end a line.
	spaces []byte
	out    []byte
	bad    bool
	err    error
}

// maxQPSpaces is how many spaces in a row qpReader holds back before
// passing them on.
const maxQPSpaces = 1024

func newQPReader(r io.Reader) io.Reader {
	return &qpReader{src: bufio.NewReader(r)}
}

func (q *qpReader) Read(p []byte) (int, error) {
	for len(q.out) == 0 && q.err == nil {
		q.step()
	}
	n := copy(p, q.out)
	q.out = q.out[n:]
	if len(q.out) == 0 && q.err != nil {
		return n, q.err
	}
	return n, nil
}

func (q *qpReader) flushSpaces() {
	q.out = append(q.out, q.spaces...)
	q.spaces = q.spaces[:0]
}

// step decodes some input into out, or sets err.
func (q *qpReader) step() {
	c, err := q.src.ReadByte()
	if err != nil {
		q.flushSpaces()
		q.err = err
		if err == io.EOF && q.bad {
			q.err = errBadEncoding
		}
		return
	}
	switch c {
	case ' ', '\t':
		q.spaces = append(q.spaces, c)
		if len(q.spaces) >= maxQPSpaces {
			q.flushSpaces()
		}
	case '\r', '\n':
		q.spaces = q.spaces[:0]
		q.out = append(q.out, c)
	case '=':
		q.flushSpaces()
		q.escape()
	default:
		q.flushSpaces()
		q.out = append(q.out, c)
	}
}

// escape handles what follows an =.
func (q *qpReader) escape() {
	b, _ := q.src.Peek(2)
	switch {
	case len(b) == 2 && isHex(b[0]) && isHex(b[1]):
		_, _ = q.src.Discard(2)
		q.out = append(q.out, unhex(b[0])<<4|unhex(b[1]))
	case len(b) >= 1 && b[0] == '\n':
		_, _ = q.src.Discard(1)
	case len(b) == 2 && b[0] == '\r' && b[1] == '\n':
		_, _ = q.src.Discard(2)
	case len(b) >= 1 && (b[0] == ' ' || b[0] == '\t'):
		// A soft break with spaces before it, or a literal =.
		n := 0
		for {
			bb, err := q.src.Peek(n + 1)
			if err != nil || len(bb) <= n || n >= maxQPSpaces {
				break
			}
			if bb[n] != ' ' && bb[n] != '\t' {
				break
			}
			n++
		}
		bb, _ := q.src.Peek(n + 2)
		switch {
		case len(bb) > n && bb[n] == '\n':
			_, _ = q.src.Discard(n + 1)
		case len(bb) > n+1 && bb[n] == '\r' && bb[n+1] == '\n':
			_, _ = q.src.Discard(n + 2)
		default:
			q.bad = true
			q.out = append(q.out, '=')
		}
	case len(b) == 0:
		// A soft break at the very end.
	default:
		q.bad = true
		q.out = append(q.out, '=')
	}
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

func unhex(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	}
	return c - 'A' + 10
}

// knownCharset reports whether charsetReader can decode label.
func knownCharset(label string) bool {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "", "utf-8", "utf8", "us-ascii", "ascii":
		return true
	}
	e, _ := charset.Lookup(label)
	return e != nil
}

// charsetReader returns a reader that decodes r from the charset label to
// UTF-8, and whether the label is one it knows. UTF-8, US-ASCII, and no
// label are read as they are, as are unknown labels.
func charsetReader(label string, r io.Reader) (io.Reader, bool) {
	switch strings.ToLower(strings.TrimSpace(label)) {
	case "", "utf-8", "utf8", "us-ascii", "ascii":
		return r, true
	}
	cr, err := charset.NewReaderLabel(label, r)
	if err != nil {
		return r, false
	}
	return cr, true
}

// wordDecoder decodes RFC 2047 encoded words, in any charset the
// html/charset package knows.
var wordDecoder = &mime.WordDecoder{
	CharsetReader: func(label string, input io.Reader) (io.Reader, error) {
		r, ok := charsetReader(label, input)
		if !ok {
			return nil, errors.New("unknown charset " + label)
		}
		return r, nil
	},
}

// decodeWords decodes the RFC 2047 encoded words in a header value,
// leaving it as it is when they can't be decoded.
func decodeWords(s string) string {
	if !strings.Contains(s, "=?") {
		return s
	}
	d, err := wordDecoder.DecodeHeader(s)
	if err != nil {
		return s
	}
	return d
}
