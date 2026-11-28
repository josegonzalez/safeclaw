package mail

import (
	"bufio"
	"bytes"
	"errors"
	"io"
)

// errNoDelimiter is a multipart's body ending before its close delimiter,
// or without any delimiter at all.
var errNoDelimiter = errors.New("the multipart ends without its close delimiter")

// splitter splits a multipart body into its parts, streaming, following
// RFC 2046: a delimiter is a line, at the start of a line, of "--" and the
// boundary, optionally followed by "--" for the close delimiter, then by
// spaces and tabs (transport padding) and a line break. The line break
// before a delimiter belongs to it, not to the part. The preamble before
// the first delimiter and the epilogue after the close delimiter are
// ignored.
//
// It is used instead of mime/multipart, whose part header parser follows
// HTTP's rules and fails on a header line net/mail accepts, such as one
// with a raw control character, which would stop the walk at that part and
// hide the parts after it. Each part, header included, is read by the
// caller, the header with readPartHeader.
type splitter struct {
	br   *bufio.Reader
	dash []byte
	cur  *partReader
	// closed is set once the close delimiter is read.
	closed bool
}

func newSplitter(r io.Reader, boundary string) *splitter {
	return &splitter{br: bufio.NewReaderSize(r, readBuffer), dash: []byte("--" + boundary)}
}

// next skips the rest of the current part, or the preamble, and returns a
// reader for the next part: io.EOF after the close delimiter, and
// errNoDelimiter when the body ends before it.
func (s *splitter) next() (io.Reader, error) {
	if s.closed {
		return nil, io.EOF
	}
	if s.cur == nil {
		s.cur = &partReader{s: s, lineStart: true}
	}
	if _, err := io.Copy(io.Discard, s.cur); err != nil {
		return nil, err
	}
	if s.closed {
		return nil, io.EOF
	}
	s.cur = &partReader{s: s, lineStart: true}
	return s.cur, nil
}

// delimiter reports whether line, a whole line at the start of a line, is a
// delimiter, and whether it is the close delimiter.
func (s *splitter) delimiter(line []byte) (is, closing bool) {
	rest, ok := bytes.CutPrefix(line, s.dash)
	if !ok {
		return false, false
	}
	rest, closing = bytes.CutPrefix(rest, []byte("--"))
	rest = bytes.TrimSuffix(rest, []byte("\n"))
	rest = bytes.TrimSuffix(rest, []byte("\r"))
	if len(bytes.Trim(rest, " \t")) != 0 {
		return false, false
	}
	return true, closing
}

// partReader reads one part, up to the next delimiter. A line break is
// held back until the next line shows it isn't a delimiter's.
type partReader struct {
	s *splitter
	// pending is read and not yet returned.
	pending []byte
	// eol is the held-back line break.
	eol []byte
	// lineStart is set when the next byte starts a line.
	lineStart bool
	err       error
}

func (p *partReader) Read(b []byte) (int, error) {
	for len(p.pending) == 0 && p.err == nil {
		p.fill()
	}
	n := copy(b, p.pending)
	p.pending = p.pending[n:]
	if len(p.pending) == 0 && p.err != nil {
		return n, p.err
	}
	return n, nil
}

// fill reads one line, or a chunk of a long one, into pending.
func (p *partReader) fill() {
	chunk, err := p.s.br.ReadSlice('\n')
	full := err == nil
	if err != nil && err != bufio.ErrBufferFull && err != io.EOF {
		p.pending = append(p.pending[:0], p.eol...)
		p.pending = append(p.pending, chunk...)
		p.eol = nil
		p.err = err
		return
	}
	// A delimiter is short, so a line too long for the buffer isn't one;
	// it can still end the input.
	if p.lineStart && err != bufio.ErrBufferFull {
		if is, closing := p.s.delimiter(chunk); is {
			p.eol = nil
			p.s.closed = closing
			p.err = io.EOF
			return
		}
	}
	p.pending = append(p.pending[:0], p.eol...)
	p.eol = nil
	body := chunk
	if full {
		end := len(body) - 1
		if end > 0 && body[end-1] == '\r' {
			end--
		}
		p.eol = append(p.eol, body[end:]...)
		body = body[:end]
	}
	p.pending = append(p.pending, body...)
	p.lineStart = full
	if err == io.EOF {
		p.pending = append(p.pending, p.eol...)
		p.eol = nil
		p.err = errNoDelimiter
	}
}
