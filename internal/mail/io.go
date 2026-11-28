package mail

import (
	"bytes"
	"context"
	"fmt"
	"io"
)

// fatalError wraps an error from writing output, or the context ending,
// which stops the walk, unlike errors reading a part, which only flag it.
type fatalError struct{ err error }

func (e *fatalError) Error() string { return e.err.Error() }
func (e *fatalError) Unwrap() error { return e.err }

// ctxReader fails reads once ctx is done, so an interrupt stops a long
// message.
type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (c *ctxReader) Read(p []byte) (int, error) {
	if err := c.ctx.Err(); err != nil {
		return 0, &fatalError{err}
	}
	return c.r.Read(p)
}

// tagReader records the first error other than io.EOF its reader returns,
// so a part's reader can tell an error in the part's source, such as a
// multipart cut short, from one decoding it.
type tagReader struct {
	r   io.Reader
	err error
}

func (t *tagReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if err != nil && err != io.EOF && t.err == nil {
		t.err = err
	}
	return n, err
}

// countReader counts the bytes read through it.
type countReader struct {
	r io.Reader
	n int64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// recorder keeps a copy of the first max bytes read through it.
type recorder struct {
	r    io.Reader
	buf  bytes.Buffer
	max  int
	over bool
	off  bool
}

func (r *recorder) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if !r.off && n > 0 {
		if r.buf.Len()+n > r.max {
			r.over = true
			r.off = true
		} else {
			r.buf.Write(p[:n])
		}
	}
	return n, err
}

// budgetWriter writes to w, failing once the walker's output would pass
// its size limit.
type budgetWriter struct {
	w io.Writer
	x *walker
}

func (b *budgetWriter) Write(p []byte) (int, error) {
	if err := b.x.reserve(len(p)); err != nil {
		return 0, err
	}
	n, err := b.w.Write(p)
	b.x.used += int64(n)
	if err != nil {
		return n, &fatalError{err}
	}
	return n, nil
}

// bufferWriter holds the text of one alternative of a multipart/alternative
// until the alternative to use is known. It counts toward the size limit
// while it is held.
type bufferWriter struct {
	buf bytes.Buffer
	x   *walker
}

func (b *bufferWriter) Write(p []byte) (int, error) {
	if err := b.x.reserve(len(p)); err != nil {
		return 0, err
	}
	b.x.buffered += int64(len(p))
	return b.buf.Write(p)
}

// release stops counting the held text.
func (b *bufferWriter) release() {
	b.x.buffered -= int64(b.buf.Len())
}

// textSink collects body text, keeping body parts apart with blank lines.
// With no writer, it discards the text.
type textSink struct {
	w     io.Writer
	n     int64
	last2 [2]byte
}

func (s *textSink) Write(p []byte) (int, error) {
	if s.w != nil {
		if n, err := s.w.Write(p); err != nil {
			return n, err
		}
	}
	for _, c := range p[max(0, len(p)-2):] {
		s.last2 = [2]byte{s.last2[1], c}
	}
	s.n += int64(len(p))
	return len(p), nil
}

// endLine ends the text with a line break, unless it is empty or does.
func (s *textSink) endLine() error {
	if s.n > 0 && s.last2[1] != '\n' {
		_, err := s.Write([]byte("\n"))
		return err
	}
	return nil
}

// block starts a new block of text: after a blank line, unless the text is
// empty.
func (s *textSink) block() error {
	if err := s.endLine(); err != nil {
		return err
	}
	if s.n > 1 && s.last2[0] != '\n' {
		_, err := s.Write([]byte("\n"))
		return err
	}
	return nil
}

// writeHeaders writes headers as Name: Value lines.
func (s *textSink) writeHeaders(headers []Header) error {
	for _, h := range headers {
		if _, err := fmt.Fprintf(s, "%s: %s\n", h.Name, h.Value); err != nil {
			return err
		}
	}
	return nil
}
