package mail

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/textproto"
	"os"
	"path/filepath"
	"strings"
)

// walker reads a message's parts in order, streaming each one: List
// counts them, and Extract writes their text to body.txt and their
// attachments to files.
type walker struct {
	ctx     context.Context
	o       Options
	extract bool
	// root is the destination, for Extract.
	root  string
	parts []Part
	// attachments counts the attachments, for their numbers.
	attachments int
	// used is what was written, and buffered the alternatives' text held.
	used, buffered int64
}

// reserve checks that n more bytes of output stay within the size limit.
func (x *walker) reserve(n int) error {
	if x.used+x.buffered+int64(n) > x.o.MaxSize {
		return &fatalError{&Error{Kind: TooLarge, Msg: fmt.Sprintf("the extracted contents are over the %d byte limit", x.o.MaxSize)}}
	}
	return nil
}

// part returns the part at index i. Parts are appended as the walk goes,
// so a pointer to one is only good until the next is added.
func (x *walker) part(i int) *Part {
	return &x.parts[i]
}

// settle sorts an error from reading part i. Errors writing output or
// from the context are returned; any other error flags the part: as
// MALFORMED when src, the part's source, failed, and as BAD-ENCODING when
// decoding it did.
func (x *walker) settle(i int, err error, src *tagReader) error {
	if err == nil || err == io.EOF {
		return nil
	}
	var f *fatalError
	if errors.As(err, &f) {
		return f.err
	}
	if cerr := x.ctx.Err(); cerr != nil {
		return cerr
	}
	if src != nil && src.err != nil {
		x.part(i).set(FlagMalformed)
	} else {
		x.part(i).set(FlagBadEncoding)
	}
	return nil
}

// fatal returns err when it stops the walk: an error writing output, or
// the context ending.
func (x *walker) fatal(err error) error {
	var f *fatalError
	if errors.As(err, &f) {
		return f.err
	}
	return x.ctx.Err()
}

// drain reads the rest of r, which counts it, and settles any error.
func (x *walker) drain(i int, r io.Reader, src *tagReader) error {
	_, err := io.Copy(io.Discard, r)
	return x.settle(i, err, src)
}

// contentType parses h's Content-Type, defType when it has none. One that
// can't be parsed is application/octet-stream, and reported as bad, so it
// is written as an attachment rather than read as text.
func contentType(h textproto.MIMEHeader, defType string) (string, map[string]string, bool) {
	ct := h.Get("Content-Type")
	if strings.TrimSpace(ct) == "" {
		return defType, map[string]string{}, false
	}
	t, params, err := mime.ParseMediaType(ct)
	switch {
	case err == nil:
		return t, params, false
	case t != "" && errors.Is(err, mime.ErrInvalidMediaParameter):
		return t, params, true
	}
	return "application/octet-stream", map[string]string{}, true
}

// node reads one part: h is its header, src its body before decoding, id
// its ID, level how deeply it is nested, msgDepth how many nested messages
// it is in, and defType its type when it has no Content-Type. Its body
// text goes to sink. Only errors that stop the walk are returned.
func (x *walker) node(h textproto.MIMEHeader, src *tagReader, id string, level, msgDepth int, defType string, sink *textSink) error {
	if err := x.ctx.Err(); err != nil {
		return err
	}
	if len(x.parts) >= MaxParts {
		return &Error{Kind: Rejected, Part: id, Msg: fmt.Sprintf("the message has over %d parts", MaxParts)}
	}
	if level >= MaxNesting {
		return &Error{Kind: Rejected, Part: id, Msg: fmt.Sprintf("the message nests parts over %d levels deep", MaxNesting)}
	}
	i := len(x.parts)
	x.parts = append(x.parts, Part{ID: id, Size: -1})
	mediatype, params, bad := contentType(h, defType)
	p := x.part(i)
	p.Type = mediatype
	if bad {
		p.set(FlagMalformed)
	}
	disposition, dparams, _ := mime.ParseMediaType(h.Get("Content-Disposition"))
	name := dparams["filename"]
	if name == "" {
		name = params["name"]
	}
	p.Name = decodeWords(name)
	decoded, ok := transferDecoder(h.Get("Content-Transfer-Encoding"), src)
	if !ok {
		p.set(FlagBadEncoding)
	}

	switch {
	case strings.HasPrefix(mediatype, "multipart/") && params["boundary"] != "":
		return x.multipart(i, mediatype, params["boundary"], decoded, src, level, msgDepth, sink)
	case strings.HasPrefix(mediatype, "multipart/"):
		p.set(FlagMalformed)
	case mediatype == "message/rfc822" || mediatype == "message/global":
		if msgDepth < x.o.Depth {
			return x.nested(i, decoded, src, level, msgDepth, sink)
		}
		p.set(FlagDepthLimit)
	case (mediatype == "text/plain" || mediatype == "text/html") && disposition != "attachment" && p.Name == "":
		return x.body(i, params["charset"], decoded, src, sink)
	}
	return x.attachment(i, decoded, src)
}

// body adds a text part's text to sink: its charset decoded, HTML turned
// into text, and control characters stripped.
func (x *walker) body(i int, label string, decoded io.Reader, src *tagReader, sink *textSink) error {
	p := x.part(i)
	p.set(FlagBody)
	if x.extract {
		p.File = BodyFile
	}
	counted := &countReader{r: decoded}
	if x.extract {
		text, ok := charsetReader(label, counted)
		if !ok {
			p.set(FlagBadEncoding)
		}
		if err := sink.block(); err != nil {
			return x.settle(i, err, src)
		}
		f := newTextFilter(sink)
		var err error
		if p.Type == "text/html" {
			err = htmlToText(text, f)
		} else {
			_, err = io.Copy(f, text)
		}
		if ferr := f.Flush(); err == nil {
			err = ferr
		}
		if err := x.settle(i, err, src); err != nil {
			return err
		}
	} else if !knownCharset(label) {
		p.set(FlagBadEncoding)
	}
	// What the conversion left unread still counts toward the size.
	err := x.drain(i, counted, src)
	x.part(i).Size = counted.n
	return err
}

// attachment writes a part to its own numbered file.
func (x *walker) attachment(i int, decoded io.Reader, src *tagReader) error {
	p := x.part(i)
	p.set(FlagAttachment)
	safe := SafeName(p.Name)
	if p.Name != "" && safe != p.Name {
		p.set(FlagUnsafeName)
	}
	if safe == "" {
		safe = "attachment"
		if p.Has(FlagDepthLimit) || p.Type == "message/rfc822" || p.Type == "message/global" {
			safe = "message.eml"
		}
	}
	x.attachments++
	counted := &countReader{r: decoded}
	if !x.extract {
		err := x.drain(i, counted, src)
		x.part(i).Size = counted.n
		return err
	}
	file := fmt.Sprintf("%d-%s", x.attachments, safe)
	f, err := os.OpenFile(filepath.Join(x.root, file), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return &Error{Kind: Failed, Part: p.ID, Msg: err.Error()}
	}
	p.File = file
	_, err = io.Copy(&budgetWriter{w: f, x: x}, counted)
	if cerr := f.Close(); cerr != nil {
		return &Error{Kind: Failed, Part: p.ID, Msg: cerr.Error()}
	}
	x.part(i).Size = counted.n
	return x.settle(i, err, src)
}

// maxRecorded is how much of a nested message is kept while its header is
// read, so one whose header can't be read is still written in full as an
// attachment: the header limit, a line past it, and the read-ahead.
const maxRecorded = MaxHeaderBytes + MaxHeaderLine + 2*readBuffer

// readBuffer is the size of the buffers headers are read through.
const readBuffer = 64 << 10

// nested follows a message/rfc822 part: its main headers go to sink after
// a separator, then its parts are read like the message's own.
func (x *walker) nested(i int, decoded io.Reader, src *tagReader, level, msgDepth int, sink *textSink) error {
	id := x.part(i).ID
	counted := &countReader{r: decoded}
	rec := &recorder{r: counted, max: maxRecorded}
	h, rest, err := readHeader(bufio.NewReaderSize(rec, readBuffer))
	rec.off = true
	if err != nil {
		var e *Error
		if errors.As(err, &e) {
			e.Part = id
			return e
		}
		if serr := x.fatal(err); serr != nil {
			return serr
		}
		// Not a message after all: written as it is, as an attachment.
		x.part(i).set(FlagMalformed)
		if rec.over {
			err := x.drain(i, counted, src)
			x.part(i).Size = counted.n
			return err
		}
		if err := x.attachment(i, io.MultiReader(&rec.buf, counted), src); err != nil {
			return err
		}
		x.part(i).Size = counted.n
		return nil
	}
	p := x.part(i)
	p.set(FlagNestedMessage)
	p.Headers = headersOf(h)
	if err := sink.block(); err != nil {
		return x.settle(i, err, src)
	}
	if _, err := fmt.Fprintf(sink, "---------- Forwarded message (part %s) ----------\n", id); err != nil {
		return x.settle(i, err, src)
	}
	if err := sink.writeHeaders(p.Headers); err != nil {
		return x.settle(i, err, src)
	}
	inner := &tagReader{r: rest}
	if err := x.node(h, inner, id+".1", level+1, msgDepth+1, "text/plain", sink); err != nil {
		return err
	}
	err = x.drain(i, counted, src)
	x.part(i).Size = counted.n
	return err
}

// alternative is one part of a multipart/alternative: the parts from start
// to end, and its text, held until the one to use is known.
type alternative struct {
	start, end int
	held       *bufferWriter
}

// multipart reads the parts of a multipart. In a multipart/alternative
// each part's text is held, then only one part's goes to sink: the first
// text/plain part, else the last part with any text.
func (x *walker) multipart(i int, mediatype, boundary string, decoded io.Reader, src *tagReader, level, msgDepth int, sink *textSink) error {
	id := x.part(i).ID
	sp := newSplitter(decoded, boundary)
	isAlt := mediatype == "multipart/alternative"
	defType := "text/plain"
	if mediatype == "multipart/digest" {
		defType = "message/rfc822"
	}
	var alts []alternative
	for n := 1; ; n++ {
		raw, err := sp.next()
		if err == io.EOF {
			break
		}
		if err != nil {
			if serr := x.fatal(err); serr != nil {
				return serr
			}
			x.part(i).set(FlagMalformed)
			break
		}
		childID := fmt.Sprintf("%s.%d", id, n)
		psrc := &tagReader{r: raw}
		rec := &recorder{r: psrc, max: maxRecorded}
		h, body, err := readPartHeader(bufio.NewReaderSize(rec, readBuffer))
		rec.off = true
		childType := defType
		badHeader := false
		if err != nil {
			var e *Error
			if errors.As(err, &e) {
				e.Part = childID
				return e
			}
			var f *fatalError
			if errors.As(err, &f) {
				return f.err
			}
			if cerr := x.ctx.Err(); cerr != nil {
				return cerr
			}
			// A header net/mail can't parse: the part is read as one with
			// no header, kept whole as an attachment.
			h, childType, badHeader = textproto.MIMEHeader{}, "application/octet-stream", true
			body = psrc
			if !rec.over {
				body = io.MultiReader(&rec.buf, psrc)
			}
		}
		childSink := sink
		var held *bufferWriter
		if isAlt {
			childSink = &textSink{}
			if x.extract {
				held = &bufferWriter{x: x}
				childSink.w = held
			}
		}
		start := len(x.parts)
		if err := x.node(h, &tagReader{r: body}, childID, level+1, msgDepth, childType, childSink); err != nil {
			return err
		}
		if badHeader {
			x.part(start).set(FlagMalformed)
		}
		if isAlt {
			alts = append(alts, alternative{start: start, end: len(x.parts), held: held})
		}
		if psrc.err != nil {
			// The multipart is cut short or broken.
			x.part(i).set(FlagMalformed)
			break
		}
	}
	if isAlt {
		if err := x.choose(alts, sink); err != nil {
			return x.settle(i, err, src)
		}
	}
	return nil
}

// choose writes the text of one alternative to sink and marks the body
// parts of the others SKIPPED.
func (x *walker) choose(alts []alternative, sink *textSink) error {
	hasBody := func(a alternative) bool {
		for j := a.start; j < a.end; j++ {
			if x.parts[j].Has(FlagBody) {
				return true
			}
		}
		return false
	}
	chosen := -1
	for n, a := range alts {
		if p := x.parts[a.start]; p.Type == "text/plain" && p.Has(FlagBody) {
			chosen = n
			break
		}
	}
	if chosen < 0 {
		for n := len(alts) - 1; n >= 0; n-- {
			if hasBody(alts[n]) {
				chosen = n
				break
			}
		}
	}
	for n, a := range alts {
		if a.held != nil {
			a.held.release()
		}
		if n == chosen {
			if a.held != nil && a.held.buf.Len() > 0 {
				if err := sink.block(); err != nil {
					return err
				}
				if _, err := sink.Write(a.held.buf.Bytes()); err != nil {
					return err
				}
			}
			continue
		}
		for j := a.start; j < a.end; j++ {
			if p := x.part(j); p.Has(FlagBody) {
				p.unset(FlagBody)
				p.set(FlagSkipped)
				p.File = ""
			}
		}
	}
	return nil
}
