package mail

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	netmail "net/mail"
	"net/textproto"
)

// mainHeaders are the header fields printed and written to body.txt, in
// order.
var mainHeaders = []string{"From", "Reply-To", "To", "Cc", "Date", "Subject", "Message-Id"}

// errNoHeader is returned by readHeader for input that doesn't start with a
// header.
var errNoHeader = errors.New("no message header")

// readHeader reads a message's header from br with net/mail, after
// reading it into memory within the header limits. It returns the header
// and the rest of the message. A first line such as "From sender date",
// which mbox files put before each message, is skipped.
//
// Input with no header at all is errNoHeader, one over a limit is a
// Rejected *Error, and one net/mail can't parse is returned as its error.
func readHeader(br *bufio.Reader) (textproto.MIMEHeader, io.Reader, error) {
	return readHeaderOf(br, false)
}

// readPartHeader reads a MIME part's header the same way, except that it
// can be empty and has no mbox line.
func readPartHeader(br *bufio.Reader) (textproto.MIMEHeader, io.Reader, error) {
	return readHeaderOf(br, true)
}

func readHeaderOf(br *bufio.Reader, part bool) (textproto.MIMEHeader, io.Reader, error) {
	var raw bytes.Buffer
	fields := 0
	first := !part
	for {
		line, err := readLine(br)
		if err != nil && err != io.EOF {
			return nil, nil, err
		}
		if first {
			first = false
			if bytes.HasPrefix(line, []byte("From ")) {
				if err == io.EOF {
					return nil, nil, errNoHeader
				}
				continue
			}
		}
		if len(bytes.TrimRight(line, "\r\n")) == 0 {
			// The empty line that ends the header, or the end of input.
			break
		}
		if len(line) > MaxHeaderLine {
			return nil, nil, &Error{Kind: Rejected, Msg: fmt.Sprintf("a header line is over %d bytes", MaxHeaderLine)}
		}
		if line[0] != ' ' && line[0] != '\t' {
			fields++
			if fields > MaxHeaderFields {
				return nil, nil, &Error{Kind: Rejected, Msg: fmt.Sprintf("a header has over %d fields", MaxHeaderFields)}
			}
		}
		if raw.Len()+len(line) > MaxHeaderBytes {
			return nil, nil, &Error{Kind: Rejected, Msg: fmt.Sprintf("a header is over %d bytes", MaxHeaderBytes)}
		}
		raw.Write(line)
		if err == io.EOF {
			break
		}
	}
	if raw.Len() == 0 {
		if part {
			return textproto.MIMEHeader{}, br, nil
		}
		return nil, nil, errNoHeader
	}
	raw.WriteString("\r\n")
	msg, err := netmail.ReadMessage(&raw)
	if err != nil {
		return nil, nil, err
	}
	if len(msg.Header) == 0 && !part {
		return nil, nil, errNoHeader
	}
	return textproto.MIMEHeader(msg.Header), br, nil
}

// readLine reads one line, with its line break, reading no more than
// MaxHeaderLine+1 bytes of it: a longer line is cut there, which the
// caller rejects.
func readLine(br *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, err := br.ReadSlice('\n')
		line = append(line, chunk...)
		switch {
		case err == bufio.ErrBufferFull:
			if len(line) > MaxHeaderLine {
				return line, nil
			}
			continue
		case err != nil:
			return line, err
		}
		return line, nil
	}
}

// headersOf returns h's main headers, each occurrence in order, decoded and
// stripped of control characters.
func headersOf(h textproto.MIMEHeader) []Header {
	var out []Header
	for _, name := range mainHeaders {
		for _, v := range h.Values(name) {
			display := name
			if name == "Message-Id" {
				display = "Message-ID"
			}
			out = append(out, Header{Name: display, Value: CleanLine(decodeWords(v))})
		}
	}
	return out
}
