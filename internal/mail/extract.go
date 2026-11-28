package mail

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/textproto"
	"os"
	"path/filepath"
)

// messageFields are header fields at least one of which a message's header
// must have, so other files of Name: Value lines aren't read as messages.
var messageFields = []string{"From", "To", "Cc", "Subject", "Date", "Message-Id", "Mime-Version", "Content-Type", "Received", "Return-Path", "Sender", "Reply-To"}

// List reads the message in file and returns its main headers and its
// parts, without writing anything. Nested messages are followed up to
// Options.Depth. The error is an *Error.
func List(ctx context.Context, file string, o Options) (*Result, error) {
	if o.Depth < 0 {
		return nil, &Error{Kind: Failed, Msg: "the depth limit can't be negative"}
	}
	f, err := openMessage(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	x := &walker{ctx: ctx, o: o}
	headers, err := x.run(f, &textSink{})
	if err != nil {
		return nil, asError(err)
	}
	return &Result{Headers: headers, Parts: x.parts}, nil
}

// Extract reads the message in file and writes it into dest, which must be
// missing or an empty directory, and not a symbolic link: body.txt, with
// the main headers and the text of every body part, nested messages
// included, and each attachment as N-NAME, N counting from 1 and NAME its
// SafeName. On any error dest is emptied, without following links, and
// the error is an *Error.
func Extract(ctx context.Context, file, dest string, o Options) (*Result, error) {
	if o.MaxSize <= 0 {
		return nil, &Error{Kind: Failed, Msg: "the size limit must be positive"}
	}
	if o.Depth < 0 {
		return nil, &Error{Kind: Failed, Msg: "the depth limit can't be negative"}
	}
	f, err := openMessage(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	root, err := prepareDest(dest)
	if err != nil {
		return nil, &Error{Kind: Failed, Msg: err.Error()}
	}
	x := &walker{ctx: ctx, o: o, extract: true, root: root}
	headers, err := x.extractTo(f)
	if err != nil {
		err = asError(err)
		if cerr := emptyDir(root); cerr != nil {
			err = errors.Join(err, fmt.Errorf("emptying %s: %w", dest, cerr))
		}
		return nil, err
	}
	return &Result{Headers: headers, Parts: x.parts, Body: BodyFile}, nil
}

// extractTo writes body.txt and the attachments.
func (x *walker) extractTo(f *os.File) ([]Header, error) {
	bf, err := os.OpenFile(filepath.Join(x.root, BodyFile), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return nil, err
	}
	bw := bufio.NewWriter(&budgetWriter{w: bf, x: x})
	headers, err := x.run(f, &textSink{w: bw})
	if err == nil {
		err = bw.Flush()
	}
	if cerr := bf.Close(); err == nil {
		err = cerr
	}
	return headers, err
}

// run reads the message's header, writes its main headers to sink, and
// walks its parts.
func (x *walker) run(f *os.File, sink *textSink) ([]Header, error) {
	br := bufio.NewReaderSize(&ctxReader{ctx: x.ctx, r: f}, readBuffer)
	h, rest, err := readHeader(br)
	if err != nil {
		var e *Error
		var fe *fatalError
		switch {
		case errors.As(err, &e):
			return nil, e
		case errors.As(err, &fe):
			return nil, fe.err
		case errors.Is(err, errNoHeader):
			return nil, &Error{Kind: NotMessage, Msg: "the file doesn't start with a message header"}
		}
		return nil, &Error{Kind: NotMessage, Msg: "the file doesn't start with a message header: " + err.Error()}
	}
	if !isMessage(h) {
		return nil, &Error{Kind: NotMessage, Msg: "the file's header has none of the fields a message has"}
	}
	headers := headersOf(h)
	if err := sink.writeHeaders(headers); err != nil {
		return nil, unwrapFatal(err)
	}
	if err := x.node(h, &tagReader{r: rest}, "1", 0, 0, "text/plain", sink); err != nil {
		return nil, unwrapFatal(err)
	}
	if err := sink.endLine(); err != nil {
		return nil, unwrapFatal(err)
	}
	return headers, nil
}

func isMessage(h textproto.MIMEHeader) bool {
	for _, k := range messageFields {
		if _, ok := h[k]; ok {
			return true
		}
	}
	return false
}

func unwrapFatal(err error) error {
	var fe *fatalError
	if errors.As(err, &fe) {
		return fe.err
	}
	return err
}

// asError makes err an *Error, Failed unless it is one.
func asError(err error) error {
	err = unwrapFatal(err)
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return &Error{Kind: Failed, Msg: err.Error()}
}

// openMessage opens file, which must be a regular file.
func openMessage(file string) (*os.File, error) {
	f, err := os.Open(file)
	if err != nil {
		return nil, &Error{Kind: Failed, Msg: err.Error()}
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, &Error{Kind: Failed, Msg: err.Error()}
	}
	if !fi.Mode().IsRegular() {
		_ = f.Close()
		return nil, &Error{Kind: Failed, Msg: fmt.Sprintf("%s is not a regular file", file)}
	}
	return f, nil
}

// prepareDest makes dest if it is missing and returns its absolute path
// with links resolved. An existing dest must be an empty directory and not
// a symbolic link. These are safeclaw-unpack's rules.
func prepareDest(dest string) (string, error) {
	abs, err := filepath.Abs(dest)
	if err != nil {
		return "", err
	}
	fi, err := os.Lstat(abs)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if err := os.Mkdir(abs, 0o755); err != nil {
			return "", err
		}
	case err != nil:
		return "", err
	case fi.Mode()&fs.ModeSymlink != 0:
		return "", fmt.Errorf("%s is a symbolic link", dest)
	case !fi.IsDir():
		return "", fmt.Errorf("%s is not a directory", dest)
	default:
		d, err := os.Open(abs)
		if err != nil {
			return "", err
		}
		names, err := d.Readdirnames(1)
		_ = d.Close()
		if err != nil && err != io.EOF {
			return "", err
		}
		if len(names) > 0 {
			return "", fmt.Errorf("%s is not empty", dest)
		}
	}
	return filepath.EvalSymlinks(abs)
}

// emptyDir removes everything in dir without following links.
func emptyDir(dir string) error {
	names, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	var errs []error
	for _, n := range names {
		errs = append(errs, os.RemoveAll(filepath.Join(dir, n.Name())))
	}
	return errors.Join(errs...)
}
