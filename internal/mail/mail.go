// Package mail lists and extracts untrusted email messages (.eml files):
// the text of their body parts, forwarded messages included, and their
// attachments under safe, numbered names. Everything it reads is bounded,
// so a crafted message can't exhaust memory, and everything it prints is
// stripped of control characters. It backs `safeclaw mail`, installed as
// safeclaw-mail in the sandbox image variant.
package mail

import (
	"errors"
	"fmt"
)

// Defaults and limits.
const (
	// DefaultMaxSize is the default limit on the total size of what Extract
	// writes: 512 MiB.
	DefaultMaxSize = 512 << 20
	// DefaultDepth is the default number of levels of nested messages
	// followed below the message given.
	DefaultDepth = 3
	// BodyFile is the file Extract writes the headers and body text to.
	BodyFile = "body.txt"

	// MaxParts limits the number of parts in a message, nested messages
	// included.
	MaxParts = 1000
	// MaxNesting limits how deeply parts can nest, counting both multipart
	// containers and nested messages.
	MaxNesting = 32
	// MaxHeaderBytes limits the size of each header: the message's, each
	// nested message's, and each part's.
	MaxHeaderBytes = 256 << 10
	// MaxHeaderFields limits the number of fields in each header.
	MaxHeaderFields = 1000
	// MaxHeaderLine limits the length of a header line.
	MaxHeaderLine = 64 << 10
	// maxHTMLToken limits how much of an HTML body is buffered for one
	// token, such as a run of text or a tag with its attributes.
	maxHTMLToken = 4 << 20
	// maxNameBytes limits the length of a safe attachment name, before its
	// number is put in front.
	maxNameBytes = 100
)

// Part flags.
const (
	// FlagBody marks a text part whose text is in body.txt.
	FlagBody = "BODY"
	// FlagSkipped marks a text part left out of body.txt because another
	// part of its multipart/alternative was used.
	FlagSkipped = "SKIPPED"
	// FlagAttachment marks a part written to its own file.
	FlagAttachment = "ATTACHMENT"
	// FlagNestedMessage marks a message/rfc822 part whose headers and parts
	// were followed.
	FlagNestedMessage = "NESTED-MESSAGE"
	// FlagDepthLimit marks a nested message deeper than Options.Depth,
	// written as an attachment instead of followed.
	FlagDepthLimit = "DEPTH-LIMIT"
	// FlagUnsafeName marks an attachment whose name had to be changed to
	// make it safe.
	FlagUnsafeName = "UNSAFE-NAME"
	// FlagBadEncoding marks a part whose transfer encoding or charset
	// couldn't be decoded in full; what could be is kept.
	FlagBadEncoding = "BAD-ENCODING"
	// FlagMalformed marks a part with an unreadable Content-Type, or a
	// multipart without a boundary or cut short; what could be read is
	// kept.
	FlagMalformed = "MALFORMED"
)

// flagOrder is the order Flags returns flags in.
var flagOrder = []string{FlagBody, FlagSkipped, FlagAttachment, FlagNestedMessage, FlagDepthLimit, FlagUnsafeName, FlagBadEncoding, FlagMalformed}

// Header is one header field, decoded and stripped of control characters.
type Header struct {
	Name  string
	Value string
}

// Part is one MIME part of a message.
type Part struct {
	// ID is the part's position: "1" for the message's own content, and
	// "X.N" for the Nth part of multipart X or, with N 1, the content of
	// nested message X.
	ID string
	// Type is the media type, lowercased, without parameters.
	Type string
	// Size is the decoded size in bytes, -1 for a multipart.
	Size int64
	// Name is the original file name, decoded but not made safe.
	Name string
	// File is where Extract wrote the part, relative to the destination:
	// body.txt for a body part, the attachment's file for an attachment,
	// and "" for none.
	File string
	// Headers are a nested message's main headers.
	Headers []Header
	flags   map[string]bool
}

// Flags returns the part's flags in a stable order.
func (p Part) Flags() []string {
	var out []string
	for _, f := range flagOrder {
		if p.flags[f] {
			out = append(out, f)
		}
	}
	return out
}

// Has reports whether the part has flag f.
func (p Part) Has(f string) bool {
	return p.flags[f]
}

func (p *Part) set(f string) {
	if p.flags == nil {
		p.flags = map[string]bool{}
	}
	p.flags[f] = true
}

func (p *Part) unset(f string) {
	delete(p.flags, f)
}

// Result is what List or Extract found.
type Result struct {
	// Headers are the message's main headers.
	Headers []Header
	// Parts are every part, in the order they appear.
	Parts []Part
	// Body is BodyFile for Extract, and "" for List.
	Body string
}

// Options configures List and Extract.
type Options struct {
	// Depth is how many levels of nested messages are followed; 0 follows
	// none, writing them as attachments.
	Depth int
	// MaxSize limits the total size of the files Extract writes.
	MaxSize int64
}

// Kind is how reading a message failed. Its value is the exit code, the
// same as safeclaw-unpack's for the same meaning.
type Kind int

// Failure kinds, and the exit codes `safeclaw mail` uses for them.
const (
	// Failed is any other failure: a usage or I/O error.
	Failed Kind = 1
	// Rejected is a message over a limit on its structure: too many parts,
	// parts nested too deeply, or a header too large.
	Rejected Kind = 2
	// TooLarge is a message whose extracted contents exceed the size limit.
	TooLarge Kind = 4
	// NotMessage is a file that doesn't start with a message header.
	NotMessage Kind = 5
)

func (k Kind) String() string {
	switch k {
	case Rejected:
		return "rejected"
	case TooLarge:
		return "too large"
	case NotMessage:
		return "not a message"
	}
	return "failed"
}

// Error is a failure to list or extract a message.
type Error struct {
	Kind Kind
	// Part is the ID of the part it happened in, when known.
	Part string
	Msg  string
}

func (e *Error) Error() string {
	if e.Part != "" {
		return fmt.Sprintf("%s: part %s: %s", e.Kind, e.Part, e.Msg)
	}
	return fmt.Sprintf("%s: %s", e.Kind, e.Msg)
}

// KindOf returns err's Kind: Failed for an error that isn't an *Error.
func KindOf(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return Failed
}
