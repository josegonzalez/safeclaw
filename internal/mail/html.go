package mail

import (
	"io"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// skippedElements are left out of an HTML body's text with everything in
// them.
var skippedElements = map[atom.Atom]bool{
	atom.Script: true, atom.Style: true, atom.Noscript: true, atom.Template: true,
	atom.Title: true, atom.Iframe: true, atom.Object: true, atom.Svg: true, atom.Math: true,
}

// paragraphElements start and end a paragraph, with a blank line around
// it.
var paragraphElements = map[atom.Atom]bool{
	atom.P: true, atom.H1: true, atom.H2: true, atom.H3: true, atom.H4: true, atom.H5: true, atom.H6: true,
	atom.Ul: true, atom.Ol: true, atom.Dl: true, atom.Table: true, atom.Blockquote: true, atom.Pre: true,
	atom.Hr: true, atom.Form: true, atom.Fieldset: true, atom.Figure: true,
}

// lineElements start and end a line.
var lineElements = map[atom.Atom]bool{
	atom.Div: true, atom.Tr: true, atom.Li: true, atom.Dt: true, atom.Dd: true, atom.Section: true,
	atom.Article: true, atom.Header: true, atom.Footer: true, atom.Nav: true, atom.Aside: true,
	atom.Main: true, atom.Address: true, atom.Caption: true, atom.Center: true, atom.Body: true,
	atom.Figcaption: true, atom.Details: true, atom.Summary: true,
}

// maxLinkText is how much of a link's text is kept to compare with its
// address.
const maxLinkText = 4096

// htmlToText writes the text of the HTML read from r to w, streaming it
// with the x/net/html tokenizer: no tree is built, and a single token over
// maxHTMLToken is an error. Scripts, styles, and the other
// skippedElements are left out with their contents; paragraphs, lines,
// list items, and line breaks become line breaks; whitespace is collapsed
// outside <pre>; and a link whose text isn't its address is followed by
// the address in angle brackets, so the text shows where it really goes.
func htmlToText(r io.Reader, w io.Writer) error {
	z := html.NewTokenizer(r)
	z.SetMaxBuf(maxHTMLToken)
	t := &textOut{w: w}
	skip, pre := 0, 0
	var href string
	var link strings.Builder
	inLink := false
	for {
		tt := z.Next()
		switch tt {
		case html.ErrorToken:
			err := z.Err()
			if err == io.EOF {
				t.finish()
				return t.err
			}
			if t.err != nil {
				return t.err
			}
			return err
		case html.TextToken:
			if skip > 0 {
				continue
			}
			text := string(z.Text())
			if inLink && link.Len() < maxLinkText {
				link.WriteString(text)
			}
			t.text(text, pre > 0)
		case html.StartTagToken, html.SelfClosingTagToken:
			name, hasAttr := z.TagName()
			a := atom.Lookup(name)
			if skippedElements[a] {
				if tt == html.StartTagToken {
					skip++
				}
				continue
			}
			if skip > 0 {
				continue
			}
			switch {
			case a == atom.Br:
				t.lineBreak()
			case a == atom.Li:
				t.endLine()
				t.raw("- ")
			case a == atom.Td || a == atom.Th:
				t.space = true
			case a == atom.A && tt == html.StartTagToken:
				href = ""
				for hasAttr {
					var k, v []byte
					k, v, hasAttr = z.TagAttr()
					if string(k) == "href" {
						href = strings.TrimSpace(string(v))
					}
				}
				inLink = true
				link.Reset()
			case a == atom.Img:
				for hasAttr {
					var k, v []byte
					k, v, hasAttr = z.TagAttr()
					if string(k) == "alt" && strings.TrimSpace(string(v)) != "" {
						t.text("["+string(v)+"]", false)
					}
				}
			case paragraphElements[a]:
				t.paragraph()
			case lineElements[a]:
				t.endLine()
			}
			if a == atom.Pre && tt == html.StartTagToken {
				pre++
			}
		case html.EndTagToken:
			name, _ := z.TagName()
			a := atom.Lookup(name)
			if skippedElements[a] {
				if skip > 0 {
					skip--
				}
				continue
			}
			if skip > 0 {
				continue
			}
			switch {
			case a == atom.A:
				if inLink && href != "" && !sameLink(link.String(), href) {
					t.text(" <"+href+">", false)
				}
				inLink = false
			case a == atom.Pre:
				if pre > 0 {
					pre--
				}
				t.paragraph()
			case paragraphElements[a]:
				t.paragraph()
			case lineElements[a]:
				t.endLine()
			}
		}
		if t.err != nil {
			return t.err
		}
	}
}

// sameLink reports whether a link's text is its address, with or without
// a mailto: or the scheme.
func sameLink(text, href string) bool {
	text = strings.TrimSpace(text)
	for _, prefix := range []string{"", "mailto:", "http://", "https://"} {
		if prefix+text == href || prefix+text+"/" == href {
			return true
		}
	}
	return false
}

// textOut writes text, collapsing whitespace and keeping at most one blank
// line in a row. Line breaks are written only when text follows them, so
// the text never starts or ends with blank lines.
type textOut struct {
	w io.Writer
	// want is how many line breaks should end the output before the next
	// text, and trailing how many do, up to 2.
	want, trailing int
	// space is a collapsed space waiting for the next text.
	space bool
	// marker is set after a list marker, which the next text follows
	// without a space.
	marker bool
	wrote  bool
	err    error
}

func (t *textOut) write(s string) {
	if t.err != nil || s == "" {
		return
	}
	_, t.err = io.WriteString(t.w, s)
	t.wrote = true
}

// emit writes the line breaks owed.
func (t *textOut) emit() {
	if t.wrote && t.want > t.trailing {
		t.write(strings.Repeat("\n", t.want-t.trailing))
		t.trailing = t.want
	}
	t.want = 0
}

func (t *textOut) lineStart() bool {
	return !t.wrote || t.trailing > 0
}

func (t *textOut) text(s string, pre bool) {
	if pre {
		if s == "" {
			return
		}
		t.emit()
		t.write(s)
		t.marker, t.space = false, false
		n := len(s) - len(strings.TrimRight(s, "\n"))
		if n == len(s) {
			t.trailing = min(t.trailing+n, 2)
		} else {
			t.trailing = min(n, 2)
		}
		return
	}
	var b strings.Builder
	for len(s) > 0 {
		r, size := utf8.DecodeRuneInString(s)
		s = s[size:]
		if unicode.IsSpace(r) {
			t.space = true
			continue
		}
		if b.Len() == 0 {
			t.emit()
			if t.space && !t.lineStart() && !t.marker {
				b.WriteByte(' ')
			}
		} else if t.space {
			b.WriteByte(' ')
		}
		t.space, t.marker = false, false
		b.WriteRune(r)
	}
	if b.Len() > 0 {
		t.write(b.String())
		t.trailing = 0
	}
}

// raw writes s at the start of a line, such as a list marker.
func (t *textOut) raw(s string) {
	t.emit()
	t.write(s)
	t.trailing, t.space, t.marker = 0, false, true
}

// endLine ends the current line.
func (t *textOut) endLine() {
	t.space = false
	t.want = max(t.want, 1)
}

// lineBreak adds a line break even at the start of a line, for <br>.
func (t *textOut) lineBreak() {
	t.space = false
	if t.wrote {
		t.want = min(max(t.want, t.trailing)+1, 2)
	}
}

// paragraph ends the current line and leaves a blank line after it.
func (t *textOut) paragraph() {
	t.space = false
	t.want = 2
}

// finish ends the text with a line break.
func (t *textOut) finish() {
	if t.wrote && t.trailing == 0 {
		t.write("\n")
	}
}
