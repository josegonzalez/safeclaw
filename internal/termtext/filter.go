package termtext

import (
	"bytes"
	"io"
	"strconv"
	"unicode/utf8"
)

// Filter passes a live terminal stream, such as a tmux client's output,
// on to a real terminal while dropping the escape sequences that act on
// the host rather than on the screen:
//
//   - OSC sequences other than window titles (0, 1, 2), hyperlinks (8),
//     and default and cursor colours (10, 11, 12 and their resets 104,
//     110, 111, 112), which drops OSC 52 clipboard writes and reads among
//     others. An allowed OSC is held back until it ends, and is dropped
//     if it is longer than 8 KiB or holds a control character.
//   - DCS, SOS, PM, and APC strings, whole, which covers tmux passthrough
//     (ESC P tmux; ...) and terminal-specific commands carried in them.
//   - CSI t window operations other than the size reports and the title
//     stack (14, 15, 16, 18, 19, 22, 23), so the stream can't move,
//     resize, or iconify the host window or read its title.
//   - C1 control bytes, raw or UTF-8 encoded, which some terminals act on
//     as 8-bit introducers.
//
// Everything else, including text, C0 controls, SGR colours, cursor
// movement, modes such as the alternate screen and mouse reporting, and
// queries whose answers go back to the stream's own input, is passed on
// unchanged. A sequence split across writes is parsed as one.
type Filter struct {
	w     io.Writer
	state filterState
	// seq holds a sequence that is held back while it is parsed: a CSI,
	// or an OSC that hasn't been dropped.
	seq []byte
	// oscAllowed is set once an OSC's number is known to be allowed.
	oscAllowed bool
	// cont counts the UTF-8 continuation bytes still expected.
	cont int
	// heldC2 is set when a 0xC2 lead byte is held back to see whether it
	// starts an encoded C1 control.
	heldC2 bool
	out    bytes.Buffer
}

type filterState int

const (
	stGround filterState = iota
	stEsc
	stEscIntermediate
	stCSI
	stCSIIgnore
	stOSC
	stOSCEsc
	stOSCDrop
	stOSCDropEsc
	stString
	stStringEsc
)

const (
	maxCSI      = 256
	maxOSC      = 8 << 10
	maxOSCDigit = 6
)

// allowedOSC are the OSC numbers Filter passes on.
var allowedOSC = map[int]bool{0: true, 1: true, 2: true, 8: true, 10: true, 11: true, 12: true, 104: true, 110: true, 111: true, 112: true}

// allowedWindowOps are the CSI t first parameters Filter passes on.
var allowedWindowOps = map[string]bool{"14": true, "15": true, "16": true, "18": true, "19": true, "22": true, "23": true}

// NewFilter returns a Filter that writes the filtered stream to w.
func NewFilter(w io.Writer) *Filter {
	return &Filter{w: w}
}

// Write filters p and writes what is kept to the underlying writer in one
// write. It returns len(p) when that write succeeds, since filtering
// changes how many bytes reach the underlying writer.
func (f *Filter) Write(p []byte) (int, error) {
	f.out.Reset()
	for _, b := range p {
		f.step(b)
	}
	if f.out.Len() > 0 {
		if _, err := f.w.Write(f.out.Bytes()); err != nil {
			return 0, err
		}
	}
	return len(p), nil
}

func (f *Filter) step(b byte) {
	switch f.state {
	case stGround:
		f.ground(b)
	case stEsc:
		f.esc(b)
	case stEscIntermediate:
		switch {
		case b >= 0x20 && b <= 0x2f:
			f.out.WriteByte(b)
		case b >= 0x30 && b <= 0x7e:
			f.out.WriteByte(b)
			f.state = stGround
		default:
			f.abort(b)
		}
	case stCSI:
		f.csi(b)
	case stCSIIgnore:
		switch {
		case b >= 0x20 && b <= 0x3f:
		case b >= 0x40 && b <= 0x7e:
			f.state = stGround
		default:
			f.abort(b)
		}
	case stOSC:
		f.osc(b)
	case stOSCEsc:
		if b == '\\' {
			f.endOSC([]byte{0x1b, '\\'})
			return
		}
		// Any other ESC cuts the string short and starts a new sequence.
		f.reset()
		f.esc(b)
	case stOSCDrop, stString:
		switch b {
		case 0x1b:
			if f.state == stOSCDrop {
				f.state = stOSCDropEsc
			} else {
				f.state = stStringEsc
			}
		case 0x07:
			if f.state == stOSCDrop {
				f.state = stGround
			}
		case 0x18, 0x1a:
			f.state = stGround
		}
	case stOSCDropEsc, stStringEsc:
		switch {
		case b == '\\':
			f.state = stGround
		case b == 0x1b && f.state == stStringEsc:
			// A doubled ESC, as tmux passthrough escapes them.
			f.state = stString
		default:
			f.reset()
			f.esc(b)
		}
	}
}

// ground handles a byte outside any escape sequence.
func (f *Filter) ground(b byte) {
	if f.heldC2 {
		f.heldC2 = false
		f.cont = 0
		if b >= 0x80 && b <= 0x9f {
			// U+0080 to U+009F: an encoded C1 control.
			return
		}
		f.out.WriteByte(0xc2)
		if b >= 0x80 && b <= 0xbf {
			f.out.WriteByte(b)
			return
		}
	}
	if f.cont > 0 {
		if b >= 0x80 && b <= 0xbf {
			f.cont--
			f.out.WriteByte(b)
			return
		}
		f.cont = 0
	}
	switch {
	case b == 0x1b:
		f.state = stEsc
	case b >= 0x80 && b <= 0x9f:
		// A raw C1 control.
	case b == 0xc2:
		f.heldC2 = true
	case b >= 0xc0 && b <= 0xdf:
		f.cont = 1
		f.out.WriteByte(b)
	case b >= 0xe0 && b <= 0xef:
		f.cont = 2
		f.out.WriteByte(b)
	case b >= 0xf0 && b <= 0xf7:
		f.cont = 3
		f.out.WriteByte(b)
	default:
		f.out.WriteByte(b)
	}
}

// esc handles the byte after ESC.
func (f *Filter) esc(b byte) {
	switch {
	case b == '[':
		f.seq = append(f.seq[:0], 0x1b, '[')
		f.state = stCSI
	case b == ']':
		f.seq = append(f.seq[:0], 0x1b, ']')
		f.state = stOSC
	case b == 'P' || b == 'X' || b == '^' || b == '_':
		f.state = stString
	case b == 0x1b:
		// The first ESC is cancelled by the second.
		f.state = stEsc
	case b >= 0x20 && b <= 0x2f:
		f.out.WriteByte(0x1b)
		f.out.WriteByte(b)
		f.state = stEscIntermediate
	case b >= 0x30 && b <= 0x7e:
		f.out.WriteByte(0x1b)
		f.out.WriteByte(b)
		f.state = stGround
	default:
		f.abort(b)
	}
}

// csi handles a byte inside a CSI sequence, which is held back until its
// final byte so window operations can be dropped.
func (f *Filter) csi(b byte) {
	switch {
	case b >= 0x20 && b <= 0x3f:
		if len(f.seq) >= maxCSI {
			f.seq = f.seq[:0]
			f.state = stCSIIgnore
			return
		}
		f.seq = append(f.seq, b)
	case b >= 0x40 && b <= 0x7e:
		f.seq = append(f.seq, b)
		if b != 't' || allowedWindowOps[windowOp(f.seq)] {
			f.out.Write(f.seq)
		}
		f.reset()
	case b == 0x1b:
		f.reset()
		f.state = stEsc
	case b < 0x20 && b != 0x18 && b != 0x1a:
		// Terminals run C0 controls inside a sequence and carry on.
		f.out.WriteByte(b)
	default:
		f.abort(b)
	}
}

// windowOp returns the first parameter of a CSI t sequence.
func windowOp(seq []byte) string {
	params := seq[2 : len(seq)-1]
	if i := bytes.IndexByte(params, ';'); i >= 0 {
		params = params[:i]
	}
	return string(params)
}

// osc handles a byte inside an OSC string. The string is held back until
// it ends, so a dropped or cut-short string never reaches the terminal in
// part, and it is dropped as soon as its number shows it isn't allowed.
func (f *Filter) osc(b byte) {
	switch b {
	case 0x07:
		f.endOSC([]byte{b})
		return
	case 0x1b:
		f.state = stOSCEsc
		return
	case 0x18, 0x1a:
		f.reset()
		return
	}
	if !f.oscAllowed {
		if b >= '0' && b <= '9' && len(f.seq) < 2+maxOSCDigit {
			f.seq = append(f.seq, b)
			return
		}
		if b != ';' || !f.numberAllowed() {
			f.drop()
			return
		}
		f.oscAllowed = true
	}
	if b < 0x20 || b == 0x7f || len(f.seq) >= maxOSC {
		f.drop()
		return
	}
	f.seq = append(f.seq, b)
}

// numberAllowed reports whether the OSC held in seq has an allowed number.
func (f *Filter) numberAllowed() bool {
	n, err := strconv.Atoi(string(f.seq[2:]))
	return err == nil && allowedOSC[n]
}

// endOSC passes on the OSC held in seq, ended by term, if it is allowed
// and its text is valid UTF-8 with no C1 controls.
func (f *Filter) endOSC(term []byte) {
	if (f.oscAllowed || f.numberAllowed()) && plainText(f.seq[2:]) {
		f.out.Write(f.seq)
		f.out.Write(term)
	}
	f.reset()
}

// plainText reports whether b is valid UTF-8 without C1 controls. C0
// controls never get into an OSC that is held back.
func plainText(b []byte) bool {
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		if (r == utf8.RuneError && size <= 1) || (r >= 0x80 && r <= 0x9f) {
			return false
		}
		b = b[size:]
	}
	return true
}

// drop discards the OSC being parsed and everything up to its end.
func (f *Filter) drop() {
	f.reset()
	f.state = stOSCDrop
}

// reset forgets the sequence being parsed and returns to text.
func (f *Filter) reset() {
	f.seq = f.seq[:0]
	f.oscAllowed = false
	f.state = stGround
}

// abort ends an escape sequence that a byte can't continue, without
// passing the sequence on, and handles the byte as text.
func (f *Filter) abort(b byte) {
	f.reset()
	f.ground(b)
}
