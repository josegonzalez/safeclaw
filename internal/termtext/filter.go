package termtext

import (
	"bytes"
	"io"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
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
//   - Hyperlinks to anything but http and https URLs on hosts other than
//     localhost and loopback addresses. Such a link is replaced by the
//     sequence that ends a link, so its text is kept as plain text.
//   - DCS, SOS, PM, and APC strings, and screen and tmux title strings
//     (ESC k), whole, which covers tmux passthrough (ESC P tmux; ...) and
//     terminal-specific commands carried in them.
//   - CSI t window operations other than the size reports and the title
//     stack (14, 15, 16, 18, 19, 22, 23), so the stream can't move,
//     resize, or iconify the host window or read its title. A title stack
//     pop with nothing the stream pushed left to pop, and a push past
//     maxStack, are dropped too, so the stream can't pop entries it
//     didn't push. Kitty keyboard flag pushes and pops are kept balanced
//     the same way.
//   - CSI i media copy, which can send what follows to a printer.
//   - C1 control bytes, raw or UTF-8 encoded, and text that isn't valid
//     UTF-8, such as overlong encodings, which some terminals decode
//     anyway.
//
// Everything else, including text, C0 controls, SGR colours, cursor
// movement, modes such as the alternate screen and mouse reporting, and
// queries whose answers go back to the stream's own input, is passed on
// unchanged. A sequence split across writes is parsed as one.
//
// Filter also keeps track of the modes the stream leaves set, so Restore
// can undo them once the stream ends.
type Filter struct {
	w     io.Writer
	state filterState
	// seq holds a sequence that is held back while it is parsed: a CSI,
	// or an OSC that hasn't been dropped.
	seq []byte
	// oscAllowed is set once an OSC's number is known to be allowed.
	oscAllowed bool
	// utf holds a UTF-8 sequence in text that has started but not ended,
	// and nutf is its length so far.
	utf  [utf8.UTFMax]byte
	nutf int
	left leftSet
	out  bytes.Buffer
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

// ground handles a byte outside any escape sequence. A multi-byte UTF-8
// sequence is held back until it ends, then passed on only if it is valid
// and isn't a C1 control. Invalid bytes, such as an overlong encoding, a
// surrogate, a sequence cut short, or a stray continuation byte, are
// dropped.
func (f *Filter) ground(b byte) {
	if f.nutf > 0 {
		if b >= 0x80 && b <= 0xbf {
			f.utf[f.nutf] = b
			f.nutf++
			if !utf8.FullRune(f.utf[:f.nutf]) {
				return
			}
			// Only continuation bytes follow the lead byte, so an invalid
			// sequence is dropped whole, as the rest can't start a rune.
			if r, size := utf8.DecodeRune(f.utf[:f.nutf]); size == f.nutf && (r < 0x80 || r > 0x9f) {
				f.out.Write(f.utf[:f.nutf])
			}
			f.nutf = 0
			return
		}
		// Cut short: drop it and handle b on its own.
		f.nutf = 0
	}
	switch {
	case b == 0x1b:
		f.state = stEsc
	case b < 0x80:
		f.out.WriteByte(b)
	case b >= 0xc2 && b <= 0xf4:
		f.utf[0] = b
		f.nutf = 1
	default:
		// A raw C1 control, a stray continuation byte, or a byte that
		// never starts a valid sequence.
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
	case b == 'P' || b == 'X' || b == '^' || b == '_' || b == 'k':
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
		f.left.escFinal(b)
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
		f.out.Write(f.left.csi(f.seq))
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
// A hyperlink whose target isn't allowed is replaced by the empty
// hyperlink that ends one, so its text is shown as plain text rather than
// as part of a link opened earlier.
func (f *Filter) endOSC(term []byte) {
	if (f.oscAllowed || f.numberAllowed()) && plainText(f.seq[2:]) {
		if isHyperlink(f.seq[2:]) && !allowedHyperlink(f.seq[2:]) {
			f.out.WriteString("\x1b]8;;")
		} else {
			f.out.Write(f.seq)
		}
		f.out.Write(term)
	}
	f.reset()
}

// isHyperlink reports whether the OSC text b is an OSC 8 hyperlink.
func isHyperlink(b []byte) bool {
	return len(b) > 0 && b[0] == '8' && (len(b) == 1 || b[1] == ';')
}

// allowedHyperlink reports whether the OSC 8 text b, 8;params;URI, may be
// passed on. The empty URI that ends a link always may. Otherwise the URI
// must be printable ASCII with no spaces or backslashes, as OSC 8 URIs are
// percent-encoded, and an http or https URL with a host that isn't a
// loopback or unspecified address. That mirrors the dashboard terminal's
// link handler: the host terminal hands a clicked link to the OS, which
// may open other schemes, such as file: into a directory the session can
// write, in another app, and a loopback target can reach the dashboard,
// whose cookie is sent to its host on any port, or a session's terminal.
func allowedHyperlink(b []byte) bool {
	parts := bytes.SplitN(b, []byte{';'}, 3)
	if len(parts) != 3 {
		return false
	}
	uri := string(parts[2])
	if uri == "" {
		return true
	}
	for i := range len(uri) {
		if c := uri[i]; c <= ' ' || c >= 0x7f || c == '\\' {
			return false
		}
	}
	u, err := url.Parse(uri)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Opaque != "" {
		return false
	}
	return allowedLinkHost(u.Hostname())
}

// allowedLinkHost reports whether a link may target host, which is
// refused when it is empty or not a plain DNS name or IP address, or
// when a browser would read it as localhost, a name under .localhost, a
// loopback address, or the unspecified address. Numeric hosts are read as
// browsers read them, so 127.1 and 0x7f000001 are loopback too.
func allowedLinkHost(host string) bool {
	if host == "" {
		return false
	}
	if strings.Contains(host, ":") {
		addr, err := netip.ParseAddr(host)
		if err != nil || addr.Zone() != "" {
			return false
		}
		addr = addr.Unmap()
		return !addr.IsLoopback() && !addr.IsUnspecified()
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if strings.ContainsFunc(host, func(r rune) bool {
		return (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' && r != '_' && r != '.'
	}) {
		return false
	}
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return false
	}
	labels := strings.Split(host, ".")
	if !numericLabel(labels[len(labels)-1]) {
		return true
	}
	addr, ok := parseURLIPv4(labels)
	return ok && !addr.IsLoopback() && !addr.IsUnspecified()
}

// numericLabel reports whether a host label makes a browser parse the
// host as an IPv4 address: decimal digits, or 0x and hex digits.
func numericLabel(s string) bool {
	if s == "" {
		return false
	}
	if t, ok := strings.CutPrefix(s, "0x"); ok {
		_, err := strconv.ParseUint("0"+t, 16, 64)
		return err == nil
	}
	_, err := strconv.ParseUint(s, 10, 64)
	return err == nil
}

// parseURLIPv4 parses the labels of a numeric host as the WHATWG URL
// standard does, where each of up to four parts is decimal, octal with a
// leading 0, or hex with 0x, and the last part fills the remaining bytes.
// It reports false for a host browsers refuse as an invalid IPv4 address.
func parseURLIPv4(labels []string) (netip.Addr, bool) {
	if len(labels) > 4 {
		return netip.Addr{}, false
	}
	nums := make([]uint64, len(labels))
	for i, l := range labels {
		base := 10
		switch {
		case strings.HasPrefix(l, "0x"):
			l, base = "0"+l[2:], 16
		case len(l) > 1 && l[0] == '0':
			l, base = l[1:], 8
		}
		n, err := strconv.ParseUint(l, base, 32)
		if err != nil {
			return netip.Addr{}, false
		}
		nums[i] = n
	}
	last := len(nums) - 1
	var v uint64
	for i, n := range nums[:last] {
		if n > 0xff {
			return netip.Addr{}, false
		}
		v |= n << (8 * (3 - i))
	}
	if nums[last] >= 1<<(8*(4-last)) {
		return netip.Addr{}, false
	}
	v |= nums[last]
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), true
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

// Restore returns the sequences that undo the modes the stream has left
// set: synchronized output, mouse reporting, focus events, bracketed
// paste, application cursor keys and keypad, xterm modifyOtherKeys, kitty
// keyboard flags, the alternate screen, a hidden cursor, and local echo.
// It also pops the title stack entries the stream pushed. Only what the
// stream set is undone, so a stream that cleaned up after itself gets an
// empty restore. Restore drops any sequence still being parsed, and
// starts tracking afresh.
func (f *Filter) Restore() []byte {
	f.reset()
	f.nutf = 0
	return f.left.restore()
}
