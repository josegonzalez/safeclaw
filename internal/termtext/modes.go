package termtext

import (
	"bytes"
	"strconv"
)

// TitlePush saves the host terminal's window and icon titles on its title
// stack, and TitlePop restores them. Write TitlePush before passing a
// stream through a Filter and TitlePop after its Restore, so titles the
// stream sets don't outlive it. Terminals without a title stack ignore
// both.
const (
	TitlePush = "\x1b[22t"
	TitlePop  = "\x1b[23t"
)

// maxStack is how many title stack or kitty keyboard flag entries the
// stream may push. Terminals cap their stacks, dropping the oldest entry
// when one is full, and xterm's title stack holds 10, so a stream kept
// under this can't push out the entry pushed before it started.
const maxStack = 8

// resetModes are the DEC private modes a stream can leave set that Restore
// resets, in the order it resets them: synchronized output first, so the
// terminal doesn't hold back the rest, then mouse reporting and its
// encodings, focus events, bracketed paste, application cursor keys, and
// the application keypad mode.
var resetModes = []int{2026, 1000, 1001, 1002, 1003, 1005, 1006, 1015, 1016, 1004, 2004, 1, 66}

// leftSet tracks what a filtered stream has set on the terminal and not
// yet reset, so it can be undone when the stream ends.
type leftSet struct {
	modes map[int]bool
	// alt is the mode, 47, 1047, or 1049, the stream switched to the
	// alternate screen with, or 0 when it is on the normal screen.
	alt          int
	cursorHidden bool
	// keypad is set by DECKPAM (ESC =) and reset by DECKPNM (ESC >).
	keypad bool
	// modifyOtherKeys is set by a non-zero xterm modifyOtherKeys, which
	// tmux sets for extended keys.
	modifyOtherKeys bool
	// localEcho is set when the stream resets SRM (CSI 12 l), which makes
	// some terminals echo keystrokes themselves.
	localEcho bool
	// kitty is the kitty keyboard protocol state on the normal screen
	// (0) and the alternate screen (1), which have stacks of their own.
	kitty [2]kittyFlags
	// titles is how many title stack entries the stream has pushed.
	titles int
}

type kittyFlags struct {
	// pushed is how many entries the stream has pushed.
	pushed int
	// set is whether the stream set flags with none of its own pushed.
	set bool
}

// screen returns 1 on the alternate screen and 0 on the normal screen.
func (l *leftSet) screen() int {
	if l.alt != 0 {
		return 1
	}
	return 0
}

// escFinal tracks a two-byte escape sequence that is passed on.
func (l *leftSet) escFinal(b byte) {
	switch b {
	case '=':
		l.keypad = true
	case '>':
		l.keypad = false
	case 'c':
		// RIS resets the terminal, title stack aside.
		*l = leftSet{titles: l.titles}
	}
}

// csi tracks the CSI sequence seq and returns what to pass on in its
// place: seq itself, a rewritten sequence, or nil to drop it.
func (l *leftSet) csi(seq []byte) []byte {
	final := seq[len(seq)-1]
	switch final {
	case 'i':
		// Media copy: CSI 5 i sends what follows to the printer.
		return nil
	case 't':
		return l.windowOp(seq)
	}
	body := seq[2 : len(seq)-1]
	if bytes.ContainsFunc(body, func(r rune) bool { return r >= 0x20 && r <= 0x2f }) {
		// A sequence with intermediates, such as DECSCUSR or DECRQM,
		// isn't one tracked here.
		return seq
	}
	var prefix byte
	if len(body) > 0 && body[0] >= 0x3c && body[0] <= 0x3f {
		prefix, body = body[0], body[1:]
	}
	params := bytes.Split(body, []byte{';'})
	switch {
	case (final == 'h' || final == 'l') && prefix == '?':
		for _, p := range params {
			l.decMode(number(p, -1), final == 'h')
		}
	case (final == 'h' || final == 'l') && prefix == 0:
		for _, p := range params {
			if number(p, -1) == 12 {
				l.localEcho = final == 'l'
			}
		}
	case (final == 'm' || final == 'n') && prefix == '>':
		if number(params[0], -1) == 4 {
			l.modifyOtherKeys = final == 'm' && len(params) > 1 && number(params[1], 0) != 0
		}
	case final == 'u' && prefix != 0 && prefix != '?':
		return l.kittyKeys(seq, prefix, params)
	}
	return seq
}

// windowOp passes on the allowed window operations, which have no prefix
// or intermediates, keeping the title stack balanced.
func (l *leftSet) windowOp(seq []byte) []byte {
	switch op := windowOp(seq); {
	case !allowedWindowOps[op]:
		return nil
	case op == "22":
		if l.titles >= maxStack {
			return nil
		}
		l.titles++
	case op == "23":
		if l.titles == 0 {
			return nil
		}
		l.titles--
	}
	return seq
}

// decMode tracks a DEC private mode being set or reset.
func (l *leftSet) decMode(mode int, set bool) {
	switch mode {
	case 47, 1047, 1049:
		if set {
			l.alt = mode
		} else {
			l.alt = 0
		}
	case 25:
		l.cursorHidden = !set
	default:
		for _, m := range resetModes {
			if m == mode {
				if l.modes == nil {
					l.modes = map[int]bool{}
				}
				l.modes[mode] = set
			}
		}
	}
}

// kittyKeys tracks a kitty keyboard protocol push (CSI > flags u), pop
// (CSI < n u), or set (CSI = flags ; mode u). Pushes past maxStack are
// dropped, and a pop is cut down to the entries the stream pushed, so it
// can't pop the host's own.
func (l *leftSet) kittyKeys(seq []byte, prefix byte, params [][]byte) []byte {
	k := &l.kitty[l.screen()]
	switch prefix {
	case '>':
		if k.pushed >= maxStack {
			return nil
		}
		k.pushed++
	case '<':
		n := max(number(params[0], 1), 1)
		if k.pushed == 0 {
			return nil
		}
		if n > k.pushed {
			n = k.pushed
			seq = []byte("\x1b[<" + strconv.Itoa(n) + "u")
		}
		k.pushed -= n
	case '=':
		if k.pushed == 0 {
			mode := 1
			if len(params) > 1 {
				mode = number(params[1], 1)
			}
			// Mode 1 sets the flags given, 2 sets those bits, and 3
			// resets them, which may leave others set, so a stream that
			// set any is still cleared.
			switch flags := number(params[0], 0); mode {
			case 1:
				k.set = flags != 0
			case 2:
				k.set = k.set || flags != 0
			}
		}
	}
	return seq
}

// restore returns the sequences that undo what the stream left set, and
// forgets it.
func (l *leftSet) restore() []byte {
	var b bytes.Buffer
	// The alternate screen's keyboard flags are popped while it is still
	// the one in use.
	if l.alt != 0 {
		l.kitty[1].restore(&b)
	}
	for _, m := range resetModes {
		if l.modes[m] {
			b.WriteString("\x1b[?" + strconv.Itoa(m) + "l")
		}
	}
	if l.keypad {
		b.WriteString("\x1b>")
	}
	if l.modifyOtherKeys {
		b.WriteString("\x1b[>4m")
	}
	if l.alt != 0 {
		b.WriteString("\x1b[?" + strconv.Itoa(l.alt) + "l")
	}
	l.kitty[0].restore(&b)
	if l.cursorHidden {
		b.WriteString("\x1b[?25h")
	}
	if l.localEcho {
		b.WriteString("\x1b[12h")
	}
	for range l.titles {
		b.WriteString(TitlePop)
	}
	*l = leftSet{}
	return b.Bytes()
}

// restore pops the entries the stream pushed, then clears flags it set.
func (k kittyFlags) restore(b *bytes.Buffer) {
	if k.pushed > 0 {
		b.WriteString("\x1b[<" + strconv.Itoa(k.pushed) + "u")
	}
	if k.set {
		b.WriteString("\x1b[=0u")
	}
}

// number parses a CSI parameter, returning def when it is empty or not a
// plain number.
func number(p []byte, def int) int {
	n, err := strconv.Atoi(string(p))
	if err != nil || n < 0 {
		return def
	}
	return n
}
