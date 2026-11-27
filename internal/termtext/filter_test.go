package termtext

import (
	"errors"
	"strings"
	"testing"
)

// filterAll runs in through a Filter split at every byte offset in turn
// and checks every split gives the same output, which it returns.
func filterAll(t *testing.T, in string) string {
	t.Helper()
	var whole string
	for split := 0; split <= len(in); split++ {
		var b strings.Builder
		f := NewFilter(&b)
		for _, part := range []string{in[:split], in[split:]} {
			if n, err := f.Write([]byte(part)); err != nil || n != len(part) {
				t.Fatalf("split %d: Write = %d, %v", split, n, err)
			}
		}
		if split == 0 {
			whole = b.String()
		} else if b.String() != whole {
			t.Fatalf("split %d: got %q, unsplit gave %q", split, b.String(), whole)
		}
	}
	// One byte per write too.
	var b strings.Builder
	f := NewFilter(&b)
	for i := range len(in) {
		_, _ = f.Write([]byte{in[i]})
	}
	if b.String() != whole {
		t.Fatalf("byte by byte: got %q, unsplit gave %q", b.String(), whole)
	}
	return whole
}

func TestFilterDrops(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"osc 52 bel", "a\x1b]52;;QVVESVQ=\x07b", "ab"},
		{"osc 52 st", "a\x1b]52;c;QVVESVQ=\x1b\\b", "ab"},
		{"osc 52 query", "a\x1b]52;c;?\x07b", "ab"},
		{"osc 52 cut short by esc", "a\x1b]52;c;QQ\x1b[31mb", "a\x1b[31mb"},
		{"osc 52 cancelled", "a\x1b]52;c;QQ\x18b", "ab"},
		{"tmux passthrough", "a\x1bPtmux;\x1b\x1b]52;c;QVVESVRfMg==\x07\x1b\\b", "ab"},
		{"dcs with doubled esc st inside", "a\x1bPtmux;\x1b\x1b]0;x\x1b\x1b\\\x1b\\b", "ab"},
		{"dcs xtgettcap", "a\x1bP+q544e\x1b\\b", "ab"},
		{"apc", "a\x1b_Gf=24;AAAA\x1b\\b", "ab"},
		{"pm", "a\x1b^private\x1b\\b", "ab"},
		{"sos", "a\x1bXstring\x1b\\b", "ab"},
		{"osc 1337", "a\x1b]1337;File=name=eA==:eA==\x07b", "ab"},
		{"osc 50 font", "a\x1b]50;?\x07b", "ab"},
		{"osc 7", "a\x1b]7;file:///etc\x07b", "ab"},
		{"osc no number", "a\x1b];x\x07b", "ab"},
		{"osc long number", "a\x1b]0000000052;x\x07b", "ab"},
		{"title with control", "a\x1b]0;x\x08y\x07b", "ab"},
		{"title with raw c1", "a\x1b]0;x\x9cy\x07b", "ab"},
		{"title with encoded c1", "a\x1b]0;x\u009dy\x07b", "ab"},
		{"title too long", "a\x1b]0;" + strings.Repeat("x", maxOSC) + "\x07b", "ab"},
		{"window move", "a\x1b[3;0;0tb", "ab"},
		{"window iconify", "a\x1b[2tb", "ab"},
		{"window report title", "a\x1b[21tb", "ab"},
		{"raw c1", "a\x9b2J\x9d52;x\x9cb", "a2J52;xb"},
		{"encoded c1", "a\u009b2J\u0090b", "a2Jb"},
		{"esc esc", "a\x1b\x1b[1mb", "a\x1b[1mb"},
		{"csi cut short", "a\x1b[31\x80b", "ab"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := filterAll(t, tc.in); got != tc.want {
				t.Errorf("Filter(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestFilterKeeps(t *testing.T) {
	cases := []struct{ name, in string }{
		{"text", "plain text\r\n\tcafé ✓ \U0001F600 “quoted” …"},
		{"sgr", "\x1b[0m\x1b[1;31mred\x1b[38;2;255;0;0mtrue\x1b[48;5;21mbg\x1b[m"},
		{"cursor", "\x1b[H\x1b[10;20H\x1b[2A\x1b[3C\x1b[K\x1b[2J\x1b7\x1b8\x1bM"},
		{"alternate screen and modes", "\x1b[?1049h\x1b[?25l\x1b[?1000h\x1b[?2004h\x1b[?2026h\x1b[?1049l"},
		{"scroll region and cursor style", "\x1b[1;24r\x1b[2 q"},
		{"charset", "\x1b(B\x1b)0\x0e\x0f\x1b#8"},
		{"keypad", "\x1b=\x1b>"},
		{"queries", "\x1b[c\x1b[>c\x1b[6n\x1b[>q\x1b[?u"},
		{"window size reports", "\x1b[14t\x1b[18t\x1b[22;0t\x1b[23;0t"},
		{"titles", "\x1b]0;title\x07\x1b]2;ünïcode “t”\x1b\\"},
		{"hyperlink", "\x1b]8;id=1;https://example.com/\x1b\\link\x1b]8;;\x1b\\"},
		{"colours", "\x1b]10;?\x1b\\\x1b]11;?\x07\x1b]12;#ff0000\x07\x1b]112\x07\x1b]104\x1b\\"},
		{"bell", "\x07"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := filterAll(t, tc.in); got != tc.in {
				t.Errorf("Filter(%q) = %q, want it unchanged", tc.in, got)
			}
		})
	}
}

func TestFilterMixedStream(t *testing.T) {
	in := "\x1b[?1049h\x1b[1;1H\x1b[32mok\x1b[0m" +
		"\x1b]52;;QVVESVRfRFVNTVk=\x07" +
		"\x1b[2;1Hmore \x1b]0;t\x07" +
		"\x1bPtmux;\x1b\x1b]52;c;QVVESVRfMg==\x07\x1b\\" +
		"end\x1b[?1049l"
	want := "\x1b[?1049h\x1b[1;1H\x1b[32mok\x1b[0m" +
		"\x1b[2;1Hmore \x1b]0;t\x07" +
		"end\x1b[?1049l"
	if got := filterAll(t, in); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("closed") }

func TestFilterWriteError(t *testing.T) {
	if _, err := NewFilter(failWriter{}).Write([]byte("x")); err == nil {
		t.Error("want the underlying write error")
	}
}
