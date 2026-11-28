package mail

import (
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/josegonzalez/safeclaw/internal/termtext"
)

// PartsFile is the file safeclaw-expand writes an email's part listing
// to, next to BodyFile, as WriteParts writes it with the file field.
const PartsFile = "parts.txt"

// WriteParts writes parts as tab-separated PART, TYPE, SIZE, NAME, and
// FLAGS lines, with a sixth FILE field when withFile is set, the way
// `safeclaw mail list` and `extract` print them. Names and files are
// escaped with termtext.EscapeField, and an empty field is "-".
func WriteParts(w io.Writer, parts []Part, withFile bool) error {
	dash := func(s string) string {
		if s == "" {
			return "-"
		}
		return s
	}
	var b strings.Builder
	for _, p := range parts {
		size := "-"
		if p.Size >= 0 {
			size = strconv.FormatInt(p.Size, 10)
		}
		name := "-"
		if p.Name != "" {
			name = termtext.EscapeField(p.Name)
		}
		fmt.Fprintf(&b, "%s\t%s\t%s\t%s\t%s", p.ID, termtext.EscapeField(p.Type), size, name, dash(strings.Join(p.Flags(), ",")))
		if withFile {
			fmt.Fprintf(&b, "\t%s", dash(termtext.EscapeField(p.File)))
		}
		b.WriteString("\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}
