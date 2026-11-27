package cli

import (
	"bytes"
	"errors"
	"testing"
)

func TestPrintErrorEscapes(t *testing.T) {
	var buf bytes.Buffer
	printError(&buf, errors.New("bad name\x1b]0;pwned\x07\nsecond line"))
	want := "Error: bad name\\x1b]0;pwned\\x07\nsecond line\n"
	if got := buf.String(); got != want {
		t.Errorf("printError = %q, want %q", got, want)
	}
}
