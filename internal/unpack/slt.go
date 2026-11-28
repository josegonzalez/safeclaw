package unpack

import (
	"fmt"
	"strconv"
	"strings"
)

// Listing is a parsed `7z l -slt` listing.
type Listing struct {
	// Type is the archive format 7z detected, such as zip or gzip.
	Type string
	// Entries are the archive's entries in listing order.
	Entries []Entry
}

// sltSeparator ends the archive's own properties and starts the entries.
const sltSeparator = "----------"

// ParseListing parses the output of `7z l -slt`. Each entry is a block of
// "Key = Value" lines starting with Path, and blocks are separated by blank
// lines. The first block that does not hold "Key = Value" lines, such as a
// trailing "Errors: 1", ends the entries. A block that does not start with
// Path or that repeats a key is an error rather than a guess, since an
// entry the parser misread could hide a link or an unsafe path.
func ParseListing(out string) (*Listing, error) {
	lines := strings.Split(strings.ReplaceAll(out, "\r\n", "\n"), "\n")
	sep := -1
	for i, l := range lines {
		if l == sltSeparator {
			sep = i
			break
		}
	}
	if sep < 0 {
		return nil, fmt.Errorf("7z listing has no %q line", sltSeparator)
	}
	l := &Listing{}
	// The archive's properties: the last block before the separator, which
	// 7z starts with a "--" line.
	for _, line := range lines[:sep] {
		if k, v, ok := splitProp(line); ok && k == "Type" {
			l.Type = v
		}
	}
	var block [][2]string
	flush := func() error {
		if len(block) == 0 {
			return nil
		}
		e, err := parseEntry(block)
		block = nil
		if err != nil {
			return err
		}
		l.Entries = append(l.Entries, e)
		return nil
	}
	for _, line := range lines[sep+1:] {
		if line == "" {
			if err := flush(); err != nil {
				return nil, err
			}
			continue
		}
		k, v, ok := splitProp(line)
		if !ok {
			if len(block) > 0 {
				return nil, fmt.Errorf("unexpected line in 7z listing: %q", line)
			}
			break
		}
		block = append(block, [2]string{k, v})
	}
	if err := flush(); err != nil {
		return nil, err
	}
	return l, nil
}

// splitProp splits a "Key = Value" line. 7z prints "Key = " for an empty
// value; "Key =" is accepted too in case the trailing space is trimmed.
func splitProp(line string) (key, value string, ok bool) {
	if k, v, found := strings.Cut(line, " = "); found && k != "" {
		return k, v, true
	}
	if k, found := strings.CutSuffix(line, " ="); found && k != "" && !strings.Contains(k, " = ") {
		return k, "", true
	}
	return "", "", false
}

func parseEntry(block [][2]string) (Entry, error) {
	if block[0][0] != "Path" {
		return Entry{}, fmt.Errorf("7z listing entry starts with %q, not Path", block[0][0])
	}
	props := make(map[string]string, len(block))
	for _, kv := range block {
		if _, dup := props[kv[0]]; dup {
			return Entry{}, fmt.Errorf("7z listing entry %q repeats %q", block[0][1], kv[0])
		}
		props[kv[0]] = kv[1]
	}
	e := Entry{Path: props["Path"], Type: TypeFile, Size: -1}
	e.UnsafePath = UnsafePath(e.Path)
	if s := props["Size"]; s != "" {
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil || n < 0 {
			return Entry{}, fmt.Errorf("7z listing entry %q has an invalid size %q", e.Path, s)
		}
		e.Size = n
	}
	e.Encrypted = props["Encrypted"] == "+"

	winAttrs, mode := splitAttributes(props["Attributes"])
	if m := props["Mode"]; m != "" {
		mode = m
	}
	var modeType byte
	if isModeString(mode) {
		modeType = mode[0]
	}
	switch {
	case props["Hard Link"] != "":
		e.Type, e.Link = TypeHardlink, props["Hard Link"]
	case props["Symbolic Link"] != "":
		e.Type, e.Link = TypeSymlink, props["Symbolic Link"]
	case modeType == 'l', strings.ContainsRune(winAttrs, 'L'):
		// 'L' is the Windows reparse point attribute, which is how links
		// from Windows (such as NTFS symbolic links and junctions) show.
		e.Type = TypeSymlink
	case modeType == 'c', modeType == 'b', modeType == 'p', modeType == 's', strings.ContainsRune(winAttrs, 'd'):
		// 'd' is the Windows device attribute.
		e.Type = TypeSpecial
	case props["Folder"] == "+", modeType == 'd', strings.ContainsRune(winAttrs, 'D'):
		e.Type = TypeDir
	}
	return e, nil
}

// splitAttributes splits 7z's Attributes value, such as "D drwxr-xr-x",
// "A -rw-r--r--", "V 01800000 0rw-------", " lrwxrwxrwx" or "D....", into
// its Windows attribute letters and its POSIX mode string, either of which
// may be missing.
func splitAttributes(v string) (win, mode string) {
	fields := strings.Fields(v)
	if len(fields) == 0 {
		return "", ""
	}
	if last := fields[len(fields)-1]; isModeString(last) {
		mode = last
		fields = fields[:len(fields)-1]
	}
	if len(fields) > 0 && isWinAttrs(fields[0]) {
		win = fields[0]
	}
	return win, mode
}

// isModeString reports whether s looks like a POSIX mode string such as
// -rw-r--r--, where 7z writes 0 for a type it doesn't know.
func isModeString(s string) bool {
	if len(s) != 10 || !strings.ContainsRune("-dlcbps0?", rune(s[0])) {
		return false
	}
	for _, c := range s[1:] {
		if !strings.ContainsRune("rwxsStT-", c) {
			return false
		}
	}
	return true
}

// isWinAttrs reports whether s is a run of 7z's Windows attribute
// characters ("RHS8DAdNTsLCOIEV"), with '.' or '_' for unset ones in older
// versions.
func isWinAttrs(s string) bool {
	for _, c := range s {
		if !strings.ContainsRune("RHS8DAdNTsLCOIEV._", c) {
			return false
		}
	}
	return s != ""
}
