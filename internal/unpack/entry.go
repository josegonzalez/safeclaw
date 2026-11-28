// Package unpack lists and extracts untrusted archives with 7z, refusing
// links and unsafe paths before extracting and checking what was written
// afterwards. It backs `safeclaw unpack`, installed as safeclaw-unpack in
// the sandbox image variant.
package unpack

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Entry types.
const (
	TypeFile     = "file"
	TypeDir      = "dir"
	TypeSymlink  = "symlink"
	TypeHardlink = "hardlink"
	// TypeSpecial is a device, fifo, or socket.
	TypeSpecial = "special"
)

// Entry flags.
const (
	// FlagEncrypted marks an entry that needs a password.
	FlagEncrypted = "ENCRYPTED"
	// FlagLink marks a symbolic or hard link.
	FlagLink = "LINK"
	// FlagSpecial marks a device, fifo, or socket.
	FlagSpecial = "SPECIAL"
	// FlagUnsafePath marks a path that is empty, absolute, starts with a
	// drive letter, has a ".." segment, or has control characters.
	FlagUnsafePath = "UNSAFE-PATH"
	// FlagDropped marks a bad entry left out by Options.DropBad.
	FlagDropped = "DROPPED"
	// FlagUnpacked marks a nested archive unpacked next to itself.
	FlagUnpacked = "UNPACKED"
	// FlagDepthLimit marks a nested archive left packed because it is
	// deeper than Options.Depth.
	FlagDepthLimit = "DEPTH-LIMIT"
	// FlagRejected, FlagNeedsPassword, FlagTooLarge, and FlagFailed mark a
	// nested archive left packed with Options.KeepGoing because it failed
	// with that Kind (see Kind.Flag).
	FlagRejected      = "REJECTED"
	FlagNeedsPassword = "NEEDS-PASSWORD"
	FlagTooLarge      = "TOO-LARGE"
	FlagFailed        = "FAILED"
)

// Entry is one entry of an archive, or one path extracted from it.
type Entry struct {
	// Path is the entry's path as the archive or 7z gives it, or, for an
	// extracted path, its path relative to the destination.
	Path string
	// Type is one of the Type constants.
	Type string
	// Size is the uncompressed size, -1 when unknown.
	Size int64
	// Link is the target of a symbolic or hard link, when known.
	Link string
	// Encrypted is set for an entry that needs a password.
	Encrypted bool
	// UnsafePath is set when Path, as the archive gives it, is unsafe (see
	// UnsafePath). It is kept apart from Path so the flag stays with the
	// entry when a directory is put in front of its path.
	UnsafePath bool
	// Extra are flags added after listing, such as FlagDropped.
	Extra []string
	// Unpacked is the directory, relative to the destination, a nested
	// archive was unpacked into.
	Unpacked string
}

// Flags returns the entry's flags in a stable order.
func (e Entry) Flags() []string {
	var out []string
	if e.Encrypted {
		out = append(out, FlagEncrypted)
	}
	switch e.Type {
	case TypeSymlink, TypeHardlink:
		out = append(out, FlagLink)
	case TypeSpecial:
		out = append(out, FlagSpecial)
	}
	if e.UnsafePath {
		out = append(out, FlagUnsafePath)
	}
	return append(out, e.Extra...)
}

// Bad reports whether the entry is a link, a special file, or has an unsafe
// path: one that extract refuses, or drops with Options.DropBad.
func (e Entry) Bad() bool {
	return e.Type == TypeSymlink || e.Type == TypeHardlink || e.Type == TypeSpecial || e.UnsafePath
}

// UnsafePath reports whether an archive path could land outside the
// destination or mislead whoever reads it: it is empty, absolute (with
// either slash), starts with a drive letter, has a ".." segment (split on
// either slash), is not valid UTF-8, or has control characters.
func UnsafePath(p string) bool {
	if p == "" || !utf8.ValidString(p) {
		return true
	}
	if strings.IndexFunc(p, unicode.IsControl) >= 0 {
		return true
	}
	if p[0] == '/' || p[0] == '\\' {
		return true
	}
	if len(p) >= 2 && p[1] == ':' && isASCIILetter(p[0]) {
		return true
	}
	for _, seg := range strings.FieldsFunc(p, func(r rune) bool { return r == '/' || r == '\\' }) {
		if seg == ".." {
			return true
		}
	}
	return false
}

func isASCIILetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}
