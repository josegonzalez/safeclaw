package unpack

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"syscall"
)

// signatures are the formats Detect knows, with the bytes they start
// with: the formats unpacked when nested. tar is checked separately, by
// its ustar magic at offset 257.
var signatures = []struct {
	format string
	magic  []byte
}{
	{"zip", []byte("PK\x03\x04")},
	{"7z", []byte("7z\xbc\xaf\x27\x1c")},
	{"rar", []byte("Rar!\x1a\x07")},
	{"gzip", []byte("\x1f\x8b")},
	{"bzip2", []byte("BZh")},
	{"xz", []byte("\xfd7zXZ\x00")},
	{"zstd", []byte("\x28\xb5\x2f\xfd")},
}

const (
	tarMagicOffset = 257
	tarMagic       = "ustar"
	// HeadSize is how much of a file Detect needs.
	HeadSize = tarMagicOffset + len(tarMagic)
)

// Detect returns the archive format head, the start of a file, has the
// signature of: zip, 7z, rar, tar, gzip, bzip2, xz, or zstd, the formats
// unpacked when nested. It returns "" for anything else.
func Detect(head []byte) string {
	for _, s := range signatures {
		if bytes.HasPrefix(head, s.magic) {
			return s.format
		}
	}
	if len(head) >= HeadSize && string(head[tarMagicOffset:HeadSize]) == tarMagic {
		return "tar"
	}
	return ""
}

// DetectFile returns the archive format the file at p starts like, as
// Detect does, or "" when it doesn't start like one. p must be a regular
// file; a link to one is followed, as List and Extract follow it. The
// error is an *Error.
func DetectFile(p string) (string, error) {
	if fi, err := os.Stat(p); err != nil {
		return "", &Error{Kind: Failed, Msg: err.Error()}
	} else if !fi.Mode().IsRegular() {
		return "", &Error{Kind: Failed, Msg: fmt.Sprintf("%s is not a regular file", p)}
	}
	format, err := detectPath(p, 0)
	if err != nil {
		return "", &Error{Kind: Failed, Msg: err.Error()}
	}
	return format, nil
}

// detectPath opens p with flag added to the read-only, non-blocking open
// and runs Detect on its start. Anything but a regular file is an error.
func detectPath(p string, flag int) (string, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NONBLOCK|flag, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil {
		return "", err
	} else if !fi.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", p)
	}
	head := make([]byte, HeadSize)
	n, err := io.ReadFull(f, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return "", err
	}
	return Detect(head[:n]), nil
}

// notArchive is the error for an archive given to List or Extract that 7z
// can't open: one that starts like an archive Detect knows is corrupt, and
// Failed, and anything else is NotArchive. Either wraps ErrNotArchive.
func notArchive(archive string) error {
	format, err := DetectFile(archive)
	if err != nil {
		return err
	}
	if format != "" {
		return &Error{Kind: Failed, Msg: fmt.Sprintf("it starts like a %s archive but 7z can't open it, so it is corrupt", format), cause: ErrNotArchive}
	}
	return &Error{Kind: NotArchive, Msg: "7z can't open it as an archive, and it doesn't start like one", cause: ErrNotArchive}
}

// archivesIn returns the regular files under dir that look like archives,
// sorted.
func archivesIn(dir string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		format, err := detectPath(p, syscall.O_NOFOLLOW)
		if format != "" {
			out = append(out, p)
		}
		return err
	})
	sort.Strings(out)
	return out, err
}

// linkCount returns a file's hard link count, 1 when it isn't known.
func linkCount(fi fs.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink) //nolint:unconvert // Nlink is uint16 on darwin, uint64 on linux
	}
	return 1
}
