package unpack

import (
	"bytes"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"syscall"
)

// magics are the signatures of the formats unpacked when nested: zip, 7z,
// rar, gzip, bzip2, xz, and zstd at the start of the file. tar is checked
// separately, by its ustar magic at offset 257.
var magics = [][]byte{
	[]byte("PK\x03\x04"),
	[]byte("7z\xbc\xaf\x27\x1c"),
	[]byte("Rar!\x1a\x07"),
	[]byte("\x1f\x8b"),
	[]byte("BZh"),
	[]byte("\xfd7zXZ\x00"),
	[]byte("\x28\xb5\x2f\xfd"),
}

const (
	tarMagicOffset = 257
	tarMagic       = "ustar"
)

// LooksLikeArchive reports whether head, the start of a file, has the
// signature of a format unpacked when nested.
func LooksLikeArchive(head []byte) bool {
	for _, m := range magics {
		if bytes.HasPrefix(head, m) {
			return true
		}
	}
	return len(head) >= tarMagicOffset+len(tarMagic) && string(head[tarMagicOffset:tarMagicOffset+len(tarMagic)]) == tarMagic
}

// archivesIn returns the regular files under dir that look like archives,
// sorted.
func archivesIn(dir string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || !d.Type().IsRegular() {
			return err
		}
		ok, err := fileLooksLikeArchive(p)
		if ok {
			out = append(out, p)
		}
		return err
	})
	sort.Strings(out)
	return out, err
}

func fileLooksLikeArchive(p string) (bool, error) {
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return false, err
	}
	defer f.Close()
	head := make([]byte, tarMagicOffset+len(tarMagic))
	n, err := io.ReadFull(f, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return false, err
	}
	return LooksLikeArchive(head[:n]), nil
}

// linkCount returns a file's hard link count, 1 when it isn't known.
func linkCount(fi fs.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink) //nolint:unconvert // Nlink is uint16 on darwin, uint64 on linux
	}
	return 1
}
