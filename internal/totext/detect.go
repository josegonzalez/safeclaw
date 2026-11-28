package totext

import (
	"bytes"
	"encoding/binary"
	"io"
	"os"
	"unicode/utf8"
)

// File types, as the report names them.
const (
	TypePDF     = "pdf"
	TypePNG     = "png"
	TypeJPEG    = "jpeg"
	TypeGIF     = "gif"
	TypeTIFF    = "tiff"
	TypeBMP     = "bmp"
	TypeWebP    = "webp"
	TypeText    = "text"
	TypeUnknown = "unknown"
)

// sniffLen is how much of a file Detect reads.
const sniffLen = 8 << 10

// pdfHeaderWindow is how far into a file a PDF's %PDF- header may start,
// as for poppler, which skips up to 1024 bytes of junk before it.
const pdfHeaderWindow = 1024

// IsImage reports whether typ is an image type, which is OCR'd.
func IsImage(typ string) bool {
	switch typ {
	case TypePNG, TypeJPEG, TypeGIF, TypeTIFF, TypeBMP, TypeWebP:
		return true
	}
	return false
}

// DetectFile returns the type of the file at path from its first bytes.
func DetectFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	buf := make([]byte, sniffLen)
	n, err := io.ReadFull(f, buf)
	if err != nil && err != io.EOF && err != io.ErrUnexpectedEOF {
		return "", err
	}
	return Detect(buf[:n], n < sniffLen), nil
}

// Detect returns a file's type from its first bytes, never from its name:
// a PDF, one of the image types tesseract reads, or text. A PDF starts
// with %PDF-, or has it within its first 1024 bytes and isn't text, since
// poppler skips that much junk before the header. complete says
// whether head is the whole file, so that a UTF-8 sequence cut off at the
// end of head isn't taken for a broken one. Text is valid UTF-8 with no
// NUL bytes, an empty file included; anything else is TypeUnknown.
func Detect(head []byte, complete bool) string {
	pdf := []byte("%PDF-")
	switch {
	case bytes.HasPrefix(head, pdf):
		return TypePDF
	case bytes.Contains(head[:min(len(head), pdfHeaderWindow)], pdf) && !isText(head, complete):
		// Junk before the header, which isn't text that just mentions it.
		return TypePDF
	case bytes.HasPrefix(head, []byte("\x89PNG\r\n\x1a\n")):
		return TypePNG
	case bytes.HasPrefix(head, []byte{0xff, 0xd8, 0xff}):
		return TypeJPEG
	case bytes.HasPrefix(head, []byte("GIF87a")), bytes.HasPrefix(head, []byte("GIF89a")):
		return TypeGIF
	case bytes.HasPrefix(head, []byte("II*\x00")), bytes.HasPrefix(head, []byte("MM\x00*")):
		return TypeTIFF
	case len(head) >= 12 && bytes.HasPrefix(head, []byte("RIFF")) && string(head[8:12]) == "WEBP":
		return TypeWebP
	case isBMP(head):
		return TypeBMP
	case isText(head, complete):
		return TypeText
	}
	return TypeUnknown
}

// isBMP checks a BMP's header as well as its "BM" magic, which plenty of
// text starts with: the size of the header that follows the file header
// must be one of the sizes BMP versions use.
func isBMP(head []byte) bool {
	if len(head) < 18 || !bytes.HasPrefix(head, []byte("BM")) {
		return false
	}
	switch binary.LittleEndian.Uint32(head[14:18]) {
	case 12, 40, 52, 56, 64, 108, 124:
		return true
	}
	return false
}

func isText(head []byte, complete bool) bool {
	if bytes.IndexByte(head, 0) >= 0 {
		return false
	}
	if !complete {
		// Drop a sequence cut off at the end of what was read.
		for i := 1; i <= utf8.UTFMax && i <= len(head); i++ {
			if utf8.RuneStart(head[len(head)-i]) {
				if !utf8.FullRune(head[len(head)-i:]) {
					head = head[:len(head)-i]
				}
				break
			}
		}
	}
	return utf8.Valid(head)
}
