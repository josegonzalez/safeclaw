// Package totexttest generates small PDFs and images for testing
// safeclaw totext with the real tools, so no binary fixtures are needed.
package totexttest

import (
	"bytes"
	"compress/zlib"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	"strconv"
	"strings"
)

// writer builds a PDF one object at a time, recording each object's
// offset for the cross-reference table.
type writer struct {
	b       bytes.Buffer
	offsets []int
}

func newWriter() *writer {
	w := &writer{}
	w.b.WriteString("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
	return w
}

// next returns the number the next object gets.
func (w *writer) next() int { return len(w.offsets) + 1 }

// obj writes an object and returns its number.
func (w *writer) obj(body string) int {
	w.offsets = append(w.offsets, w.b.Len())
	n := len(w.offsets)
	fmt.Fprintf(&w.b, "%d 0 obj\n%s\nendobj\n", n, body)
	return n
}

// stream writes a stream object with dict's entries and returns its
// number.
func (w *writer) stream(dict string, data []byte) int {
	w.offsets = append(w.offsets, w.b.Len())
	n := len(w.offsets)
	fmt.Fprintf(&w.b, "%d 0 obj\n<< %s /Length %d >>\nstream\n", n, dict, len(data))
	w.b.Write(data)
	w.b.WriteString("\nendstream\nendobj\n")
	return n
}

// finish writes the cross-reference table and trailer.
func (w *writer) finish(root int, trailer string) []byte {
	xref := w.b.Len()
	fmt.Fprintf(&w.b, "xref\n0 %d\n0000000000 65535 f \n", len(w.offsets)+1)
	for _, off := range w.offsets {
		fmt.Fprintf(&w.b, "%010d 00000 n \n", off)
	}
	fmt.Fprintf(&w.b, "trailer\n<< /Size %d /Root %d 0 R %s >>\nstartxref\n%d\n%%%%EOF\n", len(w.offsets)+1, root, trailer, xref)
	return w.b.Bytes()
}

// pdfString escapes s as a PDF literal string.
func pdfString(s string) string {
	return "(" + strings.NewReplacer(`\`, `\\`, "(", `\(`, ")", `\)`).Replace(s) + ")"
}

// textContent draws each line of text in 24 point Helvetica from the top
// of a letter page.
func textContent(text string) []byte {
	var c strings.Builder
	c.WriteString("BT /F1 24 Tf 72 700 Td 30 TL\n")
	for _, line := range strings.Split(text, "\n") {
		fmt.Fprintf(&c, "%s Tj T*\n", pdfString(line))
	}
	c.WriteString("ET\n")
	return []byte(c.String())
}

// TextPDF returns a PDF with one letter page per entry in pages, each
// drawing its text in Helvetica, so pdftotext finds it. An empty entry is a
// blank page.
func TextPDF(pages ...string) []byte {
	return textPDF(pages, nil, "")
}

// textPDF writes the PDF, encrypting each content stream with enc and
// adding encDict as its encryption dictionary when they are set.
func textPDF(pages []string, enc func(num int, data []byte) []byte, encDict string) []byte {
	w := newWriter()
	font := w.obj("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>")
	// The page tree comes after the pages, which point at it by number.
	parent := w.next() + 2*len(pages)
	var kids []string
	for _, text := range pages {
		data := textContent(text)
		if enc != nil {
			data = enc(w.next(), data)
		}
		content := w.stream("", data)
		page := w.obj(fmt.Sprintf("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 %d 0 R >> >> /Contents %d 0 R >>", parent, font, content))
		kids = append(kids, fmt.Sprintf("%d 0 R", page))
	}
	w.obj(fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", strings.Join(kids, " "), len(pages)))
	root := w.obj(fmt.Sprintf("<< /Type /Catalog /Pages %d 0 R >>", parent))
	trailer := ""
	if encDict != "" {
		trailer = fmt.Sprintf("/Encrypt %d 0 R /ID [<%s> <%s>]", w.obj(encDict), fileID, fileID)
	}
	return w.finish(root, trailer)
}

// ImagePDF returns a one-page PDF that is only img, scanned at dpi, with
// no text for pdftotext to find.
func ImagePDF(img *image.Gray, dpi int) []byte {
	b := img.Bounds()
	var z bytes.Buffer
	zw := zlib.NewWriter(&z)
	for y := b.Min.Y; y < b.Max.Y; y++ {
		i := img.PixOffset(b.Min.X, y)
		_, _ = zw.Write(img.Pix[i : i+b.Dx()])
	}
	_ = zw.Close()
	wpt := float64(b.Dx()) * 72 / float64(dpi)
	hpt := float64(b.Dy()) * 72 / float64(dpi)
	w := newWriter()
	im := w.stream(fmt.Sprintf("/Type /XObject /Subtype /Image /Width %d /Height %d /ColorSpace /DeviceGray /BitsPerComponent 8 /Filter /FlateDecode", b.Dx(), b.Dy()), z.Bytes())
	content := w.stream("", fmt.Appendf(nil, "q %.2f 0 0 %.2f 0 0 cm /Im1 Do Q\n", wpt, hpt))
	parent := w.next() + 1
	page := w.obj(fmt.Sprintf("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 %.2f %.2f] /Resources << /XObject << /Im1 %d 0 R >> >> /Contents %d 0 R >>", parent, wpt, hpt, im, content))
	w.obj(fmt.Sprintf("<< /Type /Pages /Kids [%d 0 R] /Count 1 >>", page))
	root := w.obj(fmt.Sprintf("<< /Type /Catalog /Pages %d 0 R >>", parent))
	return w.finish(root, "")
}

// padding is the password padding of the PDF standard security handler.
var padding = []byte("\x28\xbf\x4e\x5e\x4e\x75\x8a\x41\x64\x00\x4e\x56\xff\xfa\x01\x08\x2e\x2e\x00\xb6\xd0\x68\x3e\x80\x2f\x0c\xa9\xfe\x64\x53\x69\x7a")

const fileID = "0123456789abcdef0123456789abcdef"

func pad(pw string) []byte {
	return append([]byte(pw), padding...)[:32]
}

func rc4Crypt(key, data []byte) []byte {
	c, _ := rc4.NewCipher(key)
	out := make([]byte, len(data))
	c.XORKeyStream(out, data)
	return out
}

// EncryptedPDF returns TextPDF(pages...) encrypted with 40-bit RC4 under
// the standard security handler (revision 2), opening only with
// userPassword, which must not be empty.
func EncryptedPDF(userPassword string, pages ...string) ([]byte, error) {
	if userPassword == "" {
		return nil, errors.New("an empty user password opens without one")
	}
	ownerKey := md5.Sum(pad("owner-" + userPassword))
	o := rc4Crypt(ownerKey[:5], pad(userPassword))
	const p int32 = -4
	id, _ := hex.DecodeString(fileID)
	h := md5.New()
	h.Write(pad(userPassword))
	h.Write(o)
	_ = binary.Write(h, binary.LittleEndian, p)
	h.Write(id)
	key := h.Sum(nil)[:5]
	u := rc4Crypt(key, padding)
	enc := func(num int, data []byte) []byte {
		// Algorithm 1: the object's key is the file key with its number
		// and generation appended, hashed, and cut to the key's length
		// plus 5.
		k := append(append([]byte{}, key...), byte(num), byte(num>>8), byte(num>>16), 0, 0)
		sum := md5.Sum(k)
		return rc4Crypt(sum[:min(len(k), 16)], data)
	}
	encDict := fmt.Sprintf("<< /Filter /Standard /V 1 /R 2 /O <%x> /U <%x> /P %d >>", o, u, p)
	return textPDF(pages, enc, encDict), nil
}

// ParsePGM reads a binary PGM (P5) image with 8-bit samples, such as
// `pdftoppm -gray` writes.
func ParsePGM(data []byte) (*image.Gray, error) {
	if !bytes.HasPrefix(data, []byte("P5")) {
		return nil, errors.New("not a binary PGM")
	}
	var vals [3]int
	i := 2
	for f := 0; f < 3; {
		switch {
		case i >= len(data):
			return nil, errors.New("truncated PGM header")
		case data[i] == '#':
			for i < len(data) && data[i] != '\n' {
				i++
			}
		case data[i] == ' ' || data[i] == '\n' || data[i] == '\r' || data[i] == '\t':
			i++
		default:
			j := i
			for j < len(data) && data[j] >= '0' && data[j] <= '9' {
				j++
			}
			n, err := strconv.Atoi(string(data[i:j]))
			if err != nil {
				return nil, fmt.Errorf("bad PGM header: %w", err)
			}
			vals[f], f, i = n, f+1, j
		}
	}
	i++ // the one whitespace byte before the samples
	w, h := vals[0], vals[1]
	if vals[2] != 255 || w <= 0 || h <= 0 || len(data)-i < w*h {
		return nil, fmt.Errorf("unsupported PGM: %dx%d, max %d, %d bytes", w, h, vals[2], len(data)-i)
	}
	img := image.NewGray(image.Rect(0, 0, w, h))
	copy(img.Pix, data[i:i+w*h])
	return img, nil
}
