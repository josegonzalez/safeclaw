package totext

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
)

// pdfInfo is what Convert reads from pdfinfo.
type pdfInfo struct {
	pages     int
	encrypted bool
	// sizes are the pages' width and height in points, by page number.
	sizes map[int][2]float64
}

var (
	pagesRe    = regexp.MustCompile(`^Pages:\s+(\d+)\s*$`)
	encRe      = regexp.MustCompile(`^Encrypted:\s+(yes|no)\b`)
	pageSizeRe = regexp.MustCompile(`^Page\s+(\d+)\s+size:\s+([0-9.]+)\s+x\s+([0-9.]+)\s+pts\b`)
)

// parsePDFInfo parses `pdfinfo -f 1 -l N` output.
//
// pdfinfo prints the document's Title, Author, and other metadata before
// its page count, and those can hold line breaks, so a crafted file can
// print lines that look like pdfinfo's own. Only the lines after the last
// "Pages:" line are read, since nothing the file controls is printed
// after it.
func parsePDFInfo(out string) (*pdfInfo, error) {
	lines := strings.Split(out, "\n")
	start := -1
	info := &pdfInfo{sizes: map[int][2]float64{}}
	for i, l := range lines {
		if m := pagesRe.FindStringSubmatch(l); m != nil {
			n, err := strconv.Atoi(m[1])
			if err != nil {
				return nil, errors.New("pdfinfo printed a page count that is out of range")
			}
			start, info.pages = i, n
		}
	}
	if start < 0 {
		return nil, errors.New("pdfinfo printed no page count")
	}
	sawEnc := false
	for _, l := range lines[start+1:] {
		if m := encRe.FindStringSubmatch(l); m != nil {
			if sawEnc {
				return nil, errors.New("pdfinfo printed Encrypted twice")
			}
			sawEnc, info.encrypted = true, m[1] == "yes"
			continue
		}
		if m := pageSizeRe.FindStringSubmatch(l); m != nil {
			p, err1 := strconv.Atoi(m[1])
			w, err2 := strconv.ParseFloat(m[2], 64)
			h, err3 := strconv.ParseFloat(m[3], 64)
			if err1 != nil || err2 != nil || err3 != nil {
				continue
			}
			info.sizes[p] = [2]float64{w, h}
		}
	}
	return info, nil
}
