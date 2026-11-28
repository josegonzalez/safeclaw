// Package scan reads ClamAV signatures and clamscan results for the
// malware checks behind `safeclaw sandbox cp-out`, `sandbox scan`, and
// `sandbox update-signatures`. It runs nothing itself: the session package
// runs clamscan and freshclam in containers and hands their output here.
package scan

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
)

// DatabaseDir is where containers find the signatures: the directory
// clamscan and freshclam use by default in the sandbox variant.
const DatabaseDir = "/var/lib/clamav"

// Status is the result of scanning one file.
type Status string

const (
	// Clean means no signature matched.
	Clean Status = "clean"
	// Infected means a signature matched; Result.Signature names it.
	Infected Status = "infected"
	// Error means the file could not be scanned, or not fully: it was
	// missing or unreadable, exceeded the scanner's limits, or is
	// encrypted. Result.Reason says which.
	Error Status = "error"
)

// Result is one file's scan result.
type Result struct {
	// Path is the file as given to clamscan, or as clamscan printed it for
	// a file found in a directory given to it.
	Path   string `json:"path"`
	Status Status `json:"status"`
	// Signature names the signature that matched, for Infected results and
	// for the heuristics that make a file unscannable.
	Signature string `json:"signature,omitempty"`
	// Reason explains an Error result.
	Reason string `json:"reason,omitempty"`
}

// Flagged reports whether the result is anything but clean.
func (r Result) Flagged() bool { return r.Status != Clean }

// String describes the result in a few words, such as "clean",
// "infected (Eicar-Test-Signature)", or "error (is encrypted, ...)".
func (r Result) String() string {
	switch r.Status {
	case Infected:
		return fmt.Sprintf("infected (%s)", r.Signature)
	case Error:
		return fmt.Sprintf("error (%s)", r.Reason)
	}
	return string(r.Status)
}

// NoResult is the Reason given to a file clamscan printed no result for.
const NoResult = "clamscan printed no result for it"

// ClamscanArgs returns the clamscan command that scans paths with the
// signatures in DatabaseDir. Files over clamscan's size limits are flagged
// rather than passed as clean, and so are encrypted archives and documents,
// whose contents can't be scanned; Parse turns both into Error results.
func ClamscanArgs(paths []string) []string {
	args := []string{
		"clamscan",
		"--database=" + DatabaseDir,
		"--no-summary",
		"--alert-exceeds-max=yes",
		"--alert-encrypted=yes",
		"--",
	}
	return append(args, paths...)
}

// heuristics are the signature prefixes clamscan reports for files it
// could not fully scan, with the reason each gives.
var heuristics = []struct{ prefix, reason string }{
	{"Heuristics.Limits.Exceeded", "exceeds the scanner's size or time limits"},
	{"Heuristics.Encrypted", "is encrypted, so its contents could not be scanned"},
}

// classify turns what clamscan printed after "PATH: " into a result, or
// reports false when it is not a result line.
func classify(path, rest string) (Result, bool) {
	switch {
	case rest == "OK":
		return Result{Path: path, Status: Clean}, true
	case strings.HasSuffix(rest, " FOUND"):
		sig := strings.TrimSuffix(rest, " FOUND")
		if sig == "" || strings.ContainsAny(sig, " :") {
			return Result{}, false
		}
		for _, h := range heuristics {
			if strings.HasPrefix(sig, h.prefix) {
				return Result{Path: path, Status: Error, Signature: sig, Reason: h.reason}, true
			}
		}
		return Result{Path: path, Status: Infected, Signature: sig}, true
	case strings.HasSuffix(rest, " ERROR"):
		return Result{Path: path, Status: Error, Reason: strings.TrimSuffix(rest, " ERROR")}, true
	}
	return Result{}, false
}

// Parse reads clamscan's output (run with ClamscanArgs) for paths and
// returns one result per path, in the order given, followed by any results
// for files clamscan found in a path that is a directory. A path is matched
// to its line by its exact name, so a name that contains ": " or looks like
// a result can't be mistaken for another path's result. A path with no
// line of its own and no files under it gets an Error result with the
// reason NoResult. Lines that match no path are ignored.
func Parse(out []byte, paths []string) []Result {
	byLen := slices.Clone(paths)
	// Longest first, so "a: OK" is tried before "a" for the line
	// "a: OK: OK".
	slices.SortStableFunc(byLen, func(a, b string) int { return len(b) - len(a) })
	direct := map[string]Result{}
	covered := map[string]bool{}
	var nested []Result
	seen := map[string]bool{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		matched := false
		for _, p := range byLen {
			rest, ok := strings.CutPrefix(line, p+": ")
			if !ok {
				continue
			}
			if r, ok := classify(p, rest); ok {
				if _, dup := direct[p]; !dup {
					direct[p] = r
				}
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		// A file in a directory that was given: its name is everything
		// before the last ": ", since no result contains one.
		i := strings.LastIndex(line, ": ")
		if i < 0 {
			continue
		}
		name := line[:i]
		for _, p := range byLen {
			if !strings.HasPrefix(name, strings.TrimSuffix(p, "/")+"/") {
				continue
			}
			if r, ok := classify(name, line[i+2:]); ok && !seen[name] {
				seen[name] = true
				covered[p] = true
				nested = append(nested, r)
			}
			break
		}
	}
	results := make([]Result, 0, len(paths)+len(nested))
	for _, p := range paths {
		if r, ok := direct[p]; ok {
			results = append(results, r)
		} else if !covered[p] {
			results = append(results, Result{Path: p, Status: Error, Reason: NoResult})
		}
	}
	return append(results, nested...)
}

// ErrNoSignatures is returned when no signatures are installed.
var ErrNoSignatures = errors.New("no malware signatures are installed")

// Database is one installed signature database.
type Database struct {
	// Name is the database, such as daily, and File its file name, such as
	// daily.cld.
	Name string `json:"name"`
	File string `json:"file"`
	// Version is the database's version, which ClamAV raises with every
	// published update.
	Version int `json:"version"`
	// Built is when the database was published.
	Built time.Time `json:"built"`
	// Signatures is the number of signatures it holds.
	Signatures int `json:"signatures"`
}

// Signatures describes the installed signatures.
type Signatures struct {
	// Version and Date are the daily database's, which changes most often,
	// so they say how fresh the signatures are.
	Version int       `json:"version"`
	Date    time.Time `json:"date"`
	// Databases are every database found, sorted by name.
	Databases []Database `json:"databases"`
}

// String describes the signatures as "daily VERSION from DATE".
func (s Signatures) String() string {
	return fmt.Sprintf("daily %d from %s", s.Version, s.Date.UTC().Format("2006-01-02 15:04 MST"))
}

// requiredDatabases must all be present for signatures to count as
// installed. bytecode is optional, as clamscan runs without it.
var requiredDatabases = []string{"main", "daily"}

// headerSize is the size of a CVD or CLD file's header.
const headerSize = 512

// readHeader reads the "ClamAV-VDB:" header of a CVD or CLD file.
func readHeader(path string) (Database, error) {
	f, err := os.Open(path)
	if err != nil {
		return Database{}, err
	}
	defer func() { _ = f.Close() }()
	buf := make([]byte, headerSize)
	if _, err := io.ReadFull(f, buf); err != nil {
		return Database{}, fmt.Errorf("%s: reading its header: %w", path, err)
	}
	return ParseHeader(filepath.Base(path), buf)
}

// ParseHeader parses the 512-byte header of a CVD or CLD file named file:
// "ClamAV-VDB:build time:version:signatures:level:md5:dsig:builder:stime",
// padded with spaces.
func ParseHeader(file string, header []byte) (Database, error) {
	h := strings.TrimRight(string(header), " \x00\n")
	f := strings.Split(h, ":")
	if len(f) < 8 || f[0] != "ClamAV-VDB" {
		return Database{}, fmt.Errorf("%s: not a ClamAV database", file)
	}
	version, err := strconv.Atoi(strings.TrimSpace(f[2]))
	if err != nil || version < 0 {
		return Database{}, fmt.Errorf("%s: invalid version %q", file, f[2])
	}
	sigs, err := strconv.Atoi(strings.TrimSpace(f[3]))
	if err != nil || sigs < 0 {
		return Database{}, fmt.Errorf("%s: invalid signature count %q", file, f[3])
	}
	var built time.Time
	if len(f) > 8 {
		if secs, err := strconv.ParseInt(strings.TrimSpace(f[8]), 10, 64); err == nil && secs > 0 {
			built = time.Unix(secs, 0).UTC()
		}
	}
	if built.IsZero() {
		t, err := time.Parse("02 Jan 2006 15-04 -0700", strings.TrimSpace(f[1]))
		if err != nil {
			return Database{}, fmt.Errorf("%s: invalid build time %q", file, f[1])
		}
		built = t.UTC()
	}
	name := strings.TrimSuffix(file, filepath.Ext(file))
	return Database{Name: name, File: file, Version: version, Built: built, Signatures: sigs}, nil
}

// Read returns the signatures installed in dir, or an error wrapping
// ErrNoSignatures when the main or daily database is missing. When a
// database is there as both .cvd and .cld, the newer version counts.
func Read(dir string) (*Signatures, error) {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%w in %s", ErrNoSignatures, dir)
	}
	if err != nil {
		return nil, err
	}
	found := map[string]Database{}
	for _, e := range entries {
		ext := filepath.Ext(e.Name())
		if !e.Type().IsRegular() || (ext != ".cvd" && ext != ".cld") {
			continue
		}
		db, err := readHeader(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		if old, ok := found[db.Name]; !ok || db.Version > old.Version {
			found[db.Name] = db
		}
	}
	for _, name := range requiredDatabases {
		if _, ok := found[name]; !ok {
			return nil, fmt.Errorf("%w in %s: %s.cvd or %s.cld is missing", ErrNoSignatures, dir, name, name)
		}
	}
	s := &Signatures{Version: found["daily"].Version, Date: found["daily"].Built}
	for _, db := range found {
		s.Databases = append(s.Databases, db)
	}
	slices.SortFunc(s.Databases, func(a, b Database) int { return strings.Compare(a.Name, b.Name) })
	return s, nil
}

// fileMode is the mode of every installed signature file, so the sandbox
// user can read files the host user owns.
const fileMode = 0o644

// DirMode is the signature directory's mode, so the sandbox user can read
// it.
const DirMode = 0o755

// Seed copies the regular files in dir into staging, so freshclam can
// update them in place of downloading everything again. A missing dir
// copies nothing.
func Seed(dir, staging string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		if err := copyFile(filepath.Join(dir, e.Name()), filepath.Join(staging, e.Name())); err != nil {
			return err
		}
	}
	return nil
}

func copyFile(from, to string) error {
	in, err := os.Open(from)
	if err != nil {
		return err
	}
	defer func() { _ = in.Close() }()
	out, err := os.OpenFile(to, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
	if err != nil {
		return err
	}
	_, err = io.Copy(out, in)
	if closeErr := out.Close(); err == nil {
		err = closeErr
	}
	return err
}

// Install checks that staging holds a complete set of signatures, then
// moves each of its regular files into dir with a rename, and removes the
// files in dir that staging no longer has. Each file is replaced whole, so
// a scan running meanwhile reads either the old or the new copy of it, and
// signatures that fail the check leave dir as it was. It returns the
// installed signatures.
func Install(staging, dir string) (*Signatures, error) {
	sigs, err := Read(staging)
	if err != nil {
		return nil, fmt.Errorf("the update left no usable signatures: %w", err)
	}
	if err := os.MkdirAll(dir, DirMode); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, DirMode); err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(staging)
	if err != nil {
		return nil, err
	}
	keep := map[string]bool{}
	for _, e := range entries {
		if !e.Type().IsRegular() {
			continue
		}
		from := filepath.Join(staging, e.Name())
		if err := os.Chmod(from, fileMode); err != nil {
			return nil, err
		}
		if err := os.Rename(from, filepath.Join(dir, e.Name())); err != nil {
			return nil, err
		}
		keep[e.Name()] = true
	}
	old, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	for _, e := range old {
		if e.Type().IsRegular() && !keep[e.Name()] {
			if err := os.Remove(filepath.Join(dir, e.Name())); err != nil {
				return nil, err
			}
		}
	}
	return sigs, nil
}

// FreshclamConfig is the freshclam configuration update-signatures uses:
// the official mirror, no log file, no clamd to notify, and the databases
// tested before they are kept.
const FreshclamConfig = `DatabaseDirectory ` + DatabaseDir + `
DatabaseMirror database.clamav.net
DNSDatabaseInfo current.cvd.clamav.net
ScriptedUpdates yes
TestDatabases yes
Bytecode yes
Foreground yes
LogTime no
MaxAttempts 3
CVDCertsDirectory /etc/clamav/certs
`

// FreshclamScript writes FreshclamConfig to /tmp and runs freshclam with
// it, so the read-only image needs no config of its own.
const FreshclamScript = `printf '%s' "$1" > /tmp/freshclam.conf && exec freshclam --config-file=/tmp/freshclam.conf --datadir=` + DatabaseDir

// FreshclamArgs returns the command that updates the signatures in
// DatabaseDir.
func FreshclamArgs() []string {
	return []string{"/bin/sh", "-c", FreshclamScript, "sh", FreshclamConfig}
}
