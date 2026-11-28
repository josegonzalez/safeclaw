package unpack

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// Runner runs 7z. SevenZip is the real one; tests use fakes.
type Runner interface {
	// List returns the `7z l -slt` listing of archive.
	List(ctx context.Context, archive string, pw *string) (*Listing, error)
	// Extract extracts archive into dir: every entry when include is nil,
	// else only the named entries, matched literally.
	Extract(ctx context.Context, archive, dir string, include []string, pw *string) error
}

// SevenZip runs the 7z binary at Path.
//
// Every run gets -spd, so file names are never wildcards, and the archive
// is passed after "--" as an absolute path, so 7z never reads it as a
// switch or a list file. A password is written to 7z's stdin, where it
// reads its password prompt, so it is never in 7z's arguments. Without
// one, stdin is empty and 7z's prompt fails, which is how an archive that
// needs a password shows.
type SevenZip struct {
	Path string
}

// Find returns the 7z on PATH: 7z, else 7zz.
func Find() (SevenZip, error) {
	for _, name := range []string{"7z", "7zz"} {
		if p, err := exec.LookPath(name); err == nil {
			return SevenZip{Path: p}, nil
		}
	}
	return SevenZip{}, errors.New("7z not found on PATH; it is in the sandbox image variant (the 7zip package)")
}

// errNotArchive is returned when 7z can't open a file as an archive.
var errNotArchive = errors.New("not an archive 7z can open")

var (
	notArchiveRe = regexp.MustCompile(`(?i)can ?not open (the )?file as (\[\w+\] )?archive`)
	wrongPassRe  = regexp.MustCompile(`(?i)wrong password`)
	passPromptRe = regexp.MustCompile(`(?i)enter password`)
)

// List runs `7z l -slt`.
func (z SevenZip) List(ctx context.Context, archive string, pw *string) (*Listing, error) {
	stdout, err := z.run(ctx, pw, "l", "-slt", "-sccUTF-8", "-bd", "-spd", "--", archive)
	if err != nil {
		return nil, err
	}
	return ParseListing(stdout)
}

// Extract runs `7z x`, overwriting duplicates within the archive. With
// include, the names reach 7z in a list file, read as UTF-8, rather than
// as arguments.
func (z SevenZip) Extract(ctx context.Context, archive, dir string, include []string, pw *string) error {
	args := []string{"x", "-y", "-aoa", "-bd", "-sccUTF-8", "-scsUTF-8", "-spd", "-o" + dir}
	if include != nil {
		// A list file in the temporary directory, rather than a pipe,
		// which p7zip can't read one from.
		list, err := os.CreateTemp("", "safeclaw-unpack-*.txt")
		if err != nil {
			return err
		}
		defer os.Remove(list.Name())
		_, err = io.WriteString(list, strings.Join(include, "\n")+"\n")
		if cerr := list.Close(); err == nil {
			err = cerr
		}
		if err != nil {
			return err
		}
		args = append(args, "-i@"+list.Name(), "-r-")
	}
	args = append(args, "--", archive)
	_, err := z.run(ctx, pw, args...)
	return err
}

func (z SevenZip) run(ctx context.Context, pw *string, args ...string) (string, error) {
	c := exec.CommandContext(ctx, z.Path, args...)
	stdin := ""
	if pw != nil {
		stdin = *pw + "\n"
	}
	c.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	c.Stdout = &stdout
	c.Stderr = &stderr
	err := c.Run()
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if err == nil {
		return stdout.String(), nil
	}
	out, msg := stdout.String(), strings.TrimSpace(stderr.String())
	switch {
	case wrongPassRe.MatchString(msg):
		if pw == nil {
			return "", &Error{Kind: NeedsPassword, Msg: "the archive is encrypted and no password was given"}
		}
		return "", &Error{Kind: NeedsPassword, Msg: "wrong password"}
	case pw == nil && passPromptRe.MatchString(out):
		return "", &Error{Kind: NeedsPassword, Msg: "the archive is encrypted and no password was given"}
	case notArchiveRe.MatchString(msg):
		return "", errNotArchive
	}
	if msg == "" {
		msg = err.Error()
	}
	return "", &Error{Kind: Failed, Msg: "7z: " + oneLine(msg)}
}

// oneLine joins the non-blank lines of 7z's stderr with "; ".
func oneLine(s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return strings.Join(out, "; ")
}

// Kind is how an unpack failed. Its value is the exit code.
type Kind int

// Failure kinds, and the exit codes `safeclaw unpack` uses for them.
const (
	// Failed is any other failure: 7z failed, the archive is corrupt, or an
	// I/O or usage error.
	Failed Kind = 1
	// Rejected is an archive with links, special files, or unsafe paths.
	Rejected Kind = 2
	// NeedsPassword is an encrypted archive without a password, or with the
	// wrong one.
	NeedsPassword Kind = 3
	// TooLarge is an archive whose contents exceed the size limit.
	TooLarge Kind = 4
)

func (k Kind) String() string {
	switch k {
	case Rejected:
		return "rejected"
	case NeedsPassword:
		return "needs password"
	case TooLarge:
		return "too large"
	}
	return "failed"
}

// Error is an unpack failure.
type Error struct {
	Kind Kind
	// Archive is the archive it happened in, relative to the destination
	// for a nested one.
	Archive string
	Msg     string
	// Bad are the entries that got the archive rejected.
	Bad []Entry
}

func (e *Error) Error() string {
	if e.Archive != "" {
		return fmt.Sprintf("%s: %s: %s", e.Kind, e.Archive, e.Msg)
	}
	return fmt.Sprintf("%s: %s", e.Kind, e.Msg)
}

// KindOf returns err's Kind: Failed for an error that isn't an *Error.
func KindOf(err error) Kind {
	var e *Error
	if errors.As(err, &e) {
		return e.Kind
	}
	return Failed
}
