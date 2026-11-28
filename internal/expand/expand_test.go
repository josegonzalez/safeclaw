package expand

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/josegonzalez/safeclaw/internal/mail"
	"github.com/josegonzalez/safeclaw/internal/unpack"
)

// zipHead makes a file look like a zip to unpack.Detect.
const zipHead = "PK\x03\x04"

// fakeArchive is what a fakeRunner lists and extracts for one archive.
type fakeArchive struct {
	// files are written on extract, by path; "symlink:TARGET" is listed
	// and made as a link.
	files map[string]string
	// password, when set, encrypts every entry.
	password string
	listErr  error
	// block waits for the context to end while extracting.
	block bool
}

// fakeRunner stands in for 7z, keyed by the archive's base name. A file
// it has no archive for is one 7z can't open.
type fakeRunner struct {
	archives map[string]fakeArchive
	pws      []*string
}

func (f *fakeRunner) List(_ context.Context, archive string, pw *string) (*unpack.Listing, error) {
	f.pws = append(f.pws, pw)
	a, ok := f.archives[filepath.Base(archive)]
	if !ok {
		return nil, unpack.ErrNotArchive
	}
	if a.listErr != nil {
		return nil, a.listErr
	}
	var entries []unpack.Entry
	for _, name := range sortedKeys(a.files) {
		e := unpack.Entry{Path: name, Type: unpack.TypeFile, Size: int64(len(a.files[name])), Encrypted: a.password != ""}
		if strings.HasPrefix(a.files[name], "symlink:") {
			e.Type, e.Size, e.Link = unpack.TypeSymlink, -1, strings.TrimPrefix(a.files[name], "symlink:")
		}
		e.UnsafePath = unpack.UnsafePath(name)
		entries = append(entries, e)
	}
	return &unpack.Listing{Type: "fake", Entries: entries}, nil
}

func (f *fakeRunner) Extract(ctx context.Context, archive, dir string, include []string, pw *string) error {
	a := f.archives[filepath.Base(archive)]
	if a.password != "" && (pw == nil || *pw != a.password) {
		return &unpack.Error{Kind: unpack.NeedsPassword, Msg: "wrong password"}
	}
	for _, name := range sortedKeys(a.files) {
		if include != nil && !slices.Contains(include, name) {
			continue
		}
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			return err
		}
		if t, ok := strings.CutPrefix(a.files[name], "symlink:"); ok {
			if err := os.Symlink(t, p); err != nil {
				return err
			}
			continue
		}
		if err := os.WriteFile(p, []byte(a.files[name]), 0o644); err != nil {
			return err
		}
	}
	if a.block {
		<-ctx.Done()
		return ctx.Err()
	}
	return nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

var b64 = base64.StdEncoding.EncodeToString

func sha256Of(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// email returns a message with a text body and the attachments given as
// name, content pairs.
func email(subject, body string, attachments ...string) string {
	var b strings.Builder
	b.WriteString("From: Eve <eve@example.com>\r\nSubject: " + subject + "\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n")
	b.WriteString("--b\r\nContent-Type: text/plain\r\n\r\n" + body + "\r\n")
	for i := 0; i+1 < len(attachments); i += 2 {
		b.WriteString("--b\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=\"" + attachments[i] + "\"\r\nContent-Transfer-Encoding: base64\r\n\r\n" + b64([]byte(attachments[i+1])) + "\r\n")
	}
	b.WriteString("--b--\r\n")
	return b.String()
}

// forwarding returns a message whose second part is msg, inline.
func forwarding(msg string) string {
	return "From: Bob <bob@example.com>\r\nSubject: fwd\r\nContent-Type: multipart/mixed; boundary=f\r\n\r\n" +
		"--f\r\nContent-Type: text/plain\r\n\r\nsee below\r\n" +
		"--f\r\nContent-Type: message/rfc822\r\n\r\n" + msg + "\r\n--f--\r\n"
}

// writeInputs writes files, name then content, into a new directory and
// returns their paths.
func writeInputs(t *testing.T, files ...string) []string {
	t.Helper()
	dir := t.TempDir()
	var out []string
	for i := 0; i+1 < len(files); i += 2 {
		p := filepath.Join(dir, files[i])
		if err := os.WriteFile(p, []byte(files[i+1]), 0o644); err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}

// newDest returns a missing destination two directories down, so anything
// that got out would land in the test's own directory.
func newDest(t *testing.T) string {
	t.Helper()
	dest := filepath.Join(t.TempDir(), "a", "b", "out")
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		t.Fatal(err)
	}
	return dest
}

func run(t *testing.T, f *fakeRunner, o Options, inputs ...string) (string, *Manifest) {
	t.Helper()
	dest := newDest(t)
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		t.Fatal(err)
	}
	if o.MaxSize == 0 {
		o.MaxSize = DefaultMaxSize
	}
	if f != nil {
		o.Runner = f
	}
	o.PollInterval = time.Millisecond
	m, err := Run(t.Context(), inputs, dest, o)
	if err != nil {
		t.Fatal(err)
	}
	read, err := ReadManifest(dest)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(read, m) {
		t.Errorf("manifest.json = %+v\nwant %+v", read, m)
	}
	return dest, m
}

// summary is each container as PATH KIND DEPTH FLAGS -> DIR.
func summary(m *Manifest) []string {
	var out []string
	for _, c := range m.Containers {
		s := c.Path + " " + c.Kind + " " + string(rune('0'+c.Depth)) + " " + strings.Join(c.Flags, ",")
		if c.Unpacked != "" {
			s += " -> " + c.Unpacked
		}
		out = append(out, s)
	}
	return out
}

func checkSummary(t *testing.T, m *Manifest, want []string) {
	t.Helper()
	if got := summary(m); !slices.Equal(got, want) {
		t.Errorf("containers:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestRunTree opens an email carrying a zip that holds a forwarded .eml
// carrying another zip, and checks the helpers' own output is never taken
// for an email.
func TestRunTree(t *testing.T) {
	inner := email("inner", "inner text", "inner.zip", zipHead)
	f := &fakeRunner{archives: map[string]fakeArchive{
		"1-files.zip": {files: map[string]string{"fwd.eml": inner, "notes.txt": "just notes\n"}},
		"1-inner.zip": {files: map[string]string{"deep.txt": "deep\n"}},
	}}
	in := writeInputs(t, "report.eml", email("report", "see attached", "files.zip", zipHead))
	dest, m := run(t, f, Options{Depth: DefaultDepth}, in...)
	checkSummary(t, m, []string{
		"1-report.eml email 0 UNPACKED -> 1-report.eml.unpacked",
		"1-report.eml.unpacked/1-files.zip zip 1 UNPACKED -> 1-report.eml.unpacked/1-files.zip.unpacked",
		"1-report.eml.unpacked/1-files.zip.unpacked/fwd.eml email 2 UNPACKED -> 1-report.eml.unpacked/1-files.zip.unpacked/fwd.eml.unpacked",
		"1-report.eml.unpacked/1-files.zip.unpacked/fwd.eml.unpacked/1-inner.zip zip 3 UNPACKED -> 1-report.eml.unpacked/1-files.zip.unpacked/fwd.eml.unpacked/1-inner.zip.unpacked",
	})
	if got := readFile(t, filepath.Join(dest, "1-report.eml.unpacked/1-files.zip.unpacked/fwd.eml.unpacked/1-inner.zip.unpacked/deep.txt")); got != "deep\n" {
		t.Errorf("deep.txt = %q", got)
	}
	c := m.Containers[0]
	if c.Parent != "" || m.Containers[1].Parent != c.Path || m.Containers[3].Parent != m.Containers[2].Path {
		t.Errorf("parents = %+v", m.Containers)
	}
	if !slices.Equal(c.Outputs, []string{"1-report.eml.unpacked/body.txt", "1-report.eml.unpacked/parts.txt"}) {
		t.Errorf("outputs = %v", c.Outputs)
	}
	// body.txt starts with headers, but is never opened.
	body := readFile(t, filepath.Join(dest, "1-report.eml.unpacked", mail.BodyFile))
	if !strings.HasPrefix(body, "From: Eve <eve@example.com>\nSubject: report\n\nsee attached") {
		t.Errorf("body.txt = %q", body)
	}
	if _, err := os.Stat(filepath.Join(dest, "1-report.eml.unpacked/body.txt.unpacked")); err == nil {
		t.Error("body.txt was opened")
	}
	parts := readFile(t, filepath.Join(dest, "1-report.eml.unpacked", mail.PartsFile))
	if !strings.Contains(parts, "1.2\tapplication/octet-stream\t4\tfiles.zip\tATTACHMENT\t1-files.zip\n") {
		t.Errorf("parts.txt = %q", parts)
	}
	if !slices.Equal(m.Inputs, []Input{{Path: "1-report.eml", Size: m.Inputs[0].Size, Kind: KindEmail, SHA256: sha256Of(email("report", "see attached", "files.zip", zipHead))}}) || m.Inputs[0].Size == 0 {
		t.Errorf("inputs = %+v", m.Inputs)
	}
	if m.Schema != SchemaVersion || m.Status != "ok" || m.Code != 0 || m.Options != (ManifestOptions{Depth: 3, MaxSize: DefaultMaxSize, Mail: true}) {
		t.Errorf("manifest = %+v", m)
	}
	size, err := unpack.TreeSize(dest)
	if err != nil {
		t.Fatal(err)
	}
	fi, _ := os.Stat(filepath.Join(dest, ManifestFile))
	if want := size - m.Inputs[0].Size - fi.Size(); m.Size != want {
		t.Errorf("size = %d, want %d", m.Size, want)
	}

	// One level less leaves the last zip packed.
	_, m = run(t, f, Options{Depth: 2}, in...)
	if c := m.Containers[3]; c.Outcome != OutcomeDepthLimit || !slices.Equal(c.Flags, []string{"DEPTH-LIMIT"}) || c.Unpacked != "" || c.Code != 0 {
		t.Errorf("depth 2: %+v", c)
	}
	// 0 opens only the inputs.
	_, m = run(t, f, Options{Depth: 0}, in...)
	checkSummary(t, m, []string{
		"1-report.eml email 0 UNPACKED -> 1-report.eml.unpacked",
		"1-report.eml.unpacked/1-files.zip zip 1 DEPTH-LIMIT",
	})
}

// TestRunOwnOutputOnly checks that only the files the helper wrote are
// skipped: a body.txt inside an archive that starts like a message is
// opened, as is a .txt file that is a message.
func TestRunOwnOutputOnly(t *testing.T) {
	f := &fakeRunner{archives: map[string]fakeArchive{
		"1-a.zip": {files: map[string]string{"body.txt": "Subject: hi\n\nhello\n", "parts.txt": "1\ttext/plain\t5\t-\tBODY\n"}},
	}}
	_, m := run(t, f, Options{Depth: 3}, writeInputs(t, "a.zip", zipHead)...)
	checkSummary(t, m, []string{
		"1-a.zip zip 0 UNPACKED -> 1-a.zip.unpacked",
		"1-a.zip.unpacked/body.txt email 1 UNPACKED -> 1-a.zip.unpacked/body.txt.unpacked",
	})
}

// TestRunForwardedDepth checks that a forwarded message counts as a level:
// a zip attached to it is one level deeper than one attached to the email.
func TestRunForwardedDepth(t *testing.T) {
	f := &fakeRunner{archives: map[string]fakeArchive{
		"1-outer.zip": {files: map[string]string{"x.txt": "x"}},
		"2-inner.zip": {files: map[string]string{"y.txt": "y"}},
	}}
	msg := forwarding(email("inner", "inner", "inner.zip", zipHead))
	// The forwarding message's own attachment comes first.
	msg = strings.Replace(msg, "--f\r\nContent-Type: message/rfc822", "--f\r\nContent-Type: application/zip\r\nContent-Disposition: attachment; filename=outer.zip\r\nContent-Transfer-Encoding: base64\r\n\r\n"+b64([]byte(zipHead))+"\r\n--f\r\nContent-Type: message/rfc822", 1)
	in := writeInputs(t, "fwd.eml", msg)
	_, m := run(t, f, Options{Depth: 2}, in...)
	checkSummary(t, m, []string{
		"1-fwd.eml email 0 UNPACKED -> 1-fwd.eml.unpacked",
		"1-fwd.eml.unpacked/1-outer.zip zip 1 UNPACKED -> 1-fwd.eml.unpacked/1-outer.zip.unpacked",
		"1-fwd.eml.unpacked/2-inner.zip zip 2 UNPACKED -> 1-fwd.eml.unpacked/2-inner.zip.unpacked",
	})
	_, m = run(t, f, Options{Depth: 1}, in...)
	checkSummary(t, m, []string{
		"1-fwd.eml email 0 UNPACKED -> 1-fwd.eml.unpacked",
		"1-fwd.eml.unpacked/1-outer.zip zip 1 UNPACKED -> 1-fwd.eml.unpacked/1-outer.zip.unpacked",
		"1-fwd.eml.unpacked/2-inner.zip zip 2 DEPTH-LIMIT",
	})
	// With depth 0 the forwarded message isn't followed: mail writes it as
	// an attachment, which is past the depth limit.
	_, m = run(t, f, Options{Depth: 0}, in...)
	checkSummary(t, m, []string{
		"1-fwd.eml email 0 UNPACKED -> 1-fwd.eml.unpacked",
		"1-fwd.eml.unpacked/1-outer.zip zip 1 DEPTH-LIMIT",
		"1-fwd.eml.unpacked/2-message.eml email 1 DEPTH-LIMIT",
	})
}

// TestRunKeepGoing checks that every level, the inputs included, leaves a
// failing container packed and flagged and keeps everything else.
func TestRunKeepGoing(t *testing.T) {
	big := strings.Repeat("x", 600)
	f := &fakeRunner{archives: map[string]fakeArchive{
		"1-links.zip":  {files: map[string]string{"fine.txt": "fine", "l": "symlink:/etc/passwd"}},
		"2-enc.zip":    {files: map[string]string{"secret.txt": "s"}, password: "pw"},
		"3-big.zip":    {files: map[string]string{"big": big + big}},
		"4-broken.zip": {listErr: &unpack.Error{Kind: unpack.Failed, Msg: "7z: data error"}},
		"5-good.zip": {files: map[string]string{
			"a.txt":      "a",
			"nested.zip": zipHead,
			"fake.zip":   zipHead + "not really",
			"enc.zip":    zipHead,
		}},
		"nested.zip": {files: map[string]string{"n.txt": "n"}},
		"enc.zip":    {files: map[string]string{"e.txt": "e"}, password: "pw"},
	}}
	in := writeInputs(t, "links.zip", zipHead, "enc.zip", zipHead, "big.zip", zipHead, "broken.zip", zipHead, "good.zip", zipHead, "notes.txt", "notes\n", "fake.zip", zipHead)
	dest, m := run(t, f, Options{Depth: 3, MaxSize: 1000}, in...)
	checkSummary(t, m, []string{
		"1-links.zip zip 0 REJECTED",
		"2-enc.zip zip 0 NEEDS-PASSWORD",
		"3-big.zip zip 0 TOO-LARGE",
		"4-broken.zip zip 0 FAILED",
		"5-good.zip zip 0 UNPACKED -> 5-good.zip.unpacked",
		"5-good.zip.unpacked/enc.zip zip 1 NEEDS-PASSWORD",
		"5-good.zip.unpacked/nested.zip zip 1 UNPACKED -> 5-good.zip.unpacked/nested.zip.unpacked",
		"7-fake.zip zip 0 FAILED",
	})
	byPath := map[string]Container{}
	for _, c := range m.Containers {
		byPath[c.Path] = c
	}
	l := byPath["1-links.zip"]
	if l.Code != 2 || len(l.Rejected) != 1 || l.Rejected[0].Path != "l" || l.Rejected[0].Type != "symlink" || l.Rejected[0].Link != "/etc/passwd" || !slices.Equal(l.Rejected[0].Flags, []string{"LINK"}) || !strings.HasPrefix(l.Error, "rejected: ") {
		t.Errorf("links = %+v", l)
	}
	if c := byPath["2-enc.zip"]; c.Code != 3 || c.Error == "" {
		t.Errorf("enc = %+v", c)
	}
	if c := byPath["3-big.zip"]; c.Code != 4 {
		t.Errorf("big = %+v", c)
	}
	if c := byPath["4-broken.zip"]; c.Code != 1 || !strings.Contains(c.Error, "data error") {
		t.Errorf("broken = %+v", c)
	}
	// An input that only starts like an archive is corrupt.
	if c := byPath["7-fake.zip"]; c.Code != 1 || !strings.Contains(c.Error, "corrupt") {
		t.Errorf("fake input = %+v", c)
	}
	// Nothing a packed one extracted is left, and a nested file that only
	// starts like an archive is left as it is, unrecorded.
	for _, p := range []string{"1-links.zip.unpacked", "2-enc.zip.unpacked", "3-big.zip.unpacked", "4-broken.zip.unpacked", "7-fake.zip.unpacked", "5-good.zip.unpacked/fake.zip.unpacked", "5-good.zip.unpacked/enc.zip.unpacked"} {
		if _, err := os.Lstat(filepath.Join(dest, p)); err == nil {
			t.Errorf("%s left behind", p)
		}
	}
	for _, p := range []string{"1-links.zip", "6-notes.txt", "5-good.zip.unpacked/fake.zip", "5-good.zip.unpacked/a.txt"} {
		if _, err := os.Lstat(filepath.Join(dest, p)); err != nil {
			t.Errorf("%s: %v", p, err)
		}
	}
	if m.Inputs[5] != (Input{Path: "6-notes.txt", Size: 6, SHA256: sha256Of("notes\n")}) {
		t.Errorf("notes input = %+v", m.Inputs[5])
	}

	// The password opens every encrypted archive in the tree.
	pw := "pw"
	f.archives["1-enc.zip"] = f.archives["2-enc.zip"]
	f.archives["2-good.zip"] = f.archives["5-good.zip"]
	_, m = run(t, f, Options{Depth: 3, MaxSize: 1000, Password: &pw}, in[1], in[4])
	checkSummary(t, m, []string{
		"1-enc.zip zip 0 UNPACKED -> 1-enc.zip.unpacked",
		"2-good.zip zip 0 UNPACKED -> 2-good.zip.unpacked",
		"2-good.zip.unpacked/enc.zip zip 1 UNPACKED -> 2-good.zip.unpacked/enc.zip.unpacked",
		"2-good.zip.unpacked/nested.zip zip 1 UNPACKED -> 2-good.zip.unpacked/nested.zip.unpacked",
	})
	if !m.Options.Password {
		t.Error("options.password not set")
	}
	for _, p := range f.pws {
		if p != nil && *p != pw {
			t.Errorf("password = %q", *p)
		}
	}
}

// TestRunSharedBudget checks that one --max-size covers the whole tree, the
// inputs not counted, and that a container that failed gives its space
// back.
func TestRunSharedBudget(t *testing.T) {
	part := strings.Repeat("x", 400)
	f := &fakeRunner{archives: map[string]fakeArchive{
		"1-a.zip": {files: map[string]string{"a": part}},
		"2-b.zip": {files: map[string]string{"b": part + part}},
		"3-c.zip": {files: map[string]string{"c": part}},
		"4-d.zip": {files: map[string]string{"d": part}},
	}}
	in := writeInputs(t, "a.zip", zipHead+part, "b.zip", zipHead, "c.zip", zipHead, "d.zip", zipHead)
	_, m := run(t, f, Options{Depth: 3, MaxSize: 1000}, in...)
	checkSummary(t, m, []string{
		"1-a.zip zip 0 UNPACKED -> 1-a.zip.unpacked",
		"2-b.zip zip 0 TOO-LARGE",
		"3-c.zip zip 0 UNPACKED -> 3-c.zip.unpacked",
		"4-d.zip zip 0 TOO-LARGE",
	})
	if m.Size != 800 {
		t.Errorf("size = %d", m.Size)
	}

	// An email counts too, and one that no longer fits is left packed.
	msg := email("x", strings.Repeat("y", 300))
	_, m = run(t, f, Options{Depth: 3, MaxSize: 1000}, append(in[:1:1], writeInputs(t, "m.eml", msg, "n.eml", msg)...)...)
	checkSummary(t, m, []string{
		"1-a.zip zip 0 UNPACKED -> 1-a.zip.unpacked",
		"2-m.eml email 0 UNPACKED -> 2-m.eml.unpacked",
		"3-n.eml email 0 TOO-LARGE",
	})
	if m.Size > 1000 {
		t.Errorf("size = %d", m.Size)
	}
}

// TestRunNoMail checks that --no-mail leaves emails as plain files.
func TestRunNoMail(t *testing.T) {
	f := &fakeRunner{archives: map[string]fakeArchive{
		"2-a.zip": {files: map[string]string{"m.eml": email("x", "y", "z.zip", zipHead)}},
	}}
	_, m := run(t, f, Options{Depth: 3, NoMail: true}, writeInputs(t, "m.eml", email("x", "y"), "a.zip", zipHead)...)
	checkSummary(t, m, []string{"2-a.zip zip 0 UNPACKED -> 2-a.zip.unpacked"})
	if m.Inputs[0].Kind != "" || m.Options.Mail {
		t.Errorf("manifest = %+v", m)
	}
}

// TestRunNo7z checks that without 7z emails are still opened and archives
// are left packed.
func TestRunNo7z(t *testing.T) {
	_, m := run(t, nil, Options{Depth: 3}, writeInputs(t, "m.eml", email("x", "y", "z.zip", zipHead))...)
	checkSummary(t, m, []string{
		"1-m.eml email 0 UNPACKED -> 1-m.eml.unpacked",
		"1-m.eml.unpacked/1-z.zip zip 1 FAILED",
	})
	if !strings.Contains(m.Containers[1].Error, "7z not found") {
		t.Errorf("error = %q", m.Containers[1].Error)
	}
}

// TestRunEmailProblems checks that an email's part problems are flagged on
// its record, and that a rejected email is left packed.
func TestRunEmailProblems(t *testing.T) {
	msg := email("x", "y", "../../evil.pdf", "%PDF")
	rejected := "Subject: x\r\nContent-Type: multipart/mixed; boundary=b\r\n\r\n" + strings.Repeat("--b\r\nContent-Type: text/plain\r\n\r\nx\r\n", mail.MaxParts+1) + "--b--\r\n"
	_, m := run(t, nil, Options{Depth: 3}, writeInputs(t, "m.eml", msg, "r.eml", rejected)...)
	checkSummary(t, m, []string{
		"1-m.eml email 0 UNPACKED,UNSAFE-NAME -> 1-m.eml.unpacked",
		"2-r.eml email 0 REJECTED",
	})
	if m.Containers[1].Code != 2 {
		t.Errorf("rejected = %+v", m.Containers[1])
	}
}

// TestRunNameCollision checks that a container is never opened into a
// directory the archive already had.
func TestRunNameCollision(t *testing.T) {
	f := &fakeRunner{archives: map[string]fakeArchive{
		"1-a.zip": {files: map[string]string{"b.zip": zipHead, "b.zip.unpacked/x.txt": "theirs"}},
		"b.zip":   {files: map[string]string{"x.txt": "ours"}},
	}}
	dest, m := run(t, f, Options{Depth: 3}, writeInputs(t, "a.zip", zipHead)...)
	checkSummary(t, m, []string{
		"1-a.zip zip 0 UNPACKED -> 1-a.zip.unpacked",
		"1-a.zip.unpacked/b.zip zip 1 UNPACKED -> 1-a.zip.unpacked/b.zip.unpacked-2",
	})
	if got := readFile(t, filepath.Join(dest, "1-a.zip.unpacked/b.zip.unpacked/x.txt")); got != "theirs" {
		t.Errorf("theirs = %q", got)
	}
}

// TestRunInputNames checks that inputs are numbered and named safely, and
// that the same name twice doesn't collide.
func TestRunInputNames(t *testing.T) {
	a := writeInputs(t, "-x\x1b.txt", "a")
	b := writeInputs(t, "-x\x1b.txt", "b")
	dest, m := run(t, nil, Options{}, a[0], b[0])
	if m.Inputs[0].Path != "1-x.txt" || m.Inputs[1].Path != "2-x.txt" || len(m.Containers) != 0 {
		t.Errorf("manifest = %+v", m)
	}
	if readFile(t, filepath.Join(dest, "2-x.txt")) != "b" {
		t.Error("second input not copied")
	}
}

// TestRunRefuses checks the input and destination rules, and that a run
// that fails empties the destination.
func TestRunRefuses(t *testing.T) {
	in := writeInputs(t, "a.txt", "a")
	o := Options{MaxSize: 1000}
	check := func(name string, inputs []string, dest string, o Options) {
		t.Helper()
		if _, err := Run(t.Context(), inputs, dest, o); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
	dest := newDest(t)
	check("missing input", []string{filepath.Join(t.TempDir(), "nope")}, dest, o)
	check("device input", []string{os.DevNull}, dest, o)
	check("no inputs", nil, dest, o)
	check("no size", in, dest, Options{})
	check("negative depth", in, dest, Options{MaxSize: 1, Depth: -1})
	if _, err := os.Lstat(dest); err == nil {
		t.Error("dest made before the inputs were checked")
	}
	full := t.TempDir()
	if err := os.WriteFile(filepath.Join(full, "x"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	check("not empty", in, full, o)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(t.TempDir(), link); err != nil {
		t.Fatal(err)
	}
	check("symlink dest", in, link, o)
	notDir := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(notDir, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	check("file dest", in, notDir, o)

	// A link to an input is followed.
	target := writeInputs(t, "t.txt", "t")[0]
	viaLink := filepath.Join(t.TempDir(), "via.txt")
	if err := os.Symlink(target, viaLink); err != nil {
		t.Fatal(err)
	}
	d, m := run(t, nil, Options{}, viaLink)
	if fi, err := os.Lstat(filepath.Join(d, m.Inputs[0].Path)); err != nil || !fi.Mode().IsRegular() {
		t.Errorf("linked input copy: %v", err)
	}
}

// TestRunInterrupted checks that an interrupt fails the run and empties
// the destination.
func TestRunInterrupted(t *testing.T) {
	f := &fakeRunner{archives: map[string]fakeArchive{"1-a.zip": {files: map[string]string{"x": "x"}, block: true}}}
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(50*time.Millisecond, cancel)
	dest := newDest(t)
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := Run(ctx, writeInputs(t, "a.zip", zipHead), dest, Options{Runner: f, MaxSize: 1000, Depth: 3, PollInterval: time.Millisecond})
	if err == nil || !errors.Is(err, context.Canceled) || !strings.HasPrefix(err.Error(), "interrupted") {
		t.Fatalf("err = %v", err)
	}
	if names, _ := os.ReadDir(dest); len(names) > 0 {
		t.Errorf("dest not emptied: %v", names)
	}
}

// TestManifestCheck checks that a manifest naming a path outside the
// destination, or of another schema, is refused, and that ReadManifest
// doesn't follow a link.
func TestManifestCheck(t *testing.T) {
	ok := Manifest{Schema: SchemaVersion, Inputs: []Input{{Path: "1-a"}}, Containers: []Container{{Path: "1-a", Unpacked: "1-a.unpacked", Outputs: []string{"1-a.unpacked/body.txt"}}}}
	if err := ok.Check(); err != nil {
		t.Fatal(err)
	}
	for name, mod := range map[string]func(m *Manifest){
		"schema":         func(m *Manifest) { m.Schema = 2 },
		"input dotdot":   func(m *Manifest) { m.Inputs[0].Path = "../a" },
		"absolute":       func(m *Manifest) { m.Containers[0].Path = "/etc/passwd" },
		"dot":            func(m *Manifest) { m.Containers[0].Path = "." },
		"unpacked":       func(m *Manifest) { m.Containers[0].Unpacked = "a/../../b" },
		"parent":         func(m *Manifest) { m.Containers[0].Parent = "a//b" },
		"output":         func(m *Manifest) { m.Containers[0].Outputs = []string{"../body.txt"} },
		"trailing slash": func(m *Manifest) { m.Containers[0].Path = "a/" },
		"duplicate":      func(m *Manifest) { m.Containers = append(m.Containers, m.Containers[0]) },
	} {
		m := ok
		m.Inputs = slices.Clone(ok.Inputs)
		m.Containers = slices.Clone(ok.Containers)
		mod(&m)
		if err := m.Check(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	dir := t.TempDir()
	if err := writeManifest(dir, &ok); err != nil {
		t.Fatal(err)
	}
	// It is replaced in one step, leaving no temporary file.
	if err := writeManifest(dir, &ok); err != nil {
		t.Fatal(err)
	}
	if names, _ := os.ReadDir(dir); len(names) != 1 {
		t.Errorf("left behind: %v", names)
	}
	if m, err := ReadManifest(dir); err != nil || !reflect.DeepEqual(*m, ok) {
		t.Errorf("read = %+v, %v", m, err)
	}
	linked := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, ManifestFile), filepath.Join(linked, ManifestFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifest(linked); err == nil {
		t.Error("followed a link")
	}
	bad := t.TempDir()
	if err := os.WriteFile(filepath.Join(bad, ManifestFile), []byte(`{"schema":1,"containers":[{"path":"../x"}]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadManifest(bad); err == nil {
		t.Error("read a manifest naming ../x")
	}
}
