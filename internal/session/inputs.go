package session

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

// A one-off sandbox made with --keep-inputs keeps a record, on the host,
// of what `sandbox cp-in` copied into it and of the `sandbox open` runs
// made on it, so that --restore-from can rebuild it after it is lost. The
// record holds each file's host source path, sha256, size, and container
// path, never a copy of the file: the caller keeps its own originals.
const (
	// InputsSchema is the version of the input record.
	InputsSchema = 1
	// InputsFile is the name of the record in its directory.
	InputsFile = "inputs.json"
	// inputsLock serializes the writers of a record.
	inputsLock = "inputs.lock"
	// maxInputsBytes caps the record safeclaw reads or writes.
	maxInputsBytes = 16 << 20
	// maxInputFiles and maxInputOpens cap the entries of a record.
	maxInputFiles = 100_000
	maxInputOpens = 10_000
	// maxOpenArgs caps the arguments of one recorded open.
	maxOpenArgs = 10_000
)

// ErrInputs is wrapped by every error about an input record or its
// directory.
var ErrInputs = errors.New("input record")

// inputRecord is the JSON record in InputsFile.
type inputRecord struct {
	Schema int `json:"schema"`
	// Verify is set when the sandbox was made with --verify, so a restore
	// verifies the new one too.
	Verify bool         `json:"verify"`
	Files  []inputFile  `json:"files"`
	Opens  []inputOpens `json:"opens"`
}

// inputFile is one file cp-in copied.
type inputFile struct {
	// Source is the host file's absolute path.
	Source string `json:"source"`
	// SHA256 is the hex sha256 of the bytes cp-in sent.
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	// Path is where it is in the sandbox, OpenInDir/N-NAME.
	Path string `json:"path"`
}

// inputOpens is one `sandbox open` run whose safeclaw-expand finished.
type inputOpens struct {
	// Args are the safeclaw-expand flags it passed that shape the tree,
	// each --NAME or --NAME=VALUE (see openRecordedFlags). The password
	// is never recorded.
	Args []string `json:"args"`
}

// openRecordedFlags are the safeclaw-expand flags a recorded open may
// hold: the skip list and holds, and the flags a rerun of the tree must
// give again.
var openRecordedFlags = map[string]bool{
	"skip": true, "unskip": true, "hold": true, "release": true, "release-all": true,
	"depth": true, "max-size": true, "no-mail": true,
}

var sha256Hex = regexp.MustCompile(`^[0-9a-f]{64}$`)

// validate checks a record as strictly as one written by safeclaw: it is
// host-side and only safeclaw writes it, but a restore copies host files
// by what it says, so a changed record must not name a container path
// outside OpenInDir, or anything cp-in would not have written.
func (r *inputRecord) validate() error {
	if r.Schema != InputsSchema {
		return fmt.Errorf("schema %d is not %d", r.Schema, InputsSchema)
	}
	if len(r.Files) > maxInputFiles {
		return fmt.Errorf("%d files is more than %d", len(r.Files), maxInputFiles)
	}
	if len(r.Opens) > maxInputOpens {
		return fmt.Errorf("%d opens is more than %d", len(r.Opens), maxInputOpens)
	}
	seen := make(map[string]bool, len(r.Files))
	for i, f := range r.Files {
		if err := f.validate(); err != nil {
			return fmt.Errorf("file %d: %w", i+1, err)
		}
		if seen[f.Path] {
			return fmt.Errorf("file %d: %s is listed twice", i+1, QuotePath(f.Path))
		}
		seen[f.Path] = true
	}
	for i, o := range r.Opens {
		if err := validateOpenArgs(o.Args); err != nil {
			return fmt.Errorf("open %d: %w", i+1, err)
		}
	}
	return nil
}

func (f inputFile) validate() error {
	if f.Source == "" || !filepath.IsAbs(f.Source) || filepath.Clean(f.Source) != f.Source || strings.ContainsRune(f.Source, 0) {
		return fmt.Errorf("source %s is not a clean absolute path", QuotePath(f.Source))
	}
	if !sha256Hex.MatchString(f.SHA256) {
		return fmt.Errorf("sha256 %q is not 64 lowercase hex digits", f.SHA256)
	}
	if f.Size < 0 {
		return fmt.Errorf("size %d is negative", f.Size)
	}
	dir, name := path.Split(f.Path)
	if dir != OpenInDir+"/" || path.Clean(f.Path) != f.Path {
		return fmt.Errorf("path %s is not directly in %s", QuotePath(f.Path), OpenInDir)
	}
	digits, base, _ := strings.Cut(name, "-")
	n, err := strconv.Atoi(digits)
	if err != nil || n < 1 || n > MaxCopyIndex || strconv.Itoa(n) != digits || base != filepath.Base(f.Source) {
		return fmt.Errorf("path %s is not a name cp-in gives %s", QuotePath(f.Path), QuotePath(f.Source))
	}
	return nil
}

// validateOpenArgs checks a recorded open's flags: each is one of
// openRecordedFlags, printable, and one argument.
func validateOpenArgs(args []string) error {
	if len(args) > maxOpenArgs {
		return fmt.Errorf("%d arguments is more than %d", len(args), maxOpenArgs)
	}
	for _, a := range args {
		flag, ok := strings.CutPrefix(a, "--")
		name, _, _ := strings.Cut(flag, "=")
		if !ok || !openRecordedFlags[name] || !printable(a) {
			return fmt.Errorf("argument %s is not a recorded safeclaw-expand flag", QuotePath(a))
		}
	}
	return nil
}

// checkInputsDir refuses a record directory that is a symbolic link, not
// a directory, not the caller's, or open to anyone else.
func checkInputsDir(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("%w directory: %w", ErrInputs, err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%w directory %s %w", ErrInputs, dir, ErrSymlink)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w directory %s is not a directory", ErrInputs, dir)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%w directory %s is not owned by you", ErrInputs, dir)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%w directory %s is mode %04o, open to others: it must be 0700 (chmod 700 %s)", ErrInputs, dir, fi.Mode().Perm(), dir)
	}
	return nil
}

// lockInputs takes the record's lock, held while it is read and written.
func lockInputs(ctx context.Context, dir string) (func(), error) {
	if err := checkInputsDir(dir); err != nil {
		return nil, err
	}
	return lockFileCtx(ctx, dir, inputsLock)
}

// readInputs reads and validates dir's record. The record must be a
// regular file, not a link, of at most maxInputsBytes.
func readInputs(dir string) (*inputRecord, error) {
	if err := checkInputsDir(dir); err != nil {
		return nil, err
	}
	p := filepath.Join(dir, InputsFile)
	f, err := os.OpenFile(p, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, fmt.Errorf("%w %s %w", ErrInputs, p, ErrSymlink)
		}
		return nil, fmt.Errorf("%w: %w", ErrInputs, err)
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInputs, err)
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%w %s %w", ErrInputs, p, ErrNotRegular)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxInputsBytes+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInputs, err)
	}
	if len(data) > maxInputsBytes {
		return nil, fmt.Errorf("%w %s is over %d bytes", ErrInputs, p, maxInputsBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var rec inputRecord
	if err := dec.Decode(&rec); err != nil {
		return nil, fmt.Errorf("%w %s is not valid: %w", ErrInputs, p, err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%w %s is not valid: data after the record", ErrInputs, p)
	}
	if err := rec.validate(); err != nil {
		return nil, fmt.Errorf("%w %s is not valid: %w", ErrInputs, p, err)
	}
	return &rec, nil
}

// writeInputs validates rec and replaces dir's record with it atomically:
// it is written to a temporary file in dir, synced, and renamed over the
// record, so a reader sees the old record or the new one, never part of
// one.
func writeInputs(dir string, rec *inputRecord) error {
	if err := rec.validate(); err != nil {
		return fmt.Errorf("%w: %w", ErrInputs, err)
	}
	if rec.Files == nil {
		rec.Files = []inputFile{}
	}
	if rec.Opens == nil {
		rec.Opens = []inputOpens{}
	}
	data, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if len(data) > maxInputsBytes {
		return fmt.Errorf("%w would be over %d bytes", ErrInputs, maxInputsBytes)
	}
	tmp, err := os.CreateTemp(dir, ".inputs-*.json")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(0o600)
	}
	if err == nil {
		err = tmp.Sync()
	}
	if err = errors.Join(err, tmp.Close()); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), filepath.Join(dir, InputsFile)); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	return errors.Join(d.Sync(), d.Close())
}

// recordCopies appends what cp-in copied to rec and writes it to dir. The
// caller holds the record's lock and read rec under it.
func recordCopies(dir string, rec *inputRecord, srcs []*source, paths []string) error {
	for i, s := range srcs {
		abs, err := filepath.Abs(s.path)
		if err != nil {
			return err
		}
		rec.Files = append(rec.Files, inputFile{Source: abs, SHA256: hex.EncodeToString(s.sum), Size: s.size, Path: paths[i]})
	}
	return writeInputs(dir, rec)
}

// RecordOpen appends a `sandbox open` run's safeclaw-expand flags to the
// input record in dir, which is OpenRun.KeepInputs. The caller calls it
// once safeclaw-expand has finished, since a run that failed left the tree
// as it was.
func (m *Manager) RecordOpen(ctx context.Context, dir string, o OpenOptions) error {
	args := OpenRecordArgs(o)
	if err := validateOpenArgs(args); err != nil {
		return fmt.Errorf("%w: %w", ErrInputs, err)
	}
	unlock, err := lockInputs(ctx, dir)
	if err != nil {
		return err
	}
	defer unlock()
	rec, err := readInputs(dir)
	if err != nil {
		return err
	}
	rec.Opens = append(rec.Opens, inputOpens{Args: args})
	return writeInputs(dir, rec)
}

// OpenRecordArgs returns the flags of a `sandbox open` run that a record
// keeps: its safeclaw-expand policy flags, then its skips and unskips, as
// it passed them.
func OpenRecordArgs(o OpenOptions) []string {
	args := []string{}
	for _, a := range o.ExpandArgs {
		name, _, _ := strings.Cut(strings.TrimPrefix(a, "--"), "=")
		if openRecordedFlags[name] {
			args = append(args, a)
		}
	}
	for _, p := range o.Skip {
		args = append(args, "--skip="+p)
	}
	for _, p := range o.Unskip {
		args = append(args, "--unskip="+p)
	}
	return args
}

// inputsDir returns dir as an absolute path, which is what the sandbox's
// label records.
func inputsDir(dir string) (string, error) {
	if dir == "" {
		return "", fmt.Errorf("%w directory can't be empty", ErrInputs)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	if !printable(abs) {
		return "", fmt.Errorf("%w directory %s is not printable text", ErrInputs, QuotePath(abs))
	}
	return abs, nil
}

// KeepInputs creates a one-off sandbox, as EnsureSandbox does with
// opts.Remove, that keeps a record of its inputs in dir. dir is created
// with mode 0700, with any missing parents, when it doesn't exist; an
// existing one must not be a link, must be the caller's and mode 0700,
// and must not hold a record already. The record is written before the
// sandbox is created and removed again when it can't be.
func (m *Manager) KeepInputs(ctx context.Context, opts SandboxOptions, dir string) (*Result, error) {
	if !opts.Remove {
		return nil, errors.New("--keep-inputs is only for one-off sandboxes, made with --rm")
	}
	dir, err := inputsDir(dir)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("%w directory: %w", ErrInputs, err)
	}
	unlock, err := lockInputs(ctx, dir)
	if err != nil {
		return nil, err
	}
	defer unlock()
	if err := newRecord(dir, opts.Verify); err != nil {
		return nil, err
	}
	p := filepath.Join(dir, InputsFile)
	opts.keepInputs = dir
	res, err := m.EnsureSandbox(ctx, opts)
	if err != nil {
		_ = os.Remove(p)
		return nil, err
	}
	m.printf("Recording its inputs in %s\n", p)
	return res, nil
}

// errHoldsRecord is wrapped by the error refusing a record directory that
// already holds a record.
var errHoldsRecord = errors.New("already holds a record")

// holdsRecordError refuses dir for holding a record already.
func holdsRecordError(dir string) error {
	return fmt.Errorf("%w directory %s %w: restore it with --restore-from, or keep inputs in another directory", ErrInputs, dir, errHoldsRecord)
}

// newRecord writes an empty record to dir, refusing a dir that holds one
// already. The caller holds the record's lock.
func newRecord(dir string, verify bool) error {
	if _, err := os.Lstat(filepath.Join(dir, InputsFile)); !errors.Is(err, fs.ErrNotExist) {
		if err != nil {
			return fmt.Errorf("%w: %w", ErrInputs, err)
		}
		return holdsRecordError(dir)
	}
	return writeInputs(dir, &inputRecord{Schema: InputsSchema, Verify: verify})
}

// checkNoRecord refuses dir, a record directory KeepInputsUnder is about
// to name a sandbox after, when it already holds a record, or exists but
// isn't a record directory checkInputsDir accepts. A dir that doesn't
// exist yet passes.
func checkNoRecord(dir string) error {
	if _, err := os.Lstat(dir); errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err := checkInputsDir(dir); err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(dir, InputsFile)); !errors.Is(err, fs.ErrNotExist) {
		if err != nil {
			return fmt.Errorf("%w: %w", ErrInputs, err)
		}
		return holdsRecordError(dir)
	}
	return nil
}

// start starts the record of a sandbox KeepInputsUnder has just created
// in dir, the parent's directory named after it: dir is created mode 0700
// if it doesn't exist, and must then be a record directory that holds no
// record. The record is created under its lock, so of two runs that reach
// the same dir only one starts the record. A dir it created is removed
// again when the record can't be started, so only a sandbox that was kept
// leaves a directory behind.
func (u *recordUnder) start(ctx context.Context, dir string, verify bool) error {
	err := os.Mkdir(dir, 0o700)
	if err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("%w directory: %w", ErrInputs, err)
	}
	created := err == nil
	if err := startRecord(ctx, dir, verify); err != nil {
		if created {
			_ = os.Remove(filepath.Join(dir, inputsLock))
			_ = os.Remove(dir)
		}
		return err
	}
	u.dir, u.created = dir, created
	return nil
}

// remove removes the record start started, once its sandbox was removed
// again, and the directory too when start created it.
func (u *recordUnder) remove() {
	if u.dir == "" {
		return
	}
	_ = os.Remove(filepath.Join(u.dir, InputsFile))
	if u.created {
		_ = os.Remove(filepath.Join(u.dir, inputsLock))
		_ = os.Remove(u.dir)
	}
}

// startRecord writes a new record to dir under its lock.
func startRecord(ctx context.Context, dir string, verify bool) error {
	unlock, err := lockInputs(ctx, dir)
	if err != nil {
		return err
	}
	defer unlock()
	return newRecord(dir, verify)
}

// checkInputsParent refuses a KeepInputsUnder parent directory that is a
// symbolic link, not a directory, not the caller's, or writable by anyone
// else, who could otherwise swap a sandbox's record directory under it.
// Unlike a record directory, it may be readable by others: it holds only
// the record directories, each mode 0700.
func checkInputsParent(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("%w parent directory: %w", ErrInputs, err)
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		return fmt.Errorf("%w parent directory %s %w", ErrInputs, dir, ErrSymlink)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w parent directory %s is not a directory", ErrInputs, dir)
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok && int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%w parent directory %s is not owned by you", ErrInputs, dir)
	}
	if fi.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("%w parent directory %s is mode %04o, writable by others: it must not be group- or world-writable (chmod go-w %s)", ErrInputs, dir, fi.Mode().Perm(), dir)
	}
	return nil
}

// KeepInputsUnder creates a one-off sandbox, as EnsureSandbox does with
// opts.Remove, that keeps a record of its inputs in parent/NAME, NAME
// being the name it gets, so the name can be picked by opts.NamePrefix.
// parent is created mode 0700, with any missing parents, when it doesn't
// exist; an existing one must not be a link, must be the caller's, and
// must not be writable by anyone else. parent/NAME is checked as KeepInputs
// checks its dir, but is created, and its record started, only for the
// name docker accepts; with a name prefix, a name whose directory already
// holds a record is skipped like a name a container has. When the record
// can't be started, the new sandbox is removed.
func (m *Manager) KeepInputsUnder(ctx context.Context, opts SandboxOptions, parent string) (*Result, error) {
	if !opts.Remove {
		return nil, errors.New("--keep-inputs-under is only for one-off sandboxes, made with --rm")
	}
	parent, err := inputsDir(parent)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return nil, fmt.Errorf("%w parent directory: %w", ErrInputs, err)
	}
	if err := checkInputsParent(parent); err != nil {
		return nil, err
	}
	under := &recordUnder{parent: parent}
	opts.keepInputsUnder = under
	res, err := m.EnsureSandbox(ctx, opts)
	if err != nil {
		// A sandbox whose record was started can still be removed
		// afterwards, by a failed --verify.
		under.remove()
		return nil, err
	}
	return res, nil
}

// recordUnder is a KeepInputsUnder parent directory, and the record
// directory started in it once the sandbox's name was accepted.
type recordUnder struct {
	parent string
	// dir is the record directory start started a record in, and created
	// whether start created it.
	dir     string
	created bool
}

// RestoreError lists the recorded sources a restore refused, each with
// why: missing, not a regular file, or changed since it was copied in.
type RestoreError struct {
	Dir      string
	Problems []string
}

func (e *RestoreError) Error() string {
	return fmt.Sprintf("can't restore from %s, so nothing was created: %d recorded source(s) can't be copied again:\n  %s",
		e.Dir, len(e.Problems), strings.Join(e.Problems, "\n  "))
}

// Restored is what RestoreSandbox made.
type Restored struct {
	*Result
	// Files are the container paths restored, in the record's order.
	Files []string
	// Opens are the recorded `sandbox open` runs' flags, in order, for the
	// caller to run again. RestoreSandbox never runs them itself.
	Opens [][]string
}

// RestoreSandbox creates a new one-off sandbox from the input record in
// dir and copies each recorded source back to its recorded container
// path. Every source is checked before anything is created: it must still
// be a regular file, not a link, with the recorded size and sha256, and
// any that is not refuses the restore with a *RestoreError naming each.
// The sources are only hashed and sent, never opened in any other way. It
// is verified when opts.Verify or the record asks for it, and it keeps
// recording to dir, so later cp-in and open calls append to the same
// record. When the copy fails, or a source changes between its check and
// its copy, the new sandbox is removed. The recorded opens are returned,
// not run, so a restore never runs the helpers.
func (m *Manager) RestoreSandbox(ctx context.Context, opts SandboxOptions, dir string) (*Restored, error) {
	if !opts.Remove {
		return nil, errors.New("--restore-from is only for one-off sandboxes, made with --rm")
	}
	dir, err := inputsDir(dir)
	if err != nil {
		return nil, err
	}
	unlock, err := lockInputs(ctx, dir)
	if err != nil {
		return nil, err
	}
	defer unlock()
	rec, err := readInputs(dir)
	if err != nil {
		return nil, err
	}
	srcs := make([]*source, 0, len(rec.Files))
	defer func() {
		for _, s := range srcs {
			_ = s.f.Close()
		}
	}()
	var problems []string
	for _, f := range rec.Files {
		s, err := checkSource(f)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		srcs = append(srcs, s)
	}
	if len(problems) > 0 {
		return nil, &RestoreError{Dir: dir, Problems: problems}
	}

	opts.Verify = opts.Verify || rec.Verify
	opts.keepInputs = dir
	res, err := m.EnsureSandbox(ctx, opts)
	if err != nil {
		return nil, err
	}
	out := &Restored{Result: res}
	for _, o := range rec.Opens {
		out.Opens = append(out.Opens, o.Args)
	}
	if len(srcs) == 0 {
		return out, nil
	}
	if err := m.restoreFiles(ctx, res.Container, rec.Files, srcs); err != nil {
		_ = m.Docker.Remove(context.WithoutCancel(ctx), res.Container, true)
		return nil, fmt.Errorf("restoring %s into sandbox %q failed, so it was removed: %w", dir, res.Name, err)
	}
	for _, f := range rec.Files {
		out.Files = append(out.Files, f.Path)
	}
	m.printf("Restored %d file(s) into %s from %s\n", len(srcs), OpenInDir, filepath.Join(dir, InputsFile))
	return out, nil
}

// checkSource opens a recorded source as cp-in does and checks that its
// size and sha256 are the recorded ones, returning it ready to send again.
func checkSource(f inputFile) (*source, error) {
	name := QuotePath(f.Source)
	s, err := openSource(f.Source)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, fmt.Errorf("%s is missing", name)
	case errors.Is(err, ErrSymlink) || errors.Is(err, syscall.ELOOP):
		return nil, fmt.Errorf("%s is now a symbolic link", name)
	case errors.Is(err, ErrNotRegular):
		return nil, fmt.Errorf("%s is no longer a regular file", name)
	case err != nil:
		return nil, fmt.Errorf("%s can't be read: %w", name, err)
	}
	h := sha256.New()
	n, err := io.Copy(h, s.f)
	if err == nil {
		_, err = s.f.Seek(0, io.SeekStart)
	}
	if err != nil {
		_ = s.f.Close()
		return nil, fmt.Errorf("%s can't be read: %w", name, err)
	}
	if sum := hex.EncodeToString(h.Sum(nil)); n != f.Size || n != s.size || sum != f.SHA256 {
		_ = s.f.Close()
		return nil, fmt.Errorf("%s changed since it was copied in: sha256 %s, %d bytes, was %s, %d bytes", name, sum, n, f.SHA256, f.Size)
	}
	return s, nil
}

// restoreFiles sends srcs into the new sandbox as files names, under its
// copy lock, and checks that what was sent is what was recorded.
func (m *Manager) restoreFiles(ctx context.Context, container string, files []inputFile, srcs []*source) error {
	unlock, err := lockFileCtx(ctx, m.copyDir(), container+".lock")
	if err != nil {
		return err
	}
	defer unlock()
	quiet := copyExec
	quiet.MaxOutput = copyQuietMaxOutput
	if _, err := m.Docker.Exec(ctx, container, quiet, copyCommand(mkdirBin, "-p", "--", OpenInDir)...); err != nil {
		return err
	}
	names := make([]string, len(files))
	for i, f := range files {
		names[i] = path.Base(f.Path)
	}
	if err := m.sendFiles(ctx, container, OpenInDir, srcs, names); err != nil {
		return err
	}
	for i, s := range srcs {
		if hex.EncodeToString(s.sum) != files[i].SHA256 {
			return fmt.Errorf("%s changed while being copied", QuotePath(files[i].Source))
		}
	}
	return nil
}
