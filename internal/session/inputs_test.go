package session

import (
	"archive/tar"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
)

// inputsWorld is a sandbox world for input records: one-off sandboxes are
// created in it, and ls answers each sandbox's cp-in listing from what
// was extracted into it.
type inputsWorld struct {
	w *world
	r *dockertest.Runner
	m *Manager
	// listing is each container's /sandbox/in, by what tar extracted.
	listing map[string][]string
	// tarErr fails every tar -x.
	tarErr error
}

func newInputsWorld(t *testing.T) *inputsWorld {
	t.Helper()
	iw := &inputsWorld{w: &world{image: "img", containers: map[string]*fakeContainer{}}, listing: map[string][]string{}}
	iw.m, iw.r = newTestManager(t, iw.w)
	iw.r.Handler = func(args []string, stdin string) ([]byte, error) {
		if args[0] == "exec" {
			container := ""
			for _, a := range args[1:] {
				if strings.HasPrefix(a, "safeclaw-") {
					container = a
					break
				}
			}
			switch {
			case slices.Contains(args, lsBin):
				return []byte(strings.Join(iw.listing[container], "\n")), nil
			case slices.Contains(args, tarBin) && slices.Contains(args, "-x"):
				if iw.tarErr != nil {
					return nil, iw.tarErr
				}
				tr := tar.NewReader(strings.NewReader(stdin))
				for {
					hdr, err := tr.Next()
					if err != nil {
						break
					}
					iw.listing[container] = append(iw.listing[container], hdr.Name)
				}
				return nil, nil
			case slices.Contains(args, mkdirBin):
				return nil, nil
			}
		}
		return iw.w.handle(args, stdin)
	}
	return iw
}

// privateDir returns a new mode 0700 directory, as a record directory
// must be.
func privateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func sum(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

func readRecord(t *testing.T, dir string) *inputRecord {
	t.Helper()
	rec, err := readInputs(dir)
	if err != nil {
		t.Fatal(err)
	}
	return rec
}

// tarFiles returns the names and contents of the last tar -x into
// container.
func tarFiles(t *testing.T, r *dockertest.Runner, container string) map[string]string {
	t.Helper()
	var stdin string
	found := false
	for _, c := range r.Calls {
		if c.Args[0] == "exec" && slices.Contains(c.Args, container) && slices.Contains(c.Args, tarBin) {
			stdin, found = c.Stdin, true
		}
	}
	if !found {
		t.Fatalf("no tar -x into %s in %v", container, r.Commands())
	}
	got := map[string]string{}
	tr := tar.NewReader(strings.NewReader(stdin))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(tr)
		got[hdr.Name] = string(body)
	}
	return got
}

func TestKeepInputsRecordsCopies(t *testing.T) {
	iw := newInputsWorld(t)
	files := t.TempDir()
	a := writeFile(t, filepath.Join(files, "a", "report.pdf"), "first")
	b := writeFile(t, filepath.Join(files, "b", "report.pdf"), "second!")
	c := writeFile(t, filepath.Join(files, "mail.eml"), "third")
	dir := filepath.Join(t.TempDir(), "rec", "job")
	ctx := context.Background()

	res, err := iw.m.KeepInputs(ctx, SandboxOptions{Name: "job", Remove: true, Verify: false}, dir)
	if err != nil {
		t.Fatal(err)
	}
	run, _ := iw.r.Find("run ")
	if !strings.Contains(run.String(), " --label safeclaw.keep-inputs="+dir+" ") {
		t.Errorf("run has no keep-inputs label: %s", run)
	}
	fi, err := os.Stat(dir)
	if err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("DIR mode = %v, %v, want 0700", fi, err)
	}
	if fi, err := os.Stat(filepath.Join(dir, InputsFile)); err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("record mode = %v, %v, want 0600", fi, err)
	}
	if rec := readRecord(t, dir); len(rec.Files) != 0 || len(rec.Opens) != 0 || rec.Verify {
		t.Errorf("new record = %+v", rec)
	}

	// Two cp-in calls append to the record, numbered across the calls.
	if _, err := iw.m.CopyIn(ctx, res.Name, []string{a, b}, ""); err != nil {
		t.Fatal(err)
	}
	paths, err := iw.m.CopyIn(ctx, res.Name, []string{c}, "/sandbox/in")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(paths, []string{"/sandbox/in/3-mail.eml"}) {
		t.Errorf("second cp-in paths = %v", paths)
	}
	want := []inputFile{
		{Source: a, SHA256: sum("first"), Size: 5, Path: "/sandbox/in/1-report.pdf"},
		{Source: b, SHA256: sum("second!"), Size: 7, Path: "/sandbox/in/2-report.pdf"},
		{Source: c, SHA256: sum("third"), Size: 5, Path: "/sandbox/in/3-mail.eml"},
	}
	if rec := readRecord(t, dir); !reflect.DeepEqual(rec.Files, want) {
		t.Errorf("files = %+v\nwant    %+v", rec.Files, want)
	}
	// Nothing is left in DIR but the record and its lock.
	entries, _ := os.ReadDir(dir)
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if !reflect.DeepEqual(names, []string{InputsFile, inputsLock}) {
		t.Errorf("DIR holds %v", names)
	}

	// --to elsewhere is refused before anything is copied.
	before := len(iw.r.Calls)
	if _, err := iw.m.CopyIn(ctx, res.Name, []string{a}, "/sandbox/other"); err == nil || !strings.Contains(err.Error(), "copy without --to") {
		t.Errorf("--to elsewhere: err = %v", err)
	}
	for _, call := range iw.r.Calls[before:] {
		if call.Args[0] == "exec" {
			t.Errorf("refused cp-in ran %v", call.Args)
		}
	}

	// A record changed by hand refuses the copy before anything is copied.
	if err := os.WriteFile(filepath.Join(dir, InputsFile), []byte(`{"schema":2}`), 0o600); err != nil {
		t.Fatal(err)
	}
	before = len(iw.r.Calls)
	if _, err := iw.m.CopyIn(ctx, res.Name, []string{a}, ""); !errors.Is(err, ErrInputs) {
		t.Errorf("tampered record: err = %v", err)
	}
	for _, call := range iw.r.Calls[before:] {
		if call.Args[0] == "exec" && slices.Contains(call.Args, tarBin) {
			t.Errorf("cp-in with a tampered record copied: %v", call.Args)
		}
	}
}

func TestCopyInWithoutKeepInputsRecordsNothing(t *testing.T) {
	iw := newInputsWorld(t)
	file := writeFile(t, filepath.Join(t.TempDir(), "x.txt"), "x")
	res, err := iw.m.EnsureSandbox(context.Background(), SandboxOptions{Name: "plain", Remove: true})
	if err != nil {
		t.Fatal(err)
	}
	if run, _ := iw.r.Find("run "); strings.Contains(run.String(), "keep-inputs") {
		t.Errorf("plain sandbox has a keep-inputs label: %s", run)
	}
	if _, err := iw.m.CopyIn(context.Background(), res.Name, []string{file}, "/sandbox/elsewhere"); err != nil {
		t.Errorf("plain cp-in --to: %v", err)
	}
}

func TestKeepInputsDir(t *testing.T) {
	ctx := context.Background()
	opts := SandboxOptions{Name: "job", Remove: true}

	t.Run("link", func(t *testing.T) {
		iw := newInputsWorld(t)
		target := t.TempDir()
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := iw.m.KeepInputs(ctx, opts, link); !errors.Is(err, ErrSymlink) {
			t.Errorf("err = %v, want a link refused", err)
		}
		if _, ok := iw.r.Find("run "); ok {
			t.Error("a sandbox was created")
		}
		if entries, _ := os.ReadDir(target); len(entries) != 0 {
			t.Errorf("wrote through the link: %v", entries)
		}
	})
	t.Run("open to others", func(t *testing.T) {
		iw := newInputsWorld(t)
		dir := privateDir(t)
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := iw.m.KeepInputs(ctx, opts, dir); err == nil || !strings.Contains(err.Error(), "must be 0700") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("a file", func(t *testing.T) {
		iw := newInputsWorld(t)
		file := writeFile(t, filepath.Join(t.TempDir(), "f"), "x")
		if _, err := iw.m.KeepInputs(ctx, opts, file); err == nil {
			t.Error("a file was taken as DIR")
		}
	})
	t.Run("record already there", func(t *testing.T) {
		iw := newInputsWorld(t)
		dir := privateDir(t)
		if _, err := iw.m.KeepInputs(ctx, opts, dir); err != nil {
			t.Fatal(err)
		}
		if _, err := iw.m.KeepInputs(ctx, SandboxOptions{Name: "job2", Remove: true}, dir); err == nil || !strings.Contains(err.Error(), "already holds a record") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("not one-off", func(t *testing.T) {
		iw := newInputsWorld(t)
		if _, err := iw.m.KeepInputs(ctx, SandboxOptions{Name: "job"}, privateDir(t)); err == nil {
			t.Error("--keep-inputs without --rm was taken")
		}
		if _, err := iw.m.RestoreSandbox(ctx, SandboxOptions{Name: "job"}, privateDir(t)); err == nil {
			t.Error("--restore-from without --rm was taken")
		}
	})
	t.Run("creation fails", func(t *testing.T) {
		iw := newInputsWorld(t)
		iw.w.image = ""
		dir := privateDir(t)
		if _, err := iw.m.KeepInputs(ctx, opts, dir); err == nil {
			t.Fatal("no image, yet created")
		}
		if _, err := os.Lstat(filepath.Join(dir, InputsFile)); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("record left behind: %v", err)
		}
	})
}

func TestRecordOpen(t *testing.T) {
	iw := newInputsWorld(t)
	dir := privateDir(t)
	ctx := context.Background()
	if _, err := iw.m.KeepInputs(ctx, SandboxOptions{Name: "job", Remove: true}, dir); err != nil {
		t.Fatal(err)
	}
	o := OpenOptions{
		ExpandArgs: []string{"--depth=5", "--hold=mail-archives", "--release=1-a.eml.unpacked/1-b.zip"},
		Skip:       []string{"1-a.zip"},
		Unskip:     []string{"-x"},
	}
	if err := iw.m.RecordOpen(ctx, dir, o); err != nil {
		t.Fatal(err)
	}
	if err := iw.m.RecordOpen(ctx, dir, OpenOptions{}); err != nil {
		t.Fatal(err)
	}
	want := []inputOpens{
		{Args: []string{"--depth=5", "--hold=mail-archives", "--release=1-a.eml.unpacked/1-b.zip", "--skip=1-a.zip", "--unskip=-x"}},
		{Args: []string{}},
	}
	if rec := readRecord(t, dir); !reflect.DeepEqual(rec.Opens, want) {
		t.Errorf("opens = %+v\nwant    %+v", rec.Opens, want)
	}
	if got := OpenRecordArgs(OpenOptions{ExpandArgs: []string{"--other=1", "--no-mail=true"}}); !reflect.DeepEqual(got, []string{"--no-mail=true"}) {
		t.Errorf("OpenRecordArgs = %v", got)
	}
	if err := iw.m.RecordOpen(ctx, dir, OpenOptions{Skip: []string{"bad\x1bname"}}); !errors.Is(err, ErrInputs) {
		t.Errorf("unprintable skip recorded: %v", err)
	}
}

// keptSandbox makes a sandbox keeping its inputs in a new DIR, copies two
// files and records an open with a skip, then removes the sandbox, as a
// docker restart would. It returns DIR and the two sources.
func keptSandbox(t *testing.T, iw *inputsWorld) (dir, a, b string) {
	t.Helper()
	ctx := context.Background()
	files := t.TempDir()
	a = writeFile(t, filepath.Join(files, "report.eml"), "mail")
	b = writeFile(t, filepath.Join(files, "dump.zip"), "PK zip")
	dir = privateDir(t)
	res, err := iw.m.KeepInputs(ctx, SandboxOptions{Name: "job", Remove: true}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iw.m.CopyIn(ctx, res.Name, []string{a}, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := iw.m.CopyIn(ctx, res.Name, []string{b}, ""); err != nil {
		t.Fatal(err)
	}
	if err := iw.m.RecordOpen(ctx, dir, OpenOptions{Skip: []string{"2-dump.zip"}}); err != nil {
		t.Fatal(err)
	}
	delete(iw.w.containers, res.Container)
	return dir, a, b
}

func TestRestoreSandbox(t *testing.T) {
	iw := newInputsWorld(t)
	dir, _, _ := keptSandbox(t, iw)
	// Numbers taken in the new sandbox before the copy can't renumber the
	// restored files: they keep their recorded names.
	r, err := iw.m.RestoreSandbox(context.Background(), SandboxOptions{Name: "job2", Remove: true}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if r.Name != "job2" {
		t.Errorf("name = %q", r.Name)
	}
	if want := []string{"/sandbox/in/1-report.eml", "/sandbox/in/2-dump.zip"}; !reflect.DeepEqual(r.Files, want) {
		t.Errorf("files = %v", r.Files)
	}
	if want := [][]string{{"--skip=2-dump.zip"}}; !reflect.DeepEqual(r.Opens, want) {
		t.Errorf("opens = %v", r.Opens)
	}
	if got := tarFiles(t, iw.r, "safeclaw-job2"); !reflect.DeepEqual(got, map[string]string{"1-report.eml": "mail", "2-dump.zip": "PK zip"}) {
		t.Errorf("restored tar = %v", got)
	}
	var run string
	for _, c := range iw.r.Commands() {
		if strings.HasPrefix(c, "run ") && strings.Contains(c, "safeclaw-job2") {
			run = c
		}
	}
	if !strings.Contains(run, " --rm ") || !strings.Contains(run, "--label safeclaw.keep-inputs="+dir+" ") {
		t.Errorf("restored run = %q", run)
	}
	// The restored sandbox keeps recording to DIR: the next cp-in follows
	// the restored numbers.
	more := writeFile(t, filepath.Join(t.TempDir(), "more.txt"), "more")
	paths, err := iw.m.CopyIn(context.Background(), "job2", []string{more}, "")
	if err != nil || !reflect.DeepEqual(paths, []string{"/sandbox/in/3-more.txt"}) {
		t.Errorf("cp-in after restore = %v, %v", paths, err)
	}
	if rec := readRecord(t, dir); len(rec.Files) != 3 {
		t.Errorf("record after restore has %d files", len(rec.Files))
	}
}

// noRun fails when the runner created a container after the call at
// index before.
func noRun(t *testing.T, r *dockertest.Runner, before int) {
	t.Helper()
	for _, c := range r.Calls[before:] {
		if c.Args[0] == "run" {
			t.Errorf("created a sandbox: %v", c.Args)
		}
	}
}

func TestRestoreRefusesChangedSources(t *testing.T) {
	iw := newInputsWorld(t)
	dir, a, b := keptSandbox(t, iw)
	if err := os.WriteFile(a, []byte("mail, changed"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(b); err != nil {
		t.Fatal(err)
	}
	before := len(iw.r.Calls)
	_, err := iw.m.RestoreSandbox(context.Background(), SandboxOptions{Remove: true}, dir)
	restoreErr, ok := errors.AsType[*RestoreError](err)
	if !ok {
		t.Fatalf("err = %v, want a *RestoreError", err)
	}
	if len(restoreErr.Problems) != 2 || !strings.Contains(restoreErr.Problems[0], a+" changed") || !strings.Contains(restoreErr.Problems[1], b+" is missing") {
		t.Errorf("problems = %q", restoreErr.Problems)
	}
	noRun(t, iw.r, before)

	// A same-sized change is caught by the hash.
	if err := os.WriteFile(a, []byte("MAIL"), 0o600); err != nil {
		t.Fatal(err)
	}
	writeFile(t, b, "PK zip")
	before = len(iw.r.Calls)
	_, err = iw.m.RestoreSandbox(context.Background(), SandboxOptions{Remove: true}, dir)
	if restoreErr, ok := errors.AsType[*RestoreError](err); !ok || len(restoreErr.Problems) != 1 || !strings.Contains(restoreErr.Problems[0], "sha256") {
		t.Errorf("same size change: err = %v", err)
	}
	noRun(t, iw.r, before)

	// A source replaced by a link is refused.
	if err := os.Remove(a); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(b, a); err != nil {
		t.Fatal(err)
	}
	_, err = iw.m.RestoreSandbox(context.Background(), SandboxOptions{Remove: true}, dir)
	if restoreErr, ok := errors.AsType[*RestoreError](err); !ok || !strings.Contains(restoreErr.Problems[0], "symbolic link") {
		t.Errorf("linked source: err = %v", err)
	}
}

func TestRestoreCopyFailureRemovesSandbox(t *testing.T) {
	iw := newInputsWorld(t)
	dir, _, _ := keptSandbox(t, iw)
	iw.tarErr = errors.New("tar failed")
	_, err := iw.m.RestoreSandbox(context.Background(), SandboxOptions{Name: "job2", Remove: true}, dir)
	if err == nil || !strings.Contains(err.Error(), "so it was removed") {
		t.Fatalf("err = %v", err)
	}
	if _, ok := iw.w.containers["safeclaw-job2"]; ok {
		t.Error("the failed restore left its sandbox")
	}
}

func TestRestoreRefusesTamperedRecord(t *testing.T) {
	good := func(dir string) inputRecord {
		return inputRecord{Schema: 1, Files: []inputFile{
			{Source: filepath.Join(dir, "a.txt"), SHA256: sum("a"), Size: 1, Path: "/sandbox/in/1-a.txt"},
		}, Opens: []inputOpens{{Args: []string{"--skip=1-a.txt"}}}}
	}
	for name, change := range map[string]func(r *inputRecord){
		"another schema":           func(r *inputRecord) { r.Schema = 2 },
		"path outside /sandbox/in": func(r *inputRecord) { r.Files[0].Path = "/sandbox/out/1-a.txt" },
		"path going up":            func(r *inputRecord) { r.Files[0].Path = "/sandbox/in/../1-a.txt" },
		"path in a subdirectory":   func(r *inputRecord) { r.Files[0].Path = "/sandbox/in/sub/1-a.txt" },
		"path of another name":     func(r *inputRecord) { r.Files[0].Path = "/sandbox/in/1-b.txt" },
		"path without a number":    func(r *inputRecord) { r.Files[0].Path = "/sandbox/in/a.txt" },
		"padded number":            func(r *inputRecord) { r.Files[0].Path = "/sandbox/in/01-a.txt" },
		"number zero":              func(r *inputRecord) { r.Files[0].Path = "/sandbox/in/0-a.txt" },
		"relative source":          func(r *inputRecord) { r.Files[0].Source = "a.txt" },
		"unclean source":           func(r *inputRecord) { r.Files[0].Source = "/x/../a.txt" },
		"bad sha256":               func(r *inputRecord) { r.Files[0].SHA256 = strings.ToUpper(r.Files[0].SHA256) },
		"negative size":            func(r *inputRecord) { r.Files[0].Size = -1 },
		"duplicate path": func(r *inputRecord) {
			r.Files = append(r.Files, r.Files[0])
		},
		"password recorded":   func(r *inputRecord) { r.Opens[0].Args = []string{"--password=x"} },
		"not a flag":          func(r *inputRecord) { r.Opens[0].Args = []string{"/sandbox/in"} },
		"unprintable flag":    func(r *inputRecord) { r.Opens[0].Args = []string{"--skip=a\nb"} },
		"too many files":      func(r *inputRecord) { r.Files = make([]inputFile, maxInputFiles+1) },
		"helper flag smuggle": func(r *inputRecord) { r.Opens[0].Args = []string{"--plan"} },
	} {
		t.Run(name, func(t *testing.T) {
			iw := newInputsWorld(t)
			dir := privateDir(t)
			writeFile(t, filepath.Join(dir, "a.txt"), "a")
			rec := good(dir)
			change(&rec)
			data, err := json.Marshal(rec)
			if err != nil {
				t.Fatal(err)
			}
			writeFile(t, filepath.Join(dir, InputsFile), string(data))
			if _, err := iw.m.RestoreSandbox(context.Background(), SandboxOptions{Remove: true}, dir); !errors.Is(err, ErrInputs) {
				t.Errorf("err = %v, want ErrInputs", err)
			}
			noRun(t, iw.r, 0)
		})
	}
	for name, data := range map[string]string{
		"unknown field":       `{"schema":1,"verify":false,"files":[],"opens":[],"copies":[]}`,
		"trailing data":       `{"schema":1,"files":[],"opens":[]}{}`,
		"not json":            `schema: 1`,
		"over the size limit": `{"schema":1,"files":[],"opens":[]}` + strings.Repeat(" ", maxInputsBytes),
	} {
		t.Run(name, func(t *testing.T) {
			iw := newInputsWorld(t)
			dir := privateDir(t)
			writeFile(t, filepath.Join(dir, InputsFile), data)
			if _, err := iw.m.RestoreSandbox(context.Background(), SandboxOptions{Remove: true}, dir); !errors.Is(err, ErrInputs) {
				t.Errorf("err = %v, want ErrInputs", err)
			}
			noRun(t, iw.r, 0)
		})
	}
	t.Run("record is a link", func(t *testing.T) {
		iw := newInputsWorld(t)
		dir := privateDir(t)
		real := writeFile(t, filepath.Join(t.TempDir(), "real.json"), `{"schema":1,"files":[],"opens":[]}`)
		if err := os.Symlink(real, filepath.Join(dir, InputsFile)); err != nil {
			t.Fatal(err)
		}
		if _, err := iw.m.RestoreSandbox(context.Background(), SandboxOptions{Remove: true}, dir); !errors.Is(err, ErrSymlink) {
			t.Errorf("err = %v, want a link refused", err)
		}
		noRun(t, iw.r, 0)
	})
	t.Run("no record", func(t *testing.T) {
		iw := newInputsWorld(t)
		if _, err := iw.m.RestoreSandbox(context.Background(), SandboxOptions{Remove: true}, privateDir(t)); !errors.Is(err, ErrInputs) {
			t.Errorf("err = %v", err)
		}
		noRun(t, iw.r, 0)
	})
}

func TestRestoreRefusesLinkedDir(t *testing.T) {
	iw := newInputsWorld(t)
	dir, _, _ := keptSandbox(t, iw)
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	before := len(iw.r.Calls)
	if _, err := iw.m.RestoreSandbox(context.Background(), SandboxOptions{Remove: true}, link); !errors.Is(err, ErrSymlink) {
		t.Errorf("err = %v, want a link refused", err)
	}
	noRun(t, iw.r, before)
	if err := os.Chmod(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	if _, err := iw.m.RestoreSandbox(context.Background(), SandboxOptions{Remove: true}, dir); err == nil || !strings.Contains(err.Error(), "must be 0700") {
		t.Errorf("group-readable DIR: err = %v", err)
	}
	noRun(t, iw.r, before)
}

func TestRestoreVerifiesWhenRecorded(t *testing.T) {
	iw := newInputsWorld(t)
	dir := privateDir(t)
	if err := writeInputs(dir, &inputRecord{Schema: 1, Verify: true}); err != nil {
		t.Fatal(err)
	}
	// The fake can't pass the checks, so a verified restore fails them
	// and removes its sandbox, which a restore that didn't verify would
	// not.
	_, err := iw.m.RestoreSandbox(context.Background(), SandboxOptions{Name: "v", Remove: true}, dir)
	if _, ok := errors.AsType[*SandboxVerifyError](err); !ok {
		t.Errorf("err = %v, want a verify failure", err)
	}
}
