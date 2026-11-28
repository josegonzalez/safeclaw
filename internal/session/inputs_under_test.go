package session

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

// newUnderWorld is an inputs world with the fixed clock of the name
// prefix tests, whose output is returned.
func newUnderWorld(t *testing.T) (*inputsWorld, *bytes.Buffer) {
	t.Helper()
	iw := newInputsWorld(t)
	iw.m.Now = func() time.Time { return at }
	out := &bytes.Buffer{}
	iw.m.Out = out
	return iw, out
}

// onRun runs hook before each docker run the world answers, with the
// container name it was given.
func (iw *inputsWorld) onRun(hook func(container string)) {
	next := iw.r.Handler
	iw.r.Handler = func(args []string, stdin string) ([]byte, error) {
		if args[0] == "run" {
			hook(args[slices.Index(args, "--name")+1])
		}
		return next(args, stdin)
	}
}

// entries returns the names in dir.
func entries(t *testing.T, dir string) []string {
	t.Helper()
	es, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range es {
		names = append(names, e.Name())
	}
	return names
}

// startedRecord checks that dir is a mode 0700 directory holding a new,
// empty record, and that a sandbox was run labelled with it.
func startedRecord(t *testing.T, iw *inputsWorld, dir string) {
	t.Helper()
	if fi, err := os.Lstat(dir); err != nil || !fi.IsDir() || fi.Mode().Perm() != 0o700 {
		t.Errorf("record directory %s = %v, %v, want a mode 0700 directory", dir, fi, err)
	}
	if rec := readRecord(t, dir); len(rec.Files) != 0 || len(rec.Opens) != 0 {
		t.Errorf("new record = %+v", rec)
	}
	found := false
	for _, c := range iw.r.Calls {
		if c.Args[0] == "run" && strings.Contains(c.String(), " --label safeclaw.keep-inputs="+dir+" ") {
			found = true
		}
	}
	if !found {
		t.Errorf("no docker run labelled with %s: %v", dir, iw.r.Commands())
	}
}

func TestKeepInputsUnderNamePrefix(t *testing.T) {
	iw, out := newUnderWorld(t)
	parent := filepath.Join(t.TempDir(), "triage", "jobs")
	ctx := context.Background()

	res, err := iw.m.KeepInputsUnder(ctx, SandboxOptions{NamePrefix: "triage", Remove: true}, parent)
	if err != nil {
		t.Fatal(err)
	}
	if res.Name != "triage-20261128-110940" {
		t.Errorf("name = %q", res.Name)
	}
	dir := filepath.Join(parent, res.Name)
	startedRecord(t, iw, dir)
	if fi, err := os.Stat(parent); err != nil || fi.Mode().Perm() != 0o700 {
		t.Errorf("DIR = %v, %v, want created mode 0700", fi, err)
	}
	if want := "Recording its inputs in " + filepath.Join(dir, InputsFile) + "\n"; !strings.Contains(out.String(), want) {
		t.Errorf("output = %q, want %q", out.String(), want)
	}

	// cp-in records to DIR/NAME, which --restore-from takes as it is.
	file := writeFile(t, filepath.Join(t.TempDir(), "mail.eml"), "mail")
	if _, err := iw.m.CopyIn(ctx, res.Name, []string{file}, ""); err != nil {
		t.Fatal(err)
	}
	if rec := readRecord(t, dir); len(rec.Files) != 1 || rec.Files[0].Source != file {
		t.Errorf("record = %+v", rec)
	}
	delete(iw.w.containers, res.Container)
	restored, err := iw.m.RestoreSandbox(ctx, SandboxOptions{Name: "again", Remove: true}, dir)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(restored.Files, []string{"/sandbox/in/1-mail.eml"}) {
		t.Errorf("restored %v", restored.Files)
	}
}

// Two runs in the same second never share a record directory: the second
// gets the next suffix for its name, and its directory with it, whether
// the first one's container is seen before docker run or docker refuses
// the name, and only the name docker accepted gets a directory.
func TestKeepInputsUnderNamePrefixRace(t *testing.T) {
	ctx := context.Background()
	opts := SandboxOptions{NamePrefix: "triage", Remove: true}

	t.Run("seen", func(t *testing.T) {
		iw, _ := newUnderWorld(t)
		parent := privateDir(t)
		a, err := iw.m.KeepInputsUnder(ctx, opts, parent)
		if err != nil {
			t.Fatal(err)
		}
		b, err := iw.m.KeepInputsUnder(ctx, opts, parent)
		if err != nil {
			t.Fatal(err)
		}
		if a.Name != "triage-20261128-110940" || b.Name != "triage-20261128-110940-2" {
			t.Errorf("names = %q, %q", a.Name, b.Name)
		}
		startedRecord(t, iw, filepath.Join(parent, a.Name))
		startedRecord(t, iw, filepath.Join(parent, b.Name))
		if got := entries(t, parent); !slices.Equal(got, []string{a.Name, b.Name}) {
			t.Errorf("DIR holds %v", got)
		}
	})
	t.Run("docker refuses the name", func(t *testing.T) {
		iw, out := newUnderWorld(t)
		iw.w.runErrs = []runErr{{err: nameConflict("safeclaw-triage-20261128-110940")}}
		parent := privateDir(t)
		res, err := iw.m.KeepInputsUnder(ctx, opts, parent)
		if err != nil {
			t.Fatal(err)
		}
		if res.Name != "triage-20261128-110940-2" {
			t.Errorf("name = %q", res.Name)
		}
		if got := entries(t, parent); !slices.Equal(got, []string{res.Name}) {
			t.Errorf("DIR holds %v, want only the accepted name's directory", got)
		}
		startedRecord(t, iw, filepath.Join(parent, res.Name))
		if hasCall(iw.r, "rm ") {
			t.Errorf("the container that won the name was removed: %v", iw.r.Commands())
		}
		if !strings.Contains(out.String(), "Name taken meanwhile: safeclaw-triage-20261128-110940\n") {
			t.Errorf("output = %q", out.String())
		}
	})
	t.Run("record already there", func(t *testing.T) {
		// A record left by an earlier sandbox of that name, whose
		// container is gone, takes the name before docker run.
		iw, out := newUnderWorld(t)
		parent := privateDir(t)
		if _, err := iw.m.KeepInputs(ctx, SandboxOptions{Name: "old", Remove: true}, filepath.Join(parent, "triage-20261128-110940")); err != nil {
			t.Fatal(err)
		}
		res, err := iw.m.KeepInputsUnder(ctx, opts, parent)
		if err != nil {
			t.Fatal(err)
		}
		if res.Name != "triage-20261128-110940-2" {
			t.Errorf("name = %q", res.Name)
		}
		if got := runNames(iw.r); slices.Contains(got, "safeclaw-triage-20261128-110940") {
			t.Errorf("docker run was tried for the name a record has: %q", got)
		}
		if !strings.Contains(out.String(), "Name taken by a record: "+filepath.Join(parent, "triage-20261128-110940")+"\n") {
			t.Errorf("output = %q", out.String())
		}
	})
	t.Run("record made meanwhile", func(t *testing.T) {
		// A record that appears between the check and docker run removes
		// the new sandbox, leaves the record alone, and tries the next
		// suffix.
		iw, _ := newUnderWorld(t)
		parent := privateDir(t)
		first := filepath.Join(parent, "triage-20261128-110940")
		iw.onRun(func(container string) {
			if container == "safeclaw-triage-20261128-110940" {
				if err := os.Mkdir(first, 0o700); err != nil {
					t.Fatal(err)
				}
				if err := writeInputs(first, &inputRecord{Schema: InputsSchema}); err != nil {
					t.Fatal(err)
				}
			}
		})
		res, err := iw.m.KeepInputsUnder(ctx, opts, parent)
		if err != nil {
			t.Fatal(err)
		}
		if res.Name != "triage-20261128-110940-2" {
			t.Errorf("name = %q", res.Name)
		}
		if !hasCall(iw.r, "rm -v -f safeclaw-triage-20261128-110940") {
			t.Errorf("the sandbox whose record was taken was not removed: %v", iw.r.Commands())
		}
		if _, ok := iw.w.containers["safeclaw-triage-20261128-110940-2"]; !ok {
			t.Error("the -2 sandbox is gone")
		}
		if _, err := readInputs(first); err != nil {
			t.Errorf("the other record was touched: %v", err)
		}
		startedRecord(t, iw, filepath.Join(parent, res.Name))
	})
}

func TestKeepInputsUnderRandomName(t *testing.T) {
	iw, _ := newUnderWorld(t)
	parent := privateDir(t)
	res, err := iw.m.KeepInputsUnder(context.Background(), SandboxOptions{Remove: true}, parent)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.Name, oneOffPrefix) {
		t.Errorf("name = %q, want a random one", res.Name)
	}
	startedRecord(t, iw, filepath.Join(parent, res.Name))
}

func TestKeepInputsUnderName(t *testing.T) {
	iw, _ := newUnderWorld(t)
	parent := privateDir(t)
	ctx := context.Background()
	res, err := iw.m.KeepInputsUnder(ctx, SandboxOptions{Name: "job", Remove: true}, parent)
	if err != nil {
		t.Fatal(err)
	}
	startedRecord(t, iw, filepath.Join(parent, "job"))

	// The same name again, once the sandbox is gone, finds its record and
	// is refused before docker run, as --keep-inputs is.
	delete(iw.w.containers, res.Container)
	before := len(runNames(iw.r))
	if _, err := iw.m.KeepInputsUnder(ctx, SandboxOptions{Name: "job", Remove: true}, parent); !errors.Is(err, errHoldsRecord) || !strings.Contains(err.Error(), "--restore-from") {
		t.Errorf("err = %v, want the record refused", err)
	}
	if len(runNames(iw.r)) != before {
		t.Errorf("docker run was called: %v", iw.r.Commands())
	}
}

func TestKeepInputsUnderDir(t *testing.T) {
	ctx := context.Background()
	opts := SandboxOptions{Name: "job", Remove: true}
	noRun := func(t *testing.T, iw *inputsWorld) {
		t.Helper()
		if _, ok := iw.r.Find("run "); ok {
			t.Errorf("a sandbox was created: %v", iw.r.Commands())
		}
	}

	t.Run("link", func(t *testing.T) {
		iw, _ := newUnderWorld(t)
		target := privateDir(t)
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		if _, err := iw.m.KeepInputsUnder(ctx, opts, link); !errors.Is(err, ErrSymlink) {
			t.Errorf("err = %v, want a link refused", err)
		}
		noRun(t, iw)
		if got := entries(t, target); len(got) != 0 {
			t.Errorf("wrote through the link: %v", got)
		}
	})
	t.Run("writable by others", func(t *testing.T) {
		for _, mode := range []os.FileMode{0o770, 0o702, 0o777} {
			iw, _ := newUnderWorld(t)
			parent := privateDir(t)
			if err := os.Chmod(parent, mode); err != nil {
				t.Fatal(err)
			}
			if _, err := iw.m.KeepInputsUnder(ctx, opts, parent); err == nil || !strings.Contains(err.Error(), "writable by others") {
				t.Errorf("mode %04o: err = %v", mode, err)
			}
			noRun(t, iw)
		}
	})
	t.Run("readable by others", func(t *testing.T) {
		iw, _ := newUnderWorld(t)
		parent := privateDir(t)
		if err := os.Chmod(parent, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := iw.m.KeepInputsUnder(ctx, opts, parent); err != nil {
			t.Fatal(err)
		}
		startedRecord(t, iw, filepath.Join(parent, "job"))
	})
	t.Run("a file", func(t *testing.T) {
		iw, _ := newUnderWorld(t)
		file := writeFile(t, filepath.Join(t.TempDir(), "f"), "x")
		if _, err := iw.m.KeepInputsUnder(ctx, opts, file); err == nil {
			t.Error("a file was taken as DIR")
		}
		noRun(t, iw)
	})
	t.Run("DIR/NAME a link", func(t *testing.T) {
		iw, _ := newUnderWorld(t)
		parent, target := privateDir(t), privateDir(t)
		if err := os.Symlink(target, filepath.Join(parent, "job")); err != nil {
			t.Fatal(err)
		}
		if _, err := iw.m.KeepInputsUnder(ctx, opts, parent); !errors.Is(err, ErrSymlink) {
			t.Errorf("err = %v, want a link refused", err)
		}
		noRun(t, iw)
		if got := entries(t, target); len(got) != 0 {
			t.Errorf("wrote through the link: %v", got)
		}
	})
	t.Run("DIR/NAME open to others", func(t *testing.T) {
		iw, _ := newUnderWorld(t)
		parent := privateDir(t)
		if err := os.Mkdir(filepath.Join(parent, "job"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(parent, "job"), 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := iw.m.KeepInputsUnder(ctx, opts, parent); err == nil || !strings.Contains(err.Error(), "must be 0700") {
			t.Errorf("err = %v", err)
		}
		noRun(t, iw)
	})
	t.Run("DIR/NAME empty", func(t *testing.T) {
		// An existing, empty record directory is used, as --keep-inputs
		// uses one.
		iw, _ := newUnderWorld(t)
		parent := privateDir(t)
		if err := os.Mkdir(filepath.Join(parent, "job"), 0o700); err != nil {
			t.Fatal(err)
		}
		if _, err := iw.m.KeepInputsUnder(ctx, opts, parent); err != nil {
			t.Fatal(err)
		}
		startedRecord(t, iw, filepath.Join(parent, "job"))
	})
	t.Run("not one-off", func(t *testing.T) {
		iw, _ := newUnderWorld(t)
		if _, err := iw.m.KeepInputsUnder(ctx, SandboxOptions{Name: "job"}, privateDir(t)); err == nil {
			t.Error("--keep-inputs-under without --rm was taken")
		}
	})
}

func TestKeepInputsUnderCreateFails(t *testing.T) {
	ctx := context.Background()

	t.Run("sandbox not created", func(t *testing.T) {
		iw, _ := newUnderWorld(t)
		iw.w.image = ""
		parent := privateDir(t)
		if _, err := iw.m.KeepInputsUnder(ctx, SandboxOptions{NamePrefix: "triage", Remove: true}, parent); err == nil {
			t.Fatal("no image, yet created")
		}
		if got := entries(t, parent); len(got) != 0 {
			t.Errorf("DIR holds %v", got)
		}
	})
	t.Run("record can't be started", func(t *testing.T) {
		// When the record can't be started once the container exists, the
		// container is removed and nothing is left in DIR.
		iw, _ := newUnderWorld(t)
		parent := privateDir(t)
		ctx, cancel := context.WithCancel(ctx)
		iw.onRun(func(string) { cancel() })
		_, err := iw.m.KeepInputsUnder(ctx, SandboxOptions{NamePrefix: "triage", Remove: true}, parent)
		if err == nil || !strings.Contains(err.Error(), `so sandbox "triage-20261128-110940" was removed`) {
			t.Errorf("err = %v", err)
		}
		if !hasCall(iw.r, "rm -v -f safeclaw-triage-20261128-110940") {
			t.Errorf("the sandbox was not removed: %v", iw.r.Commands())
		}
		if len(iw.w.containers) != 0 {
			t.Errorf("containers left: %v", iw.w.containers)
		}
		if got := entries(t, parent); len(got) != 0 {
			t.Errorf("DIR holds %v", got)
		}
	})
	t.Run("DIR/NAME taken by a file", func(t *testing.T) {
		iw, _ := newUnderWorld(t)
		parent := privateDir(t)
		iw.onRun(func(string) { writeFile(t, filepath.Join(parent, "job"), "x") })
		_, err := iw.m.KeepInputsUnder(ctx, SandboxOptions{Name: "job", Remove: true}, parent)
		if !errors.Is(err, ErrInputs) || !strings.Contains(err.Error(), `so sandbox "job" was removed`) {
			t.Errorf("err = %v", err)
		}
		if len(iw.w.containers) != 0 {
			t.Errorf("containers left: %v", iw.w.containers)
		}
	})
	t.Run("verify fails", func(t *testing.T) {
		// A sandbox removed by a failed --verify after its record was
		// started takes the record, and the directory made for it, too.
		w := newVerifyWorld(nil)
		w.bad = true
		m, _, _ := newVerifyManager(t, w)
		m.Now = func() time.Time { return at }
		parent := privateDir(t)
		_, err := m.KeepInputsUnder(ctx, SandboxOptions{NamePrefix: "triage", Remove: true, Verify: true}, parent)
		var ve *SandboxVerifyError
		if !errors.As(err, &ve) {
			t.Fatalf("err = %v, want a failed verify", err)
		}
		if got := entries(t, parent); len(got) != 0 {
			t.Errorf("DIR holds %v", got)
		}
	})
}
