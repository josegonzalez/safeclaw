package expand

import (
	"context"
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"
)

// rerun runs Run on dest, which an earlier run made, and checks the
// manifest it returns is the one it wrote.
func rerun(t *testing.T, f *fakeRunner, dest string, o Options, inputs ...string) *Manifest {
	t.Helper()
	m, err := runErr(t, f, dest, o, inputs...)
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
	return m
}

func runErr(t *testing.T, f *fakeRunner, dest string, o Options, inputs ...string) (*Manifest, error) {
	t.Helper()
	if o.MaxSize == 0 {
		o.MaxSize = DefaultMaxSize
	}
	if f != nil {
		o.Runner = f
	}
	o.PollInterval = time.Millisecond
	return Run(t.Context(), inputs, dest, o)
}

// snapshot is every path under dir with its type, and a file's content or
// a link's target, so a test can check a run changed nothing.
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		switch {
		case d.Type()&fs.ModeSymlink != 0:
			target, err := os.Readlink(p)
			out[rel] = "link " + target
			return err
		case d.IsDir():
			out[rel] = "dir"
		default:
			b, err := os.ReadFile(p)
			out[rel] = "file " + string(b)
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func checkUnchanged(t *testing.T, name, dest string, before map[string]string) {
	t.Helper()
	if after := snapshot(t, dest); !reflect.DeepEqual(after, before) {
		var diff []string
		for k, v := range after {
			if before[k] != v {
				diff = append(diff, "+ "+k)
			}
		}
		for k := range before {
			if _, ok := after[k]; !ok {
				diff = append(diff, "- "+k)
			}
		}
		slices.Sort(diff)
		t.Errorf("%s: dest changed:\n%s", name, strings.Join(diff, "\n"))
	}
}

// TestResumePasswordRetry checks that a rerun with a password opens the
// containers that needed one, at every level, keeps the rest as they are,
// and opens new inputs, without copying an input given again.
func TestResumePasswordRetry(t *testing.T) {
	f := &fakeRunner{archives: map[string]fakeArchive{
		"1-enc.zip":   {files: map[string]string{"secret.txt": "s", "deeper.zip": zipHead}, password: "pw"},
		"deeper.zip":  {files: map[string]string{"d.txt": "d"}, password: "pw"},
		"2-good.zip":  {files: map[string]string{"inner.zip": zipHead, "x.txt": "x"}},
		"inner.zip":   {files: map[string]string{"i.txt": "i"}, password: "pw"},
		"3-links.zip": {files: map[string]string{"l": "symlink:/etc/passwd"}},
		"4-new.zip":   {files: map[string]string{"n.txt": "n"}},
	}}
	in := writeInputs(t, "enc.zip", zipHead+"1", "good.zip", zipHead+"2", "links.zip", zipHead+"3")
	dest, m := run(t, f, Options{Depth: 3}, in...)
	checkSummary(t, m, []string{
		"1-enc.zip zip 0 NEEDS-PASSWORD",
		"2-good.zip zip 0 UNPACKED -> 2-good.zip.unpacked",
		"2-good.zip.unpacked/inner.zip zip 1 NEEDS-PASSWORD",
		"3-links.zip zip 0 REJECTED",
	})
	links := m.Containers[3]

	// A rerun with no password changes nothing but the record.
	m = rerun(t, f, dest, Options{Depth: 3})
	checkSummary(t, m, []string{
		"1-enc.zip zip 0 NEEDS-PASSWORD",
		"2-good.zip zip 0 UNPACKED -> 2-good.zip.unpacked",
		"2-good.zip.unpacked/inner.zip zip 1 NEEDS-PASSWORD",
		"3-links.zip zip 0 REJECTED",
	})

	pw := "pw"
	newIn := writeInputs(t, "new.zip", zipHead+"4")
	m = rerun(t, f, dest, Options{Depth: 3, Password: &pw}, append(in, newIn...)...)
	checkSummary(t, m, []string{
		"1-enc.zip zip 0 UNPACKED -> 1-enc.zip.unpacked",
		"2-good.zip zip 0 UNPACKED -> 2-good.zip.unpacked",
		"2-good.zip.unpacked/inner.zip zip 1 UNPACKED -> 2-good.zip.unpacked/inner.zip.unpacked",
		"3-links.zip zip 0 REJECTED",
		"1-enc.zip.unpacked/deeper.zip zip 1 UNPACKED -> 1-enc.zip.unpacked/deeper.zip.unpacked",
		"4-new.zip zip 0 UNPACKED -> 4-new.zip.unpacked",
	})
	if c := m.Containers[0]; c.Code != 0 || c.Error != "" {
		t.Errorf("retried record keeps its failure: %+v", c)
	}
	if !reflect.DeepEqual(m.Containers[3], links) {
		t.Errorf("rejected record changed: %+v", m.Containers[3])
	}
	if got := readFile(t, filepath.Join(dest, "1-enc.zip.unpacked/deeper.zip.unpacked/d.txt")); got != "d" {
		t.Errorf("d.txt = %q", got)
	}
	var paths []string
	for _, in := range m.Inputs {
		paths = append(paths, in.Path)
	}
	if !slices.Equal(paths, []string{"1-enc.zip", "2-good.zip", "3-links.zip", "4-new.zip"}) {
		t.Errorf("inputs = %v", paths)
	}
	if !m.Options.Password {
		t.Error("options.password not set")
	}

	// A rerun with nothing left to do keeps everything.
	before := snapshot(t, dest)
	m2 := rerun(t, f, dest, Options{Depth: 3}, in...)
	delete(before, ManifestFile)
	after := snapshot(t, dest)
	delete(after, ManifestFile)
	if !reflect.DeepEqual(before, after) || len(m2.Containers) != len(m.Containers) {
		t.Errorf("an idle rerun changed dest")
	}
}

// TestResumeSkip checks --skip and --unskip, for inputs and for nested
// containers not found yet, and that skips are remembered.
func TestResumeSkip(t *testing.T) {
	f := &fakeRunner{archives: map[string]fakeArchive{
		"1-a.zip":   {files: map[string]string{"a.txt": "a"}},
		"1-b.zip":   {files: map[string]string{"inner.zip": zipHead, "other.zip": zipHead}},
		"2-b.zip":   {files: map[string]string{"inner.zip": zipHead, "other.zip": zipHead}},
		"inner.zip": {files: map[string]string{"i.txt": "i"}},
		"other.zip": {files: map[string]string{"o.txt": "o"}},
		"3-enc.zip": {files: map[string]string{"e.txt": "e"}, password: "pw"},
	}}
	in := writeInputs(t, "a.zip", zipHead+"a", "b.zip", zipHead+"b", "enc.zip", zipHead+"e")
	dest := newDest(t)
	m := rerun(t, f, dest, Options{Depth: 3, Skip: []string{"1-a.zip", "2-b.zip.unpacked/inner.zip", "9-never.zip"}}, in...)
	checkSummary(t, m, []string{
		"1-a.zip zip 0 SKIPPED",
		"2-b.zip zip 0 UNPACKED -> 2-b.zip.unpacked",
		"2-b.zip.unpacked/inner.zip zip 1 SKIPPED",
		"2-b.zip.unpacked/other.zip zip 1 UNPACKED -> 2-b.zip.unpacked/other.zip.unpacked",
		"3-enc.zip zip 0 NEEDS-PASSWORD",
	})
	if !slices.Equal(m.Skip, []string{"1-a.zip", "2-b.zip.unpacked/inner.zip", "9-never.zip"}) {
		t.Errorf("skip = %v", m.Skip)
	}
	if _, err := os.Lstat(filepath.Join(dest, "1-a.zip.unpacked")); err == nil {
		t.Error("skipped input opened")
	}

	// Skips are remembered, and a container that needs a password can be
	// skipped instead of retried.
	pw := "pw"
	m = rerun(t, f, dest, Options{Depth: 3, Password: &pw, Skip: []string{"3-enc.zip"}})
	checkSummary(t, m, []string{
		"1-a.zip zip 0 SKIPPED",
		"2-b.zip zip 0 UNPACKED -> 2-b.zip.unpacked",
		"2-b.zip.unpacked/inner.zip zip 1 SKIPPED",
		"2-b.zip.unpacked/other.zip zip 1 UNPACKED -> 2-b.zip.unpacked/other.zip.unpacked",
		"3-enc.zip zip 0 SKIPPED",
	})
	if c := m.Containers[4]; c.Code != 0 || c.Error != "" {
		t.Errorf("skipped record keeps its failure: %+v", c)
	}

	// Usage errors change nothing.
	before := snapshot(t, dest)
	for name, o := range map[string]Options{
		"skip an opened one":     {Depth: 3, Skip: []string{"2-b.zip"}},
		"unskip one not skipped": {Depth: 3, Unskip: []string{"2-b.zip.unpacked/other.zip"}},
		"skip and unskip":        {Depth: 3, Skip: []string{"1-a.zip"}, Unskip: []string{"1-a.zip"}},
		"skip outside":           {Depth: 3, Skip: []string{"../x"}},
	} {
		if _, err := runErr(t, f, dest, o); err == nil {
			t.Errorf("%s: no error", name)
		}
		checkUnchanged(t, name, dest, before)
	}

	m = rerun(t, f, dest, Options{Depth: 3, Password: &pw, Unskip: []string{"1-a.zip", "3-enc.zip", "2-b.zip.unpacked/inner.zip"}})
	checkSummary(t, m, []string{
		"1-a.zip zip 0 UNPACKED -> 1-a.zip.unpacked",
		"2-b.zip zip 0 UNPACKED -> 2-b.zip.unpacked",
		"2-b.zip.unpacked/inner.zip zip 1 UNPACKED -> 2-b.zip.unpacked/inner.zip.unpacked",
		"2-b.zip.unpacked/other.zip zip 1 UNPACKED -> 2-b.zip.unpacked/other.zip.unpacked",
		"3-enc.zip zip 0 UNPACKED -> 3-enc.zip.unpacked",
	})
	if !slices.Equal(m.Skip, []string{"9-never.zip"}) {
		t.Errorf("skip = %v", m.Skip)
	}

	// An input skipped before it is given.
	dest2 := newDest(t)
	rerun(t, f, dest2, Options{Depth: 3}, in[0])
	m = rerun(t, f, dest2, Options{Depth: 3, Skip: []string{"2-b.zip"}}, in[1])
	checkSummary(t, m, []string{
		"1-a.zip zip 0 UNPACKED -> 1-a.zip.unpacked",
		"2-b.zip zip 0 SKIPPED",
	})
	// A container past the depth limit stays DEPTH-LIMIT when skipped.
	_, m = run(t, f, Options{Depth: 0, Skip: []string{"1-b.zip.unpacked/inner.zip"}}, in[1])
	checkSummary(t, m, []string{
		"1-b.zip zip 0 UNPACKED -> 1-b.zip.unpacked",
		"1-b.zip.unpacked/inner.zip zip 1 DEPTH-LIMIT",
		"1-b.zip.unpacked/other.zip zip 1 DEPTH-LIMIT",
	})
}

// TestResumeBudget checks that --max-size counts what is already in the
// destination, measured on disk, so reruns can't go past it.
func TestResumeBudget(t *testing.T) {
	part := strings.Repeat("x", 400)
	f := &fakeRunner{archives: map[string]fakeArchive{
		"1-a.zip": {files: map[string]string{"a": part}},
		"2-b.zip": {files: map[string]string{"b": part + part}},
		"3-c.zip": {files: map[string]string{"c": part}},
	}}
	in := writeInputs(t, "a.zip", zipHead+"a", "b.zip", zipHead+"b")
	dest, m := run(t, f, Options{Depth: 3, MaxSize: 1000}, in...)
	checkSummary(t, m, []string{"1-a.zip zip 0 UNPACKED -> 1-a.zip.unpacked", "2-b.zip zip 0 TOO-LARGE"})

	// The same limit again: 400 used, 600 left, still too large.
	m = rerun(t, f, dest, Options{Depth: 3, MaxSize: 1000})
	if m.Containers[1].Outcome != OutcomeTooLarge || m.Size != 400 {
		t.Errorf("same limit: %+v, size %d", m.Containers[1], m.Size)
	}
	// A new input fills the rest.
	m = rerun(t, f, dest, Options{Depth: 3, MaxSize: 1000}, writeInputs(t, "c.zip", zipHead+"c")...)
	if m.Containers[2].Outcome != OutcomeUnpacked || m.Size != 800 {
		t.Errorf("new input: %+v, size %d", m.Containers[2], m.Size)
	}
	// What code in the sandbox added counts too.
	if err := os.WriteFile(filepath.Join(dest, "1-a.zip.unpacked", "extra"), []byte(strings.Repeat("y", 300)), 0o644); err != nil {
		t.Fatal(err)
	}
	m = rerun(t, f, dest, Options{Depth: 3, MaxSize: 1700})
	if m.Containers[1].Outcome != OutcomeTooLarge || m.Size != 1100 {
		t.Errorf("with extra: %+v, size %d", m.Containers[1], m.Size)
	}
	// And a smaller recorded size doesn't help.
	editManifest(t, dest, func(m map[string]any) { m["size"] = 0 })
	m = rerun(t, f, dest, Options{Depth: 3, MaxSize: 1700})
	if m.Containers[1].Outcome != OutcomeTooLarge || m.Size != 1100 {
		t.Errorf("tampered size: %+v, size %d", m.Containers[1], m.Size)
	}
	m = rerun(t, f, dest, Options{Depth: 3, MaxSize: 1900})
	if m.Containers[1].Outcome != OutcomeUnpacked || m.Size != 1900 {
		t.Errorf("larger limit: %+v, size %d", m.Containers[1], m.Size)
	}
}

// TestResumeOptions checks that the depth limit and --no-mail are the
// destination's, and that the first-run rules still hold.
func TestResumeOptions(t *testing.T) {
	f := &fakeRunner{archives: map[string]fakeArchive{"1-a.zip": {files: map[string]string{"a": "a"}, password: "pw"}}}
	in := writeInputs(t, "a.zip", zipHead)
	dest, _ := run(t, f, Options{Depth: 2}, in...)
	before := snapshot(t, dest)
	for name, o := range map[string]Options{
		"depth":   {Depth: 3},
		"no mail": {Depth: 2, NoMail: true},
	} {
		if _, err := runErr(t, f, dest, o); err == nil || !strings.Contains(err.Error(), "a later run keeps") {
			t.Errorf("%s: err = %v", name, err)
		}
		checkUnchanged(t, name, dest, before)
	}
	// Without a manifest, DEST must still be empty.
	if err := os.Remove(filepath.Join(dest, ManifestFile)); err != nil {
		t.Fatal(err)
	}
	if _, err := runErr(t, f, dest, Options{Depth: 2}, in...); err == nil || !strings.Contains(err.Error(), "not empty") {
		t.Errorf("no manifest: err = %v", err)
	}
	// And with no inputs there is nothing to do.
	if _, err := runErr(t, f, newDest(t), Options{Depth: 2}); err == nil {
		t.Error("no inputs and no manifest accepted")
	}
	// Nothing is skipped before a first run, and DEST isn't made.
	missing := newDest(t)
	if _, err := runErr(t, f, missing, Options{Depth: 2, Unskip: []string{"1-a.zip"}}, in...); err == nil || !strings.Contains(err.Error(), "not skipped") {
		t.Errorf("unskip on a first run: err = %v", err)
	}
	if _, err := os.Lstat(missing); err == nil {
		t.Error("dest made")
	}
}

// TestResumeFailureKeepsDest checks that a rerun that fails removes what it
// added and leaves the manifest as it was.
func TestResumeFailureKeepsDest(t *testing.T) {
	f := &fakeRunner{archives: map[string]fakeArchive{
		"1-a.zip": {files: map[string]string{"a": "a", "n.zip": zipHead}, password: "pw"},
		"n.zip":   {files: map[string]string{"n": "n"}},
		"2-b.zip": {files: map[string]string{"b": "b", "c.zip": zipHead}},
		"c.zip":   {files: map[string]string{"c": "c"}, block: true},
	}}
	in := writeInputs(t, "a.zip", zipHead+"a")
	dest, _ := run(t, f, Options{Depth: 3}, in...)
	before := snapshot(t, dest)

	// Interrupted while an archive in a new input extracts, after the
	// retried one and its nested one were opened.
	ctx, cancel := context.WithCancel(t.Context())
	time.AfterFunc(50*time.Millisecond, cancel)
	pw := "pw"
	_, err := Run(ctx, writeInputs(t, "b.zip", zipHead+"b"), dest, Options{Runner: f, MaxSize: 1000, Depth: 3, Password: &pw, PollInterval: time.Millisecond})
	if err == nil || !strings.HasPrefix(err.Error(), "interrupted") {
		t.Fatalf("err = %v", err)
	}
	checkUnchanged(t, "interrupted", dest, before)

	// A new input that can't be copied in, since code in the sandbox took
	// its name, fails the run without touching that file.
	if err := os.WriteFile(filepath.Join(dest, "2-b.zip"), []byte("theirs"), 0o644); err != nil {
		t.Fatal(err)
	}
	before = snapshot(t, dest)
	if _, err := runErr(t, f, dest, Options{Depth: 3, Password: &pw}, writeInputs(t, "b.zip", zipHead+"b")...); err == nil {
		t.Fatal("no error")
	}
	checkUnchanged(t, "name taken", dest, before)
}

// TestResumeLocked checks that two runs never share a destination.
func TestResumeLocked(t *testing.T) {
	dest, _ := run(t, nil, Options{}, writeInputs(t, "a.txt", "a")...)
	d, err := os.Open(dest)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if err := syscall.Flock(int(d.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	if _, err := runErr(t, nil, dest, Options{}); err == nil || !strings.Contains(err.Error(), "another run") {
		t.Errorf("err = %v", err)
	}
	if _, err := Plan(t.Context(), nil, dest, Options{}); err == nil || !strings.Contains(err.Error(), "another run") {
		t.Errorf("plan err = %v", err)
	}
}

// editManifest changes dest's manifest as JSON.
func editManifest(t *testing.T, dest string, edit func(m map[string]any)) {
	t.Helper()
	p := filepath.Join(dest, ManifestFile)
	var m map[string]any
	if err := json.Unmarshal([]byte(readFile(t, p)), &m); err != nil {
		t.Fatal(err)
	}
	edit(m)
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, b, 0o644); err != nil {
		t.Fatal(err)
	}
}

func containerAt(m map[string]any, i int) map[string]any {
	return m["containers"].([]any)[i].(map[string]any)
}

// TestResumeTampered checks that a rerun refuses a manifest or a tree
// that code in the sandbox changed, and changes nothing.
func TestResumeTampered(t *testing.T) {
	f := &fakeRunner{archives: map[string]fakeArchive{
		"1-a.zip": {files: map[string]string{"n.zip": zipHead, "x.txt": "x"}},
		"n.zip":   {files: map[string]string{"n": "n"}, password: "pw"},
		"2-b.zip": {files: map[string]string{"b": "b"}, password: "pw"},
		"3-c.zip": {files: map[string]string{"c": "c"}},
	}}
	in := writeInputs(t, "a.zip", zipHead+"a", "b.zip", zipHead+"b", "c.zip", zipHead+"c")
	setup := func() string {
		dest, m := run(t, f, Options{Depth: 3}, in...)
		checkSummary(t, m, []string{
			"1-a.zip zip 0 UNPACKED -> 1-a.zip.unpacked",
			"1-a.zip.unpacked/n.zip zip 1 NEEDS-PASSWORD",
			"2-b.zip zip 0 NEEDS-PASSWORD",
			"3-c.zip zip 0 UNPACKED -> 3-c.zip.unpacked",
		})
		return dest
	}
	outside := t.TempDir()
	cases := map[string]func(dest string){
		"container outside": func(dest string) {
			editManifest(t, dest, func(m map[string]any) { containerAt(m, 1)["path"] = "../../../x/n.zip" })
		},
		"input outside": func(dest string) {
			editManifest(t, dest, func(m map[string]any) { m["inputs"].([]any)[0].(map[string]any)["path"] = "../1-a.zip" })
		},
		"input not a copy name": func(dest string) {
			editManifest(t, dest, func(m map[string]any) { m["inputs"].([]any)[0].(map[string]any)["path"] = "1-a.zip.unpacked/n.zip" })
		},
		"absolute skip": func(dest string) {
			editManifest(t, dest, func(m map[string]any) { m["skip"] = []string{"/etc/passwd"} })
		},
		"unpacked dir elsewhere": func(dest string) {
			editManifest(t, dest, func(m map[string]any) { containerAt(m, 0)["unpacked"] = "3-c.zip.unpacked" })
		},
		"child outside its parent": func(dest string) {
			editManifest(t, dest, func(m map[string]any) {
				containerAt(m, 1)["path"] = "3-c.zip.unpacked/c"
			})
		},
		"depth not below parent": func(dest string) {
			editManifest(t, dest, func(m map[string]any) { containerAt(m, 1)["depth"] = 0 })
		},
		"no parent": func(dest string) {
			editManifest(t, dest, func(m map[string]any) { delete(containerAt(m, 1), "parent") })
		},
		"unknown outcome": func(dest string) {
			editManifest(t, dest, func(m map[string]any) { containerAt(m, 2)["outcome"] = "opened" })
		},
		"wrong flag": func(dest string) {
			editManifest(t, dest, func(m map[string]any) { containerAt(m, 2)["flags"] = []string{"UNPACKED"} })
		},
		"extra flag": func(dest string) {
			editManifest(t, dest, func(m map[string]any) { containerAt(m, 2)["flags"] = []string{"NEEDS-PASSWORD", "EVIL"} })
		},
		"skipped without a skip": func(dest string) {
			editManifest(t, dest, func(m map[string]any) {
				containerAt(m, 2)["outcome"] = "skipped"
				containerAt(m, 2)["flags"] = []string{"SKIPPED"}
			})
		},
		"failed status": func(dest string) {
			editManifest(t, dest, func(m map[string]any) { m["status"] = "failed" })
		},
		"other schema": func(dest string) {
			editManifest(t, dest, func(m map[string]any) { m["schema"] = 2 })
		},
		"bad sha256": func(dest string) {
			editManifest(t, dest, func(m map[string]any) { m["inputs"].([]any)[0].(map[string]any)["sha256"] = "nope" })
		},
		"invalid json": func(dest string) {
			if err := os.WriteFile(filepath.Join(dest, ManifestFile), []byte(`{"schema":1,`), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"oversized": func(dest string) {
			b := []byte(readFile(t, filepath.Join(dest, ManifestFile)))
			b = append(b, make([]byte, maxManifestSize)...)
			for i := len(b) - maxManifestSize; i < len(b); i++ {
				b[i] = ' '
			}
			if err := os.WriteFile(filepath.Join(dest, ManifestFile), b, 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"manifest is a link": func(dest string) {
			p := filepath.Join(dest, ManifestFile)
			if err := os.Rename(p, filepath.Join(outside, fmt.Sprint(time.Now().UnixNano()))); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(outside, "nope"), p); err != nil {
				t.Fatal(err)
			}
		},
		"missing packed file": func(dest string) {
			if err := os.Remove(filepath.Join(dest, "2-b.zip")); err != nil {
				t.Fatal(err)
			}
		},
		"packed file is a link": func(dest string) {
			p := filepath.Join(dest, "2-b.zip")
			target := filepath.Join(outside, "b.zip")
			if err := os.WriteFile(target, []byte(zipHead), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, p); err != nil {
				t.Fatal(err)
			}
		},
		"packed file is a directory": func(dest string) {
			p := filepath.Join(dest, "2-b.zip")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(p, 0o755); err != nil {
				t.Fatal(err)
			}
		},
		"packed file changed kind": func(dest string) {
			if err := os.WriteFile(filepath.Join(dest, "2-b.zip"), []byte("just text\n"), 0o644); err != nil {
				t.Fatal(err)
			}
		},
		"symlinked directory": func(dest string) {
			// The nested one's directory is moved out and linked back.
			dir := filepath.Join(dest, "1-a.zip.unpacked")
			moved := filepath.Join(outside, fmt.Sprint(time.Now().UnixNano()))
			if err := os.Rename(dir, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(moved, dir); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, tamper := range cases {
		dest := setup()
		tamper(dest)
		before := snapshot(t, dest)
		outsideBefore := snapshot(t, outside)
		pw := "pw"
		_, err := runErr(t, f, dest, Options{Depth: 3, Password: &pw}, writeInputs(t, "new.zip", zipHead)...)
		if err == nil || !strings.HasPrefix(err.Error(), "refusing to resume") {
			t.Errorf("%s: err = %v", name, err)
		}
		t.Logf("%s: %v", name, err)
		checkUnchanged(t, name, dest, before)
		checkUnchanged(t, name+" (outside)", outside, outsideBefore)
		if _, err := Plan(t.Context(), nil, dest, Options{Depth: 3, Password: &pw}); err == nil {
			t.Errorf("%s: plan accepted it", name)
		}
	}
}

// TestPlan checks that --plan lists what isn't opened yet, and the new
// inputs, without changing anything.
func TestPlan(t *testing.T) {
	f := &fakeRunner{archives: map[string]fakeArchive{
		"1-enc.zip":   {files: map[string]string{"secret.txt": "s"}, password: "pw"},
		"2-links.zip": {files: map[string]string{"l": "symlink:/etc/passwd"}},
		"3-deep.zip":  {files: map[string]string{"d.zip": zipHead}},
		"d.zip":       {files: map[string]string{"x": "x"}},
		"4-skip.zip":  {files: map[string]string{"k": "k"}},
		// A plan lists a new input where it is, outside the destination.
		"new.zip":   {files: map[string]string{"n": "n"}},
		"enc.zip":   {files: map[string]string{"secret.txt": "s"}, password: "pw"},
		"links.zip": {files: map[string]string{"l": "symlink:/etc/passwd"}},
	}}
	big := email("big", strings.Repeat("y", 2000))
	in := writeInputs(t, "enc.zip", zipHead+"1", "links.zip", zipHead+"2", "deep.zip", zipHead+"3", "skip.zip", zipHead+"4")
	dest := newDest(t)
	rerun(t, f, dest, Options{Depth: 0, MaxSize: 1000, Skip: []string{"4-skip.zip"}}, append(in, writeInputs(t, "m.eml", big)...)...)
	before := snapshot(t, dest)

	newIn := writeInputs(t, "new.zip", zipHead+"5", "notes.txt", "notes\n")
	items, err := Plan(t.Context(), append(in[:1:1], newIn...), dest, Options{Runner: f, Depth: 0})
	if err != nil {
		t.Fatal(err)
	}
	checkUnchanged(t, "plan", dest, before)
	var got []string
	for _, it := range items {
		s := it.Path + " " + strings.Join(it.Flags, ",")
		if it.Listed {
			s += " listed"
		}
		for _, e := range it.Entries {
			s += " " + e.Path
		}
		for _, p := range it.Parts {
			s += " " + p.ID
		}
		if it.ListError != "" {
			s += " error"
		}
		got = append(got, s)
	}
	want := []string{
		"1-enc.zip NEEDS-PASSWORD listed secret.txt",
		"2-links.zip REJECTED",
		"3-deep.zip.unpacked/d.zip DEPTH-LIMIT",
		"4-skip.zip SKIPPED listed k",
		"5-m.eml TOO-LARGE listed 1 1.1",
		"6-new.zip NEW listed n",
	}
	if !slices.Equal(got, want) {
		t.Errorf("plan:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if !items[0].Entries[0].Encrypted {
		t.Errorf("entry = %+v", items[0].Entries[0])
	}

	// Without 7z, archives can't be listed.
	items, err = Plan(t.Context(), nil, dest, Options{Depth: 0})
	if err != nil || items[0].ListError == "" || !strings.Contains(items[0].ListError, "7z") {
		t.Errorf("no 7z: %+v, %v", items, err)
	}
	for name, o := range map[string]Options{
		"skip":    {Depth: 0, Skip: []string{"1-enc.zip"}},
		"unskip":  {Depth: 0, Unskip: []string{"4-skip.zip"}},
		"depth":   {Depth: 3},
		"no mail": {Depth: 0, NoMail: true},
	} {
		if _, err := Plan(t.Context(), nil, dest, o); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	checkUnchanged(t, "plan errors", dest, before)

	// A plan for a first run lists the inputs, and makes nothing.
	missing := newDest(t)
	items, err = Plan(t.Context(), in[:2], missing, Options{Runner: f, Depth: 3, Skip: nil})
	if err != nil || len(items) != 2 || items[0].Path != "1-enc.zip" || items[1].Path != "2-links.zip" || !slices.Equal(items[1].Flags, []string{FlagNew}) || items[1].Entries[0].Link != "/etc/passwd" {
		t.Errorf("first plan = %+v, %v", items, err)
	}
	if _, err := os.Lstat(missing); err == nil {
		t.Error("plan made dest")
	}
	if _, err := Plan(t.Context(), nil, missing, Options{Depth: 3}); err == nil {
		t.Error("plan with nothing accepted")
	}
}
