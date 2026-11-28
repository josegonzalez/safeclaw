package expand

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
)

// inputDir writes files, name then content, into a new directory and
// returns it.
func inputDir(t *testing.T, files ...string) string {
	t.Helper()
	dir := t.TempDir()
	for i := 0; i+1 < len(files); i += 2 {
		if err := os.WriteFile(filepath.Join(dir, files[i]), []byte(files[i+1]), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// ignored collects what Options.Ignore is given, as NAME: WHY.
type ignored []string

func (g *ignored) add(p, why string) { *g = append(*g, filepath.Base(p)+": "+why) }

func inputPathsOf(m *Manifest) []string {
	var out []string
	for _, in := range m.Inputs {
		out = append(out, in.Path)
	}
	return out
}

// TestRunDirectory checks that a directory input is every regular file
// directly in it, sorted, that anything else in it is left out unfollowed
// and noted, and that rerunning on the same directory copies only what is
// new.
func TestRunDirectory(t *testing.T) {
	f := &fakeRunner{archives: map[string]fakeArchive{
		"2-b.zip": {files: map[string]string{"x.txt": "x"}},
	}}
	dir := inputDir(t, "b.zip", zipHead, "a.txt", "a")
	outside := writeInputs(t, "secret.txt", "secret")[0]
	if err := os.Symlink(outside, filepath.Join(dir, "link.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "nested.txt"), []byte("n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "fifo"), 0o644); err != nil {
		t.Fatal(err)
	}
	var g ignored
	dest, m := run(t, f, Options{Ignore: g.add}, dir)
	if got, want := inputPathsOf(m), []string{"1-a.txt", "2-b.zip"}; !slices.Equal(got, want) {
		t.Errorf("inputs = %v, want %v", got, want)
	}
	checkSummary(t, m, []string{"2-b.zip zip 0 UNPACKED -> 2-b.zip.unpacked"})
	if want := []string{"fifo: not a regular file", "link.txt: a symbolic link", "sub: a directory"}; !slices.Equal(g, want) {
		t.Errorf("ignored = %v, want %v", g, want)
	}
	for _, p := range []string{"3-link.txt", "3-secret.txt", "3-nested.txt", "3-fifo"} {
		if _, err := os.Lstat(filepath.Join(dest, p)); err == nil {
			t.Errorf("%s copied", p)
		}
	}

	// The same command line again copies nothing, and once a file is added
	// copies only it.
	m = rerun(t, f, dest, Options{}, dir)
	if got := inputPathsOf(m); len(got) != 2 {
		t.Errorf("rerun inputs = %v", got)
	}
	if err := os.WriteFile(filepath.Join(dir, "c.txt"), []byte("c"), 0o644); err != nil {
		t.Fatal(err)
	}
	m = rerun(t, f, dest, Options{}, dir)
	if got, want := inputPathsOf(m), []string{"1-a.txt", "2-b.zip", "3-c.txt"}; !slices.Equal(got, want) {
		t.Errorf("inputs = %v, want %v", got, want)
	}
	// A changed file is a new input, as a file given by name is.
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a2"), 0o644); err != nil {
		t.Fatal(err)
	}
	m = rerun(t, f, dest, Options{}, dir)
	if got := inputPathsOf(m); len(got) != 4 || got[3] != "4-a.txt" {
		t.Errorf("inputs = %v", got)
	}
}

// TestRunDirectoryMixed checks that files and directories given together
// keep their order, that a link to a directory is followed, and that a file
// given by name and found in a directory is copied once.
func TestRunDirectoryMixed(t *testing.T) {
	dir := inputDir(t, "y.txt", "y", "x.txt", "x")
	link := filepath.Join(t.TempDir(), "dirlink")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	first := writeInputs(t, "first.txt", "first")[0]
	_, m := run(t, nil, Options{}, first, link, filepath.Join(dir, "x.txt"))
	if got, want := inputPathsOf(m), []string{"1-first.txt", "2-x.txt", "3-y.txt"}; !slices.Equal(got, want) {
		t.Errorf("inputs = %v, want %v", got, want)
	}
}

// TestRunEmptyDirectory checks that an empty directory is no inputs: a
// first run writes an empty manifest, and the same command line resumes
// from it.
func TestRunEmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	dest, m := run(t, nil, Options{}, dir)
	if len(m.Inputs) != 0 || len(m.Containers) != 0 {
		t.Errorf("manifest = %+v", m)
	}
	if names, err := os.ReadDir(dest); err != nil || len(names) != 1 || names[0].Name() != ManifestFile {
		t.Errorf("dest = %v, %v", names, err)
	}
	m = rerun(t, nil, dest, Options{}, dir)
	if len(m.Inputs) != 0 {
		t.Errorf("rerun = %+v", m)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("a"), 0o644); err != nil {
		t.Fatal(err)
	}
	if m = rerun(t, nil, dest, Options{}, dir); !slices.Equal(inputPathsOf(m), []string{"1-a.txt"}) {
		t.Errorf("inputs = %v", inputPathsOf(m))
	}
	// Naming no inputs at all is still an error without a manifest.
	if _, err := Run(t.Context(), nil, newDest(t), Options{MaxSize: 1}); err == nil {
		t.Error("no inputs accepted")
	}
}

// TestRunDirectoryContainment checks that an input directory that is DEST,
// holds it, or is inside it is refused before anything is made, also
// through links.
func TestRunDirectoryContainment(t *testing.T) {
	o := Options{MaxSize: 1000}
	dir := inputDir(t, "a.txt", "a")
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	for name, dest := range map[string]string{
		"dest is the directory":        dir,
		"dest inside":                  filepath.Join(dir, "out"),
		"dest deeper inside, via link": filepath.Join(link, "a", "b", "out"),
	} {
		if _, err := Run(t.Context(), []string{dir}, dest, o); err == nil || !strings.Contains(err.Error(), "inside the input directory") {
			t.Errorf("%s: %v", name, err)
		}
		if _, err := Plan(t.Context(), []string{dir}, dest, Options{}); err == nil {
			t.Errorf("%s: plan accepted", name)
		}
	}
	if _, err := os.Lstat(filepath.Join(dir, "out")); err == nil {
		t.Error("dest made")
	}

	dest, _ := run(t, nil, Options{}, filepath.Join(dir, "a.txt"))
	sub := filepath.Join(dest, "1-a.txt.d")
	if err := os.Mkdir(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, dest)
	for name, in := range map[string]string{"dest itself": dest, "inside dest": sub} {
		if _, err := runErr(t, nil, dest, Options{}, in); err == nil || !strings.Contains(err.Error(), "is inside") {
			t.Errorf("%s: %v", name, err)
		}
	}
	checkUnchanged(t, "refused", dest, before)
}

// TestOpenSourceInDir checks that a file listed in an input directory is
// opened without following a link, as it was listed, while one given by
// name is followed.
func TestOpenSourceInDir(t *testing.T) {
	target := writeInputs(t, "t.txt", "t")[0]
	link := filepath.Join(t.TempDir(), "l.txt")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if f, err := openSource(source{path: link, inDir: true}); err == nil {
		_ = f.Close()
		t.Error("link in a directory followed")
	}
	f, err := openSource(source{path: link})
	if err != nil {
		t.Fatal(err)
	}
	_ = f.Close()
}

// TestPlanDirectory checks that a plan resolves directories as a run does,
// and that one with only empty directories plans nothing, making nothing.
func TestPlanDirectory(t *testing.T) {
	f := &fakeRunner{archives: map[string]fakeArchive{"b.zip": {files: map[string]string{"x.txt": "x"}}}}
	dir := inputDir(t, "b.zip", zipHead, "a.txt", "a")
	if err := os.Mkdir(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	var g ignored
	dest := newDest(t)
	items, err := Plan(t.Context(), []string{dir}, dest, Options{Runner: f, Ignore: g.add})
	if err != nil || len(items) != 1 || items[0].Path != "2-b.zip" || len(items[0].Entries) != 1 {
		t.Errorf("plan = %+v, %v", items, err)
	}
	if !slices.Equal(g, ignored{"sub: a directory"}) {
		t.Errorf("ignored = %v", g)
	}
	items, err = Plan(t.Context(), []string{t.TempDir()}, dest, Options{})
	if err != nil || len(items) != 0 {
		t.Errorf("empty plan = %+v, %v", items, err)
	}
	if _, err := os.Lstat(dest); err == nil {
		t.Error("plan made dest")
	}
}
