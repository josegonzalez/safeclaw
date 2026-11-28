package expand

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

var holdMail = []string{HoldMailArchives}

// holdTree is a fake 7z and inputs for the hold tests: an email carrying a
// zip that holds another zip and an email carrying a third, and a file that
// only starts like a zip; a message forwarding an email that carries a zip;
// and an input zip holding a zip.
func holdTree(t *testing.T) (*fakeRunner, []string) {
	t.Helper()
	f := &fakeRunner{archives: map[string]fakeArchive{
		"1-files.zip":  {files: map[string]string{"mail.eml": email("m", "m", "deep.zip", zipHead), "sub.zip": zipHead}},
		"sub.zip":      {files: map[string]string{"s.txt": "s"}},
		"1-deep.zip":   {files: map[string]string{"d.txt": "d"}},
		"1-inner.zip":  {files: map[string]string{"i.txt": "i"}},
		"3-top.zip":    {files: map[string]string{"nested.zip": zipHead, "t.txt": "t"}},
		"nested.zip":   {files: map[string]string{"n.txt": "n"}},
		"1-direct.zip": {files: map[string]string{"x.txt": "x"}},
	}}
	return f, writeInputs(t,
		"report.eml", email("report", "see attached", "files.zip", zipHead, "fake.zip", zipHead),
		"fwd.eml", forwarding(email("inner", "inner", "inner.zip", zipHead)),
		"top.zip", zipHead+"top",
	)
}

// TestHoldMailArchives checks that --hold mail-archives leaves every
// archive that came out of an email packed and HELD, a forwarded message's
// included, while emails and archives in archives are opened, and that
// reruns open them only when released.
func TestHoldMailArchives(t *testing.T) {
	f, in := holdTree(t)
	dest := newDest(t)
	m := rerun(t, f, dest, Options{Depth: 3, Hold: holdMail}, in...)
	checkSummary(t, m, []string{
		"1-report.eml email 0 UNPACKED -> 1-report.eml.unpacked",
		"1-report.eml.unpacked/1-files.zip zip 1 HELD",
		"2-fwd.eml email 0 UNPACKED -> 2-fwd.eml.unpacked",
		"2-fwd.eml.unpacked/1-inner.zip zip 2 HELD",
		"3-top.zip zip 0 UNPACKED -> 3-top.zip.unpacked",
		"3-top.zip.unpacked/nested.zip zip 1 UNPACKED -> 3-top.zip.unpacked/nested.zip.unpacked",
	})
	if !slices.Equal(m.Options.Hold, holdMail) {
		t.Errorf("options = %+v", m.Options)
	}
	for _, c := range []int{1, 3} {
		if c := m.Containers[c]; c.Code != 0 || c.Error != "" || c.Unpacked != "" {
			t.Errorf("held record = %+v", c)
		}
	}
	for _, p := range []string{"1-report.eml.unpacked/1-files.zip.unpacked", "2-fwd.eml.unpacked/1-inner.zip.unpacked"} {
		if _, err := os.Lstat(filepath.Join(dest, p)); err == nil {
			t.Errorf("%s opened", p)
		}
	}

	// The plan lists the held archives' entries.
	items, err := Plan(t.Context(), nil, dest, Options{Runner: f, Depth: 3, Hold: holdMail})
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || !items[0].Listed || len(items[0].Entries) != 2 || items[0].Entries[0].Path != "mail.eml" || !slices.Equal(items[1].Flags, []string{FlagHeld}) || len(items[1].Entries) != 1 {
		t.Errorf("plan = %+v", items)
	}

	// A rerun keeps them held, and releasing one opens it, the zip in it as
	// usual, and the email in it, whose zip is held again.
	m = rerun(t, f, dest, Options{Depth: 3, Hold: holdMail}, in...)
	if m.Containers[1].Outcome != OutcomeHeld || m.Containers[3].Outcome != OutcomeHeld || len(m.Containers) != 6 || len(m.Inputs) != 3 {
		t.Errorf("rerun = %v", summary(m))
	}
	m = rerun(t, f, dest, Options{Depth: 3, Hold: holdMail, Release: []string{"1-report.eml.unpacked/1-files.zip"}})
	checkSummary(t, m, []string{
		"1-report.eml email 0 UNPACKED -> 1-report.eml.unpacked",
		"1-report.eml.unpacked/1-files.zip zip 1 UNPACKED -> 1-report.eml.unpacked/1-files.zip.unpacked",
		"2-fwd.eml email 0 UNPACKED -> 2-fwd.eml.unpacked",
		"2-fwd.eml.unpacked/1-inner.zip zip 2 HELD",
		"3-top.zip zip 0 UNPACKED -> 3-top.zip.unpacked",
		"3-top.zip.unpacked/nested.zip zip 1 UNPACKED -> 3-top.zip.unpacked/nested.zip.unpacked",
		"1-report.eml.unpacked/1-files.zip.unpacked/mail.eml email 2 UNPACKED -> 1-report.eml.unpacked/1-files.zip.unpacked/mail.eml.unpacked",
		"1-report.eml.unpacked/1-files.zip.unpacked/mail.eml.unpacked/1-deep.zip zip 3 HELD",
		"1-report.eml.unpacked/1-files.zip.unpacked/sub.zip zip 2 UNPACKED -> 1-report.eml.unpacked/1-files.zip.unpacked/sub.zip.unpacked",
	})

	// --release-all opens the rest but the ones skipped, which stay packed
	// for good.
	inner := "2-fwd.eml.unpacked/1-inner.zip"
	m = rerun(t, f, dest, Options{Depth: 3, Hold: holdMail, ReleaseAll: true, Skip: []string{inner}})
	if c := m.Containers[3]; c.Outcome != OutcomeSkipped || !slices.Equal(m.Skip, []string{inner}) {
		t.Errorf("skipped = %+v, skip %v", c, m.Skip)
	}
	if c := m.Containers[7]; c.Outcome != OutcomeUnpacked {
		t.Errorf("released = %+v", c)
	}
	m = rerun(t, f, dest, Options{Depth: 3, Hold: holdMail, ReleaseAll: true})
	if c := m.Containers[3]; c.Outcome != OutcomeSkipped {
		t.Errorf("skipped after --release-all = %+v", c)
	}

	// Unskipped, it is held again, unless it is released too.
	m = rerun(t, f, dest, Options{Depth: 3, Hold: holdMail, Unskip: []string{inner}})
	if c := m.Containers[3]; c.Outcome != OutcomeHeld || len(m.Skip) != 0 {
		t.Errorf("unskipped = %+v, skip %v", c, m.Skip)
	}
	rerun(t, f, dest, Options{Depth: 3, Hold: holdMail, Skip: []string{inner}})
	m = rerun(t, f, dest, Options{Depth: 3, Hold: holdMail, Unskip: []string{inner}, Release: []string{inner}})
	if c := m.Containers[3]; c.Outcome != OutcomeUnpacked {
		t.Errorf("unskipped and released = %+v", c)
	}
	if got := readFile(t, filepath.Join(dest, inner+".unpacked/i.txt")); got != "i" {
		t.Errorf("i.txt = %q", got)
	}
}

// TestHoldPrecedence checks that a container past the depth limit or
// skipped isn't held, that a held one that needs a password after its
// release is retried as usual, and that without 7z an archive from an
// email is held.
func TestHoldPrecedence(t *testing.T) {
	f, in := holdTree(t)
	_, m := run(t, f, Options{Depth: 0, Hold: holdMail}, in[0])
	checkSummary(t, m, []string{
		"1-report.eml email 0 UNPACKED -> 1-report.eml.unpacked",
		"1-report.eml.unpacked/1-files.zip zip 1 DEPTH-LIMIT",
		"1-report.eml.unpacked/2-fake.zip zip 1 DEPTH-LIMIT",
	})
	_, m = run(t, f, Options{Depth: 3, Hold: holdMail, Skip: []string{"1-report.eml.unpacked/1-files.zip"}}, in[0])
	checkSummary(t, m, []string{
		"1-report.eml email 0 UNPACKED -> 1-report.eml.unpacked",
		"1-report.eml.unpacked/1-files.zip zip 1 SKIPPED",
	})

	// Without 7z it can't be told from a file that only starts like an
	// archive, so both are held, and released they fail.
	dest := newDest(t)
	o := Options{Depth: 3, MaxSize: DefaultMaxSize, Hold: holdMail}
	m, err := Run(t.Context(), in[:1], dest, o)
	if err != nil {
		t.Fatal(err)
	}
	checkSummary(t, m, []string{
		"1-report.eml email 0 UNPACKED -> 1-report.eml.unpacked",
		"1-report.eml.unpacked/1-files.zip zip 1 HELD",
		"1-report.eml.unpacked/2-fake.zip zip 1 HELD",
	})
	o.ReleaseAll = true
	if m, err = Run(t.Context(), nil, dest, o); err != nil {
		t.Fatal(err)
	}
	checkSummary(t, m, []string{
		"1-report.eml email 0 UNPACKED -> 1-report.eml.unpacked",
		"1-report.eml.unpacked/1-files.zip zip 1 FAILED",
		"1-report.eml.unpacked/2-fake.zip zip 1 FAILED",
	})
	// Released, they are retried as any failed container is, with no
	// --release needed, and the one 7z can't open stays FAILED.
	m = rerun(t, f, dest, Options{Depth: 3, Hold: holdMail})
	if c := m.Containers[1]; c.Outcome != OutcomeUnpacked {
		t.Errorf("retried = %+v", c)
	}
	if c := m.Containers[2]; c.Outcome != OutcomeFailed {
		t.Errorf("fake = %+v", c)
	}

	// An archive attached to an email that needs a password is held, as a
	// password is only tried when it is released.
	f.archives["1-direct.zip"] = fakeArchive{files: map[string]string{"x.txt": "x"}, password: "pw"}
	dest = newDest(t)
	rerun(t, f, dest, Options{Depth: 3, Hold: holdMail}, writeInputs(t, "d.eml", email("d", "d", "direct.zip", zipHead))...)
	m = rerun(t, f, dest, Options{Depth: 3, Hold: holdMail, Release: []string{"1-d.eml.unpacked/1-direct.zip"}})
	if c := m.Containers[1]; c.Outcome != OutcomeNeedsPassword {
		t.Errorf("released without a password = %+v", c)
	}
	pw := "pw"
	m = rerun(t, f, dest, Options{Depth: 3, Hold: holdMail, Password: &pw})
	if c := m.Containers[1]; c.Outcome != OutcomeUnpacked {
		t.Errorf("retried with the password = %+v", c)
	}
}

// TestHoldErrors checks that the hold is the destination's, and that
// releases are checked against the manifest, both changing nothing.
func TestHoldErrors(t *testing.T) {
	f, in := holdTree(t)
	dest := newDest(t)
	rerun(t, f, dest, Options{Depth: 3, Hold: holdMail}, in...)
	plain := newDest(t)
	rerun(t, f, plain, Options{Depth: 3}, in[2])
	held := "1-report.eml.unpacked/1-files.zip"
	for name, c := range map[string]struct {
		dest string
		o    Options
		want string
	}{
		"rerun without --hold":   {dest, Options{Depth: 3}, "a later run keeps it (--hold mail-archives)"},
		"--hold added":           {plain, Options{Depth: 3, Hold: holdMail}, "holding nothing"},
		"unknown kind":           {dest, Options{Depth: 3, Hold: []string{"everything"}}, `unknown hold kind "everything"`},
		"release unknown":        {dest, Options{Depth: 3, Hold: holdMail, Release: []string{"9-nothing.zip"}}, "no container has that path"},
		"release opened":         {dest, Options{Depth: 3, Hold: holdMail, Release: []string{"3-top.zip"}}, "is not held, it is UNPACKED"},
		"release outside":        {dest, Options{Depth: 3, Hold: holdMail, Release: []string{"../x"}}, "not a path inside"},
		"release and skip":       {dest, Options{Depth: 3, Hold: holdMail, Release: []string{held}, Skip: []string{held}}, "both skipped and released"},
		"release and all":        {dest, Options{Depth: 3, Hold: holdMail, Release: []string{held}, ReleaseAll: true}, "--release-all can't be given with --release"},
		"release without hold":   {plain, Options{Depth: 3, ReleaseAll: true}, "nothing is held without --hold"},
		"release on a first run": {newDest(t), Options{Depth: 3, Hold: holdMail, Release: []string{held}}, "no container has that path"},
	} {
		before := snapshot(t, filepath.Dir(c.dest))
		_, err := runErr(t, f, c.dest, c.o, in...)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
		checkUnchanged(t, name, filepath.Dir(c.dest), before)
	}

	// A skipped container isn't held, so it can't be released.
	rerun(t, f, dest, Options{Depth: 3, Hold: holdMail, Skip: []string{held}})
	before := snapshot(t, dest)
	if _, err := runErr(t, f, dest, Options{Depth: 3, Hold: holdMail, Release: []string{held}}); err == nil || !strings.Contains(err.Error(), "is not held, it is SKIPPED") {
		t.Errorf("release skipped: err = %v", err)
	}
	checkUnchanged(t, "release skipped", dest, before)

	// --release-all with nothing held, and --hold given twice, are fine.
	if _, err := Run(t.Context(), in[2:], newDest(t), Options{Depth: 3, MaxSize: DefaultMaxSize, Runner: f, Hold: []string{HoldMailArchives, HoldMailArchives}, ReleaseAll: true}); err != nil {
		t.Errorf("--release-all on a first run: %v", err)
	}

	// The plan keeps the hold too, and releases nothing.
	for name, o := range map[string]Options{
		"no hold":     {Depth: 3},
		"release":     {Depth: 3, Hold: holdMail, Release: []string{held}},
		"release all": {Depth: 3, Hold: holdMail, ReleaseAll: true},
	} {
		if _, err := Plan(t.Context(), nil, dest, o); err == nil {
			t.Errorf("plan %s: accepted", name)
		}
	}
}

// TestHoldTampered checks that a rerun refuses a held record a run
// couldn't have written, and changes nothing.
func TestHoldTampered(t *testing.T) {
	f, in := holdTree(t)
	setup := func() string {
		dest := newDest(t)
		m := rerun(t, f, dest, Options{Depth: 3, Hold: holdMail}, in...)
		if m.Containers[1].Outcome != OutcomeHeld || m.Containers[5].Outcome != OutcomeUnpacked {
			t.Fatalf("setup = %v", summary(m))
		}
		return dest
	}
	held := func(m map[string]any, i int) {
		containerAt(m, i)["outcome"] = OutcomeHeld
		containerAt(m, i)["flags"] = []string{FlagHeld}
		delete(containerAt(m, i), "unpacked")
		delete(containerAt(m, i), "outputs")
	}
	for name, edit := range map[string]func(m map[string]any){
		"held with no hold": func(m map[string]any) { delete(m["options"].(map[string]any), "hold") },
		"unknown hold kind": func(m map[string]any) { m["options"].(map[string]any)["hold"] = []string{"everything"} },
		"hold twice": func(m map[string]any) {
			m["options"].(map[string]any)["hold"] = []string{HoldMailArchives, HoldMailArchives}
		},
		"held in an archive": func(m map[string]any) { held(m, 5) },
		"held input":         func(m map[string]any) { held(m, 4) },
		"held on the skip list": func(m map[string]any) {
			m["skip"] = []string{"1-report.eml.unpacked/1-files.zip"}
		},
		"held with a failure": func(m map[string]any) {
			containerAt(m, 1)["code"] = 3
			containerAt(m, 1)["error"] = "needs a password"
		},
	} {
		dest := setup()
		editManifest(t, dest, edit)
		before := snapshot(t, dest)
		_, err := runErr(t, f, dest, Options{Depth: 3, Hold: holdMail, ReleaseAll: true})
		if err == nil || !strings.HasPrefix(err.Error(), "refusing to resume") {
			t.Errorf("%s: err = %v", name, err)
		}
		t.Logf("%s: %v", name, err)
		checkUnchanged(t, name, dest, before)
		if _, err := Plan(t.Context(), nil, dest, Options{Depth: 3, Hold: holdMail}); err == nil {
			t.Errorf("%s: plan accepted it", name)
		}
	}
}
