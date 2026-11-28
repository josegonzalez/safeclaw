package session

import (
	"archive/tar"
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
	"github.com/josegonzalez/safeclaw/internal/scan"
)

// eicarMarker stands in for malware in the unit tests: the fake clamscan
// flags any file containing it.
const eicarMarker = "EICAR-MARKER"

// writeSigs installs fake signatures (daily version) in dir.
func writeSigs(t *testing.T, dir string, version int) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, db := range []struct {
		file    string
		version int
	}{{"main.cvd", 62}, {"daily.cld", version}} {
		h := fmt.Sprintf("ClamAV-VDB:27 Nov 2026 07-23 -0500:%d:100:90:md5:dsig:builder:1795000000", db.version)
		h += strings.Repeat(" ", 512-len(h))
		if err := os.WriteFile(filepath.Join(dir, db.file), []byte(h), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// mountSource returns the src of the --mount whose dst is dst.
func mountSource(args []string, dst string) (string, bool) {
	for i, a := range args {
		if a != "--mount" || i+1 >= len(args) {
			continue
		}
		fields, err := csv.NewReader(strings.NewReader(args[i+1])).Read()
		if err != nil {
			continue
		}
		var src, d string
		for _, f := range fields {
			if v, ok := strings.CutPrefix(f, "src="); ok {
				src = v
			}
			if v, ok := strings.CutPrefix(f, "dst="); ok {
				d = v
			}
		}
		if d == dst {
			return src, true
		}
	}
	return "", false
}

// fakeClamscan answers a clamscan run like clamscan would, reading the
// files from the scan mount's host directory: FOUND for any containing
// eicarMarker, OK for the rest.
func fakeClamscan(args []string) ([]byte, error) {
	src, ok := mountSource(args, scanMount)
	if !ok {
		return nil, errors.New("no scan mount")
	}
	var out strings.Builder
	found := false
	for _, p := range args[slices.Index(args, "--")+1:] {
		b, err := os.ReadFile(filepath.Join(src, strings.TrimPrefix(p, scanMount+"/")))
		switch {
		case err != nil:
			fmt.Fprintf(&out, "%s: Can't open file ERROR\n", p)
		case strings.Contains(string(b), eicarMarker):
			fmt.Fprintf(&out, "%s: Eicar-Test-Signature FOUND\n", p)
			found = true
		default:
			fmt.Fprintf(&out, "%s: OK\n", p)
		}
	}
	if found {
		return []byte(out.String()), &docker.Error{Args: args, Err: errors.New("exit status 1")}
	}
	return []byte(out.String()), nil
}

// newScanManager is newCopyManager with signatures installed and docker
// runs of clamscan answered by fakeClamscan, or by run when it is set.
func newScanManager(t *testing.T, f *copyFake, run func(args []string) ([]byte, error)) (*Manager, *dockertest.Runner) {
	t.Helper()
	m, r := newCopyManager(t, f)
	writeSigs(t, m.SignaturesDir, 27830)
	if run == nil {
		run = fakeClamscan
	}
	h := r.Handler
	r.Handler = func(args []string, stdin string) ([]byte, error) {
		if args[0] == "run" && slices.Contains(args, "clamscan") {
			return run(args)
		}
		return h(args, stdin)
	}
	return m, r
}

var scanTar = []entry{
	{"./", tar.TypeDir, "", 0o755},
	{"./a.txt", tar.TypeReg, "alpha", 0o644},
	{"./bad.txt", tar.TypeReg, "x " + eicarMarker + " x", 0o644},
	{"./c.txt", tar.TypeReg, "gamma", 0o644},
}

func TestCopyOutScansClean(t *testing.T) {
	host := t.TempDir()
	m, r := newScanManager(t, &copyFake{tarOut: makeTar(t, scanTar[0], scanTar[1], scanTar[3])}, nil)
	res, err := m.CopyOutReport(context.Background(), "box", "out", host, CopyOutOptions{Only: []string{"*.txt"}})
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{filepath.Join(host, "a.txt"), filepath.Join(host, "c.txt")}; !reflect.DeepEqual(res.Paths, want) {
		t.Errorf("paths = %v", res.Paths)
	}
	if res.Scan == nil || res.Scan.Signatures.Version != 27830 {
		t.Fatalf("scan = %+v", res.Scan)
	}
	want := []scan.Result{{Path: "a.txt", Status: scan.Clean}, {Path: "c.txt", Status: scan.Clean}}
	if !reflect.DeepEqual(res.Scan.Results, want) {
		t.Errorf("results = %v", res.Scan.Results)
	}
	if got := dirContents(t, host); !reflect.DeepEqual(got, map[string]string{"a.txt": "alpha", "c.txt": "gamma"}) {
		t.Errorf("host dir = %v", got)
	}

	// The scan runs in a fresh container with no network, only the
	// signatures and the copied files mounted read-only, the host user,
	// and the sandbox's limits with at least DefaultScanMemory.
	var run dockertest.Call
	for _, c := range r.Calls {
		if c.Args[0] == "run" {
			run = c
		}
	}
	s := run.String()
	for _, want := range []string{
		"run --rm --user " + hostUser() + " ",
		" --cap-drop ALL --security-opt no-new-privileges --log-driver none --read-only --tmpfs " + scanTmpfs + " ",
		" --network none --memory 3221225472 --pids-limit 256 --cpus 1 ",
		" --mount " + ReadOnlyBind{Source: m.SignaturesDir, Target: scan.DatabaseDir}.Mount() + " ",
		",dst=/scan,readonly,bind-propagation=rprivate,bind-recursive=readonly ",
		" --label safeclaw.image=safeclaw:sandbox sha256:img clamscan --database=/var/lib/clamav ",
		" -- /scan/0 /scan/1",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("scan run = %q\nlacks %q", s, want)
		}
	}
	if strings.Count(s, "--mount") != 2 || strings.Contains(s, "--env-file") || strings.Contains(s, "--name") {
		t.Errorf("scan run has more than it needs: %q", s)
	}
	// The scan's files are gone with the temporary directory.
	entries, _ := os.ReadDir(host)
	if len(entries) != 2 {
		t.Errorf("host dir entries = %v", entries)
	}
}

func TestCopyOutScanUsesSandboxLimits(t *testing.T) {
	host := t.TempDir()
	m, r := newScanManager(t, &copyFake{tarOut: makeTar(t, scanTar[0], scanTar[1])}, nil)
	// Give the sandbox bigger limits than the scan's floor.
	w := r.Handler
	r.Handler = func(args []string, stdin string) ([]byte, error) {
		out, err := w(args, stdin)
		if args[0] == "container" && args[1] == "inspect" {
			s := strings.Replace(string(out), `"Memory":0`, `"Memory":8589934592`, 1)
			s = strings.Replace(s, `"NanoCpus":0`, `"NanoCpus":2500000000`, 1)
			s = strings.Replace(s, `"PidsLimit":0`, `"PidsLimit":64`, 1)
			return []byte(s), err
		}
		return out, err
	}
	if _, err := m.CopyOut(context.Background(), "box", "out", host, CopyOutOptions{Only: []string{"*"}}); err != nil {
		t.Fatal(err)
	}
	run, _ := r.Find("run ")
	if !strings.Contains(run.String(), " --memory 8589934592 --pids-limit 64 --cpus 2.5 ") {
		t.Errorf("scan run = %q", run.String())
	}
}

func TestCopyOutRefusesFlagged(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts CopyOutOptions
	}{
		{"plain", CopyOutOptions{Only: []string{"*.txt"}}},
		{"force", CopyOutOptions{Only: []string{"*.txt"}, Force: true}},
		{"replace", CopyOutOptions{Only: []string{"*.txt"}, Replace: true}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			host := t.TempDir()
			writeFile(t, filepath.Join(host, "a.txt"), "old a")
			writeFile(t, filepath.Join(host, "stale.txt"), "stale")
			before := hostEntries(t, host)
			m, _ := newScanManager(t, &copyFake{tarOut: makeTar(t, scanTar...)}, nil)
			_, err := m.CopyOut(context.Background(), "box", "out", host, tc.opts)
			var flagged *FlaggedError
			if !errors.As(err, &flagged) || !errors.Is(err, ErrFlagged) {
				t.Fatalf("err = %v", err)
			}
			if got := flagged.Report.Flagged(); len(got) != 1 || got[0].Path != "bad.txt" || got[0].Signature != "Eicar-Test-Signature" {
				t.Errorf("flagged = %v", got)
			}
			if !strings.Contains(err.Error(), `"bad.txt": infected (Eicar-Test-Signature)`) || !strings.Contains(err.Error(), "--allow-flagged") {
				t.Errorf("err = %v", err)
			}
			if got := hostEntries(t, host); !reflect.DeepEqual(got, before) {
				t.Errorf("host dir = %v, want %v", got, before)
			}
		})
	}
}

func TestCopyOutAllowFlagged(t *testing.T) {
	host := t.TempDir()
	m, _ := newScanManager(t, &copyFake{tarOut: makeTar(t, scanTar...)}, nil)
	res, err := m.CopyOutReport(context.Background(), "box", "out", host, CopyOutOptions{Only: []string{"*.txt"}, AllowFlagged: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Paths) != 3 || len(res.Scan.Flagged()) != 1 {
		t.Errorf("result = %+v", res)
	}
	if got := dirContents(t, host); got["bad.txt"] == "" {
		t.Errorf("host dir = %v", got)
	}
}

func TestCopyOutScanFailureRefuses(t *testing.T) {
	host := t.TempDir()
	m, _ := newScanManager(t, &copyFake{tarOut: makeTar(t, scanTar[0], scanTar[1])}, func(args []string) ([]byte, error) {
		return nil, &docker.Error{Args: args, Stderr: "LibClamAV Error: out of memory", Err: errors.New("exit status 137")}
	})
	_, err := m.CopyOut(context.Background(), "box", "out", host, CopyOutOptions{Only: []string{"*"}})
	var flagged *FlaggedError
	if !errors.As(err, &flagged) {
		t.Fatalf("err = %v", err)
	}
	if r := flagged.Report.Results[0]; r.Status != scan.Error || !strings.Contains(r.Reason, "the scan failed") || !strings.Contains(r.Reason, "out of memory") {
		t.Errorf("result = %+v", r)
	}
	if got := dirContents(t, host); len(got) != 0 {
		t.Errorf("host dir = %v", got)
	}
}

func TestCopyOutNoSignatures(t *testing.T) {
	host := t.TempDir()
	m, r := newCopyManager(t, &copyFake{tarOut: makeTar(t, scanTar...)})
	_, err := m.CopyOut(context.Background(), "box", "out", host, CopyOutOptions{Only: []string{"*"}})
	if !errors.Is(err, scan.ErrNoSignatures) || !strings.Contains(err.Error(), "safeclaw sandbox update-signatures") || !strings.Contains(err.Error(), "--no-scan") {
		t.Fatalf("err = %v", err)
	}
	// Nothing is read from the sandbox, and nothing is written.
	if hasExec(r) {
		t.Errorf("read the sandbox without signatures: %v", r.Commands())
	}
	if entries, _ := os.ReadDir(host); len(entries) != 0 {
		t.Errorf("host dir = %v", entries)
	}
	// --no-scan copies without them.
	if _, err := m.CopyOut(context.Background(), "box", "out", host, CopyOutOptions{Only: []string{"*"}, NoScan: true}); err != nil {
		t.Fatal(err)
	}
	if hasCall(r, "run ") {
		t.Errorf("scanned with NoScan: %v", r.Commands())
	}
}

func TestCopyOutNoScanImage(t *testing.T) {
	host := t.TempDir()
	m, r := newScanManager(t, &copyFake{tarOut: makeTar(t, scanTar...)}, nil)
	h := r.Handler
	r.Handler = func(args []string, stdin string) ([]byte, error) {
		if args[0] == "image" && args[len(args)-1] == "safeclaw:sandbox" {
			return nil, dockertest.NotFound(args)
		}
		return h(args, stdin)
	}
	_, err := m.CopyOut(context.Background(), "box", "out", host, CopyOutOptions{Only: []string{"*"}})
	if !errors.Is(err, ErrScanImage) || !strings.Contains(err.Error(), "--no-scan") {
		t.Fatalf("err = %v", err)
	}
	if hasExec(r) {
		t.Errorf("read the sandbox without a scan image: %v", r.Commands())
	}
}

func TestCopyOutScanNothing(t *testing.T) {
	host := t.TempDir()
	m, r := newScanManager(t, &copyFake{tarOut: makeTar(t, scanTar[0])}, nil)
	res, err := m.CopyOutReport(context.Background(), "box", "out", host, CopyOutOptions{Only: []string{"*"}})
	if err != nil || len(res.Paths) != 0 || len(res.Scan.Results) != 0 {
		t.Fatalf("res = %+v, %v", res, err)
	}
	if hasCall(r, "run ") {
		t.Errorf("ran a scan for no files: %v", r.Commands())
	}
}

func TestScanSandbox(t *testing.T) {
	m, _ := newScanManager(t, &copyFake{}, nil)
	ctx := context.Background()
	// The fake sandbox has no signature mount, like one created before
	// sandboxes got one.
	if _, err := m.ScanSandbox(ctx, "box", []string{"in/a"}); !errors.Is(err, ErrNoSignatureMount) {
		t.Fatalf("err = %v", err)
	}
	if _, err := m.ScanSandbox(ctx, "chat", []string{"a"}); !errors.Is(err, ErrNotSandbox) {
		t.Errorf("session: %v", err)
	}
	if _, err := m.ScanSandbox(ctx, "box", nil); err == nil {
		t.Error("no paths accepted")
	}

	w := &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-box": {Running: true, Image: "img", Labels: sandboxLabels, NetworkMode: "none", Offline: true, Mounts: []string{"/sigs:/var/lib/clamav:ro"}},
	}}
	m2, r2 := newTestManager(t, w)
	writeSigs(t, m2.SignaturesDir, 27900)
	r2.Handler = func(args []string, stdin string) ([]byte, error) {
		if args[0] == "exec" && slices.Contains(args, "clamscan") {
			return []byte("in/a: OK\nin/b: Eicar-Test-Signature FOUND\n"), &docker.Error{Args: args, Stderr: "in/c: No such file or directory", Err: errors.New("exit status 2")}
		}
		return w.handle(args, stdin)
	}
	report, err := m2.ScanSandbox(ctx, "box", []string{"in/a", "in/b", "in/c"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Signatures.Version != 27900 {
		t.Errorf("signatures = %+v", report.Signatures)
	}
	if len(report.Results) != 3 || report.Results[0].Status != scan.Clean || report.Results[1].Status != scan.Infected ||
		report.Results[2].Status != scan.Error || !strings.Contains(report.Results[2].Reason, "No such file") {
		t.Errorf("results = %+v", report.Results)
	}
	want := "exec --user sandbox --workdir /sandbox safeclaw-box " + umaskSh + " clamscan --database=/var/lib/clamav"
	if !hasCall(r2, want) {
		t.Errorf("missing %q in %v", want, r2.Commands())
	}
}

func TestUpdateSignatures(t *testing.T) {
	m, r := newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{}})
	writeSigs(t, m.SignaturesDir, 27000)
	h := r.Handler
	var staging string
	r.Handler = func(args []string, stdin string) ([]byte, error) {
		if args[0] != "run" {
			return h(args, stdin)
		}
		src, ok := mountSource(args, scan.DatabaseDir)
		if !ok {
			return nil, errors.New("no mount")
		}
		staging = src
		// Seeded with the current signatures.
		if _, err := os.Stat(filepath.Join(src, "daily.cld")); err != nil {
			return nil, err
		}
		writeSigs(t, src, 27830)
		return []byte("daily.cld updated (version: 27830)\x1b[31m\n"), nil
	}
	out := &strings.Builder{}
	m.Out = out
	sigs, err := m.UpdateSignatures(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sigs.Version != 27830 {
		t.Errorf("signatures = %+v", sigs)
	}
	if got, err := scan.Read(m.SignaturesDir); err != nil || got.Version != 27830 {
		t.Errorf("installed = %+v, %v", got, err)
	}
	if _, err := os.Stat(staging); !os.IsNotExist(err) {
		t.Errorf("staging left behind: %v", err)
	}
	if filepath.Dir(staging) != filepath.Dir(m.SignaturesDir) {
		t.Errorf("staging %q is not next to %q", staging, m.SignaturesDir)
	}
	if strings.Contains(out.String(), "\x1b") || !strings.Contains(out.String(), "daily.cld updated") {
		t.Errorf("output = %q", out.String())
	}
	run, _ := r.Find("run ")
	s := run.String()
	for _, want := range []string{
		"run --rm --user " + hostUser() + " ",
		" --cap-drop ALL --security-opt no-new-privileges --log-driver none --read-only ",
		" --network bridge --memory 3221225472 --pids-limit 256 --mount type=bind,src=" + staging + ",dst=/var/lib/clamav,bind-propagation=rprivate ",
		" --label safeclaw.image=safeclaw:sandbox sha256:img /bin/sh -c ",
		"freshclam --config-file=/tmp/freshclam.conf",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("update run = %q\nlacks %q", s, want)
		}
	}
	if strings.Count(s, "--mount") != 1 || strings.Contains(s, "--env-file") || strings.Contains(s, " -p ") {
		t.Errorf("update run has more than it needs: %q", s)
	}

	// A failed update keeps the old signatures.
	r.Handler = func(args []string, stdin string) ([]byte, error) {
		if args[0] != "run" {
			return h(args, stdin)
		}
		src, _ := mountSource(args, scan.DatabaseDir)
		_ = os.WriteFile(filepath.Join(src, "daily.cld"), []byte("half"), 0o644)
		return nil, &docker.Error{Args: args, Stderr: "ERROR: Download failed", Err: errors.New("exit status 1")}
	}
	if _, err := m.UpdateSignatures(context.Background()); err == nil || !strings.Contains(err.Error(), "old signatures were kept") {
		t.Fatalf("err = %v", err)
	}
	if got, err := scan.Read(m.SignaturesDir); err != nil || got.Version != 27830 {
		t.Errorf("after failure = %+v, %v", got, err)
	}
}

func TestUpdateSignaturesNoImage(t *testing.T) {
	m, r := newTestManager(t, &world{images: map[string]string{"safeclaw": "base"}, containers: map[string]*fakeContainer{}})
	if _, err := m.UpdateSignatures(context.Background()); !errors.Is(err, ErrScanImage) {
		t.Fatalf("err = %v", err)
	}
	if hasCall(r, "run ") {
		t.Error("ran without the image")
	}
}

func TestSandboxSignatureMount(t *testing.T) {
	// The signature directory is created readable by the sandbox user.
	m, _ := newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{}})
	if _, err := m.EnsureSandbox(context.Background(), SandboxOptions{Name: "box"}); err != nil {
		t.Fatal(err)
	}
	if fi, err := os.Stat(m.SignaturesDir); err != nil || fi.Mode().Perm() != scan.DirMode {
		t.Errorf("signature dir = %v, %v", fi, err)
	}
	// A volume can't take the signatures' place.
	_, err := SandboxRunArgs("safeclaw-box", SandboxOptions{signatures: "/sigs", Volumes: []string{"/x:/var/lib/clamav"}, image: "sha256:x"})
	if err == nil || !strings.Contains(err.Error(), "the malware signatures") {
		t.Errorf("err = %v", err)
	}
	// A recreated sandbox gets the mount once, not again as a kept volume.
	w := &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-box": {Running: true, Image: "img", Labels: sandboxLabels, Mounts: []string{"/in:/in:ro", m.SignaturesDir + ":/var/lib/clamav:ro"}},
	}}
	m2, r2 := newTestManager(t, w)
	m2.SignaturesDir = m.SignaturesDir
	if _, err := m2.EnsureSandbox(context.Background(), SandboxOptions{Name: "box", Memory: "4g", Recreate: true}); err != nil {
		t.Fatal(err)
	}
	run, _ := r2.Find("run ")
	if n := strings.Count(run.String(), "dst=/var/lib/clamav"); n != 1 || !strings.Contains(run.String(), "dst=/in,") {
		t.Errorf("run = %q", run.String())
	}
}

func TestCopyOutScanRelativeHostDir(t *testing.T) {
	// docker refuses a relative mount source, so a relative HOST_DIR must
	// still give the scan an absolute one.
	host := t.TempDir()
	t.Chdir(host)
	m, r := newScanManager(t, &copyFake{tarOut: makeTar(t, scanTar[0], scanTar[1])}, nil)
	if _, err := m.CopyOut(context.Background(), "box", "out", ".", CopyOutOptions{Only: []string{"*"}}); err != nil {
		t.Fatal(err)
	}
	run, _ := r.Find("run ")
	src, ok := mountSource(run.Args, scanMount)
	if !ok || !filepath.IsAbs(src) {
		t.Errorf("scan mount source = %q", src)
	}
}

func TestScanFailedOneLine(t *testing.T) {
	got := scanFailed(errors.New("docker run: bad\n\nRun 'docker run --help'"))
	if got != "the scan failed: docker run: bad Run 'docker run --help'" {
		t.Errorf("scanFailed = %q", got)
	}
}
