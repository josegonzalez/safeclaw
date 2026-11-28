package cli

import (
	"archive/tar"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
	"github.com/josegonzalez/safeclaw/internal/scan"
	"github.com/josegonzalez/safeclaw/internal/session"
)

// scanWorld fakes docker for the scan commands: a running sandbox "box"
// whose out directory holds files, the sandbox variant's image, and
// clamscan, which flags any file containing "EICAR".
type scanWorld struct {
	files    map[string]string
	sigsDir  string
	mounted  bool
	noImage  bool
	execOut  string
	execErr  error
	freshErr error
}

func (w *scanWorld) tar(t *testing.T) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	names := make([]string, 0, len(w.files))
	for n := range w.files {
		names = append(names, n)
	}
	slices.Sort(names)
	for _, n := range names {
		body := w.files[n]
		if err := tw.WriteHeader(&tar.Header{Typeflag: tar.TypeReg, Name: "./" + n, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		_, _ = tw.Write([]byte(body))
	}
	_ = tw.Close()
	return buf.Bytes()
}

func writeFakeSigs(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for file, v := range map[string]int{"main.cvd": 62, "daily.cld": 27830} {
		h := fmt.Sprintf("ClamAV-VDB:27 Nov 2026 07-23 -0500:%d:100:90:md5:dsig:builder:1795000000", v)
		if err := os.WriteFile(filepath.Join(dir, file), []byte(h+strings.Repeat(" ", 512-len(h))), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func fakeScanWorld(t *testing.T, w *scanWorld) {
	t.Helper()
	w.sigsDir = filepath.Join(t.TempDir(), "clamav")
	mounts := `[]`
	if w.mounted {
		mounts = `[{"Type":"bind","Source":"` + w.sigsDir + `","Destination":"/var/lib/clamav","RW":false}]`
	}
	box := `{"Id":"id","Name":"/safeclaw-box","State":{"Status":"running","Running":true},` +
		`"Config":{"Image":"safeclaw:sandbox","User":"sandbox","Labels":{"safeclaw.type":"sandbox"}},` +
		`"HostConfig":{"NetworkMode":"none","Memory":2147483648},"Mounts":` + mounts + `}`
	r := &dockertest.Runner{Handler: func(args []string, _ string) ([]byte, error) {
		switch {
		case args[0] == "container" && args[1] == "inspect":
			if args[2] == "safeclaw-box" {
				return []byte("[" + box + "]"), nil
			}
			return nil, dockertest.NotFound(args)
		case args[0] == "image" && args[1] == "inspect":
			if w.noImage {
				return nil, dockertest.NotFound(args)
			}
			return []byte(`{"Id":"sha256:sb","Config":{"Labels":{}}}`), nil
		case args[0] == "exec" && slices.Contains(args, "/usr/bin/tar"):
			return w.tar(t), nil
		case args[0] == "exec" && slices.Contains(args, "clamscan"):
			return []byte(w.execOut), w.execErr
		case args[0] == "run" && slices.Contains(args, "clamscan"):
			var src string
			for i, a := range args {
				if a == "--mount" && strings.Contains(args[i+1], "dst=/scan,") {
					src = strings.TrimPrefix(strings.Split(args[i+1], ",")[1], "src=")
				}
			}
			var out strings.Builder
			for _, p := range args[slices.Index(args, "--")+1:] {
				b, _ := os.ReadFile(filepath.Join(src, filepath.Base(p)))
				if strings.Contains(string(b), "EICAR") {
					fmt.Fprintf(&out, "%s: Eicar-Test-Signature FOUND\n", p)
				} else {
					fmt.Fprintf(&out, "%s: OK\n", p)
				}
			}
			return []byte(out.String()), nil
		case args[0] == "run" && slices.Contains(args, "/bin/sh"):
			if w.freshErr != nil {
				return nil, w.freshErr
			}
			for i, a := range args {
				if a == "--mount" {
					src := strings.TrimPrefix(strings.Split(args[i+1], ",")[1], "src=")
					writeFakeSigs(t, src)
				}
			}
			return []byte("daily.cld updated\n"), nil
		}
		return nil, nil
	}}
	orig := newManager
	t.Cleanup(func() { newManager = orig })
	newManager = func() *session.Manager {
		return &session.Manager{Docker: r.Client(), CopyDir: t.TempDir(), SignaturesDir: w.sigsDir}
	}
}

func TestCopyOutScanCLI(t *testing.T) {
	w := &scanWorld{files: map[string]string{"a.txt": "alpha", "bad.txt": "EICAR"}}
	fakeScanWorld(t, w)
	host := t.TempDir()

	// No signatures: refused, pointing at update-signatures and --no-scan.
	_, _, err := runStderr("sandbox", "cp-out", "box", "out", host, "--only", "*.txt")
	if !errors.Is(err, scan.ErrNoSignatures) || !strings.Contains(err.Error(), "update-signatures") || !strings.Contains(err.Error(), "--no-scan") {
		t.Fatalf("no signatures: %v", err)
	}

	writeFakeSigs(t, w.sigsDir)
	out, errOut, err := runStderr("sandbox", "cp-out", "box", "out", host, "--only", "*.txt")
	if !errors.Is(err, session.ErrFlagged) {
		t.Fatalf("flagged: %v", err)
	}
	if out != "" || !strings.Contains(errOut, "signatures daily 27830 from ") ||
		!strings.Contains(errOut, "infected (Eicar-Test-Signature)  bad.txt  refused") || !strings.Contains(errOut, "clean                            a.txt") {
		t.Errorf("flagged output = %q, stderr = %q", out, errOut)
	}
	if entries, _ := os.ReadDir(host); len(entries) != 0 {
		t.Errorf("host dir = %v", entries)
	}

	out, errOut, err = runStderr("sandbox", "cp-out", "box", "out", host, "--only", "*.txt", "--allow-flagged")
	if err != nil {
		t.Fatal(err)
	}
	if out != filepath.Join(host, "a.txt")+"\n"+filepath.Join(host, "bad.txt")+"\n" || !strings.Contains(errOut, "bad.txt  copied because of --allow-flagged") {
		t.Errorf("allowed output = %q, stderr = %q", out, errOut)
	}

	out, errOut, err = runStderr("sandbox", "cp-out", "box", "out", host, "--only", "*.txt", "--no-scan", "--force")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "bad.txt") || errOut != "Not scanned for malware (--no-scan)\n" {
		t.Errorf("no-scan output = %q, stderr = %q", out, errOut)
	}

	if _, _, err := runStderr("sandbox", "cp-out", "box", "out", host, "--only", "*", "--no-scan", "--allow-flagged"); err == nil {
		t.Error("--no-scan with --allow-flagged accepted")
	}
}

func TestSandboxScanCLI(t *testing.T) {
	w := &scanWorld{mounted: true, execOut: "a: OK\n", execErr: nil}
	fakeScanWorld(t, w)
	writeFakeSigs(t, w.sigsDir)

	out, errOut, err := runStderr("sandbox", "scan", "box", "a")
	if err != nil || out != "clean  a\n" || !strings.Contains(errOut, "advisory") {
		t.Errorf("clean: out = %q, stderr = %q, err = %v", out, errOut, err)
	}

	w.execOut = "a: OK\nb: Eicar-Test-Signature FOUND\n"
	w.execErr = &docker.Error{Err: errors.New("exit status 2"), Stderr: "c: No such file"}
	out, _, err = runStderr("sandbox", "scan", "box", "a", "b", "c", "--json")
	var exit exitCodeError
	if !errors.As(err, &exit) || exit.code != scanInfectedExitCode {
		t.Errorf("infected: err = %v", err)
	}
	var got scanJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("json %q: %v", out, err)
	}
	if got.Schema != 1 || !got.Advisory || got.Signatures.Version != 27830 || len(got.Results) != 3 ||
		got.Results[1].Signature != "Eicar-Test-Signature" || got.Results[2].Status != scan.Error {
		t.Errorf("json = %+v", got)
	}

	w.execOut = "a: OK\n"
	_, _, err = runStderr("sandbox", "scan", "box", "a", "c")
	if !errors.As(err, &exit) || exit.code != scanErrorExitCode {
		t.Errorf("error: err = %v", err)
	}
}

func TestScanExitCode(t *testing.T) {
	clean, inf, bad := scan.Result{Status: scan.Clean}, scan.Result{Status: scan.Infected}, scan.Result{Status: scan.Error}
	for _, tc := range []struct {
		results []scan.Result
		want    int
	}{
		{nil, 0},
		{[]scan.Result{clean}, 0},
		{[]scan.Result{clean, bad}, scanErrorExitCode},
		{[]scan.Result{bad, inf}, scanInfectedExitCode},
	} {
		if got := scanExitCode(tc.results); got != tc.want {
			t.Errorf("%v = %d, want %d", tc.results, got, tc.want)
		}
	}
}

func TestWriteScanResultsQuotes(t *testing.T) {
	var buf strings.Builder
	err := writeScanResults(&buf, []scan.Result{{Path: "a\x1b[31m", Status: scan.Error, Reason: "bad\nthing"}}, "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(buf.String(), "\x1b") || strings.Count(buf.String(), "\n") != 1 {
		t.Errorf("output = %q", buf.String())
	}
}

func TestUpdateSignaturesCLI(t *testing.T) {
	w := &scanWorld{}
	fakeScanWorld(t, w)
	out, errOut, err := runStderr("sandbox", "update-signatures")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(out, "Signatures: daily 27830 from ") || !strings.Contains(out, "daily.cld  version 27830") || !strings.Contains(errOut, "freshclam") {
		t.Errorf("out = %q, stderr = %q", out, errOut)
	}

	w.freshErr = &docker.Error{Err: errors.New("exit status 1"), Stderr: "Can't download"}
	if _, _, err := runStderr("sandbox", "update-signatures"); err == nil || !strings.Contains(err.Error(), "old signatures were kept") {
		t.Errorf("failed update: %v", err)
	}
	w.noImage = true
	if _, _, err := runStderr("sandbox", "update-signatures"); !errors.Is(err, session.ErrScanImage) {
		t.Errorf("no image: %v", err)
	}
}
