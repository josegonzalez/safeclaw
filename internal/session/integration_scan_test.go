//go:build integration

package session

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/scan"
	"github.com/josegonzalez/safeclaw/internal/variant"
)

// eicar returns the EICAR anti-virus test string, built here rather than
// kept in a file so nothing in the repository looks like malware.
func eicar() string {
	return `X5O!P%@AP[4\PZX54(P^)7CC)7}$` + "EICAR-STANDARD-" + "ANTIVIRUS-TEST-FILE!$H+H*"
}

// scanSandbox starts a sandbox of the sandbox variant whose /sandbox/out
// holds eicar.txt and clean.txt, both generated inside it, and returns its
// name.
func scanSandbox(t *testing.T, m *Manager, name string) string {
	t.Helper()
	ctx := context.Background()
	if id, err := m.Docker.ImageID(ctx, variant.Image(variant.Sandbox)); err != nil || id == "" {
		t.Skip("sandbox variant not built; run `safeclaw build --variant sandbox` first")
	}
	container := config.ContainerName(name)
	_ = m.Docker.Remove(ctx, container, true)
	t.Cleanup(func() { _ = m.Docker.Remove(context.Background(), container, true) })
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: name}); err != nil {
		t.Fatal(err)
	}
	if out, err := m.Docker.Exec(ctx, container, copyExec, SandboxCommand([]string{"sh", "-c",
		`mkdir -p out && printf '%s' "$1" > out/eicar.txt && echo clean > out/clean.txt`, "sh", eicar()})...); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	return name
}

// TestIntegrationScanNoSignatures checks that cp-out refuses to copy
// without signatures, copies with --no-scan, and that the scan's
// prerequisites are checked before anything is read.
func TestIntegrationScanNoSignatures(t *testing.T) {
	ctx := context.Background()
	m := &Manager{Docker: docker.New(), SignaturesDir: filepath.Join(t.TempDir(), "clamav")}
	name := scanSandbox(t, m, "itest-scan-nosigs")
	host := t.TempDir()

	_, err := m.CopyOut(ctx, name, "/sandbox/out", host, CopyOutOptions{Only: []string{"*.txt"}})
	if !errors.Is(err, scan.ErrNoSignatures) || !strings.Contains(err.Error(), "update-signatures") || !strings.Contains(err.Error(), "--no-scan") {
		t.Fatalf("err = %v", err)
	}
	if entries, _ := os.ReadDir(host); len(entries) != 0 {
		t.Fatalf("host dir = %v", entries)
	}
	got, err := m.CopyOut(ctx, name, "/sandbox/out", host, CopyOutOptions{Only: []string{"*.txt"}, NoScan: true})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got, []string{filepath.Join(host, "clean.txt"), filepath.Join(host, "eicar.txt")}) {
		t.Errorf("copied %v", got)
	}
	if b, _ := os.ReadFile(filepath.Join(host, "eicar.txt")); string(b) != eicar() {
		t.Errorf("eicar.txt = %q", b)
	}
	// The sandbox mounts the (empty) signature directory read-only.
	if _, err := m.Docker.Exec(ctx, config.ContainerName(name), copyExec, "touch", scan.DatabaseDir+"/x"); err == nil {
		t.Error("the signature directory is writable in the sandbox")
	}
}

// TestIntegrationScanSignatures downloads the real signatures with
// update-signatures (into the real cache directory, where later runs only
// fetch what changed) and checks that cp-out refuses EICAR, copies it with
// --allow-flagged, leaves the host directory alone on a refusal with
// --replace, and that `sandbox scan` flags it inside the sandbox. It needs
// the network, so it only runs with SAFECLAW_TEST_SIGNATURES=1.
func TestIntegrationScanSignatures(t *testing.T) {
	if os.Getenv("SAFECLAW_TEST_SIGNATURES") == "" {
		t.Skip("set SAFECLAW_TEST_SIGNATURES=1 to download signatures and scan with them")
	}
	ctx := context.Background()
	m := &Manager{Docker: docker.New(), SignaturesDir: config.SignaturesDir()}
	if id, err := m.Docker.ImageID(ctx, variant.Image(variant.Sandbox)); err != nil || id == "" {
		t.Skip("sandbox variant not built; run `safeclaw build --variant sandbox` first")
	}
	sigs, err := m.UpdateSignatures(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if sigs.Version == 0 || sigs.Date.IsZero() {
		t.Errorf("signatures = %+v", sigs)
	}
	name := scanSandbox(t, m, "itest-scan-sigs")

	// Refused, and nothing changes in the host directory, even with
	// --replace.
	host := t.TempDir()
	writeFile(t, filepath.Join(host, "stale.txt"), "stale")
	_, err = m.CopyOut(ctx, name, "/sandbox/out", host, CopyOutOptions{Only: []string{"*.txt"}, Replace: true})
	var flagged *FlaggedError
	if !errors.As(err, &flagged) {
		t.Fatalf("err = %v", err)
	}
	if f := flagged.Report.Flagged(); len(f) != 1 || f[0].Path != "eicar.txt" || f[0].Status != scan.Infected || !strings.Contains(f[0].Signature, "Eicar") {
		t.Errorf("flagged = %+v", f)
	}
	if got := hostEntries(t, host); len(got) != 1 || got["stale.txt"] != "file:stale" {
		t.Errorf("host dir after refusal = %v", got)
	}

	// --allow-flagged copies it, reporting the result.
	res, err := m.CopyOutReport(ctx, name, "/sandbox/out", host, CopyOutOptions{Only: []string{"*.txt"}, AllowFlagged: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Paths) != 2 || len(res.Scan.Flagged()) != 1 || res.Scan.Signatures.Version != sigs.Version {
		t.Errorf("allowed = %+v", res)
	}
	if b, _ := os.ReadFile(filepath.Join(host, "eicar.txt")); string(b) != eicar() {
		t.Errorf("eicar.txt = %q", b)
	}

	// --no-scan copies it without scanning.
	host2 := t.TempDir()
	res, err = m.CopyOutReport(ctx, name, "/sandbox/out", host2, CopyOutOptions{Only: []string{"eicar.txt"}, NoScan: true})
	if err != nil || len(res.Paths) != 1 || res.Scan != nil {
		t.Errorf("no-scan = %+v, %v", res, err)
	}

	// The advisory scan inside the sandbox flags it too.
	report, err := m.ScanSandbox(ctx, name, []string{"out/eicar.txt", "out/clean.txt", "out/missing"})
	if err != nil {
		t.Fatal(err)
	}
	r := report.Results
	if len(r) != 3 || r[0].Status != scan.Infected || r[1].Status != scan.Clean || r[2].Status != scan.Error {
		t.Errorf("sandbox scan = %+v", r)
	}
}
