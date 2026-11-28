//go:build integration

package cli

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/secrets"
	"github.com/josegonzalez/safeclaw/internal/session"
	"github.com/josegonzalez/safeclaw/internal/variant"
)

// TestIntegrationSandboxRestore creates a one-off sandbox of the sandbox
// variant with --keep-inputs, copies in two files over two cp-in calls,
// opens them with a skip, and removes the sandbox, as a docker restart
// would. It then restores it with --restore-from, checks that the files
// are back at the same paths with the same hashes and that the open is
// printed rather than run, runs the printed open, and checks that a
// changed source refuses another restore before anything is created.
func TestIntegrationSandboxRestore(t *testing.T) {
	d := docker.New()
	ctx := context.Background()
	if id, err := d.ImageID(ctx, variant.Image(variant.Sandbox)); err != nil || id == "" {
		t.Skip("sandbox variant not built; run `safeclaw build --variant sandbox` first")
	}
	dir := t.TempDir()
	m := &session.Manager{Docker: d, Secrets: secrets.FileStore{Dir: filepath.Join(dir, ".secrets")}, CopyDir: filepath.Join(dir, "copy")}
	orig := newManager
	t.Cleanup(func() { newManager = orig })
	newManager = func() *session.Manager { return m }

	first, second := "itest-keep", "itest-restore"
	for _, name := range []string{first, second} {
		container := config.ContainerName(name)
		_ = d.Remove(ctx, container, true)
		t.Cleanup(func() { _ = d.Remove(context.Background(), container, true) })
	}
	record := filepath.Join(dir, "record")

	out, stderr, err := runStderr("sandbox", "run", "--rm", "-s", first, "--keep-inputs", record)
	if err != nil || out != first+"\n" {
		t.Fatalf("run --keep-inputs: %q, %v\n%s", out, err, stderr)
	}

	files := filepath.Join(dir, "files")
	if err := os.Mkdir(files, 0o755); err != nil {
		t.Fatal(err)
	}
	notes := filepath.Join(files, "notes.txt")
	if err := os.WriteFile(notes, []byte("read me\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var zb bytes.Buffer
	zw := zip.NewWriter(&zb)
	fw, err := zw.Create("inner.txt")
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write([]byte("inside the zip\n"))
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	archive := filepath.Join(files, "bundle.zip")
	if err := os.WriteFile(archive, zb.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{}
	for i, f := range []string{notes, archive} {
		paths, err := m.CopyIn(ctx, first, []string{f}, "")
		if err != nil {
			t.Fatal(err)
		}
		b, _ := os.ReadFile(f)
		h := sha256.Sum256(b)
		want[paths[0]] = hex.EncodeToString(h[:])
		if wantPath := []string{"/sandbox/in/1-notes.txt", "/sandbox/in/2-bundle.zip"}[i]; paths[0] != wantPath {
			t.Errorf("cp-in %s = %s, want %s", f, paths[0], wantPath)
		}
	}

	skip := "2-2-bundle.zip"
	out, stderr, err = runStderr("sandbox", "open", first, "--skip", skip)
	if err != nil && !errors.Is(err, exitCodeError{openLeftPacked}) {
		t.Fatalf("open --skip: %v\n%s%s", err, out, stderr)
	}
	if !strings.Contains(out, skip+"\tSKIPPED\t-\n") {
		t.Fatalf("open --skip didn't skip %s:\n%s", skip, out)
	}

	if err := d.Remove(ctx, config.ContainerName(first), true); err != nil {
		t.Fatal(err)
	}

	out, stderr, err = runStderr("sandbox", "run", "--rm", "-s", second, "--restore-from", record)
	if err != nil || out != second+"\n" {
		t.Fatalf("run --restore-from: %q, %v\n%s", out, err, stderr)
	}
	replay := "  safeclaw sandbox open " + second + " --skip=" + skip + "\n"
	if !strings.Contains(stderr, replay) {
		t.Errorf("restore didn't print the open to run again:\n%s", stderr)
	}
	sums, err := d.Exec(ctx, config.ContainerName(second), docker.ExecOptions{User: config.SandboxUser}, "sha256sum", "/sandbox/in/1-notes.txt", "/sandbox/in/2-bundle.zip")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for line := range strings.Lines(string(sums)) {
		sum, p, _ := strings.Cut(strings.TrimSpace(line), "  ")
		got[p] = sum
	}
	for p, sum := range want {
		if got[p] != sum {
			t.Errorf("%s: sha256 %q, want %q", p, got[p], sum)
		}
	}
	// The restore ran no helper: there is no tree until the open is run.
	if _, err := d.Exec(ctx, config.ContainerName(second), docker.ExecOptions{User: config.SandboxUser}, "test", "-e", session.OpenTreeDir); err == nil {
		t.Error("the restore made a tree")
	}
	out, stderr, err = runStderr("sandbox", "open", second, "--skip="+skip)
	if (err != nil && !errors.Is(err, exitCodeError{openLeftPacked})) || !strings.Contains(out, skip+"\tSKIPPED\t-\n") {
		t.Errorf("replayed open: %v\n%s%s", err, out, stderr)
	}

	// A changed source refuses the restore before anything is created.
	if err := d.Remove(ctx, config.ContainerName(second), true); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(notes, []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, stderr, err = runStderr("sandbox", "run", "--rm", "-s", second, "--restore-from", record)
	if err == nil || !strings.Contains(err.Error(), notes+" changed since it was copied in") {
		t.Errorf("restore after a change: %v\n%s", err, stderr)
	}
	if c, _ := d.InspectOne(ctx, config.ContainerName(second)); c != nil {
		t.Error("a refused restore created a sandbox")
	}
}

// TestIntegrationSandboxRestoreUnder starts two one-off sandboxes with the
// same --name-prefix and --keep-inputs-under in the same second, at once,
// one through `sandbox run` and one through a separate manager, so only
// docker keeps them apart. It checks that each records in its own
// DIR/NAME, that `sandbox run` printed only the name to stdout and the
// record to stderr, and that `sandbox inspect` shows it, then copies a
// file into one, removes it, and restores it with --restore-from DIR/NAME.
func TestIntegrationSandboxRestoreUnder(t *testing.T) {
	d := docker.New()
	ctx := context.Background()
	if id, err := d.ImageID(ctx, config.ImageName); err != nil || id == "" {
		t.Skip("safeclaw image not built; run `safeclaw build` first")
	}
	dir := t.TempDir()
	now := time.Now()
	newTestManager := func(sub string) *session.Manager {
		return &session.Manager{Docker: d, Secrets: secrets.FileStore{Dir: filepath.Join(dir, sub, ".secrets")},
			CopyDir: filepath.Join(dir, sub, "copy"), Out: io.Discard, Now: func() time.Time { return now }}
	}
	m := newTestManager("cli")
	orig := newManager
	t.Cleanup(func() { newManager = orig })
	newManager = func() *session.Manager { return m }

	prefix := fmt.Sprintf("itest-under-%d", os.Getpid())
	base := prefix + "-" + now.UTC().Format("20060102-150405")
	restored := prefix + "-restored"
	for _, name := range []string{base, base + "-2", restored} {
		container := config.ContainerName(name)
		t.Cleanup(func() { _ = d.Remove(context.Background(), container, true) })
	}
	parent := filepath.Join(dir, "triage")

	var cliOut, cliErr string
	var cliRunErr, otherErr error
	var other *session.Result
	var wg sync.WaitGroup
	wg.Go(func() {
		cliOut, cliErr, cliRunErr = runStderr("sandbox", "run", "--rm", "--name-prefix", prefix, "--keep-inputs-under", parent, "--variant", config.BaseVariant)
	})
	wg.Go(func() {
		other, otherErr = newTestManager("other").KeepInputsUnder(ctx, session.SandboxOptions{Remove: true, NamePrefix: prefix, Variant: config.BaseVariant}, parent)
	})
	wg.Wait()
	if cliRunErr != nil || otherErr != nil {
		t.Fatalf("sandbox run: %v\n%s\nother: %v", cliRunErr, cliErr, otherErr)
	}
	name := strings.TrimSuffix(cliOut, "\n")
	names := []string{name, other.Name}
	slices.Sort(names)
	if want := []string{base, base + "-2"}; !slices.Equal(names, want) {
		t.Fatalf("names = %q (stdout %q), want %q", names, cliOut, want)
	}
	record := filepath.Join(parent, name)
	if !strings.Contains(cliErr, "Recording its inputs in "+filepath.Join(record, session.InputsFile)+"\n") {
		t.Errorf("stderr doesn't name the record:\n%s", cliErr)
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
		fi, err := os.Stat(filepath.Join(parent, e.Name(), session.InputsFile))
		if err != nil || !fi.Mode().IsRegular() {
			t.Errorf("%s holds no record: %v", e.Name(), err)
		}
	}
	if !slices.Equal(got, names) {
		t.Errorf("DIR holds %q, want %q", got, names)
	}
	out, stderr, err := runStderr("sandbox", "inspect", name, "--field", "keep_inputs")
	if err != nil || out != record+"\n" {
		t.Errorf("inspect --field keep_inputs: %q, %v\n%s", out, err, stderr)
	}

	notes := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(notes, []byte("read me\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := m.CopyIn(ctx, name, []string{notes}, ""); err != nil {
		t.Fatal(err)
	}
	if err := d.Remove(ctx, config.ContainerName(name), true); err != nil {
		t.Fatal(err)
	}
	out, stderr, err = runStderr("sandbox", "run", "--rm", "-s", restored, "--restore-from", record, "--variant", config.BaseVariant)
	if err != nil || out != restored+"\n" {
		t.Fatalf("run --restore-from: %q, %v\n%s", out, err, stderr)
	}
	sum, err := d.Exec(ctx, config.ContainerName(restored), docker.ExecOptions{User: config.SandboxUser}, "sha256sum", "/sandbox/in/1-notes.txt")
	h := sha256.Sum256([]byte("read me\n"))
	if err != nil || !strings.HasPrefix(string(sum), hex.EncodeToString(h[:])+" ") {
		t.Errorf("restored file: %q, %v", sum, err)
	}
	out, _, err = runStderr("sandbox", "inspect", restored, "--field", "keep_inputs")
	if err != nil || out != record+"\n" {
		t.Errorf("restored sandbox's keep_inputs: %q, %v", out, err)
	}
}
