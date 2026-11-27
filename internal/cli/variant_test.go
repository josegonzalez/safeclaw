package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
	"github.com/josegonzalez/safeclaw/internal/session"
	"github.com/josegonzalez/safeclaw/internal/variant"
)

const testConfig = `
variants:
  docs:
    packages: [pandoc]
  notes:
    run: [echo hi]
`

// fakeImages answers docker calls with the given local images (name to ID)
// and containers (inspect JSON). Pulls of names in failPull fail.
type fakeImages struct {
	images     map[string]string
	containers string
	failPull   map[string]bool
	// digests answers `buildx imagetools inspect` with each ref's
	// manifest digest.
	digests map[string]string
	// dockerfiles records the Dockerfile of each variant build, by tag.
	dockerfiles map[string]string
}

func (f *fakeImages) handle(args []string, _ string) ([]byte, error) {
	switch {
	case args[0] == "image" && args[1] == "inspect":
		if id := f.images[args[len(args)-1]]; id != "" {
			return []byte(id + "\n"), nil
		}
		return nil, dockertest.NotFound(args)
	case args[0] == "buildx" && args[1] == "imagetools" && args[2] == "inspect":
		if d, ok := f.digests[args[3]]; ok {
			return []byte(`{"mediaType":"application/vnd.oci.image.index.v1+json","digest":"` + d + `"}` + "\n"), nil
		}
		return nil, errors.New("not found")
	case args[0] == "pull" && f.failPull[args[1]]:
		return nil, errors.New("manifest unknown")
	case args[0] == "build" && args[1] == "-t" && strings.HasPrefix(args[2], "safeclaw:"):
		b, err := os.ReadFile(filepath.Join(args[len(args)-1], "Dockerfile"))
		if err != nil {
			return nil, err
		}
		f.dockerfiles[args[2]] = string(b)
	case args[0] == "ps":
		if f.containers == "" {
			return nil, nil
		}
		return []byte("safeclaw-a\nsafeclaw-b\n"), nil
	case args[0] == "container" && args[1] == "inspect":
		return f.inspect(args[2:])
	}
	return nil, nil
}

// inspect returns the inspect JSON of the named containers.
func (f *fakeImages) inspect(names []string) ([]byte, error) {
	var all []map[string]any
	if f.containers != "" {
		if err := json.Unmarshal([]byte(f.containers), &all); err != nil {
			return nil, err
		}
	}
	var out []map[string]any
	for _, c := range all {
		if slices.Contains(names, strings.TrimPrefix(fmt.Sprint(c["Name"]), "/")) {
			out = append(out, c)
		}
	}
	if len(out) == 0 {
		return nil, dockertest.NotFound(names)
	}
	return json.Marshal(out)
}

// withFakes swaps in a fake docker and a parsed config for one test.
func withFakes(t *testing.T, f *fakeImages, config string) *dockertest.Runner {
	t.Helper()
	if f.dockerfiles == nil {
		f.dockerfiles = map[string]string{}
	}
	r := &dockertest.Runner{Handler: f.handle}
	set, err := variant.Parse([]byte(config))
	if err != nil {
		t.Fatal(err)
	}
	origDocker, origManager, origLoad := newDocker, newManager, loadVariants
	t.Cleanup(func() { newDocker, newManager, loadVariants = origDocker, origManager, origLoad })
	newDocker = func() *docker.Client { return r.Client() }
	netDir, choicesDir := t.TempDir(), t.TempDir()
	newManager = func() *session.Manager { return &session.Manager{NetworkDir: netDir, ChoicesDir: choicesDir} }
	loadVariants = func() (*variant.Set, error) { return set, nil }
	return r
}

func run(t *testing.T, cmd *cobra.Command, args ...string) (string, error) {
	t.Helper()
	var out strings.Builder
	cmd.SetArgs(args)
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	err := cmd.Execute()
	return out.String(), err
}

// calls returns the recorded build, pull, and tag calls.
func calls(r *dockertest.Runner) []string {
	var out []string
	for _, c := range r.Commands() {
		for _, p := range []string{"build ", "pull ", "tag "} {
			if strings.HasPrefix(c, p) {
				out = append(out, c)
			}
		}
	}
	return out
}

func TestBuildVariants(t *testing.T) {
	// docs is built locally already; notes and sandbox are not.
	f := &fakeImages{images: map[string]string{"safeclaw": "base", "safeclaw:docs": "old-docs"}}
	r := withFakes(t, f, testConfig)
	dir := t.TempDir()
	if _, err := run(t, newBuildCommand(), "--context", dir, "--variant", "sandbox"); err != nil {
		t.Fatal(err)
	}
	got := calls(r)
	if len(got) != 3 || !strings.HasPrefix(got[0], "build -t safeclaw --build-arg VERSION=") || !strings.HasSuffix(got[0], " "+dir) {
		t.Fatalf("calls = %v", got)
	}
	for i, tag := range []string{"safeclaw:docs", "safeclaw:sandbox"} {
		if !strings.HasPrefix(got[i+1], "build -t "+tag+" --build-arg BASE=safeclaw /") {
			t.Errorf("call %d = %q, want a %s build", i+1, got[i+1], tag)
		}
	}
	if !strings.Contains(f.dockerfiles["safeclaw:sandbox"], "tesseract-ocr") || !strings.Contains(f.dockerfiles["safeclaw:docs"], "pandoc") {
		t.Errorf("dockerfiles = %v", f.dockerfiles)
	}

	// --no-cache applies to variants too, and base is not a variant.
	r = withFakes(t, &fakeImages{images: map[string]string{"safeclaw": "base"}}, testConfig)
	if _, err := run(t, newBuildCommand(), "--context", dir, "--no-cache", "--variant", "base,notes"); err != nil {
		t.Fatal(err)
	}
	got = calls(r)
	if len(got) != 2 || !strings.Contains(got[0], " --no-cache ") || !strings.HasPrefix(got[1], "build -t safeclaw:notes --build-arg BASE=safeclaw --no-cache /") {
		t.Errorf("calls = %v", got)
	}

	// An unknown variant fails before anything is built.
	r = withFakes(t, &fakeImages{}, testConfig)
	if _, err := run(t, newBuildCommand(), "--context", dir, "--variant", "nope"); !errors.Is(err, variant.ErrUnknown) {
		t.Errorf("err = %v", err)
	}
	if len(calls(r)) != 0 {
		t.Errorf("built anyway: %v", calls(r))
	}
}

func TestPullVariants(t *testing.T) {
	f := &fakeImages{images: map[string]string{"safeclaw": "base", "safeclaw:docs": "old-docs"}}
	r := withFakes(t, f, testConfig)
	out, err := run(t, newPullCommand(), "--tag", "1.2.3", "--variant", "sandbox")
	if err != nil {
		t.Fatal(err)
	}
	got := calls(r)
	want := []string{
		"pull ghcr.io/josegonzalez/safeclaw:1.2.3",
		"tag ghcr.io/josegonzalez/safeclaw:1.2.3 safeclaw",
		"build -t safeclaw:docs --build-arg BASE=safeclaw /",
		"pull ghcr.io/josegonzalez/safeclaw:1.2.3-sandbox",
		"tag ghcr.io/josegonzalez/safeclaw:1.2.3-sandbox safeclaw:sandbox",
	}
	if len(got) != len(want) {
		t.Fatalf("calls = %v", got)
	}
	for i := range want {
		if !strings.HasPrefix(got[i], want[i]) {
			t.Errorf("call %d = %q, want %q", i, got[i], want[i])
		}
	}
	if !strings.Contains(out, "Tagged ghcr.io/josegonzalez/safeclaw:1.2.3-sandbox as safeclaw:sandbox") {
		t.Errorf("out = %q", out)
	}

	// An overridden built-in is built, not pulled.
	r = withFakes(t, &fakeImages{images: map[string]string{"safeclaw": "base"}}, "variants:\n  sandbox:\n    packages: [file]\n")
	if _, err := run(t, newPullCommand(), "--tag", "latest", "--variant", "sandbox"); err != nil {
		t.Fatal(err)
	}
	got = calls(r)
	if len(got) != 3 || !strings.HasPrefix(got[2], "build -t safeclaw:sandbox ") {
		t.Errorf("calls = %v", got)
	}

	// A tag without the variant suggests building it.
	withFakes(t, &fakeImages{failPull: map[string]bool{"ghcr.io/josegonzalez/safeclaw:0.1.0-sandbox": true}}, "")
	_, err = run(t, newPullCommand(), "--tag", "0.1.0", "--variant", "sandbox")
	if err == nil || !strings.Contains(err.Error(), "`safeclaw build --variant sandbox`") {
		t.Errorf("err = %v", err)
	}
}

func TestReportStaleVariants(t *testing.T) {
	containers := `[
		{"Name": "/safeclaw-a", "Image": "base", "Config": {"Labels": {}}},
		{"Name": "/safeclaw-b", "Image": "old-sb", "Config": {"Labels": {"safeclaw.type": "sandbox", "safeclaw.variant": "sandbox"}}}
	]`
	f := &fakeImages{images: map[string]string{"safeclaw": "base", "safeclaw:sandbox": "new-sb"}, containers: containers}
	r := withFakes(t, f, "")
	var out strings.Builder
	if err := reportStale(t.Context(), r.Client(), &out, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "  a\n") || !strings.Contains(out.String(), "  b (sandbox)\n") {
		t.Errorf("out = %q", out.String())
	}

	// A container whose variant image is gone is stale.
	f.images = map[string]string{"safeclaw": "base"}
	f.containers = strings.Replace(containers, "old-sb", "new-sb", 1)
	out.Reset()
	if err := reportStale(t.Context(), r.Client(), &out, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "  b (sandbox)\n") {
		t.Errorf("out = %q", out.String())
	}
}

func TestVariantList(t *testing.T) {
	withFakes(t, &fakeImages{images: map[string]string{"safeclaw": "base", "safeclaw:sandbox": "sb"}},
		testConfig+"defaults:\n  session: docs\n")
	out, err := run(t, newVariantCommand(), "ls")
	if err != nil {
		t.Fatal(err)
	}
	want := "VARIANT   SOURCE     PACKAGES                                                  IMAGE                        DEFAULT FOR\n" +
		"base      built-in   -                                                         safeclaw (present)           -\n" +
		"docs      config     pandoc                                                    safeclaw:docs (missing)      session\n" +
		"notes     config     (+1 run)                                                  safeclaw:notes (missing)     -\n" +
		"sandbox   built-in   7zip file poppler-utils tesseract-ocr tesseract-ocr-eng   safeclaw:sandbox (present)   sandbox\n"
	if out != want {
		t.Errorf("variant ls =\n%s\nwant\n%s", out, want)
	}
}

func TestVariantDockerfile(t *testing.T) {
	withFakes(t, &fakeImages{}, testConfig)
	out, err := run(t, newVariantCommand(), "dockerfile", "docs")
	if err != nil {
		t.Fatal(err)
	}
	v, _ := variant.Default().Get("sandbox")
	if !strings.Contains(out, "install -y --no-install-recommends pandoc") || strings.Contains(out, variant.Dockerfile(v)) {
		t.Errorf("dockerfile = %q", out)
	}
	if _, err := run(t, newVariantCommand(), "dockerfile", "nope"); !errors.Is(err, variant.ErrUnknown) {
		t.Errorf("err = %v", err)
	}
}

func TestReportStaleSkipsOffline(t *testing.T) {
	containers := `[
		{"Id": "a1", "Name": "/safeclaw-a", "Image": "old", "Config": {"Labels": {}}, "HostConfig": {"NetworkMode": "bridge"}, "NetworkSettings": {"Networks": {}}},
		{"Id": "b1", "Name": "/safeclaw-b", "Image": "old", "Config": {"Labels": {}}, "HostConfig": {"NetworkMode": "bridge"}, "NetworkSettings": {"Networks": {"bridge": {}}}}
	]`
	f := &fakeImages{images: map[string]string{"safeclaw": "new"}, containers: containers}
	r := withFakes(t, f, "")
	var out strings.Builder
	if err := reportStale(t.Context(), r.Client(), &out, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "  a (offline)\n") || !strings.Contains(out.String(), "  b\n") {
		t.Errorf("out = %q", out.String())
	}

	out.Reset()
	if err := reportStale(t.Context(), r.Client(), &out, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Skipping offline session: a") {
		t.Errorf("out = %q", out.String())
	}
	if _, ok := r.Find("rm -v -f safeclaw-a"); ok {
		t.Error("offline session removed")
	}
	if _, ok := r.Find("rm -v -f safeclaw-b"); !ok {
		t.Error("online stale session not removed")
	}
}

func TestReportStaleSkipsHeld(t *testing.T) {
	// b is held offline but still attached, as after a failed disconnect.
	containers := `[
		{"Id": "a1", "Name": "/safeclaw-a", "Image": "old", "Config": {"Labels": {}}, "HostConfig": {"NetworkMode": "bridge"}, "NetworkSettings": {"Networks": {"bridge": {}}}},
		{"Id": "b1", "Name": "/safeclaw-b", "Image": "old", "Config": {"Labels": {}}, "HostConfig": {"NetworkMode": "bridge"}, "NetworkSettings": {"Networks": {"bridge": {}}}}
	]`
	f := &fakeImages{images: map[string]string{"safeclaw": "new"}, containers: containers}
	r := withFakes(t, f, "")
	dir := newManager().NetworkDir
	state := filepath.Join(dir, "b.json")
	if err := os.WriteFile(state, []byte(`{"containerId": "b1", "networks": [{"name": "bridge"}], "holds": [{"owner": "job"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := reportStale(t.Context(), r.Client(), &out, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "  a\n") || !strings.Contains(out.String(), "  b (offline)\n") {
		t.Errorf("out = %q", out.String())
	}

	out.Reset()
	if err := reportStale(t.Context(), r.Client(), &out, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Skipping offline session: b") || !strings.Contains(out.String(), "Removed old container: safeclaw-a") {
		t.Errorf("out = %q", out.String())
	}
	if _, ok := r.Find("rm -v -f safeclaw-b"); ok {
		t.Error("held session removed")
	}
	if _, ok := r.Find("rm -v -f safeclaw-a"); !ok {
		t.Error("online stale session not removed")
	}
	if _, err := os.Stat(state); err != nil {
		t.Errorf("hold state removed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, ".lock")); err != nil {
		t.Errorf("recreate did not take the network lock: %v", err)
	}
}

// A session whose saved state can't be read may be held, so build
// --recreate skips it and goes on with the others.
func TestReportStaleSkipsUnreadableState(t *testing.T) {
	containers := `[
		{"Id": "a1", "Name": "/safeclaw-a", "Image": "old", "Config": {"Labels": {}}, "HostConfig": {"NetworkMode": "bridge"}, "NetworkSettings": {"Networks": {"bridge": {}}}},
		{"Id": "b1", "Name": "/safeclaw-b", "Image": "old", "Config": {"Labels": {}}, "HostConfig": {"NetworkMode": "bridge"}, "NetworkSettings": {"Networks": {"bridge": {}}}}
	]`
	f := &fakeImages{images: map[string]string{"safeclaw": "new"}, containers: containers}
	r := withFakes(t, f, "")
	dir := newManager().NetworkDir
	state := filepath.Join(dir, "b.json")
	if err := os.WriteFile(state, []byte(`{not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := reportStale(t.Context(), r.Client(), &out, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "  b (offline)\n") {
		t.Errorf("out = %q", out.String())
	}

	out.Reset()
	if err := reportStale(t.Context(), r.Client(), &out, true); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), `Skipping session: session "b" may be held offline`) || !strings.Contains(out.String(), "Removed old container: safeclaw-a") {
		t.Errorf("out = %q", out.String())
	}
	if _, ok := r.Find("rm -v -f safeclaw-b"); ok {
		t.Error("session with unreadable state removed")
	}
	if _, err := os.Stat(state); err != nil {
		t.Errorf("state removed: %v", err)
	}
}

// build --recreate keeps the secrets and auto memory choices of the
// sessions it removes, so running them again keeps them.
func TestReportStaleKeepsChoices(t *testing.T) {
	containers := `[
		{"Id": "a1", "Name": "/safeclaw-a", "Image": "old", "Config": {"Labels": {"safeclaw.memory": "off", "safeclaw.secrets": ""}}, "HostConfig": {"NetworkMode": "bridge"}, "NetworkSettings": {"Networks": {"bridge": {}}}},
		{"Id": "b1", "Name": "/safeclaw-b", "Image": "old", "Config": {"Labels": {"safeclaw.type": "sandbox"}}, "HostConfig": {"NetworkMode": "bridge"}, "NetworkSettings": {"Networks": {"bridge": {}}}}
	]`
	f := &fakeImages{images: map[string]string{"safeclaw": "new"}, containers: containers}
	r := withFakes(t, f, "")
	var out strings.Builder
	if err := reportStale(t.Context(), r.Client(), &out, true); err != nil {
		t.Fatal(err)
	}
	if _, ok := r.Find("rm -v -f safeclaw-a"); !ok {
		t.Fatalf("not removed: %v", r.Commands())
	}
	dir := newManager().ChoicesDir
	b, err := os.ReadFile(filepath.Join(dir, "a.json"))
	if err != nil || string(b) != `{"secrets":[],"noMemory":true}`+"\n" {
		t.Errorf("kept choices = %q, %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "b.json")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("sandbox choices kept: %v", err)
	}
}
