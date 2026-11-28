//go:build integration

package session

import (
	"context"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/variant"
)

// TestIntegrationSandboxTotextReplace runs safeclaw-totext --recursive in
// a sandbox of the sandbox variant over two exec calls: the first converts
// a tree, and the second, after the tree changed, is refused without
// --replace and replaces the earlier results with it. OUTDIRs holding
// something the manifest doesn't list, or a changed manifest, are then
// refused and left as they were.
func TestIntegrationSandboxTotextReplace(t *testing.T) {
	d := docker.New()
	ctx := context.Background()
	if id, err := d.ImageID(ctx, variant.Image(variant.Sandbox)); err != nil || id == "" {
		t.Skip("sandbox variant not built; run `safeclaw build --variant sandbox` first")
	}
	m := &Manager{Docker: d}
	name := "itest-totext-replace"
	container := config.ContainerName(name)
	_ = d.Remove(ctx, container, true)
	t.Cleanup(func() { _ = d.Remove(context.Background(), container, true) })
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: name}); err != nil {
		t.Fatal(err)
	}
	run := func(script string) string {
		t.Helper()
		out, err := d.Exec(ctx, container, copyExec, SandboxCommand([]string{"sh", "-c", script})...)
		if err != nil {
			t.Fatalf("%v\n%s", err, out)
		}
		return string(out)
	}
	first := run(`
mkdir -p tree/sub && printf 'one\n' > tree/a.txt && printf 'two\n' > tree/sub/b.txt || exit
safeclaw-totext --recursive tree text >/dev/null; echo "first=$?"
ls -1 text
`)
	second := run(`
rm tree/a.txt && printf 'three \033[2J\n' > tree/c.txt || exit
safeclaw-totext --recursive tree text >/dev/null; echo "plain=$?"
safeclaw-totext --recursive --replace tree text; echo "replace=$?"
ls -1 text
echo "--- beside"
ls -1A /sandbox
echo "--- unlisted"
cp -R text extra && printf 'mine\n' > extra/notes.md && ln -s /sandbox/tree extra/link || exit
safeclaw-totext --recursive --replace tree extra >/dev/null; echo "unlisted=$?"
ls -1 extra/link/ | tr '\n' ' '; cat extra/notes.md
echo "--- tampered"
cp -R text tampered && sed -i 's/001-c.txt.text.txt/..\/tree\/c.txt/' tampered/manifest.txt && cp tampered/manifest.txt before.txt || exit
safeclaw-totext --recursive --replace tree tampered >/dev/null; echo "tampered=$?"
cmp -s tampered/manifest.txt before.txt && test -f tree/c.txt && echo unchanged
`)
	for _, c := range []struct{ out, want string }{
		{first, "first=0\n001-a.txt.text.txt\n002-sub_b.txt.text.txt\nmanifest.txt\n"},
		{second, "plain=1\n"},
		{second, "plain=1\ntree\tok\t2\t"},
		{second, "\nfile\t001\tc.txt\tok\ttext\t"},
		{second, "replace=0\n001-c.txt.text.txt\n002-sub_b.txt.text.txt\nmanifest.txt\n--- beside\n"},
		{second, "unlisted=1\nc.txt sub mine\n"},
		{second, "tampered=1\nunchanged\n"},
	} {
		if !strings.Contains(c.out, c.want) {
			t.Errorf("output lacks %q:\n%s", c.want, c.out)
		}
	}
	if strings.Contains(second, "\x1b") {
		t.Errorf("output has an escape:\n%q", second)
	}
	// Nothing the run made is left beside OUTDIR.
	beside, _, _ := strings.Cut(second, "--- unlisted\n")
	if _, beside, _ = strings.Cut(beside, "--- beside\n"); strings.Contains(beside, ".text.") {
		t.Errorf("left beside OUTDIR:\n%s", beside)
	}
}
