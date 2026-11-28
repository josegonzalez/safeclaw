package cli

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const fakeGH = `#!/bin/sh
echo "$*" >> "$GH_LOG"
case "$1" in
auth) exit "${GH_AUTH_EXIT:-0}" ;;
attestation)
	if [ -n "$GH_FAIL" ]; then
		case "$3" in *"$GH_FAIL"*) echo "no attestations found" >&2; exit 1 ;; esac
	fi
	echo "verified" ;;
esac
`

var (
	baseDigest    = "sha256:" + strings.Repeat("a", 64)
	sandboxDigest = "sha256:" + strings.Repeat("b", 64)
)

// withFakeGH puts a fake gh alone on PATH and returns the file its calls
// are logged to.
func withFakeGH(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "gh"), []byte(fakeGH), 0o755); err != nil {
		t.Fatal(err)
	}
	log := filepath.Join(t.TempDir(), "gh.log")
	t.Setenv("PATH", dir)
	t.Setenv("GH_LOG", log)
	t.Setenv("GH_AUTH_EXIT", "0")
	t.Setenv("GH_FAIL", "")
	return log
}

func ghCalls(t *testing.T, log string) []string {
	t.Helper()
	b, err := os.ReadFile(log)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(b)), "\n")
}

func verifyDigests() map[string]string {
	return map[string]string{
		"ghcr.io/josegonzalez/safeclaw:1.2.3":         baseDigest,
		"ghcr.io/josegonzalez/safeclaw:1.2.3-sandbox": sandboxDigest,
	}
}

func TestPullVerify(t *testing.T) {
	log := withFakeGH(t)
	f := &fakeImages{images: map[string]string{"safeclaw": "base", "safeclaw:docs": "old-docs"}, digests: verifyDigests()}
	r := withFakes(t, f, testConfig)
	out, err := run(t, newPullCommand(), "--tag", "1.2.3", "--variant", "sandbox", "--verify")
	if err != nil {
		t.Fatal(err)
	}
	got := calls(r)
	want := []string{
		"pull ghcr.io/josegonzalez/safeclaw@" + baseDigest,
		"tag ghcr.io/josegonzalez/safeclaw@" + baseDigest + " safeclaw",
		"build -t safeclaw:docs --build-arg BASE=safeclaw /",
		"pull ghcr.io/josegonzalez/safeclaw@" + sandboxDigest,
		"tag ghcr.io/josegonzalez/safeclaw@" + sandboxDigest + " safeclaw:sandbox",
	}
	if len(got) != len(want) {
		t.Fatalf("calls = %v", got)
	}
	for i := range want {
		if !strings.HasPrefix(got[i], want[i]) {
			t.Errorf("call %d = %q, want %q", i, got[i], want[i])
		}
	}
	for _, ref := range []string{"ghcr.io/josegonzalez/safeclaw:1.2.3", "ghcr.io/josegonzalez/safeclaw:1.2.3-sandbox"} {
		if _, ok := r.Find("buildx imagetools inspect " + ref + " "); !ok {
			t.Errorf("%s was not resolved: %v", ref, r.Commands())
		}
	}
	flags := " --repo josegonzalez/safeclaw --signer-workflow josegonzalez/safeclaw/.github/workflows/release.yml"
	wantGH := []string{
		"auth status",
		"attestation verify oci://ghcr.io/josegonzalez/safeclaw@" + baseDigest + flags,
		"attestation verify oci://ghcr.io/josegonzalez/safeclaw@" + sandboxDigest + flags,
	}
	if gh := ghCalls(t, log); !slices.Equal(gh, wantGH) {
		t.Errorf("gh calls = %q, want %q", gh, wantGH)
	}
	if !strings.Contains(out, "Verified ghcr.io/josegonzalez/safeclaw:1.2.3 ("+baseDigest+")") ||
		!strings.Contains(out, "Tagged ghcr.io/josegonzalez/safeclaw@"+sandboxDigest+" as safeclaw:sandbox") {
		t.Errorf("out = %q", out)
	}
}

func TestPullWithoutVerify(t *testing.T) {
	log := withFakeGH(t)
	r := withFakes(t, &fakeImages{digests: verifyDigests()}, "")
	if _, err := run(t, newPullCommand(), "--tag", "1.2.3"); err != nil {
		t.Fatal(err)
	}
	if gh := ghCalls(t, log); gh != nil {
		t.Errorf("gh called: %q", gh)
	}
	if _, ok := r.Find("buildx"); ok {
		t.Errorf("resolved a digest: %v", r.Commands())
	}
	if got := calls(r); len(got) != 2 || got[0] != "pull ghcr.io/josegonzalez/safeclaw:1.2.3" {
		t.Errorf("calls = %v", got)
	}
}

func TestPullVerifyRefused(t *testing.T) {
	for _, tc := range []struct {
		name    string
		setup   func(t *testing.T)
		digests map[string]string
		want    string
		pulled  int
	}{
		{
			name:  "no gh",
			setup: func(t *testing.T) { t.Setenv("PATH", t.TempDir()) },
			want:  "needs the GitHub CLI (gh) on your PATH",
		},
		{
			name:  "not logged in",
			setup: func(t *testing.T) { t.Setenv("GH_AUTH_EXIT", "1") },
			want:  "run `gh auth login`",
		},
		{
			name:  "base not attested",
			setup: func(t *testing.T) { t.Setenv("GH_FAIL", baseDigest) },
			want:  "no attestations found",
		},
		{
			// The base image is already pulled when the variant fails.
			name:   "variant not attested",
			setup:  func(t *testing.T) { t.Setenv("GH_FAIL", sandboxDigest) },
			want:   "no attestations found",
			pulled: 2,
		},
		{
			name:    "bad digest",
			digests: map[string]string{"ghcr.io/josegonzalez/safeclaw:1.2.3": "sha256:nope"},
			want:    "unexpected digest",
		},
		{
			name:    "unresolved",
			digests: map[string]string{},
			want:    "needs docker buildx",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			withFakeGH(t)
			if tc.setup != nil {
				tc.setup(t)
			}
			digests := tc.digests
			if digests == nil {
				digests = verifyDigests()
			}
			r := withFakes(t, &fakeImages{digests: digests}, "")
			_, err := run(t, newPullCommand(), "--tag", "1.2.3", "--variant", "sandbox", "--verify")
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if got := calls(r); len(got) != tc.pulled {
				t.Errorf("calls = %v", got)
			}
		})
	}
}
