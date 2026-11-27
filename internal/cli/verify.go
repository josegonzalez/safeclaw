package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strings"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/termtext"
)

const (
	// attestationRepo is the repository whose release workflow attests the
	// published images.
	attestationRepo = "josegonzalez/safeclaw"
	// signerWorkflow is the workflow an image's attestation must be signed by.
	signerWorkflow = attestationRepo + "/.github/workflows/release.yml"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

// verifier checks published images' build provenance attestations with
// the GitHub CLI.
type verifier struct {
	gh string
}

// newVerifier finds gh and checks that it is logged in, which
// `gh attestation verify` needs to fetch attestations.
func newVerifier(ctx context.Context) (*verifier, error) {
	gh, err := exec.LookPath("gh")
	if err != nil {
		return nil, errors.New("--verify needs the GitHub CLI (gh) on your PATH: install it from https://cli.github.com, then run `gh auth login`")
	}
	if err := exec.CommandContext(ctx, gh, "auth", "status").Run(); err != nil {
		return nil, errors.New("--verify needs the GitHub CLI to be logged in: run `gh auth login`")
	}
	return &verifier{gh: gh}, nil
}

// verify checks that ref, an image pinned by digest, was attested by the
// release workflow.
func (v *verifier) verify(ctx context.Context, ref string) error {
	var out bytes.Buffer
	c := exec.CommandContext(ctx, v.gh, "attestation", "verify", "oci://"+ref,
		"--repo", attestationRepo, "--signer-workflow", signerWorkflow)
	c.Stdout, c.Stderr = &out, &out
	if err := c.Run(); err != nil {
		msg := strings.TrimSpace(out.String())
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("verify %s: %s (releases before attestations were added have none)", ref, termtext.Escape(msg))
	}
	return nil
}

// resolveDigest returns the registry's manifest digest for ref.
func resolveDigest(ctx context.Context, d *docker.Client, ref string) (string, error) {
	out, err := d.R.Output(ctx, nil, "buildx", "imagetools", "inspect", ref, "--format", "{{json .Manifest}}")
	if err != nil {
		return "", fmt.Errorf("resolve the digest of %s (--verify needs docker buildx): %w", ref, err)
	}
	var m struct {
		Digest string `json:"digest"`
	}
	if err := json.Unmarshal(out, &m); err != nil {
		return "", fmt.Errorf("resolve the digest of %s: %w", ref, err)
	}
	if !digestPattern.MatchString(m.Digest) {
		return "", fmt.Errorf("resolve the digest of %s: unexpected digest %q", ref, termtext.Escape(m.Digest))
	}
	return m.Digest, nil
}

// pullImage pulls ref and tags it as local. With a verifier, ref is first
// resolved to a digest, that digest's attestation is checked, and the image
// is pulled and tagged by that digest, so what runs is what was verified.
func pullImage(ctx context.Context, d *docker.Client, out io.Writer, v *verifier, ref, local string) error {
	if v != nil {
		digest, err := resolveDigest(ctx, d, ref)
		if err != nil {
			return err
		}
		pinned := config.RemoteImage + "@" + digest
		if err := v.verify(ctx, pinned); err != nil {
			return err
		}
		fmt.Fprintf(out, "Verified %s (%s)\n", ref, digest)
		ref = pinned
	}
	if err := d.R.Passthrough(ctx, "pull", ref); err != nil {
		return err
	}
	if err := d.Tag(ctx, ref, local); err != nil {
		return err
	}
	fmt.Fprintf(out, "Tagged %s as %s\n", ref, local)
	return nil
}
