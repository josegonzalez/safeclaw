package expand

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/josegonzalez/safeclaw/internal/mail"
	"github.com/josegonzalez/safeclaw/internal/unpack"
)

// FlagNew is the flag Plan gives an input that isn't in the destination
// yet. It is never in a manifest.
const FlagNew = "NEW"

// PlanItem is a container Plan lists.
type PlanItem struct {
	// Container is its record, or for a new input its path and kind as a
	// run would record them, with no outcome and the flag NEW, or SKIPPED
	// when the skip list has its path.
	Container
	// Listed is set for a container a later run could open: one that
	// needed a password, was too large, failed, or was skipped, or a new
	// input. Its entries or parts follow, or ListError says why they
	// couldn't be listed.
	Listed bool
	// Entries are an archive's entries, as `safeclaw-unpack list` lists
	// them.
	Entries []unpack.Entry
	// Parts are an email's parts, as `safeclaw-mail list` lists them.
	Parts     []mail.Part
	ListError string
}

// Plan returns the containers in dest not opened yet, in the manifest's
// order, then the new inputs among inputs, without opening or changing
// anything. Rejected containers and those past the depth limit are
// returned without a listing, since a later run keeps them packed; every
// other container left packed is listed with Options.Runner and
// Options.Password. The manifest is checked as Run checks it, and with no
// manifest dest must be missing or an empty directory and inputs given.
// Options.Depth and Options.NoMail must be the destination's; skips and
// the size limit aren't used.
func Plan(ctx context.Context, inputs []string, dest string, o Options) ([]PlanItem, error) {
	if len(o.Skip) > 0 || len(o.Unskip) > 0 {
		return nil, errors.New("a plan doesn't change the skip list")
	}
	if err := checkOptions(inputs, o); err != nil {
		return nil, err
	}
	st, err := openStateLocked(dest, false)
	if err != nil {
		return nil, err
	}
	defer st.close()
	m := &Manifest{Options: ManifestOptions{Depth: o.Depth, Mail: !o.NoMail}}
	if st != nil {
		m = st.m
		if err := checkPolicy(m.Options, o); err != nil {
			return nil, err
		}
	} else {
		if names, err := os.ReadDir(dest); err == nil && len(names) > 0 {
			return nil, fmt.Errorf("%s is not empty", dest)
		} else if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
		if len(inputs) == 0 {
			return nil, errors.New("no inputs, and no manifest in the destination to plan from")
		}
	}
	skip := map[string]bool{}
	for _, p := range m.Skip {
		skip[p] = true
	}
	items := []PlanItem{}
	for _, c := range m.Containers {
		if c.Outcome == OutcomeUnpacked {
			continue
		}
		it := PlanItem{Container: c}
		if c.Outcome != OutcomeRejected && c.Outcome != OutcomeDepthLimit {
			list(ctx, &it, filepath.Join(st.root, filepath.FromSlash(c.Path)), o)
		}
		items = append(items, it)
	}
	have := map[string]bool{}
	for _, in := range m.Inputs {
		if in.SHA256 != "" {
			have[inputKey(in.Path, in.SHA256)] = true
		}
	}
	n := len(m.Inputs)
	for _, in := range inputs {
		p := fmt.Sprintf("%d-%s", n+1, inputName(in))
		_, sum, err := hashFile(in)
		if err != nil {
			return nil, err
		}
		if have[inputKey(p, sum)] {
			continue
		}
		have[inputKey(p, sum)] = true
		n++
		real, err := filepath.EvalSymlinks(in)
		if err != nil {
			return nil, err
		}
		kind, err := detectKind(real, o.NoMail)
		if err != nil {
			return nil, err
		}
		if kind == "" {
			continue
		}
		it := PlanItem{Container: Container{Path: p, Kind: kind, Flags: []string{FlagNew}}}
		if skip[p] {
			it.Outcome, it.Flags = OutcomeSkipped, []string{FlagSkipped}
		}
		list(ctx, &it, real, o)
		items = append(items, it)
	}
	return items, nil
}

// list lists the container it, at p, into it.
func list(ctx context.Context, it *PlanItem, p string, o Options) {
	it.Listed = true
	if it.Kind == KindEmail {
		res, err := mail.List(ctx, p, mail.Options{Depth: max(o.Depth-it.Depth, 0)})
		if err != nil {
			it.ListError = err.Error()
			return
		}
		it.Parts = res.Parts
		return
	}
	if o.Runner == nil {
		it.ListError = "7z not found on PATH; it is in the sandbox image variant (the 7zip package)"
		return
	}
	l, err := unpack.List(ctx, o.Runner, p, o.Password)
	if err != nil {
		it.ListError = err.Error()
		return
	}
	it.Entries = l.Entries
}
