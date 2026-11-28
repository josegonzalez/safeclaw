package expand

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

// SchemaVersion is the version of the manifest's layout. Fields, outcomes,
// and flags may be added within a version, but are never renamed, removed,
// or given a new meaning without a new version, so a reader should treat
// an outcome it doesn't know as a container left packed.
const SchemaVersion = 1

// ManifestFile is the manifest's name in the destination.
const ManifestFile = "manifest.json"

// maxManifestSize limits how much of a manifest ReadManifest reads.
const maxManifestSize = 64 << 20

// Manifest is what the runs on a destination did: one record per input and
// per container, every path relative to the destination. It is also the
// state a later run resumes from.
type Manifest struct {
	// Schema is SchemaVersion.
	Schema int `json:"schema"`
	// Status is "ok", and Code 0, for a run that finished, even with
	// containers left packed.
	Status string `json:"status"`
	Code   int    `json:"code"`
	// Options are the policy the last run had.
	Options ManifestOptions `json:"options"`
	// Size is the total size of what was opened, the input copies not
	// included: what counts toward Options.MaxSize.
	Size int64 `json:"size"`
	// Inputs are the copies of the inputs, in the order they were given,
	// across runs.
	Inputs []Input `json:"inputs"`
	// Containers are every email and archive found, each before the
	// containers found in it. A container opened again by a later run
	// keeps its place, and what is found in it comes after the records
	// already there.
	Containers []Container `json:"containers"`
	// Skip are the containers to leave packed, flagged SKIPPED, by path,
	// whether or not they have been found yet.
	Skip []string `json:"skip,omitempty"`
}

// ManifestOptions is the policy a run had.
type ManifestOptions struct {
	Depth   int   `json:"depth"`
	MaxSize int64 `json:"max_size"`
	// Mail is whether emails were opened.
	Mail bool `json:"mail"`
	// Password is whether a password was given; the password itself is
	// never written.
	Password bool `json:"password"`
}

// Input is one input's copy in the destination.
type Input struct {
	// Path is the copy, N-NAME, N counting inputs from 1 and NAME the
	// input's base name made safe as attachment names are.
	Path string `json:"path"`
	Size int64  `json:"size"`
	// Kind is the copy's container kind, "" when it isn't a container.
	Kind string `json:"kind,omitempty"`
	// SHA256 is the hex SHA-256 of the copy's content. An input with the
	// same content as one already in the destination isn't copied again.
	SHA256 string `json:"sha256,omitempty"`
}

// Container is one email or archive. Its Path is its key: it is unique in
// a manifest and stays the same for the same inputs.
type Container struct {
	// Path is the container's file.
	Path string `json:"path"`
	// Kind is KindEmail or the archive format unpack.Detect names.
	Kind string `json:"kind"`
	// Depth is 0 for an input, and one more than the container it was
	// found in, or, inside an email, one more for each forwarded message
	// around it.
	Depth int `json:"depth"`
	// Parent is the container it was found in, "" for an input.
	Parent string `json:"parent,omitempty"`
	// Outcome is one of the Outcome constants.
	Outcome string `json:"outcome"`
	// Flags are the outcome's flag, then for an email the problems its
	// parts had: UNSAFE-NAME, BAD-ENCODING, and MALFORMED.
	Flags []string `json:"flags"`
	// Unpacked is the directory it was opened into, "" when it was left
	// packed.
	Unpacked string `json:"unpacked,omitempty"`
	// Outputs are the files in Unpacked that Run wrote itself rather than
	// took from the container: an email's body.txt and parts.txt. They are
	// never opened as containers.
	Outputs []string `json:"outputs,omitempty"`
	// Code is the exit code safeclaw-unpack or safeclaw-mail would have
	// given for the container's own failure, 0 when it didn't fail.
	Code int `json:"code"`
	// Error says why it was left packed.
	Error string `json:"error,omitempty"`
	// Rejected are the entries that got an archive rejected, with their
	// paths inside the archive as it listed them, which can be unsafe;
	// they are not paths in the destination.
	Rejected []Entry `json:"rejected,omitempty"`
}

// Entry is an archive entry that got the archive rejected.
type Entry struct {
	Type string `json:"type"`
	// Size is null when unknown.
	Size  *int64   `json:"size"`
	Path  string   `json:"path"`
	Flags []string `json:"flags"`
	Link  string   `json:"link,omitempty"`
}

// Check reports an error when m isn't a manifest of SchemaVersion or names
// a path that isn't a clean path inside the destination: every input,
// container, parent, directory, output, and skip must be relative, use
// slashes, and have no empty, ".", or ".." elements, and container paths
// must be unique. Run checks much more before resuming from a manifest.
func (m *Manifest) Check() error {
	if m.Schema != SchemaVersion {
		return fmt.Errorf("manifest schema %d, want %d", m.Schema, SchemaVersion)
	}
	for _, in := range m.Inputs {
		if !fs.ValidPath(in.Path) || in.Path == "." {
			return fmt.Errorf("manifest input %q is not a path inside the destination", in.Path)
		}
	}
	seen := map[string]bool{}
	for _, c := range m.Containers {
		if !fs.ValidPath(c.Path) || c.Path == "." {
			return fmt.Errorf("manifest container %q is not a path inside the destination", c.Path)
		}
		if seen[c.Path] {
			return fmt.Errorf("manifest container %q is listed twice", c.Path)
		}
		seen[c.Path] = true
		for _, p := range append([]string{c.Parent, c.Unpacked}, c.Outputs...) {
			if p != "" && (!fs.ValidPath(p) || p == ".") {
				return fmt.Errorf("manifest container %q names %q, which is not a path inside the destination", c.Path, p)
			}
		}
	}
	for _, p := range m.Skip {
		if !fs.ValidPath(p) || p == "." {
			return fmt.Errorf("manifest skip %q is not a path inside the destination", p)
		}
	}
	return nil
}

// ReadManifest reads and checks the manifest in dest, refusing a manifest
// that is a link or not a regular file, is over 64 MiB, or fails Check.
// The paths it names are only checked as names: a reader must still open
// them without following links.
func ReadManifest(dest string) (*Manifest, error) {
	f, err := os.OpenFile(filepath.Join(dest, ManifestFile), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil {
		return nil, err
	} else if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", ManifestFile)
	}
	data, err := io.ReadAll(io.LimitReader(f, maxManifestSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxManifestSize {
		return nil, fmt.Errorf("%s is over %d bytes", ManifestFile, maxManifestSize)
	}
	var m Manifest
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("reading %s: %w", ManifestFile, err)
	}
	if err := m.Check(); err != nil {
		return nil, err
	}
	return &m, nil
}

// writeManifest writes m into root in one step: into a new file with a
// random name, which then replaces the manifest, so a reader or a later
// run sees either the old manifest or the new one, never part of one.
func writeManifest(root string, m *Manifest) error {
	if err := m.Check(); err != nil {
		return err
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	if len(data) >= maxManifestSize {
		return fmt.Errorf("the manifest would be over %d bytes", maxManifestSize)
	}
	f, err := os.CreateTemp(root, ".manifest-*.json")
	if err != nil {
		return err
	}
	_, err = f.Write(append(data, '\n'))
	err = errors.Join(err, f.Chmod(0o644), f.Close())
	if err == nil {
		err = os.Rename(f.Name(), filepath.Join(root, ManifestFile))
	}
	if err != nil {
		_ = os.Remove(f.Name())
	}
	return err
}
