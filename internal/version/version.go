// Package version holds build information injected with -ldflags.
package version

import (
	"fmt"
	"strconv"
	"strings"
)

// Set at build time with -ldflags "-X github.com/josegonzalez/safeclaw/internal/version.Version=...".
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// Schema is the version of the Info JSON: fields may be added within a
// schema version, but are never renamed, removed, or given a new meaning
// without a new one.
const Schema = 1

// Info is the build information printed by `safeclaw version --json`.
type Info struct {
	Schema  int    `json:"schema"`
	Version string `json:"version"`
	Commit  string `json:"commit"`
	Built   string `json:"built"`
}

// Get returns this build's information.
func Get() Info {
	return Info{Schema: Schema, Version: Version, Commit: Commit, Built: Date}
}

// String returns a one-line description of the build.
func String() string {
	return Version + " (commit " + Commit + ", built " + Date + ")"
}

// ImageTag returns the published image tag matching this build: the version
// without its "v" prefix, or "latest" for dev builds.
func ImageTag() string {
	if Version == "" || Version == "dev" || strings.Contains(Version, "SNAPSHOT") {
		return "latest"
	}
	return strings.TrimPrefix(Version, "v")
}

// Release is a release version, MAJOR.MINOR.PATCH.
type Release [3]uint64

func (r Release) String() string {
	return fmt.Sprintf("%d.%d.%d", r[0], r[1], r[2])
}

// Compare returns -1, 0, or 1 as r is older than, the same as, or newer
// than o.
func (r Release) Compare(o Release) int {
	for i := range r {
		switch {
		case r[i] < o[i]:
			return -1
		case r[i] > o[i]:
			return 1
		}
	}
	return 0
}

// ParseRelease parses a release version, MAJOR.MINOR.PATCH with an optional
// leading "v", such as 0.3.0 or v0.3.0. Anything else, including
// pre-releases, git describe output, and snapshots, is refused.
func ParseRelease(s string) (Release, error) {
	var r Release
	parts := strings.Split(strings.TrimPrefix(s, "v"), ".")
	if len(parts) != len(r) {
		return r, fmt.Errorf("invalid version %q: want MAJOR.MINOR.PATCH, such as 0.3.0", s)
	}
	for i, p := range parts {
		if p == "" || strings.Trim(p, "0123456789") != "" || (len(p) > 1 && p[0] == '0') {
			return r, fmt.Errorf("invalid version %q: want MAJOR.MINOR.PATCH, such as 0.3.0", s)
		}
		n, err := strconv.ParseUint(p, 10, 64)
		if err != nil {
			return r, fmt.Errorf("invalid version %q: %w", s, err)
		}
		r[i] = n
	}
	return r, nil
}

// Require checks that the installed version, v, is at least required, a
// release version that has already been parsed. A v that is not a release
// version, such as a development build, fails, since its version is
// unknown.
func Require(v string, required Release) error {
	installed, err := ParseRelease(v)
	if err != nil {
		return fmt.Errorf("safeclaw %s is a development build with no release version, so it can't be checked against the required %s", v, required)
	}
	if installed.Compare(required) < 0 {
		return fmt.Errorf("safeclaw %s is older than the required %s", installed, required)
	}
	return nil
}
