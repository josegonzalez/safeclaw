// Package version holds build information injected with -ldflags.
package version

import "strings"

// Set at build time with -ldflags "-X github.com/josegonzalez/safeclaw/internal/version.Version=...".
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

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
