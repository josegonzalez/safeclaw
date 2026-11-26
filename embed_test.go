package safeclaw

import (
	"io/fs"
	"testing"
)

func TestBuildContextHasEverythingTheDockerfileNeeds(t *testing.T) {
	for _, path := range []string{
		"Dockerfile",
		".dockerignore",
		"go.mod",
		"go.sum",
		"setup/.bashrc",
		"setup/CLAUDE.md",
		"setup/settings.json",
		"setup/skills/gdoc/SKILL.md",
		"cmd/safeclaw/main.go",
		"internal/cli/root.go",
		"internal/dashboard/static/htmx.min.js",
	} {
		if _, err := fs.Stat(BuildContext, path); err != nil {
			t.Errorf("embedded build context is missing %s: %v", path, err)
		}
	}
}
