package safeclaw

import (
	"io/fs"
	"regexp"
	"strings"
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

// fetchingFiles returns the Dockerfile and every skill, the files whose
// commands fetch build or runtime inputs.
func fetchingFiles(t *testing.T) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := fs.WalkDir(BuildContext, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path != "Dockerfile" && (d.IsDir() || !strings.HasPrefix(path, "setup/skills/")) {
			return nil
		}
		b, err := fs.ReadFile(BuildContext, path)
		if err != nil {
			return err
		}
		files[path] = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestDockerfilePinsBaseImagesByDigest(t *testing.T) {
	b, err := fs.ReadFile(BuildContext, "Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	matches := regexp.MustCompile(`(?m)^FROM\s+(\S+)`).FindAllStringSubmatch(string(b), -1)
	if len(matches) == 0 {
		t.Fatal("Dockerfile has no FROM lines")
	}
	pinned := regexp.MustCompile(`^[^@\s]+:[^@\s]+@sha256:[0-9a-f]{64}$`)
	for _, m := range matches {
		if !pinned.MatchString(m[1]) {
			t.Errorf("FROM %s is not pinned by tag and digest", m[1])
		}
	}
}

func TestBuildInputsAreFetchedSafely(t *testing.T) {
	curl := regexp.MustCompile(`curl\s+(-\S+)`)
	for path, body := range fetchingFiles(t) {
		for _, m := range curl.FindAllStringSubmatch(body, -1) {
			if !strings.Contains(m[1], "f") {
				t.Errorf("%s: %q does not fail on HTTP errors (-f)", path, m[0])
			}
		}
		for _, bad := range []string{"releases/latest", "/main/", "chmod -R 777"} {
			if strings.Contains(body, bad) {
				t.Errorf("%s contains %q", path, bad)
			}
		}
	}
}
