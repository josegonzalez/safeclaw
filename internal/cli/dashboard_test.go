package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDashboardDevRefusesWritableDirectory checks that dashboard --dev
// refuses a group-writable internal/dashboard under the working directory
// before it listens, naming the absolute directory.
func TestDashboardDevRefusesWritableDirectory(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	wd := t.TempDir()
	dir := filepath.Join(wd, "internal", "dashboard")
	for _, sub := range []string{"templates", "static"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(dir, 0o775); err != nil {
		t.Fatal(err)
	}
	t.Chdir(wd)
	abs, err := filepath.Abs(dir)
	if err != nil {
		t.Fatal(err)
	}
	_, err = runCLI(t, "", "dashboard", "--dev", "--port", "1")
	if err == nil || !strings.Contains(err.Error(), abs+": it is group- or world-writable") {
		t.Errorf("dashboard --dev = %v", err)
	}
}
