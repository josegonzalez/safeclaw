package session

import (
	"os"
	"testing"
)

// TestMain points the cache directory at a temporary one, so creating
// sandboxes in tests never touches the real signature directory. The
// integration tests that scan with real signatures set
// SAFECLAW_TEST_SIGNATURES and use the real cache directory, where
// `update-signatures` keeps them between runs.
func TestMain(m *testing.M) {
	code := func() int {
		if os.Getenv("SAFECLAW_TEST_SIGNATURES") == "" {
			dir, err := os.MkdirTemp("", "safeclaw-cache-")
			if err != nil {
				panic(err)
			}
			defer func() { _ = os.RemoveAll(dir) }()
			_ = os.Setenv("XDG_CACHE_HOME", dir)
		}
		return m.Run()
	}()
	os.Exit(code)
}
