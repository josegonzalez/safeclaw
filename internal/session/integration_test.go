//go:build integration

package session

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/secrets"
)

// TestIntegrationLifecycle runs a real session against the local safeclaw
// image: create, check ttyd answers, stop, start, and delete.
func TestIntegrationLifecycle(t *testing.T) {
	d := docker.New()
	ctx := context.Background()
	if id, err := d.ImageID(ctx, config.ImageName); err != nil || id == "" {
		t.Skip("safeclaw image not built; run `safeclaw build` first")
	}

	dir := t.TempDir()
	store := secrets.Store{Dir: filepath.Join(dir, ".secrets")}
	if _, err := store.Set(secrets.ClaudeToken, "integration-dummy"); err != nil {
		t.Fatal(err)
	}
	m := &Manager{
		Docker:      d,
		Secrets:     store,
		SessionsDir: filepath.Join(dir, "sessions"),
		Out:         os.Stdout,
		OpenBrowser: func(string) error { return nil },
	}
	name := fmt.Sprintf("itest-%d", rand.IntN(1_000_000))
	t.Cleanup(func() { _ = d.Remove(ctx, config.ContainerName(name), true) })

	res, err := m.Ensure(ctx, Options{Name: name, NoOpen: true})
	if err != nil {
		t.Fatal(err)
	}
	waitHTTP(t, res.URL)

	if err := m.Stop(ctx, name); err != nil {
		t.Fatal(err)
	}
	res2, err := m.Ensure(ctx, Options{Name: name, NoOpen: true})
	if err != nil {
		t.Fatal(err)
	}
	if res2.Port != res.Port {
		t.Errorf("restart changed port %d -> %d", res.Port, res2.Port)
	}
	waitHTTP(t, res2.URL)

	if err := m.Stop(ctx, name); err != nil {
		t.Fatal(err)
	}
	if err := m.Delete(ctx, name, false); err != nil {
		t.Fatal(err)
	}
	if ok, _ := m.Exists(ctx, name); ok {
		t.Error("container still exists after delete")
	}
}

func waitHTTP(t *testing.T, url string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := http.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	t.Fatalf("ttyd did not answer at %s", url)
}
