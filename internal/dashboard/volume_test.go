package dashboard

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeHome points HOME at a new directory with a safeclaw config directory
// and a project in it, and returns the home.
func fakeHome(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_RUNTIME_DIR", "")
	t.Setenv("DOCKER_HOST", "")
	for _, d := range []string{filepath.Join(home, ".config", "safeclaw", "ttyd"), filepath.Join(home, "proj")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	return home
}

// unsafeVolumes expose the config directory of the home fakeHome made.
func unsafeVolumes(t *testing.T, home string) []string {
	link := filepath.Join(t.TempDir(), "home")
	if err := os.Symlink(home, link); err != nil {
		t.Fatal(err)
	}
	return []string{"~:/h", "~/.config:/c", "~/.config/safeclaw:/s", "~/.config/safeclaw/ttyd:/t", link + ":/h"}
}

func TestCreateRefusesConfigDirVolume(t *testing.T) {
	home := fakeHome(t)
	f := &fakeSessions{list: sampleSessions()}
	h := newTestServer(t, f)
	for _, v := range unsafeVolumes(t, home) {
		rec := do(h, "POST", "/sessions", url.Values{"name": {"new"}, "volume": {v}}, nil)
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "config directory") {
			t.Errorf("%s: %d %s", v, rec.Code, rec.Body)
		}
	}
	if len(f.ensured) != 0 {
		t.Fatalf("refused volume reached Ensure: %+v", f.ensured)
	}
	if rec := do(h, "POST", "/sessions", url.Values{"name": {"new"}, "volume": {"~/proj:/home/sclaw/proj"}}, nil); rec.Code != http.StatusNoContent || len(f.ensured) != 1 {
		t.Errorf("project: %d %s", rec.Code, rec.Body)
	}
}

func TestAPICreateRefusesConfigDirVolume(t *testing.T) {
	home := fakeHome(t)
	f := &fakeSessions{list: sampleSessions()}
	h := newTestServer(t, f)
	for _, v := range unsafeVolumes(t, home) {
		code, r := postJSON(h, "/api/create", `{"name":"new","volume":"`+v+`"}`)
		if code != http.StatusBadRequest || r.Success || !strings.Contains(r.Error, "config directory") {
			t.Errorf("%s = %d %+v", v, code, r)
		}
	}
	// With recreate, an existing session's start is refused the same way.
	if code, r := postJSON(h, "/api/create", `{"name":"work","volume":"~:/h","recreate":true}`); code != http.StatusBadRequest || r.Success {
		t.Errorf("recreate = %d %+v", code, r)
	}
	if len(f.ensured) != 0 {
		t.Fatalf("refused volume reached Ensure: %+v", f.ensured)
	}
	if code, r := postJSON(h, "/api/create", `{"name":"new","volume":"~/proj:/home/sclaw/proj"}`); code != http.StatusOK || !r.Success || len(r.Warnings) != 0 {
		t.Errorf("project = %d %+v", code, r)
	}
}

func TestCreateWarnsAboutRuntimeSocket(t *testing.T) {
	home := fakeHome(t)
	sock := filepath.Join(home, "docker.sock")
	if err := os.WriteFile(sock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("DOCKER_HOST", "unix://"+sock)
	f := &fakeSessions{list: sampleSessions()}
	h := newTestServer(t, f)
	volume := sock + ":/var/run/docker.sock"

	rec := do(h, "POST", "/sessions", url.Values{"name": {"new"}, "volume": {volume}, "open_tab": {"1"}}, nil)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "container runtime socket "+sock) || !strings.Contains(body, `href="/sessions/new/terminal"`) {
		t.Errorf("form: %d %s", rec.Code, body)
	}
	if trig := rec.Header().Get("HX-Trigger"); !strings.Contains(trig, "sessions") || strings.Contains(trig, "session-created") {
		t.Errorf("trigger = %s", trig)
	}

	code, r := postJSON(h, "/api/create", `{"name":"other","volume":"`+volume+`"}`)
	if code != http.StatusOK || !r.Success || len(r.Warnings) != 1 || !strings.Contains(r.Warnings[0], sock) {
		t.Errorf("api = %d %+v", code, r)
	}
	if len(f.ensured) != 2 {
		t.Errorf("ensured %+v", f.ensured)
	}
}
