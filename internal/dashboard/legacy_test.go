package dashboard

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
	"github.com/josegonzalez/safeclaw/internal/session"
)

// legacyRequest is a dashboard request that acts on the session "work".
type legacyRequest struct {
	method, path string
	form         url.Values
	json         string
}

func (lr legacyRequest) String() string {
	return lr.method + " " + lr.path + " " + lr.form.Encode() + lr.json
}

func (lr legacyRequest) do(h http.Handler) (int, string) {
	if lr.json != "" {
		rec := doJSON(h, lr.path, lr.json)
		return rec.Code, rec.Body.String()
	}
	rec := do(h, lr.method, lr.path, lr.form, nil)
	return rec.Code, rec.Body.String()
}

// legacyRequests are every dashboard action that acts on an existing
// session by name, besides start and create, which Ensure checks.
var legacyRequests = []legacyRequest{
	{method: "POST", path: "/sessions/work/stop"},
	{method: "POST", path: "/sessions/work/stop", form: url.Values{"confirm": {"1"}}},
	{method: "POST", path: "/sessions/work/delete"},
	{method: "POST", path: "/sessions/work/delete", form: url.Values{"confirm": {"1"}, "variant": {"link"}}},
	{method: "POST", path: "/sessions/work/offline", form: url.Values{}},
	{method: "POST", path: "/sessions/work/online", form: url.Values{}},
	{method: "POST", path: "/sessions/work/online", form: url.Values{"force": {"1"}, "confirm_name": {"work"}}},
	{method: "POST", path: "/api/stop", json: `{"name":"work"}`},
	{method: "POST", path: "/api/delete", json: `{"name":"safeclaw-work"}`},
	{method: "POST", path: "/api/net/off", json: `{"name":"work","owner":"triage"}`},
	{method: "POST", path: "/api/net/on", json: `{"name":"work","owner":"triage"}`},
	{method: "GET", path: "/sessions/work/terminal/ws"},
}

// While a container left from a mixed-case name shares the session's
// history, ttyd credential, and network state, every dashboard action on
// the session is refused with 409 and the `docker rm -f` guidance, before
// anything is stopped, removed, or changed, as the CLI refuses them.
func TestActionsRefuseLegacyContainer(t *testing.T) {
	f := &fakeSessions{list: sampleSessions(), legacy: []string{"safeclaw-Work"}}
	terms := &fakeTerminals{}
	s, err := New(Options{Sessions: f, Terminals: terms, Token: testToken, TokenFile: "unused"})
	if err != nil {
		t.Fatal(err)
	}
	h := authed(s.Handler())
	for _, lr := range legacyRequests {
		code, body := lr.do(h)
		if code != http.StatusConflict || !strings.Contains(body, "docker rm -f safeclaw-Work") {
			t.Errorf("%v = %d %s, want 409 naming docker rm -f", lr, code, body)
		}
	}
	if len(f.stopped) > 0 || len(f.deleted) > 0 || len(f.netOffs) > 0 || len(f.netOns) > 0 || terms.calls > 0 {
		t.Errorf("acted on the session: stopped %v, deleted %v, net off %v, net on %v, terminal %d", f.stopped, f.deleted, f.netOffs, f.netOns, terms.calls)
	}
	// The check is made with the canonical name.
	for _, n := range f.resolved {
		if n != "work" {
			t.Errorf("resolved %q", n)
		}
	}

	// Once the old container is removed, the actions go ahead.
	f.mu.Lock()
	f.legacy, f.resolved = nil, nil
	f.mu.Unlock()
	for _, lr := range legacyRequests {
		if code, body := lr.do(h); code == http.StatusConflict || code >= 500 {
			t.Errorf("%v = %d %s", lr, code, body)
		}
	}
	if !slices.Equal(f.stopped, []string{"work", "work"}) || !slices.Equal(f.deleted, []string{"work", "work"}) {
		t.Errorf("stopped %v, deleted %v", f.stopped, f.deleted)
	}
	if len(f.netOffs) != 2 || len(f.netOns) != 3 || terms.calls != 1 {
		t.Errorf("net off %d, net on %d, terminal %d", len(f.netOffs), len(f.netOns), terms.calls)
	}
}

// An invalid name is still refused as invalid, without listing containers.
func TestLegacyCheckSkipsInvalidNames(t *testing.T) {
	f := &fakeSessions{list: sampleSessions(), legacy: []string{"safeclaw-Work"}}
	h := newTestServer(t, f)
	if code, r := postJSON(h, "/api/stop", `{"name":"Work"}`); code != http.StatusBadRequest || !strings.Contains(r.Error, "invalid session name") {
		t.Errorf("/api/stop Work = %d %+v", code, r)
	}
	if len(f.resolved) > 0 {
		t.Errorf("resolved %v", f.resolved)
	}
}

// authed adds the bearer token to requests without one, as newTestServer
// does.
func authed(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			r.Header.Set("Authorization", "Bearer "+testToken)
		}
		h.ServeHTTP(w, r)
	})
}

// legacyDocker fakes docker with the named containers, recording stops and
// removals.
type legacyDocker struct {
	mu    sync.Mutex
	names []string
}

func (d *legacyDocker) handle(args []string, _ string) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case len(args) > 0 && args[0] == "ps":
		return []byte(strings.Join(d.names, "\n")), nil
	case len(args) > 2 && args[0] == "container" && args[1] == "inspect":
		var out []map[string]any
		for _, n := range args[2:] {
			if slices.Contains(d.names, n) {
				out = append(out, map[string]any{"Id": "id-" + n, "Name": "/" + n, "State": map[string]any{"Status": "running", "Running": true}})
			}
		}
		if len(out) == 0 {
			return nil, dockertest.NotFound(args)
		}
		return json.Marshal(out)
	case len(args) > 0 && args[0] == "stop":
		return nil, nil
	case len(args) > 0 && args[0] == "rm":
		d.names = slices.DeleteFunc(d.names, func(n string) bool { return n == args[len(args)-1] })
		return nil, nil
	}
	return nil, dockertest.NotFound(args)
}

// With the real session manager, stop and delete of `work` are refused
// next to safeclaw-Work with the manager's own message, and touch neither
// container, then work once it is removed.
func TestStopDeleteRefuseLegacyContainerManager(t *testing.T) {
	d := &legacyDocker{names: []string{"safeclaw-Work", "safeclaw-work"}}
	r := &dockertest.Runner{Handler: d.handle}
	dir := t.TempDir()
	m := &session.Manager{
		Docker:      r.Client(),
		SessionsDir: filepath.Join(dir, "sessions"),
		TTYDDir:     filepath.Join(dir, "ttyd"),
		NetworkDir:  filepath.Join(dir, "network"),
		Out:         io.Discard,
	}
	s, err := New(Options{Manager: m, Token: testToken, TokenFile: "unused"})
	if err != nil {
		t.Fatal(err)
	}
	h := authed(s.Handler())
	for _, path := range []string{"/api/stop", "/api/delete"} {
		code, res := postJSON(h, path, `{"name":"work"}`)
		if code != http.StatusConflict || res.Success || !strings.Contains(res.Error, "`docker rm -f safeclaw-Work`") || !strings.Contains(res.Error, session.ErrLegacyName.Error()) {
			t.Errorf("%s = %d %+v", path, code, res)
		}
	}
	rec := do(h, "POST", "/sessions/work/delete", url.Values{"confirm": {"1"}}, nil)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "docker rm -f safeclaw-Work") {
		t.Errorf("delete = %d %s", rec.Code, rec.Body)
	}
	for _, c := range r.Commands() {
		if strings.HasPrefix(c, "stop ") || strings.HasPrefix(c, "rm ") {
			t.Errorf("ran %q", c)
		}
	}

	d.mu.Lock()
	d.names = []string{"safeclaw-work"}
	d.mu.Unlock()
	for _, path := range []string{"/api/stop", "/api/delete"} {
		if code, res := postJSON(h, path, `{"name":"work"}`); code != http.StatusOK || !res.Success {
			t.Errorf("%s = %d %+v", path, code, res)
		}
	}
	if _, ok := r.Find("rm "); !ok {
		t.Errorf("work was not removed: %v", r.Commands())
	}
}
