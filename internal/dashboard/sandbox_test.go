package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/session"
)

func withSandboxes() []session.Session {
	return append(sampleSessions(),
		session.Session{Container: "safeclaw-box", Name: "box", Active: true, Volume: "/in:/in", Type: "sandbox"},
		session.Session{Container: "safeclaw-crate", Name: "crate", Volume: "-", Type: "sandbox"},
		session.Session{Container: "safeclaw-tmp-1", Name: "tmp-1", Active: true, Volume: "-", Type: "sandbox", AutoRemove: true},
	)
}

// refuseSandboxes mimics Manager.Ensure refusing a sandbox name.
func refuseSandboxes(o session.Options) (*session.Result, error) {
	if o.Name == "box" || o.Name == "crate" {
		return nil, fmt.Errorf("session %q %w", o.Name, session.ErrIsSandbox)
	}
	return &session.Result{Name: o.Name, URL: "http://localhost:7690", Port: 7690}, nil
}

func TestSandboxRowsAreReadOnly(t *testing.T) {
	h := newTestServer(t, &fakeSessions{list: withSandboxes()})
	body := do(h, "GET", "/fragments/sessions", nil, nil).Body.String()
	for _, want := range []string{
		`<span class="session-name">box</span> <span class="badge"`,
		`hx-post="/sessions/box/stop"`,
		`hx-post="/sessions/crate/delete"`,
		`/in:/in`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("sessions missing %q", want)
		}
	}
	for _, bad := range []string{
		`/sessions/box/info`,
		`/sessions/crate/info`,
		`hx-post="/sessions/crate/start"`,
	} {
		if strings.Contains(body, bad) {
			t.Errorf("sandbox row should not have %q", bad)
		}
	}
	frames := do(h, "GET", "/fragments/frames", nil, nil).Body.String()
	if strings.Contains(frames, "safeclaw-box") {
		t.Error("sandbox should not get an iframe")
	}
}

func TestSandboxStartAndInfoConflict(t *testing.T) {
	f := &fakeSessions{list: withSandboxes(), ensureFn: refuseSandboxes}
	h := newTestServer(t, f)

	rec := do(h, "POST", "/sessions/crate/start", url.Values{}, nil)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "is a sandbox") {
		t.Errorf("start: %d %s", rec.Code, rec.Body)
	}
	rec = do(h, "GET", "/sessions/box/info", nil, nil)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "is a sandbox") || strings.Contains(rec.Body.String(), "tmux attach") {
		t.Errorf("info: %d %s", rec.Code, rec.Body)
	}
	// Stop and delete still work on sandboxes.
	if rec := do(h, "POST", "/sessions/box/stop", url.Values{"confirm": {"1"}}, nil); rec.Code != http.StatusNoContent || f.stopped[0] != "box" {
		t.Errorf("stop: %d %v", rec.Code, f.stopped)
	}
	if rec := do(h, "POST", "/sessions/crate/delete", url.Values{"confirm": {"1"}}, nil); rec.Code != http.StatusNoContent || f.deleted[0] != "crate" {
		t.Errorf("delete: %d %v", rec.Code, f.deleted)
	}
	// A sandbox name is taken for new sessions.
	rec = do(h, "POST", "/sessions", url.Values{"name": {"box"}}, nil)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "already seems to exist") {
		t.Errorf("create: %d %s", rec.Code, rec.Body)
	}
}

func TestSandboxJSONAPI(t *testing.T) {
	h := newTestServer(t, &fakeSessions{list: withSandboxes(), ensureFn: refuseSandboxes})

	var list []apiSession
	_ = json.Unmarshal(do(h, "GET", "/api/sessions", nil, nil).Body.Bytes(), &list)
	if len(list) != 5 || list[2].Name != "safeclaw-box" || list[2].Type != "sandbox" || list[2].Port != nil || list[2].URL != nil {
		t.Errorf("api sessions = %+v", list)
	}
	if list[2].AutoRemove || !list[4].AutoRemove || list[4].Name != "safeclaw-tmp-1" {
		t.Errorf("api autoRemove = %+v", list)
	}

	for _, path := range []string{"/api/start", "/api/create"} {
		req := httptest.NewRequest("POST", "http://localhost:7680"+path, strings.NewReader(`{"name":"box"}`))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var r apiResult
		_ = json.Unmarshal(rec.Body.Bytes(), &r)
		if rec.Code != http.StatusConflict || r.Success || !strings.Contains(r.Error, "is a sandbox") {
			t.Errorf("%s = %d %+v", path, rec.Code, r)
		}
	}
}

func TestOneOffSandboxBadge(t *testing.T) {
	h := newTestServer(t, &fakeSessions{list: withSandboxes()})
	body := do(h, "GET", "/fragments/sessions", nil, nil).Body.String()
	badge := `<span class="badge" title="one-off sandbox: removed when stopped">one-off</span>`
	if strings.Count(body, badge) != 1 {
		t.Errorf("want one one-off badge, got %d", strings.Count(body, badge))
	}
	_, row, ok := strings.Cut(body, `id="row-safeclaw-tmp-1"`)
	row, _, _ = strings.Cut(row, "</tr>")
	if !ok || !strings.Contains(row, badge) || !strings.Contains(row, `hx-post="/sessions/tmp-1/stop"`) {
		t.Errorf("one-off row = %s", row)
	}
}
