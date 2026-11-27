package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/session"
)

// withForeign adds a container named like a session that is neither a
// session nor a sandbox.
func withForeign() []session.Session {
	return append(sampleSessions(), session.Session{Container: "safeclaw-other", Name: "other", Volume: "-", Type: "something-else"})
}

func postJSON(h http.Handler, path, body string) (int, apiResult) {
	req := httptest.NewRequest("POST", "http://localhost:7680"+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var r apiResult
	_ = json.Unmarshal(rec.Body.Bytes(), &r)
	return rec.Code, r
}

func TestStopDeleteCheckTarget(t *testing.T) {
	f := &fakeSessions{list: withForeign()}
	h := newTestServer(t, f)

	for _, kind := range []string{"stop", "delete"} {
		for _, c := range []struct {
			name   string
			status int
		}{
			{"..", http.StatusBadRequest},
			{".hidden", http.StatusBadRequest},
			{"_x", http.StatusBadRequest},
			{"missing", http.StatusNotFound},
			{"other", http.StatusConflict},
		} {
			for _, form := range []url.Values{{}, {"confirm": {"1"}}} {
				if c.name == ".." {
					continue // the mux redirects the cleaned path
				}
				rec := do(h, "POST", "/sessions/"+url.PathEscape(c.name)+"/"+kind, form, nil)
				if rec.Code != c.status {
					t.Errorf("%s %q %v = %d %s", kind, c.name, form, rec.Code, rec.Body)
				}
			}
			code, r := postJSON(h, "/api/"+kind, `{"name":"`+c.name+`"}`)
			if code != c.status || r.Success || r.Error == "" {
				t.Errorf("/api/%s %q = %d %+v", kind, c.name, code, r)
			}
		}
	}
	if len(f.stopped) != 0 || len(f.deleted) != 0 {
		t.Errorf("refused targets reached docker: stopped %v, deleted %v", f.stopped, f.deleted)
	}

	if body := do(h, "POST", "/sessions/other/stop", url.Values{}, nil).Body.String(); !strings.Contains(body, "failed") || !strings.Contains(body, "is not a safeclaw session or sandbox") {
		t.Errorf("foreign type button = %s", body)
	}

	if code, r := postJSON(h, "/api/stop", `{"name":"work"}`); code != http.StatusOK || !r.Success {
		t.Errorf("/api/stop work = %d %+v", code, r)
	}
	if code, r := postJSON(h, "/api/delete", `{"name":"safeclaw-old"}`); code != http.StatusOK || !r.Success {
		t.Errorf("/api/delete old = %d %+v", code, r)
	}
	if len(f.stopped) != 1 || len(f.deleted) != 1 {
		t.Errorf("stopped %v, deleted %v", f.stopped, f.deleted)
	}
}

func TestAPICreateRefusesExisting(t *testing.T) {
	f := &fakeSessions{list: withSandboxes()}
	h := newTestServer(t, f)

	code, r := postJSON(h, "/api/create", `{"name":"work","volume":"/x:/y"}`)
	if code != http.StatusConflict || r.Success || !strings.Contains(r.Error, "set recreate") {
		t.Errorf("existing = %d %+v", code, r)
	}
	if len(f.ensured) != 0 {
		t.Fatalf("existing name reached Ensure: %+v", f.ensured)
	}

	code, r = postJSON(h, "/api/create", `{"name":"work","volume":"/x:/y","recreate":true}`)
	if code != http.StatusOK || !r.Success || len(f.ensured) != 1 || f.ensured[0].Volume != "/x:/y" {
		t.Errorf("recreate = %d %+v %+v", code, r, f.ensured)
	}

	// A sandbox's name is refused whatever recreate says.
	for _, body := range []string{`{"name":"box"}`, `{"name":"box","recreate":true}`} {
		code, r = postJSON(h, "/api/create", body)
		if code != http.StatusConflict || !strings.Contains(r.Error, "is a sandbox") {
			t.Errorf("%s = %d %+v", body, code, r)
		}
	}
	if len(f.ensured) != 1 {
		t.Errorf("sandbox name reached Ensure: %+v", f.ensured)
	}

	if code, r = postJSON(h, "/api/create", `{"name":"fresh"}`); code != http.StatusOK || !r.Success {
		t.Errorf("new name = %d %+v", code, r)
	}
}

func TestButtonVariantRestricted(t *testing.T) {
	h := newTestServer(t, &fakeSessions{list: sampleSessions()})
	evil := `", "confirm": "1`
	for _, rec := range []*httptest.ResponseRecorder{
		do(h, "GET", "/sessions/work/actions?kind=stop&variant="+url.QueryEscape(evil), nil, nil),
		do(h, "POST", "/sessions/work/stop", url.Values{"variant": {evil}}, nil),
	} {
		body := rec.Body.String()
		if strings.Contains(body, "confirm&#34;: &#34;1") || strings.Contains(html.UnescapeString(body), evil) {
			t.Errorf("variant echoed: %s", body)
		}
		if !strings.Contains(body, `class="stop-btn"`) {
			t.Errorf("unknown variant should be the table style: %s", body)
		}
	}
	if body := do(h, "GET", "/sessions/work/actions?kind=stop&variant=link", nil, nil).Body.String(); !strings.Contains(body, `hx-vals='{&#34;variant&#34;:&#34;link&#34;}'`) {
		t.Errorf("link variant = %s", body)
	}
}

func TestHxValsAndPaths(t *testing.T) {
	// hx-vals is marshalled, so a quote in a value stays inside it once
	// the attribute is decoded.
	got, err := hxVals("variant", `x", "confirm": "1`)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	if err := json.Unmarshal([]byte(got), &m); err != nil || len(m) != 1 || m["variant"] != `x", "confirm": "1` {
		t.Errorf("vals = %s %v", got, m)
	}
	if _, err := hxVals("odd"); err == nil {
		t.Error("odd vals accepted")
	}

	for name, want := range map[string]string{
		"work":    "/sessions/work/stop",
		"a/../b":  "/sessions/a%2F..%2Fb/stop",
		"a b?c#d": "/sessions/a%20b%3Fc%23d/stop",
	} {
		if got := sessionPath(name, "stop"); got != want {
			t.Errorf("sessionPath(%q) = %q, want %q", name, got, want)
		}
	}
	if got := revertPath("a/b", "stop", "link&x=1"); got != "/sessions/a%2Fb/actions?kind=stop&variant=link%26x%3D1" {
		t.Errorf("revertPath = %q", got)
	}
	if got := terminalPath("safeclaw-a b"); got != "/sessions/a%20b/terminal" {
		t.Errorf("terminalPath = %q", got)
	}

	// Rendered names go through them too.
	h := newTestServer(t, &fakeSessions{list: []session.Session{{Container: "safeclaw-a&b", Name: "a&b", Active: true, Port: 7681, URL: "http://localhost:7681", Type: "session", Network: session.NetOnline}}})
	body := do(h, "GET", "/", nil, nil).Body.String()
	for _, want := range []string{`hx-post="/sessions/a&amp;b/stop"`, `hx-get="/sessions/a&amp;b/info"`, `src="/sessions/a&amp;b/terminal"`} {
		if !strings.Contains(body, want) {
			t.Errorf("index missing %s", want)
		}
	}
}

func TestInvalidNamesRefused(t *testing.T) {
	h := newTestServer(t, &fakeSessions{list: sampleSessions()})
	for _, path := range []string{"/sessions/..%2Fx/info", "/sessions/.x/actions?kind=stop", "/sessions/-x/terminal"} {
		if rec := do(h, "GET", path, nil, nil); rec.Code != http.StatusBadRequest && rec.Code != http.StatusNotFound {
			t.Errorf("%s = %d %s", path, rec.Code, rec.Body)
		}
	}
	if rec := do(h, "POST", "/sessions/.x/online", url.Values{"force": {"1"}, "confirm_name": {".x"}}, nil); rec.Code != http.StatusBadRequest {
		t.Errorf("force online invalid name = %d", rec.Code)
	}
}

func TestHostRestrictedToAdvertised(t *testing.T) {
	h := newTestServer(t, &fakeSessions{})
	for host, want := range map[string]int{
		"127.0.0.1:7680":    http.StatusOK,
		"localhost:7680":    http.StatusOK,
		"localhost":         http.StatusOK,
		"[::1]:7680":        http.StatusForbidden,
		"::1":               http.StatusForbidden,
		"127.0.0.2:7680":    http.StatusForbidden,
		"localhost.:7680":   http.StatusForbidden,
		"evil.example:7680": http.StatusForbidden,
	} {
		req := httptest.NewRequest("GET", "http://127.0.0.1:7680/fragments/sessions", nil)
		req.Host = host
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != want {
			t.Errorf("Host %s = %d, want %d", host, rec.Code, want)
		}
	}
}

// failingList is a fakeSessions whose List fails.
type failingList struct{ *fakeSessions }

func (failingList) List(context.Context) ([]session.Session, error) {
	return nil, errors.New("docker is down")
}

func TestCreateRefusesWhenListFails(t *testing.T) {
	f := &failingList{fakeSessions: &fakeSessions{}}
	s, err := New(Options{Sessions: f, Token: testToken, TokenFile: "unused"})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	req := httptest.NewRequest("POST", "http://localhost:7680/sessions", strings.NewReader("name=fresh"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "could not check the name") {
		t.Errorf("create = %d %s", rec.Code, rec.Body)
	}
	if len(f.ensured) != 0 {
		t.Errorf("create went ahead: %+v", f.ensured)
	}
}
