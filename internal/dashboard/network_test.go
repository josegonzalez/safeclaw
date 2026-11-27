package dashboard

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/session"
)

func networkSessions() []session.Session {
	return []session.Session{
		{Container: "safeclaw-work", Name: "work", Active: true, Port: 7681, URL: "http://localhost:7681", Volume: "-", Type: "session", Network: session.NetOnline},
		{Container: "safeclaw-triage", Name: "triage", Active: true, Port: 7682, URL: "http://localhost:7682", Volume: "-", Type: "session", Network: session.NetOffline,
			Holds: []session.Hold{{Owner: "job", Reason: "opening a pdf"}}},
		{Container: "safeclaw-box", Name: "box", Active: true, Volume: "-", Type: "sandbox", Network: session.NetNone},
	}
}

func TestOfflineRendering(t *testing.T) {
	h := newTestServer(t, &fakeSessions{list: networkSessions()})
	body := fullPage(h)

	if !strings.Contains(body, `title="disconnected from every network, held by job (opening a pdf)">offline</span>`) {
		t.Error("offline badge with holders missing")
	}
	if strings.Contains(body, `href="/sessions/triage/terminal"`) || strings.Contains(body, `iframe-safeclaw-triage`) {
		t.Error("offline session still links or frames its web terminal")
	}
	if !strings.Contains(body, `id="offline-safeclaw-triage"`) || !strings.Contains(body, "safeclaw net on triage") {
		t.Error("offline placeholder missing")
	}
	if !strings.Contains(body, `class="frame-offline-placeholder" id="offline-safeclaw-triage"`) {
		t.Error("offline placeholder lost its own class")
	}
	if !strings.Contains(body, `<iframe id="iframe-safeclaw-work" src="/sessions/work/terminal" sandbox="allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox">`) {
		t.Error("online frame missing")
	}
	for _, want := range []string{
		`hx-post="/sessions/work/offline"`,
		`hx-post="/sessions/triage/online"`,
		`class="link-btn frame-online"`,
		`class="link-btn frame-offline"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("missing %s", want)
		}
	}
	if strings.Contains(body, "/sessions/box/offline") || strings.Contains(body, "/sessions/box/online") {
		t.Error("sandbox got a network button")
	}
}

func TestOfflineAction(t *testing.T) {
	f := &fakeSessions{list: networkSessions()}
	h := newTestServer(t, f)
	rec := do(h, "POST", "/sessions/work/offline", url.Values{}, nil)
	if rec.Code != http.StatusNoContent || rec.Header().Get("HX-Trigger") != "sessions" {
		t.Errorf("offline = %d %q", rec.Code, rec.Header().Get("HX-Trigger"))
	}
	if len(f.netOffs) != 1 || f.netOffs[0].Owner != "" {
		t.Errorf("net offs = %+v, want one unnamed hold", f.netOffs)
	}

	f.netOffFn = func(n string, _ session.NetOffOptions) (*session.NetResult, error) {
		return nil, fmt.Errorf("session %q %w", n, session.ErrHostNetwork)
	}
	rec = do(h, "POST", "/sessions/work/offline", url.Values{}, nil)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "failed") {
		t.Errorf("host network = %d %s", rec.Code, rec.Body.String())
	}
}

func TestOnlineActionForceConfirm(t *testing.T) {
	f := &fakeSessions{list: networkSessions()}
	held := []session.Hold{{Owner: "job", Reason: "opening a pdf"}}
	f.netOnFn = func(n string, o session.NetOnOptions) (*session.NetResult, error) {
		if o.Force {
			return &session.NetResult{Name: n}, nil
		}
		return &session.NetResult{Name: n, Offline: true, Holds: held}, fmt.Errorf("session %q %w by job", n, session.ErrHeld)
	}
	h := newTestServer(t, f)

	// The click opens the force dialog in place of the info dialog.
	rec := do(h, "POST", "/sessions/triage/online", url.Values{}, nil)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || rec.Header().Get("HX-Retarget") != "#session-info" || rec.Header().Get("HX-Reswap") != "innerHTML" {
		t.Errorf("first click = %d %v", rec.Code, rec.Header())
	}
	for _, want := range []string{
		`<li>job (opening a pdf)</li>`,
		`hx-post="/sessions/triage/online" hx-vals='{&#34;force&#34;:&#34;1&#34;}'`,
		`name="confirm_name" data-confirm-name="triage"`,
		`data-confirm-submit disabled`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("force dialog missing %s: %s", want, body)
		}
	}

	// Forcing needs the session name typed.
	for _, typed := range []string{"", "Triage", "work"} {
		rec = do(h, "POST", "/sessions/triage/online", url.Values{"force": {"1"}, "confirm_name": {typed}}, nil)
		if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), `type &#34;triage&#34; to force it online`) {
			t.Errorf("force with %q = %d %s", typed, rec.Code, rec.Body.String())
		}
	}
	if len(f.netOns) != 1 {
		t.Fatalf("a mistyped name reached NetOn: %+v", f.netOns)
	}

	rec = do(h, "POST", "/sessions/triage/online", url.Values{"force": {"1"}, "confirm_name": {"triage"}}, nil)
	if rec.Code != http.StatusNoContent {
		t.Errorf("force = %d %s", rec.Code, rec.Body.String())
	}
	var trig map[string]bool
	if err := json.Unmarshal([]byte(rec.Header().Get("HX-Trigger")), &trig); err != nil || !trig["sessions"] || !trig["close-dialog"] {
		t.Errorf("force trigger = %q", rec.Header().Get("HX-Trigger"))
	}
	if len(f.netOns) != 2 || f.netOns[0].Force || !f.netOns[1].Force {
		t.Errorf("net ons = %+v", f.netOns)
	}

	// A release that leaves other holds also offers to force.
	f.netOnFn = func(n string, _ session.NetOnOptions) (*session.NetResult, error) {
		return &session.NetResult{Name: n, Offline: true, Holds: held}, nil
	}
	if rec := do(h, "POST", "/sessions/triage/online", url.Values{}, nil); rec.Header().Get("HX-Retarget") != "#session-info" || !strings.Contains(rec.Body.String(), "data-confirm-name") {
		t.Errorf("partial release = %s", rec.Body.String())
	}
	// A force that still leaves holds says so in the dialog.
	rec = do(h, "POST", "/sessions/triage/online", url.Values{"force": {"1"}, "confirm_name": {"triage"}}, nil)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "still held offline by job") {
		t.Errorf("force with holds left = %d %s", rec.Code, rec.Body.String())
	}

	if body := do(h, "GET", "/sessions/triage/actions?kind=online", nil, nil).Body.String(); !strings.Contains(body, `hx-post="/sessions/triage/online"`) || strings.Contains(body, "force") {
		t.Errorf("revert = %s", body)
	}
}

func TestNetAPI(t *testing.T) {
	f := &fakeSessions{list: networkSessions()}
	f.list[1].Holds[0].Since = time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	h := newTestServer(t, f)

	var list []apiSession
	_ = json.Unmarshal(do(h, "GET", "/api/sessions", nil, nil).Body.Bytes(), &list)
	if len(list) != 3 || list[0].Network != "online" || len(list[0].Holds) != 0 || list[1].Network != "offline" || list[2].Network != "none" {
		t.Fatalf("api sessions = %+v", list)
	}
	if hold := list[1].Holds[0]; hold.Owner != "job" || hold.Reason != "opening a pdf" || hold.Since != "2026-11-27T12:00:00Z" {
		t.Errorf("hold = %+v", hold)
	}

	post := func(path, body string) (int, apiNetResult) {
		req := httptest.NewRequest("POST", "http://localhost:7680"+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var r apiNetResult
		_ = json.Unmarshal(rec.Body.Bytes(), &r)
		return rec.Code, r
	}
	code, r := post("/api/net/off", `{"name":"safeclaw-work","owner":"job","reason":"why"}`)
	if code != 200 || !r.Success || !r.Offline || len(r.Holds) != 1 || f.netOffs[0] != (session.NetOffOptions{Owner: "job", Reason: "why"}) {
		t.Errorf("net off = %d %+v %+v", code, r, f.netOffs)
	}
	code, r = post("/api/net/on", `{"name":"work","owner":"job","force":true}`)
	if code != 200 || !r.Success || r.Offline || f.netOns[0] != (session.NetOnOptions{Owner: "job", Force: true}) {
		t.Errorf("net on = %d %+v %+v", code, r, f.netOns)
	}

	f.netOnFn = func(n string, _ session.NetOnOptions) (*session.NetResult, error) {
		return &session.NetResult{Name: n, Offline: true, Holds: []session.Hold{{Owner: "job"}}}, fmt.Errorf("session %q %w by job", n, session.ErrHeld)
	}
	code, r = post("/api/net/on", `{"name":"work"}`)
	if code != http.StatusConflict || r.Success || !r.Offline || len(r.Holds) != 1 || r.Error == "" {
		t.Errorf("held = %d %+v", code, r)
	}

	f.ensureFn = func(o session.Options) (*session.Result, error) {
		return nil, fmt.Errorf("session %q %w", o.Name, session.ErrOffline)
	}
	req := httptest.NewRequest("POST", "http://localhost:7680/api/create", strings.NewReader(`{"name":"triage","volume":"/a:/b"}`))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Errorf("create offline = %d", rec.Code)
	}
}

func TestHubNetworkEvents(t *testing.T) {
	h := NewHub()
	ch, unsubscribe := h.Subscribe()
	defer unsubscribe()
	h.IsSession = func(id string) (bool, error) { return id == "abc", nil }

	h.Handle(docker.Event{Type: "network", Action: "disconnect", Name: "bridge", Container: "other"})
	h.Handle(docker.Event{Type: "network", Action: "create", Name: "bridge", Container: "abc"})
	h.Handle(docker.Event{Type: "network", Action: "disconnect", Name: "bridge", Container: "abc"})
	h.lookups.Wait()
	select {
	case got := <-ch:
		if got != "disconnect" {
			t.Errorf("published %q", got)
		}
	default:
		t.Fatal("network event not published")
	}
	select {
	case got := <-ch:
		t.Errorf("unexpected %q", got)
	default:
	}
}
