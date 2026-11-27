package dashboard

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/session"
	"github.com/josegonzalez/safeclaw/internal/variant"
)

type fakeSessions struct {
	mu       sync.Mutex
	list     []session.Session
	ensured  []session.Options
	stopped  []string
	deleted  []string
	ensureFn func(session.Options) (*session.Result, error)
	// deleteErr fails Delete.
	deleteErr error
	// variants is returned by Variants; nil means the built-ins.
	variants   *variant.Set
	variantErr error
	// secretNames is returned by SecretNames.
	secretNames []string
	secretErr   error
	// token is returned by ClaudeTokenStatus; the zero value is a valid
	// token.
	token    session.TokenStatus
	tokenErr error
	// netOffs and netOns record network calls, answered by the optional
	// netOffFn and netOnFn.
	netOffs  []session.NetOffOptions
	netOns   []session.NetOnOptions
	netOffFn func(string, session.NetOffOptions) (*session.NetResult, error)
	netOnFn  func(string, session.NetOnOptions) (*session.NetResult, error)
	// legacy are containers left from mixed-case names, which ResolveName
	// refuses the lowercase session for; resolved records its calls.
	legacy   []string
	resolved []string
}

func (f *fakeSessions) ResolveName(_ context.Context, name string) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.resolved = append(f.resolved, name)
	for _, c := range f.legacy {
		if strings.EqualFold(c, "safeclaw-"+name) {
			return "", fmt.Errorf("session %q: %w: remove it with `docker rm -f %s` first", name, session.ErrLegacyName, c)
		}
	}
	return name, nil
}

func (f *fakeSessions) SecretNames() ([]string, error) {
	return f.secretNames, f.secretErr
}

func (f *fakeSessions) ClaudeTokenStatus(time.Time) (session.TokenStatus, error) {
	if f.token.State == "" {
		return session.TokenStatus{State: session.TokenValid}, f.tokenErr
	}
	return f.token, f.tokenErr
}

func (f *fakeSessions) Variants() (*variant.Set, error) {
	if f.variantErr != nil {
		return nil, f.variantErr
	}
	if f.variants == nil {
		return variant.Default(), nil
	}
	return f.variants, nil
}

func (f *fakeSessions) List(context.Context) ([]session.Session, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.list, nil
}

func (f *fakeSessions) Ensure(_ context.Context, o session.Options) (*session.Result, error) {
	f.mu.Lock()
	f.ensured = append(f.ensured, o)
	f.mu.Unlock()
	if f.ensureFn != nil {
		return f.ensureFn(o)
	}
	return &session.Result{Name: o.Name, URL: "http://localhost:7690", Port: 7690}, nil
}

func (f *fakeSessions) Stop(_ context.Context, n string) error {
	f.stopped = append(f.stopped, n)
	return nil
}

func (f *fakeSessions) Delete(_ context.Context, n string, _ bool) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	f.deleted = append(f.deleted, n)
	return nil
}

func (f *fakeSessions) NetOff(_ context.Context, n string, o session.NetOffOptions) (*session.NetResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.netOffs = append(f.netOffs, o)
	if f.netOffFn != nil {
		return f.netOffFn(n, o)
	}
	return &session.NetResult{Name: n, Offline: true, Holds: []session.Hold{{Owner: o.Owner}}}, nil
}

func (f *fakeSessions) NetOn(_ context.Context, n string, o session.NetOnOptions) (*session.NetResult, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.netOns = append(f.netOns, o)
	if f.netOnFn != nil {
		return f.netOnFn(n, o)
	}
	return &session.NetResult{Name: n}, nil
}

func sampleSessions() []session.Session {
	return []session.Session{
		{Container: "safeclaw-work", Name: "work", Active: true, Port: 7681, URL: "http://localhost:7681", Volume: "/p:/home/sclaw/p", Type: "session"},
		{Container: "safeclaw-old", Name: "old", Volume: "-", Type: "session"},
	}
}

// testToken is the launch token of test servers.
const testToken = "test-token"

// newTestServer returns the handler of a server over f. Requests without
// an Authorization header or cookie get the bearer token added; access_test
// covers requests without one.
func newTestServer(t *testing.T, f *fakeSessions) http.Handler {
	t.Helper()
	s, err := New(Options{Sessions: f, Token: testToken, TokenFile: "unused"})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" && r.Header.Get("Cookie") == "" {
			r.Header.Set("Authorization", "Bearer "+testToken)
		}
		h.ServeHTTP(w, r)
	})
}

func do(h http.Handler, method, target string, form url.Values, hdr map[string]string) *httptest.ResponseRecorder {
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req := httptest.NewRequest(method, "http://localhost:7680"+target, body)
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// pageFragments are what the page shell fetches once it loads.
var pageFragments = []string{"/fragments/auth", "/fragments/sessions", "/fragments/frames", "/fragments/options"}

// fullPage returns what the page shows once htmx has loaded its fragments:
// the shell followed by each fragment.
func fullPage(h http.Handler) string {
	var b strings.Builder
	b.WriteString(do(h, "GET", "/", nil, nil).Body.String())
	for _, p := range pageFragments {
		b.WriteString(do(h, "GET", p, nil, nil).Body.String())
	}
	return b.String()
}

// TestIndexIsAShell checks that the page a browser opens with only the
// cookie shows no state, and fetches every part that does.
func TestIndexIsAShell(t *testing.T) {
	f := &fakeSessions{list: sampleSessions(), secretNames: []string{"GH_TOKEN"}, token: session.TokenStatus{State: session.TokenMissing}}
	h := newTestServer(t, f)
	rec := do(h, "GET", "/", nil, nil)
	if rec.Code != 200 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	for _, leak := range []string{"work", "/p:/home/sclaw/p", "GH_TOKEN", "No Claude Code token", "session-variant"} {
		if strings.Contains(body, leak) {
			t.Errorf("shell shows %q", leak)
		}
	}
	for _, want := range []string{
		`hx-sse:connect="/events"`,
		`<div id="auth-banner" hx-get="/fragments/auth" hx-trigger="load, sessions from:body" hx-swap="innerMorph"></div>`,
		`<div id="sessions" hx-get="/fragments/sessions" hx-trigger="load, sessions from:body" hx-swap="innerMorph"></div>`,
		`<div hx-get="/fragments/frames" hx-trigger="load" hx-swap="outerHTML"></div>`,
		`<div hx-get="/fragments/options" hx-trigger="load" hx-swap="outerHTML"></div>`,
		`<p id="login-needed" class="load-error" hidden>`,
		`<dialog id="new-session-modal"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("shell missing %q", want)
		}
	}
}

func TestIndexRendersSessionsAndFrames(t *testing.T) {
	h := newTestServer(t, &fakeSessions{list: sampleSessions()})
	body := fullPage(h)
	for _, want := range []string{
		`<a href="/sessions/work/terminal" target="_blank" title="localhost:7681"><bdi>localhost:7681</bdi></a>`,
		`<td class="volume" title="/p:/home/sclaw/p"><bdi>/p:/home/sclaw/p</bdi></td>`,
		`hx-post="/sessions/work/stop"`,
		`hx-post="/sessions/old/start"`,
		`hx-post="/sessions/old/delete"`,
		`class="inactive-row"`,
		`/p:/home/sclaw/p`,
		`<iframe id="iframe-safeclaw-work" src="/sessions/work/terminal" sandbox="allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox">`,
		`class="frames single"`,
		`<dialog id="new-session-modal"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("index missing %q", want)
		}
	}
	if strings.Contains(body, "iframe-safeclaw-old") {
		t.Error("stopped session should not get an iframe")
	}
}

func TestEmptyState(t *testing.T) {
	h := newTestServer(t, &fakeSessions{})
	body := do(h, "GET", "/fragments/sessions", nil, nil).Body.String()
	if !strings.Contains(body, "no sessions") || !strings.Contains(body, "safeclaw run -s name") || !strings.Contains(body, "tip: ") {
		t.Errorf("empty state wrong: %s", body)
	}
}

func TestConfirmFlow(t *testing.T) {
	f := &fakeSessions{list: sampleSessions()}
	h := newTestServer(t, f)

	rec := do(h, "POST", "/sessions/work/stop", url.Values{}, nil)
	body := rec.Body.String()
	if !strings.Contains(body, "stop?") || !strings.Contains(body, `hx-vals='{&#34;confirm&#34;:&#34;1&#34;,&#34;variant&#34;:&#34;&#34;}'`) || !strings.Contains(body, `hx-trigger="load delay:3s"`) {
		t.Errorf("confirm fragment wrong: %s", body)
	}
	if len(f.stopped) != 0 {
		t.Error("first click must not stop")
	}

	rec = do(h, "POST", "/sessions/work/stop", url.Values{"confirm": {"1"}}, nil)
	if rec.Code != http.StatusNoContent || rec.Header().Get("HX-Trigger") != "sessions" {
		t.Errorf("confirmed stop: %d %q", rec.Code, rec.Header().Get("HX-Trigger"))
	}
	if len(f.stopped) != 1 || f.stopped[0] != "work" {
		t.Errorf("stopped = %v", f.stopped)
	}

	rec = do(h, "POST", "/sessions/old/delete", url.Values{"confirm": {"1"}}, nil)
	if rec.Code != http.StatusNoContent || len(f.deleted) != 1 {
		t.Errorf("delete: %d %v", rec.Code, f.deleted)
	}

	body = do(h, "GET", "/sessions/work/actions?kind=stop&variant=link", nil, nil).Body.String()
	if !strings.Contains(body, "link-btn frame-stop") || strings.Contains(body, "stop?") {
		t.Errorf("revert fragment wrong: %s", body)
	}
}

func TestStart(t *testing.T) {
	f := &fakeSessions{list: sampleSessions()}
	h := newTestServer(t, f)
	rec := do(h, "POST", "/sessions/old/start", url.Values{}, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status %d", rec.Code)
	}
	if len(f.ensured) != 1 || f.ensured[0].Name != "old" || !f.ensured[0].NoOpen || f.ensured[0].Interactive {
		t.Errorf("ensure = %+v", f.ensured)
	}

	f.ensureFn = func(session.Options) (*session.Result, error) { return nil, errors.New("boom") }
	body := do(h, "POST", "/sessions/old/start", url.Values{}, nil).Body.String()
	if !strings.Contains(body, "failed") || !strings.Contains(body, `title="boom"`) {
		t.Errorf("failure fragment: %s", body)
	}
}

func TestValidate(t *testing.T) {
	h := newTestServer(t, &fakeSessions{list: sampleSessions()})
	body := do(h, "GET", "/sessions/validate?name=Work", nil, nil).Body.String()
	if !strings.Contains(body, `session "work" already seems to exist`) {
		t.Errorf("exists hint: %s", body)
	}
	body = do(h, "GET", "/sessions/validate?name=fresh", nil, nil).Body.String()
	if !strings.Contains(body, "use a unique name") {
		t.Errorf("fresh hint: %s", body)
	}
}

func TestCreate(t *testing.T) {
	f := &fakeSessions{list: sampleSessions()}
	h := newTestServer(t, f)

	rec := do(h, "POST", "/sessions", url.Values{"name": {"work"}}, nil)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "already seems to exist") {
		t.Errorf("duplicate: %d %s", rec.Code, rec.Body)
	}

	rec = do(h, "POST", "/sessions", url.Values{"name": {"New One"}, "volume": {" ~/p:/home/sclaw/p "}, "query": {"hi"}, "open_tab": {"1"}}, nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	var trig map[string]json.RawMessage
	if err := json.Unmarshal([]byte(rec.Header().Get("HX-Trigger")), &trig); err != nil {
		t.Fatal(err)
	}
	var created createResult
	_ = json.Unmarshal(trig["session-created"], &created)
	if created.URL != "/sessions/new-one/terminal" || !created.OpenTab {
		t.Errorf("trigger = %s", rec.Header().Get("HX-Trigger"))
	}
	if _, ok := trig["sessions"]; !ok {
		t.Error("create should also refresh sessions")
	}
	o := f.ensured[0]
	if o.Name != "new-one" || o.Volume != "~/p:/home/sclaw/p" || o.Query != "hi" || !o.NoOpen || o.Interactive {
		t.Errorf("ensure opts = %+v", o)
	}

	f.ensureFn = func(session.Options) (*session.Result, error) { return nil, session.ErrNoClaudeToken }
	rec = do(h, "POST", "/sessions", url.Values{"name": {"another"}}, nil)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "no Claude Code token") {
		t.Errorf("error: %d %s", rec.Code, rec.Body)
	}
}

func TestInfo(t *testing.T) {
	h := newTestServer(t, &fakeSessions{})
	body := do(h, "GET", "/sessions/work/info", nil, nil).Body.String()
	if !strings.Contains(body, `value="safeclaw attach work"`) {
		t.Errorf("info: %s", body)
	}
}

func TestCrossOriginAndHostProtection(t *testing.T) {
	f := &fakeSessions{list: sampleSessions()}
	h := newTestServer(t, f)

	rec := do(h, "POST", "/sessions/work/stop", url.Values{"confirm": {"1"}}, map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"})
	if rec.Code != http.StatusForbidden || len(f.stopped) != 0 {
		t.Errorf("cross-site POST allowed: %d", rec.Code)
	}

	req := httptest.NewRequest("GET", "http://evil.example/", nil)
	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Code != http.StatusForbidden {
		t.Errorf("foreign Host allowed: %d", rec2.Code)
	}

	rec = do(h, "POST", "/sessions/work/stop", url.Values{"confirm": {"1"}}, map[string]string{"Sec-Fetch-Site": "same-origin"})
	if rec.Code != http.StatusNoContent {
		t.Errorf("same-origin POST blocked: %d", rec.Code)
	}
}

// Deleting a session held offline is refused with a conflict that names
// its holders, from the dashboard and the API alike.
func TestDeleteHeld(t *testing.T) {
	f := &fakeSessions{list: sampleSessions(), deleteErr: fmt.Errorf(`session "old" %w by triage: release the holds first`, session.ErrHeld)}
	h := newTestServer(t, f)

	rec := do(h, "POST", "/sessions/old/delete", url.Values{"confirm": {"1"}}, nil)
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "held offline by triage") {
		t.Errorf("delete: %d %s", rec.Code, rec.Body.String())
	}

	req := httptest.NewRequest("POST", "http://localhost:7680/api/delete", strings.NewReader(`{"name":"old"}`))
	req.Header.Set("Content-Type", "application/json")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var r apiResult
	_ = json.Unmarshal(rec.Body.Bytes(), &r)
	if rec.Code != http.StatusConflict || r.Success || !strings.Contains(r.Error, "held offline by triage") {
		t.Errorf("api delete: %d %+v", rec.Code, r)
	}
	if len(f.deleted) != 0 {
		t.Errorf("deleted = %v", f.deleted)
	}
}

func TestJSONAPI(t *testing.T) {
	f := &fakeSessions{list: sampleSessions()}
	h := newTestServer(t, f)

	var list []apiSession
	_ = json.Unmarshal(do(h, "GET", "/api/sessions", nil, nil).Body.Bytes(), &list)
	if len(list) != 2 || list[0].Name != "safeclaw-work" || *list[0].Port != "7681" || list[1].Port != nil || list[1].URL != nil {
		t.Errorf("api sessions = %+v", list)
	}

	post := func(path, body string) apiResult {
		req := httptest.NewRequest("POST", "http://localhost:7680"+path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		var r apiResult
		_ = json.Unmarshal(rec.Body.Bytes(), &r)
		return r
	}
	if r := post("/api/stop", `{"name":"safeclaw-work"}`); !r.Success || f.stopped[0] != "work" {
		t.Errorf("stop = %+v %v", r, f.stopped)
	}
	if r := post("/api/start", `{"name":"safeclaw-old"}`); !r.Success || r.URL != "http://localhost:7690" {
		t.Errorf("start = %+v", r)
	}
	if r := post("/api/create", `{"name":"x","volume":"/a:/b","query":"q"}`); !r.Success {
		t.Errorf("create = %+v", r)
	}
	if r := post("/api/delete", `not json`); r.Success || r.Error == "" {
		t.Errorf("bad json = %+v", r)
	}
}

func TestHubAndEvents(t *testing.T) {
	events := make(chan docker.Event)
	src := func(ctx context.Context, fn func(docker.Event)) error {
		for {
			select {
			case <-ctx.Done():
				return nil
			case ev := <-events:
				fn(ev)
			}
		}
	}
	s, err := New(Options{Sessions: &fakeSessions{}, Events: src, Token: testToken, TokenFile: "unused"})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.hub.Run(ctx, src)

	srv := httptest.NewServer(s.Handler())
	// Registered before the stream bodies so they close first (cleanups run LIFO).
	t.Cleanup(srv.Close)
	read := func(path string) *bufio.Reader {
		u := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1)
		req, _ := http.NewRequest("GET", u+path, nil)
		req.Header.Set("Authorization", "Bearer "+testToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = resp.Body.Close() })
		if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
			t.Fatalf("content type %q", ct)
		}
		return bufio.NewReader(resp.Body)
	}
	htmlStream := read("/events")
	apiStream := read("/api/events")
	expectLine := func(r *bufio.Reader, want string) {
		t.Helper()
		done := make(chan string, 1)
		go func() {
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					done <- "ERR " + err.Error()
					return
				}
				if strings.TrimSpace(line) == want {
					done <- want
					return
				}
			}
		}()
		select {
		case got := <-done:
			if got != want {
				t.Errorf("stream: %s", got)
			}
		case <-time.After(2 * time.Second):
			t.Errorf("timed out waiting for %q", want)
		}
	}
	expectLine(htmlStream, ": connected")
	expectLine(apiStream, "data: connected")

	// Wait until both streams subscribed.
	for i := 0; i < 100; i++ {
		s.hub.mu.Lock()
		n := len(s.hub.clients)
		s.hub.mu.Unlock()
		if n == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	events <- docker.Event{Action: "exec_start", Name: "safeclaw-a"} // ignored action
	events <- docker.Event{Action: "stop", Name: "other"}            // ignored container
	events <- docker.Event{Action: "die", Name: "safeclaw-a"}
	expectLine(htmlStream, "event: sessions")
	expectLine(apiStream, "data: die")
}
