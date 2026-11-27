package dashboard

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/josegonzalez/safeclaw/internal/session"
)

// fakeTTYD is a ttyd stand-in that records the upgrade request and the
// first message, and echoes later input back as output.
type fakeTTYD struct {
	srv  *httptest.Server
	host string

	mu     sync.Mutex
	hdr    http.Header
	reqH   string
	path   string
	hello  map[string]any
	dialed int
}

func newFakeTTYD(t *testing.T) *fakeTTYD {
	t.Helper()
	f := &fakeTTYD{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.dialed++
		f.hdr = r.Header.Clone()
		f.reqH = r.Host
		f.path = r.URL.RequestURI()
		f.mu.Unlock()
		if r.URL.Path != "/ws" {
			http.NotFound(w, r)
			return
		}
		// Like ttyd -O: the Origin must match the Host.
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"tty"}})
		if err != nil {
			return
		}
		defer func() { _ = c.CloseNow() }()
		_, msg, err := c.Read(r.Context())
		if err != nil {
			return
		}
		var hello map[string]any
		_ = json.Unmarshal(msg, &hello)
		f.mu.Lock()
		f.hello = hello
		f.mu.Unlock()
		for {
			typ, msg, err := c.Read(r.Context())
			if err != nil {
				return
			}
			if err := c.Write(r.Context(), typ, append([]byte("0"), msg[1:]...)); err != nil {
				return
			}
		}
	}))
	t.Cleanup(f.srv.Close)
	_, port, _ := net.SplitHostPort(f.srv.Listener.Addr().String())
	f.host = "localhost:" + port
	return f
}

type fakeTerminals struct {
	t     *session.Terminal
	calls int
}

func (f *fakeTerminals) Terminal(_ context.Context, name string) (*session.Terminal, error) {
	f.calls++
	if name != "work" {
		return nil, session.ErrNoTerminal
	}
	return f.t, nil
}

var testCred = session.Credential{User: "safeclaw", Password: "ttyd-secret"}

// newTerminalServer serves a dashboard whose "work" session's terminal is
// a fakeTTYD.
func newTerminalServer(t *testing.T) (*httptest.Server, *fakeTTYD, *fakeTerminals) {
	t.Helper()
	tty := newFakeTTYD(t)
	terms := &fakeTerminals{t: &session.Terminal{Addr: tty.srv.Listener.Addr().String(), Host: tty.host, Credential: testCred}}
	s, err := New(Options{Sessions: &fakeSessions{list: sampleSessions()}, Terminals: terms, Token: testToken, TokenFile: "unused"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	return srv, tty, terms
}

// dialDashboard opens the WebSocket at path and returns the handshake's
// status, 0 if there was no response.
func dialDashboard(ctx context.Context, srv *httptest.Server, path string, h http.Header) (*websocket.Conn, int, error) {
	c, resp, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+path, &websocket.DialOptions{
		HTTPHeader:   h,
		Subprotocols: []string{"tty"},
	})
	status := 0
	if resp != nil {
		status = resp.StatusCode
		if resp.Body != nil {
			_ = resp.Body.Close()
		}
	}
	return c, status, err
}

func TestTerminalProxyAddsCredentialAndDropsDashboardAuth(t *testing.T) {
	srv, tty, _ := newTerminalServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	browser := browserLogin(t, srv.Config.Handler)
	tk := mintTicket(t, srv.Config.Handler, browser, "/sessions/work/terminal/ws")
	h := http.Header{}
	h.Set("Origin", srv.URL)
	h.Set("Cookie", browser["Cookie"]+"; other=1")
	// A browser may send basic credentials it cached for the host.
	h.Set("Authorization", "Basic Zm9vOmJhcg==")
	c, status, err := dialDashboard(ctx, srv, "/sessions/work/terminal/ws?ticket="+tk, h)
	if err != nil {
		t.Fatalf("dial: %v (%d)", err, status)
	}
	defer func() { _ = c.CloseNow() }()
	if c.Subprotocol() != "tty" {
		t.Errorf("subprotocol = %q", c.Subprotocol())
	}
	if err := c.Write(ctx, websocket.MessageBinary, []byte(`{"AuthToken":"forged","columns":80,"rows":24}`)); err != nil {
		t.Fatal(err)
	}
	if err := c.Write(ctx, websocket.MessageBinary, []byte("0hello")); err != nil {
		t.Fatal(err)
	}
	_, msg, err := c.Read(ctx)
	if err != nil || string(msg) != "0hello" {
		t.Fatalf("echo = %q, %v", msg, err)
	}

	tty.mu.Lock()
	defer tty.mu.Unlock()
	if got := tty.hdr.Get("Authorization"); got != "Basic "+testCred.Token() {
		t.Errorf("upstream Authorization = %q, want ttyd's basic credential", got)
	}
	if got := tty.hdr.Values("Cookie"); len(got) != 0 {
		t.Errorf("upstream got the browser's cookies: %q", got)
	}
	if tty.path != "/ws" {
		t.Errorf("upstream path %q, want /ws without the ticket", tty.path)
	}
	if got := tty.hdr.Get("Origin"); got != "http://"+tty.host || tty.reqH != tty.host {
		t.Errorf("upstream Origin %q, Host %q, want both %s for ttyd -O", got, tty.reqH, tty.host)
	}
	if tty.hello["AuthToken"] != testCred.Token() || tty.hello["columns"] != float64(80) {
		t.Errorf("hello = %v, want AuthToken replaced with the credential", tty.hello)
	}
}

func TestTerminalProxyNeedsDashboardAuth(t *testing.T) {
	srv, tty, terms := newTerminalServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for name, hdr := range map[string]map[string]string{
		"no auth":      {"Origin": srv.URL},
		"wrong cookie": {"Origin": srv.URL, "Cookie": "safeclaw_dashboard_7680=nope"},
		"cookie only":  {"Origin": srv.URL, "Cookie": login(t, srv.Config.Handler)},
		"ttyd basic":   {"Origin": srv.URL, "Authorization": "Basic " + testCred.Token()},
	} {
		h := http.Header{}
		for k, v := range hdr {
			h.Set(k, v)
		}
		_, status, err := dialDashboard(ctx, srv, "/sessions/work/terminal/ws", h)
		if err == nil || status != http.StatusUnauthorized {
			t.Errorf("%s: err = %v, status = %d, want 401", name, err, status)
		}
	}
	for _, p := range []string{"/sessions/work/terminal", "/static/xterm/xterm.min.js"} {
		resp, err := http.Get(srv.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("GET %s without auth = %d", p, resp.StatusCode)
		}
	}
	if terms.calls != 0 || tty.dialed != 0 {
		t.Errorf("unauthenticated requests reached the session: %d lookups, %d dials", terms.calls, tty.dialed)
	}
}

// TestTerminalProxyRefusesOtherOrigins covers pages on other ports of
// 127.0.0.1, such as a session still published there, which the browser
// sends the SameSite cookie from because they are the same site.
func TestTerminalProxyRefusesOtherOrigins(t *testing.T) {
	srv, tty, _ := newTerminalServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	browser := browserLogin(t, srv.Config.Handler)
	for _, origin := range []string{"http://127.0.0.1:7681", "http://localhost:7680", "http://evil.example", "null"} {
		tk := mintTicket(t, srv.Config.Handler, browser, "/sessions/work/terminal/ws")
		h := http.Header{}
		h.Set("Origin", origin)
		h.Set("Cookie", browser["Cookie"])
		_, status, err := dialDashboard(ctx, srv, "/sessions/work/terminal/ws?ticket="+tk, h)
		if err == nil || status != http.StatusForbidden {
			t.Errorf("origin %s: err = %v, status = %d, want 403", origin, err, status)
		}
	}
	if tty.dialed != 0 {
		t.Errorf("refused origins reached the session %d times", tty.dialed)
	}
}

func TestTerminalProxyUnknownSession(t *testing.T) {
	srv, _, _ := newTerminalServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	h := http.Header{}
	h.Set("Origin", srv.URL)
	h.Set("Authorization", "Bearer "+testToken)
	_, status, err := dialDashboard(ctx, srv, "/sessions/gone/terminal/ws", h)
	if err == nil || status != http.StatusNotFound {
		t.Errorf("err = %v, status = %d, want 404", err, status)
	}
}

// TestTerminalPageIsDashboardContent checks that the terminal page is the
// dashboard's own, locked down by CSP, and is rendered without contacting
// the session, so nothing a session serves runs on the dashboard origin.
func TestTerminalPageIsDashboardContent(t *testing.T) {
	tty := newFakeTTYD(t)
	terms := &fakeTerminals{t: &session.Terminal{Addr: tty.srv.Listener.Addr().String(), Host: tty.host, Credential: testCred}}
	s, err := New(Options{Sessions: &fakeSessions{list: sampleSessions()}, Terminals: terms, Token: testToken, TokenFile: "unused"})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	req := httptest.NewRequest("GET", "http://127.0.0.1:7680/sessions/work/terminal", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	body := rec.Body.String()
	for _, want := range []string{`data-terminal="/sessions/work/terminal/ws"`, `src="/static/xterm/xterm.min.js"`, `src="/static/app.js"`} {
		if !strings.Contains(body, want) {
			t.Errorf("page missing %q", want)
		}
	}
	csp := rec.Header().Get("Content-Security-Policy")
	for _, want := range []string{"default-src 'none'", "script-src 'self'", "connect-src 'self'"} {
		if !strings.Contains(csp, want) {
			t.Errorf("CSP %q missing %q", csp, want)
		}
	}
	if terms.calls != 0 || tty.dialed != 0 {
		t.Errorf("rendering the page contacted the session: %d lookups, %d dials", terms.calls, tty.dialed)
	}
	req = httptest.NewRequest("GET", "http://127.0.0.1:7680/sessions/bad%20name/terminal", nil)
	req.Header.Set("Authorization", "Bearer "+testToken)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Errorf("invalid name = %d", rec.Code)
	}
}

// TestSessionTerminalsNotOnCookieHost guards the cookie leak: cookies are
// not scoped by port, so a session published on the cookie's host could
// read the dashboard cookie by serving a page on its own port.
func TestSessionTerminalsNotOnCookieHost(t *testing.T) {
	if session.PublishHost == cookieHost || strings.Trim(session.PublishHost, "[]") == cookieHost {
		t.Fatalf("sessions are published on %s, the dashboard cookie's host", session.PublishHost)
	}
	if u := session.URLFor(7681); strings.Contains(u, cookieHost) {
		t.Errorf("session URL %s uses the cookie host", u)
	}
}

// ttydOriginOK is ttyd 1.7.7's -O check (check_host_origin): Origin's host,
// which libwebsockets parses without brackets, plus its port unless it is
// 80 or 443, must equal the Host header as sent.
func ttydOriginOK(origin, host string) bool {
	u, err := url.Parse(origin)
	if err != nil || u.Host == "" {
		return false
	}
	want := u.Hostname()
	if p := u.Port(); p != "" && p != "80" && p != "443" {
		want += ":" + p
	}
	return strings.EqualFold(want, host)
}

// TestTerminalRelayPassesTTYDOriginCheckOnIPv6 relays to a session published
// on [::1], as sessions are, through a stand-in that applies ttyd's origin
// check. The relay dials [::1] but names localhost as the Host and Origin,
// since ttyd never accepts a bracketed [::1] Host.
func TestTerminalRelayPassesTTYDOriginCheckOnIPv6(t *testing.T) {
	if ttydOriginOK("http://[::1]:7681", "[::1]:7681") || !ttydOriginOK("http://localhost:7681", "localhost:7681") {
		t.Fatal("ttydOriginOK does not match ttyd")
	}
	l, err := net.Listen("tcp", net.JoinHostPort(session.PublishHost, "0"))
	if err != nil {
		t.Skipf("can't listen on [%s]: %v", session.PublishHost, err)
	}
	var mu sync.Mutex
	var gotHost, gotOrigin string
	hello := make(chan map[string]any, 1)
	tty := &httptest.Server{Listener: l, Config: &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		gotHost, gotOrigin = r.Host, r.Header.Get("Origin")
		mu.Unlock()
		if !ttydOriginOK(r.Header.Get("Origin"), r.Host) {
			http.Error(w, "origin", http.StatusForbidden)
			return
		}
		c, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"tty"}, InsecureSkipVerify: true})
		if err != nil {
			return
		}
		defer func() { _ = c.CloseNow() }()
		_, msg, err := c.Read(r.Context())
		if err != nil {
			return
		}
		var h map[string]any
		_ = json.Unmarshal(msg, &h)
		hello <- h
		_ = c.Close(websocket.StatusNormalClosure, "")
	})}}
	tty.Start()
	t.Cleanup(tty.Close)
	_, port, _ := net.SplitHostPort(l.Addr().String())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	term := &session.Terminal{Addr: l.Addr().String(), Host: "localhost:" + port, Credential: testCred}
	c, err := dialTerminal(ctx, term)
	mu.Lock()
	host, origin := gotHost, gotOrigin
	mu.Unlock()
	if err != nil {
		t.Fatalf("dial %s: %v (Host %q, Origin %q)", term.Addr, err, host, origin)
	}
	defer func() { _ = c.CloseNow() }()
	if err := c.Write(ctx, websocket.MessageText, []byte(`{"columns":80}`)); err != nil {
		t.Fatal(err)
	}
	select {
	case h := <-hello:
		if h["columns"] != float64(80) {
			t.Errorf("hello = %v", h)
		}
	case <-ctx.Done():
		t.Fatal("no hello")
	}
}
