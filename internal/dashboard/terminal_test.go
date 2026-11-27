package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"

	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
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
	mu    sync.Mutex
	t     *session.Terminal
	err   error
	calls int
}

func (f *fakeTerminals) Terminal(_ context.Context, name string) (*session.Terminal, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	if name != "work" {
		return nil, session.ErrNoTerminal
	}
	if f.err != nil {
		return nil, f.err
	}
	return f.t, nil
}

// set makes the "work" session's terminal t, or its lookup fail with err.
func (f *fakeTerminals) set(t *session.Terminal, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.t, f.err = t, err
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
		"cookie only":  {"Origin": srv.URL, "Cookie": loginCookie(t, srv.Config.Handler)},
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

// openTerminal mints a ticket for the "work" session's terminal with
// browser's login and opens its WebSocket with it, as the terminal page
// does, returning the ticket too.
func openTerminal(ctx context.Context, t *testing.T, srv *httptest.Server, browser map[string]string) (*websocket.Conn, string, int, error) {
	t.Helper()
	tk := mintTicket(t, srv.Config.Handler, browser, "/sessions/work/terminal/ws")
	c, status, err := dialWithTicket(ctx, srv, browser, tk)
	return c, tk, status, err
}

func dialWithTicket(ctx context.Context, srv *httptest.Server, browser map[string]string, tk string) (*websocket.Conn, int, error) {
	h := http.Header{}
	h.Set("Origin", srv.URL)
	h.Set("Cookie", browser["Cookie"])
	return dialDashboard(ctx, srv, "/sessions/work/terminal/ws?ticket="+tk, h)
}

// wantTryAgainLater checks that the relay accepted c's upgrade and then
// closed it with StatusTryAgainLater, which the terminal page retries.
func wantTryAgainLater(ctx context.Context, t *testing.T, c *websocket.Conn, reason string) {
	t.Helper()
	defer func() { _ = c.CloseNow() }()
	// The page sends its hello on open, before the relay closes.
	_ = c.Write(ctx, websocket.MessageBinary, []byte(`{"columns":80,"rows":24}`))
	_, _, err := c.Read(ctx)
	var ce websocket.CloseError
	if !errors.As(err, &ce) || ce.Code != websocket.StatusTryAgainLater || ce.Reason != reason {
		t.Fatalf("read = %v, want a close with %v %q", err, websocket.StatusTryAgainLater, reason)
	}
}

// wantEcho checks that c reaches the fake ttyd.
func wantEcho(ctx context.Context, t *testing.T, c *websocket.Conn) {
	t.Helper()
	if err := c.Write(ctx, websocket.MessageBinary, []byte(`{"columns":80,"rows":24}`)); err != nil {
		t.Fatal(err)
	}
	if err := c.Write(ctx, websocket.MessageBinary, []byte("0hi")); err != nil {
		t.Fatal(err)
	}
	if _, msg, err := c.Read(ctx); err != nil || string(msg) != "0hi" {
		t.Fatalf("echo = %q, %v", msg, err)
	}
}

// startingManager returns a session.Manager whose "work" session's
// container is running with its terminal port published at tty's address,
// as it is from `docker run` on, and the directory its ttyd credential goes
// in, which starts empty, as it is until Ensure starts ttyd.
func startingManager(t *testing.T, tty *fakeTTYD) (*session.Manager, string) {
	t.Helper()
	host, port, _ := net.SplitHostPort(tty.srv.Listener.Addr().String())
	inspect := `[{"Id":"abc","Name":"/safeclaw-work","State":{"Status":"running","Running":true},` +
		`"HostConfig":{"NetworkMode":"bridge","PortBindings":{"7681/tcp":[{"HostIp":"` + host + `","HostPort":"` + port + `"}]}},` +
		`"NetworkSettings":{"Networks":{"bridge":{}}}}]`
	r := &dockertest.Runner{Handler: func(args []string, _ string) ([]byte, error) {
		if strings.Join(args, " ") == "container inspect safeclaw-work" {
			return []byte(inspect), nil
		}
		return nil, dockertest.NotFound(args)
	}}
	dir := t.TempDir()
	return &session.Manager{Docker: r.Client(), TTYDDir: dir, NetworkDir: t.TempDir()}, dir
}

// TestTerminalRelayRetriesWhileSessionStarts opens a session's terminal
// while it is being created, as a frame that loads as soon as its container
// starts does: the real session.Manager finds the container running with
// its port published, but no ttyd credential yet. The relay accepts the
// upgrade and closes it with StatusTryAgainLater, since a browser can't see
// the status of a refused upgrade, without contacting the session. The
// ticket was used up, so the retry takes a new one, and connects once the
// credential is written.
func TestTerminalRelayRetriesWhileSessionStarts(t *testing.T) {
	tty := newFakeTTYD(t)
	m, dir := startingManager(t, tty)
	s, err := New(Options{Sessions: &fakeSessions{list: sampleSessions()}, Terminals: m, Token: testToken, TokenFile: "unused"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	browser := browserLogin(t, srv.Config.Handler)

	c, tk, status, err := openTerminal(ctx, t, srv, browser)
	if err != nil {
		t.Fatalf("dial while starting: %v (%d), want the upgrade accepted", err, status)
	}
	wantTryAgainLater(ctx, t, c, terminalStartingReason)
	tty.mu.Lock()
	dialed := tty.dialed
	tty.mu.Unlock()
	if dialed != 0 {
		t.Errorf("a session without a credential was dialed %d times", dialed)
	}
	// Tickets stay single-use: the refused attempt used its ticket up.
	if _, status, err := dialWithTicket(ctx, srv, browser, tk); err == nil || status != http.StatusUnauthorized {
		t.Errorf("reused ticket: err = %v, status = %d, want 401", err, status)
	}

	// A credential that isn't ttyd's user:password is broken, not starting.
	if err := os.WriteFile(filepath.Join(dir, "work"), []byte("garbage\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, status, err := openTerminal(ctx, t, srv, browser); err == nil || status != http.StatusBadGateway {
		t.Errorf("invalid credential: err = %v, status = %d, want 502", err, status)
	}

	if err := os.WriteFile(filepath.Join(dir, "work"), []byte(testCred.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, _, status, err = openTerminal(ctx, t, srv, browser)
	if err != nil {
		t.Fatalf("dial once ready: %v (%d)", err, status)
	}
	defer func() { _ = c.CloseNow() }()
	wantEcho(ctx, t, c)
	tty.mu.Lock()
	defer tty.mu.Unlock()
	if tty.hello["AuthToken"] != testCred.Token() {
		t.Errorf("hello = %v, want the credential written meanwhile", tty.hello)
	}
}

// TestTerminalRelayRetriesUntilTTYDListens covers the rest of the start:
// the credential is written but ttyd isn't listening yet, or was started
// with a credential rotated after the lookup. The relay closes with
// StatusTryAgainLater, and a retry with a new ticket connects once ttyd
// answers.
func TestTerminalRelayRetriesUntilTTYDListens(t *testing.T) {
	srv, tty, terms := newTerminalServer(t)
	ready := terms.t
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	down := l.Addr().String()
	_ = l.Close()
	terms.set(&session.Terminal{Addr: down, Host: tty.host, Credential: testCred}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	browser := browserLogin(t, srv.Config.Handler)

	c, _, status, err := openTerminal(ctx, t, srv, browser)
	if err != nil {
		t.Fatalf("dial while ttyd is down: %v (%d)", err, status)
	}
	wantTryAgainLater(ctx, t, c, "the session's terminal is not answering")

	terms.set(ready, nil)
	c, _, status, err = openTerminal(ctx, t, srv, browser)
	if err != nil {
		t.Fatalf("dial once ttyd listens: %v (%d)", err, status)
	}
	defer func() { _ = c.CloseNow() }()
	wantEcho(ctx, t, c)
}

// TestTerminalRelayRefusesBrokenLookups checks that failures a retry won't
// fix are still refused before the upgrade: a session without a running
// terminal with 404, and a lookup that fails otherwise with 502.
func TestTerminalRelayRefusesBrokenLookups(t *testing.T) {
	srv, tty, terms := newTerminalServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	browser := browserLogin(t, srv.Config.Handler)
	for _, tc := range []struct {
		err    error
		status int
	}{
		{fmt.Errorf("session %q %w: it is stopped", "work", session.ErrNoTerminal), http.StatusNotFound},
		{fmt.Errorf("session %q %w: it is held offline by triage", "work", session.ErrNoTerminal), http.StatusNotFound},
		// Saved offline state that can't be read keeps it closed, whatever
		// the reason, even a missing file.
		{fmt.Errorf("session %q %w: %w", "work", session.ErrNoTerminal, &fs.PathError{Op: "open", Path: "/net/work.json", Err: fs.ErrNotExist}), http.StatusNotFound},
		{errors.New("docker inspect: daemon unavailable"), http.StatusBadGateway},
	} {
		terms.set(nil, tc.err)
		if _, _, status, err := openTerminal(ctx, t, srv, browser); err == nil || status != tc.status {
			t.Errorf("%v: err = %v, status = %d, want %d", tc.err, err, status, tc.status)
		}
	}
	tty.mu.Lock()
	defer tty.mu.Unlock()
	if tty.dialed != 0 {
		t.Errorf("failed lookups reached the session %d times", tty.dialed)
	}
}

func TestTerminalStarting(t *testing.T) {
	missing := &fs.PathError{Op: "open", Path: "/ttyd/work", Err: fs.ErrNotExist}
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{nil, false},
		{fmt.Errorf("session %q: read ttyd credential: %w", "work", missing), true},
		{fmt.Errorf("session %q %w: it does not exist", "work", session.ErrNoTerminal), false},
		{fmt.Errorf("%w: %w", session.ErrNoTerminal, missing), false},
		{errors.New("invalid ttyd credential in /ttyd/work"), false},
	} {
		if got := terminalStarting(tc.err); got != tc.want {
			t.Errorf("terminalStarting(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}
