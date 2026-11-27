package dashboard

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
	"github.com/josegonzalez/safeclaw/internal/secrets"
	"github.com/josegonzalez/safeclaw/internal/session"
	"github.com/josegonzalez/safeclaw/internal/variant"
)

// noSessions fails the test on any session call.
type noSessions struct{ t *testing.T }

func (n noSessions) fail(what string) { n.t.Errorf("unauthenticated request reached %s", what) }

func (n noSessions) List(context.Context) ([]session.Session, error) {
	n.fail("List")
	return nil, nil
}

func (n noSessions) Ensure(context.Context, session.Options) (*session.Result, error) {
	n.fail("Ensure")
	return &session.Result{}, nil
}

func (n noSessions) Stop(context.Context, string) error {
	n.fail("Stop")
	return nil
}

func (n noSessions) Delete(context.Context, string, bool) error {
	n.fail("Delete")
	return nil
}

func (n noSessions) NetOff(context.Context, string, session.NetOffOptions) (*session.NetResult, error) {
	n.fail("NetOff")
	return &session.NetResult{}, nil
}

func (n noSessions) NetOn(context.Context, string, session.NetOnOptions) (*session.NetResult, error) {
	n.fail("NetOn")
	return &session.NetResult{}, nil
}

func (n noSessions) Variants() (*variant.Set, error) {
	n.fail("Variants")
	return variant.Default(), nil
}

func (n noSessions) SecretNames() ([]string, error) {
	n.fail("SecretNames")
	return nil, nil
}

func (n noSessions) ClaudeTokenStatus(time.Time) (session.TokenStatus, error) {
	n.fail("ClaudeTokenStatus")
	return session.TokenStatus{}, nil
}

// routes covers every route the dashboard serves.
var routes = []struct{ method, path, body string }{
	{"GET", "/", ""},
	{"GET", "/static/app.js", ""},
	{"GET", "/static/htmx.min.js", ""},
	{"GET", "/fragments/sessions", ""},
	{"GET", "/fragments/frames", ""},
	{"GET", "/fragments/auth", ""},
	{"GET", "/events", ""},
	{"POST", "/sessions", "name=x"},
	{"GET", "/sessions/validate?name=x", ""},
	{"GET", "/sessions/work/info", ""},
	{"GET", "/sessions/work/actions", ""},
	{"GET", "/sessions/work/terminal", ""},
	{"GET", "/sessions/work/terminal/ws", ""},
	{"POST", "/sessions/work/start", ""},
	{"POST", "/sessions/work/stop", "confirm=1"},
	{"POST", "/sessions/work/delete", "confirm=1"},
	{"POST", "/sessions/work/offline", ""},
	{"POST", "/sessions/work/online", "force=1"},
	{"GET", "/api/sessions", ""},
	{"POST", "/api/start", `{"name":"work"}`},
	{"POST", "/api/stop", `{"name":"work"}`},
	{"POST", "/api/delete", `{"name":"work"}`},
	{"POST", "/api/create", `{"name":"v2","volume":"/:/host","secrets":"all","query":"q"}`},
	{"POST", "/api/net/off", `{"name":"work"}`},
	{"POST", "/api/net/on", `{"name":"work","force":true}`},
	{"GET", "/api/events", ""},
	{"POST", "/tickets", "path=/sessions/work/terminal/ws"},
	{"POST", "/logout", ""},
	{"GET", "/missing", ""},
}

// isPage reports whether path is one of the page shells or static files,
// which the cookie opens on its own.
func isPage(method, path string) bool {
	return method == "GET" && (path == "/" || strings.HasPrefix(path, "/static/") || path == "/sessions/work/terminal")
}

func newAuthServer(t *testing.T, sessions Sessions) http.Handler {
	t.Helper()
	s, err := New(Options{Sessions: sessions, Token: testToken, TokenFile: "/cfg/dashboard/7680.token"})
	if err != nil {
		t.Fatal(err)
	}
	return s.Handler()
}

// loginCookie opens the launch URL on h like a browser and returns the session
// cookie it gets, as a Cookie header value.
func loginCookie(t *testing.T, h http.Handler) string {
	t.Helper()
	rec := send(h, "GET", "http://127.0.0.1:7680/?token="+testToken, "", nil)
	cookies := rec.Result().Cookies()
	if rec.Code != http.StatusSeeOther || len(cookies) != 1 {
		t.Fatalf("exchange = %d, cookies %v", rec.Code, cookies)
	}
	return cookies[0].Name + "=" + cookies[0].Value
}

// browserLogin opens the launch URL on h like a browser and returns the
// headers its pages then send: the cookie, and the second secret from the
// redirect's fragment.
func browserLogin(t *testing.T, h http.Handler) map[string]string {
	t.Helper()
	rec := send(h, "GET", "http://127.0.0.1:7680/?token="+testToken, "", nil)
	cookies := rec.Result().Cookies()
	if rec.Code != http.StatusSeeOther || len(cookies) != 1 {
		t.Fatalf("exchange = %d, cookies %v", rec.Code, cookies)
	}
	return map[string]string{"Cookie": cookies[0].Name + "=" + cookies[0].Value, secretHeader: fragmentSecret(t, rec.Header().Get("Location"))}
}

// fragmentSecret returns the second secret in the fragment of loc.
func fragmentSecret(t *testing.T, loc string) string {
	t.Helper()
	_, frag, ok := strings.Cut(loc, "#")
	secret, found := strings.CutPrefix(frag, secretFragment+"=")
	if !ok || !found || len(secret) < 26 {
		t.Fatalf("redirect %q carries no secret", loc)
	}
	return secret
}

// with returns a copy of hdr with the extra pairs set.
func with(hdr map[string]string, pairs ...string) map[string]string {
	out := map[string]string{}
	for k, v := range hdr {
		out[k] = v
	}
	for i := 0; i+1 < len(pairs); i += 2 {
		out[pairs[i]] = pairs[i+1]
	}
	return out
}

func send(h http.Handler, method, target, body string, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if strings.HasPrefix(body, "{") {
		req.Header.Set("Content-Type", "application/json")
	} else if body != "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestEveryRouteNeedsTheToken(t *testing.T) {
	h := newAuthServer(t, noSessions{t})
	creds := map[string]map[string]string{
		"missing":             nil,
		"wrong bearer":        {"Authorization": "Bearer nope"},
		"empty bearer":        {"Authorization": "Bearer "},
		"basic":               {"Authorization": "Basic " + testToken},
		"wrong cookie":        {"Cookie": "safeclaw_dashboard_7680=nope"},
		"other port's cookie": {"Cookie": "safeclaw_dashboard_7690=" + testToken},
		// Another 127.0.0.1 port gets the cookie, so it must not be the
		// token, and the token is no good as the cookie.
		"token as cookie":     {"Cookie": "safeclaw_dashboard_7680=" + testToken},
		"same-origin browser": {"Sec-Fetch-Site": "same-origin", "Origin": "http://127.0.0.1:7680"},
	}
	for name, hdr := range creds {
		for _, rt := range routes {
			for _, host := range []string{"127.0.0.1:7680", "localhost:7680"} {
				rec := send(h, rt.method, "http://"+host+rt.path, rt.body, hdr)
				if rec.Code != http.StatusUnauthorized {
					t.Errorf("%s: %s %s on %s = %d, want 401", name, rt.method, rt.path, host, rec.Code)
					continue
				}
				if rec.Header().Get("WWW-Authenticate") == "" || rec.Header().Get("Set-Cookie") != "" {
					t.Errorf("%s: %s %s headers %v", name, rt.method, rt.path, rec.Header())
				}
				if !strings.Contains(rec.Body.String(), "/cfg/dashboard/7680.token") {
					t.Errorf("401 body does not name the token file: %q", rec.Body)
				}
			}
		}
	}
}

// TestEveryResponseRefusesFraming checks that every response, refusals
// included, tells the browser not to render it in another page's frame.
// Only the terminal page, which the dashboard frames itself, may be framed,
// and only by the dashboard's own origin.
func TestEveryResponseRefusesFraming(t *testing.T) {
	h := newAuthServer(t, &fakeSessions{list: sampleSessions()})
	bearer := map[string]string{"Authorization": "Bearer " + testToken}
	// The SSE routes stream until the request ends, so they get a request
	// that has already ended.
	done, cancel := context.WithCancel(context.Background())
	cancel()
	type request struct {
		name, target string
		hdr          map[string]string
	}
	for _, rt := range routes {
		cases := []request{
			{"unauthenticated", "http://127.0.0.1:7680" + rt.path, nil},
			{"authenticated", "http://127.0.0.1:7680" + rt.path, bearer},
			{"cross-site", "http://127.0.0.1:7680" + rt.path, map[string]string{"Authorization": bearer["Authorization"], "Sec-Fetch-Site": "cross-site"}},
			{"foreign host", "http://evil.example" + rt.path, bearer},
		}
		if rt.method == "GET" {
			sep := "?"
			if strings.Contains(rt.path, "?") {
				sep = "&"
			}
			cases = append(cases,
				request{"token exchange", "http://127.0.0.1:7680" + rt.path + sep + "token=" + testToken, nil},
				request{"token exchange on localhost", "http://localhost:7680" + rt.path + sep + "token=" + testToken, nil},
			)
		}
		for _, tc := range cases {
			req := httptest.NewRequestWithContext(done, rt.method, tc.target, strings.NewReader(rt.body))
			if strings.HasPrefix(rt.body, "{") {
				req.Header.Set("Content-Type", "application/json")
			} else if rt.body != "" {
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}
			for k, v := range tc.hdr {
				req.Header.Set(k, v)
			}
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			xfo, csp := "DENY", pageCSP
			if rt.path == "/sessions/work/terminal" && rec.Code == http.StatusOK {
				xfo, csp = "SAMEORIGIN", terminalCSP
			}
			got := rec.Header()
			if v := got.Values("X-Frame-Options"); len(v) != 1 || v[0] != xfo {
				t.Errorf("%s: %s %s = %d, X-Frame-Options %q, want %q", tc.name, rt.method, rt.path, rec.Code, v, xfo)
			}
			if v := got.Values("Content-Security-Policy"); len(v) != 1 || v[0] != csp {
				t.Errorf("%s: %s %s = %d, Content-Security-Policy %q, want %q", tc.name, rt.method, rt.path, rec.Code, v, csp)
			}
		}
	}
}

// TestTerminalPageFramedOnlyBySelf checks the one page the dashboard frames
// keeps its own policy, which allows its own origin and no other.
func TestTerminalPageFramedOnlyBySelf(t *testing.T) {
	h := newAuthServer(t, &fakeSessions{list: sampleSessions()})
	rec := send(h, "GET", "http://127.0.0.1:7680/sessions/work/terminal", "", map[string]string{"Authorization": "Bearer " + testToken})
	if rec.Code != http.StatusOK {
		t.Fatalf("terminal page = %d", rec.Code)
	}
	var ancestors []string
	for _, d := range strings.Split(rec.Header().Get("Content-Security-Policy"), ";") {
		if f := strings.Fields(d); len(f) > 0 && f[0] == "frame-ancestors" {
			ancestors = append(ancestors, strings.Join(f[1:], " "))
		}
	}
	if len(ancestors) != 1 || ancestors[0] != "'self'" {
		t.Errorf("terminal page frame-ancestors = %q, want only 'self'", ancestors)
	}
	if !strings.Contains(rec.Header().Get("Content-Security-Policy"), "script-src 'self'") {
		t.Errorf("terminal page lost its own policy: %q", rec.Header().Get("Content-Security-Policy"))
	}
}

func TestTokenInPOSTQueryIsRefused(t *testing.T) {
	h := newAuthServer(t, noSessions{t})
	rec := send(h, "POST", "http://127.0.0.1:7680/api/create?token="+testToken, `{"name":"x"}`, nil)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("POST with the token in the query = %d", rec.Code)
	}
}

func TestBearerAndCookieAuthorize(t *testing.T) {
	f := &fakeSessions{list: sampleSessions()}
	h := newAuthServer(t, f)
	browser := browserLogin(t, h)
	for name, hdr := range map[string]map[string]string{
		"bearer":            {"Authorization": "Bearer " + testToken},
		"lowercase bearer":  {"Authorization": "bearer " + testToken},
		"cookie and secret": browser,
	} {
		for _, path := range []string{"/", "/static/app.js", "/fragments/sessions", "/api/sessions"} {
			if rec := send(h, "GET", "http://127.0.0.1:7680"+path, "", hdr); rec.Code != http.StatusOK {
				t.Errorf("%s: GET %s = %d", name, path, rec.Code)
			}
		}
	}
	rec := send(h, "POST", "http://localhost:7680/api/stop", `{"name":"work"}`, map[string]string{"Authorization": "Bearer " + testToken})
	if rec.Code != http.StatusOK || len(f.stopped) != 1 {
		t.Errorf("bearer POST = %d, stopped %v", rec.Code, f.stopped)
	}
	// Host and cross-origin checks still apply to authenticated requests.
	if rec := send(h, "GET", "http://evil.example/", "", map[string]string{"Authorization": "Bearer " + testToken}); rec.Code != http.StatusForbidden {
		t.Errorf("foreign Host with the token = %d", rec.Code)
	}
	rec = send(h, "POST", "http://127.0.0.1:7680/sessions/work/stop", "confirm=1", with(browser, "Sec-Fetch-Site", "cross-site"))
	if rec.Code != http.StatusForbidden {
		t.Errorf("cross-site POST with the cookie and secret = %d", rec.Code)
	}
}

// TestCookieIsNotTheToken is the regression test for the cookie reaching
// other 127.0.0.1 ports: what they get is not the bearer token, works only
// as the cookie, and only for this run of the dashboard.
func TestCookieIsNotTheToken(t *testing.T) {
	h := newAuthServer(t, &fakeSessions{list: sampleSessions()})
	browser := browserLogin(t, h)
	cookie := browser["Cookie"]
	name, value, _ := strings.Cut(cookie, "=")
	if name != "safeclaw_dashboard_7680" || value == testToken || strings.Contains(value, testToken) || len(value) < 26 {
		t.Fatalf("cookie = %q", cookie)
	}
	if secret := browser[secretHeader]; secret == value || secret == testToken || strings.Contains(secret, testToken) {
		t.Fatalf("secret = %q, cookie %q", secret, value)
	}
	// Each login gets its own cookie and secret.
	if again := browserLogin(t, h); again["Cookie"] == cookie || again[secretHeader] == browser[secretHeader] {
		t.Errorf("second login got %v, want a new cookie and secret, not %v", again, browser)
	}
	if rec := send(h, "GET", "http://127.0.0.1:7680/api/sessions", "", browser); rec.Code != http.StatusOK {
		t.Errorf("cookie and secret = %d", rec.Code)
	}
	for name, hdr := range map[string]map[string]string{
		"cookie value as bearer": {"Authorization": "Bearer " + value},
		"cookie value as token":  nil,
	} {
		target := "http://127.0.0.1:7680/api/sessions"
		if hdr == nil {
			target = "http://127.0.0.1:7680/?token=" + value
		}
		if rec := send(h, "GET", target, "", hdr); rec.Code != http.StatusUnauthorized {
			t.Errorf("%s = %d, want 401", name, rec.Code)
		}
	}
	// A bearer header decides on its own; a valid cookie beside a wrong
	// bearer doesn't let it through.
	if rec := send(h, "GET", "http://127.0.0.1:7680/api/sessions", "", with(browser, "Authorization", "Bearer nope")); rec.Code != http.StatusUnauthorized {
		t.Errorf("wrong bearer with the cookie = %d", rec.Code)
	}
	// Another run of the dashboard, with the same token, refuses it.
	other := newAuthServer(t, &fakeSessions{list: sampleSessions()})
	if rec := send(other, "GET", "http://127.0.0.1:7680/api/sessions", "", browser); rec.Code != http.StatusUnauthorized {
		t.Errorf("cookie and secret from another run = %d", rec.Code)
	}
	if rec := send(other, "GET", "http://127.0.0.1:7680/", "", browser); rec.Code != http.StatusUnauthorized {
		t.Errorf("page with the cookie from another run = %d", rec.Code)
	}
}

// TestCookieAloneOpensOnlyPages is the regression test for #106: the
// browser sends the cookie to every port on 127.0.0.1, so whoever listens
// on one can replay it from a client without Origin or Sec-Fetch-Site. The
// cookie alone, or with any header such a client can make up, only opens
// the page shells and static files, which show no state.
func TestCookieAloneOpensOnlyPages(t *testing.T) {
	h := newAuthServer(t, noSessions{t})
	browser := browserLogin(t, h)
	cookie := browser["Cookie"]
	_, value, _ := strings.Cut(cookie, "=")
	for name, hdr := range map[string]map[string]string{
		"cookie":             {"Cookie": cookie},
		"wrong secret":       {"Cookie": cookie, secretHeader: "nope"},
		"token as secret":    {"Cookie": cookie, secretHeader: testToken},
		"cookie as secret":   {"Cookie": cookie, secretHeader: value},
		"forged same-origin": {"Cookie": cookie, "Origin": "http://127.0.0.1:7680", "Sec-Fetch-Site": "same-origin"},
		"made up ticket":     {"Cookie": cookie},
	} {
		for _, rt := range routes {
			target := "http://127.0.0.1:7680" + rt.path
			if name == "made up ticket" {
				target += "?ticket=" + value
			}
			rec := send(h, rt.method, target, rt.body, hdr)
			want := http.StatusUnauthorized
			if isPage(rt.method, rt.path) {
				want = http.StatusOK
			}
			if rec.Code != want {
				t.Errorf("%s: %s %s = %d, want %d", name, rt.method, rt.path, rec.Code, want)
			}
		}
	}
	// The secret without the cookie is no good either.
	if rec := send(h, "GET", "http://127.0.0.1:7680/api/sessions", "", map[string]string{secretHeader: browser[secretHeader]}); rec.Code != http.StatusUnauthorized {
		t.Errorf("secret without the cookie = %d", rec.Code)
	}

	// The browser's own requests, which carry the secret, go through.
	f := &fakeSessions{list: sampleSessions()}
	h = newAuthServer(t, f)
	browser = browserLogin(t, h)
	cookieOnly := map[string]string{"Cookie": browser["Cookie"]}
	create := `{"name":"v2","volume":"/:/host"}`
	if rec := send(h, "POST", "http://127.0.0.1:7680/api/create", create, cookieOnly); rec.Code != http.StatusUnauthorized || len(f.ensured) != 0 {
		t.Fatalf("cookie-only create = %d, ensured %v", rec.Code, f.ensured)
	}
	if rec := send(h, "GET", "http://127.0.0.1:7680/api/sessions", "", cookieOnly); rec.Code != http.StatusUnauthorized {
		t.Errorf("cookie-only sessions = %d", rec.Code)
	}
	if rec := send(h, "GET", "http://127.0.0.1:7680/api/sessions", "", browser); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"name":"safeclaw-work"`) {
		t.Errorf("sessions with the secret = %d %s", rec.Code, rec.Body)
	}
	if rec := send(h, "POST", "http://127.0.0.1:7680/api/create", create, browser); rec.Code != http.StatusOK || len(f.ensured) != 1 || f.ensured[0].Volume != "/:/host" {
		t.Errorf("create with the secret = %d %s, ensured %v", rec.Code, rec.Body, f.ensured)
	}
}

// mintTicket asks h for a ticket for path with hdr and returns it.
func mintTicket(t *testing.T, h http.Handler, hdr map[string]string, path string) string {
	t.Helper()
	rec := send(h, "POST", "http://127.0.0.1:7680/tickets", "path="+path, hdr)
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("ticket for %s = %d %q", path, rec.Code, rec.Body)
	}
	return rec.Body.String()
}

func TestTickets(t *testing.T) {
	h := newAuthServer(t, &fakeSessions{list: sampleSessions()})
	browser := browserLogin(t, h)
	cookieOnly := map[string]string{"Cookie": browser["Cookie"]}
	const ws = "/sessions/work/terminal/ws"

	if rec := send(h, "POST", "http://127.0.0.1:7680/tickets", "path="+ws, cookieOnly); rec.Code != http.StatusUnauthorized {
		t.Errorf("ticket with only the cookie = %d", rec.Code)
	}
	for _, bad := range []string{"/api/sessions", "/events", ws + "?x=1", "http://127.0.0.1:7680" + ws, "sessions/work/terminal/ws", ""} {
		if rec := send(h, "POST", "http://127.0.0.1:7680/tickets", "path="+url.QueryEscape(bad), browser); rec.Code != http.StatusBadRequest {
			t.Errorf("ticket for %q = %d", bad, rec.Code)
		}
	}

	// A ticket opens only its own path, only with the cookie, and only once.
	// The terminal route answers 404 here, since the server has no
	// terminals, which shows the request got past authentication.
	tk := mintTicket(t, h, browser, ws)
	if rec := send(h, "GET", "http://127.0.0.1:7680/sessions/other/terminal/ws?ticket="+tk, "", cookieOnly); rec.Code != http.StatusUnauthorized {
		t.Errorf("ticket on another path = %d", rec.Code)
	}
	if rec := send(h, "GET", "http://127.0.0.1:7680"+ws+"?ticket="+tk, "", cookieOnly); rec.Code != http.StatusUnauthorized {
		t.Errorf("ticket used after a refused try = %d", rec.Code)
	}
	tk = mintTicket(t, h, browser, ws)
	if rec := send(h, "GET", "http://127.0.0.1:7680"+ws+"?ticket="+tk, "", nil); rec.Code != http.StatusUnauthorized {
		t.Errorf("ticket without the cookie = %d", rec.Code)
	}
	tk = mintTicket(t, h, browser, ws)
	if rec := send(h, "GET", "http://127.0.0.1:7680/api/sessions?ticket="+tk, "", cookieOnly); rec.Code != http.StatusUnauthorized {
		t.Errorf("ticket on the API = %d", rec.Code)
	}
	tk = mintTicket(t, h, browser, ws)
	if rec := send(h, "GET", "http://127.0.0.1:7680"+ws+"?ticket="+tk, "", cookieOnly); rec.Code != http.StatusNotFound {
		t.Errorf("ticket = %d, want it past authentication", rec.Code)
	}
	if rec := send(h, "GET", "http://127.0.0.1:7680"+ws+"?ticket="+tk, "", cookieOnly); rec.Code != http.StatusUnauthorized {
		t.Errorf("ticket used twice = %d", rec.Code)
	}
	// Bearer callers can mint them too.
	mintTicket(t, h, map[string]string{"Authorization": "Bearer " + testToken}, ws)
}

func TestTicketExpiryAndLimit(t *testing.T) {
	a := NewAccess(testToken, 7680, "")
	now := time.Unix(1000, 0)
	a.now = func() time.Time { return now }
	const ws = "/sessions/work/terminal/ws"
	tk, ok := a.mint(ws, nil)
	if !ok {
		t.Fatal("mint refused")
	}
	now = now.Add(ticketTTL)
	if a.redeem(tk, ws, nil) {
		t.Error("expired ticket redeemed")
	}
	for i := range maxTickets {
		if _, ok := a.mint(ws, nil); !ok {
			t.Fatalf("mint %d refused", i)
		}
	}
	if _, ok := a.mint(ws, nil); ok {
		t.Error("minted past the limit")
	}
	// Expired tickets make room again.
	now = now.Add(ticketTTL)
	if _, ok := a.mint(ws, nil); !ok {
		t.Error("expired tickets kept their room")
	}
}

func TestTokenExchange(t *testing.T) {
	h := newAuthServer(t, &fakeSessions{list: sampleSessions()})

	rec := send(h, "GET", "http://127.0.0.1:7680/?token="+testToken, "", nil)
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/#"+secretFragment+"=") {
		t.Fatalf("exchange = %d to %q", rec.Code, loc)
	}
	secret := fragmentSecret(t, loc)
	if secret == testToken || strings.Contains(secret, testToken) {
		t.Errorf("secret = %q", secret)
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Errorf("exchange headers %v", rec.Header())
	}
	cookies := rec.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatalf("cookies = %v", cookies)
	}
	c := cookies[0]
	if c.Name != "safeclaw_dashboard_7680" || c.Value == "" || c.Value == testToken || c.Value == secret || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Path != "/" || c.Domain != "" || c.MaxAge != int(loginLifetime/time.Second) {
		t.Errorf("cookie = %+v", c)
	}

	rec = send(h, "GET", "http://127.0.0.1:7680/fragments/sessions?a=1&token="+testToken, "", nil)
	if loc, _, _ := strings.Cut(rec.Header().Get("Location"), "#"); rec.Code != http.StatusSeeOther || loc != "/fragments/sessions?a=1" {
		t.Errorf("exchange keeps other params: %d to %q", rec.Code, rec.Header().Get("Location"))
	}

	rec = send(h, "GET", "http://127.0.0.1:7680//evil.example/?token="+testToken, "", nil)
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/evil.example/#"+secretFragment+"=") {
		t.Errorf("exchange redirects off-site: %q", loc)
	}

	// localhost is sent to 127.0.0.1 first, so the cookie is never set for
	// localhost, where session terminals are served.
	rec = send(h, "GET", "http://localhost:7680/?token="+testToken, "", nil)
	if rec.Code != http.StatusTemporaryRedirect || rec.Header().Get("Location") != "http://127.0.0.1:7680/?token="+testToken || len(rec.Result().Cookies()) != 0 {
		t.Errorf("exchange on localhost = %d to %q, cookies %v", rec.Code, rec.Header().Get("Location"), rec.Result().Cookies())
	}
	// ::1 is not advertised, and nothing listens on it, so it is refused.
	rec = send(h, "GET", "http://[::1]:7680/?token="+testToken, "", nil)
	if rec.Code != http.StatusForbidden || len(rec.Result().Cookies()) != 0 {
		t.Errorf("exchange on [::1] = %d, cookies %v", rec.Code, rec.Result().Cookies())
	}

	for _, bad := range []string{"nope", "", testToken + "x"} {
		rec = send(h, "GET", "http://127.0.0.1:7680/?token="+bad, "", nil)
		if rec.Code != http.StatusUnauthorized || len(rec.Result().Cookies()) != 0 {
			t.Errorf("exchange with %q = %d, cookies %v", bad, rec.Code, rec.Result().Cookies())
		}
	}
}

// TestBrowserFlow follows the printed URL like a browser and then opens the
// SSE stream with the cookie it got.
func TestBrowserFlow(t *testing.T) {
	s, err := New(Options{Sessions: &fakeSessions{list: sampleSessions()}, Token: testToken, TokenFile: "unused"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Jar: jar}

	// The URL the dashboard prints, with localhost to exercise both redirects.
	launch := strings.Replace(srv.URL, "127.0.0.1", "localhost", 1) + "/?token=" + testToken
	resp, err := client.Get(launch)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	landed := *resp.Request.URL
	landed.Fragment, landed.RawFragment = "", ""
	if resp.StatusCode != http.StatusOK || landed.String() != srv.URL+"/" || !bytes.Contains(body, []byte(`hx-sse:connect="/events"`)) {
		t.Fatalf("launch = %d at %s", resp.StatusCode, resp.Request.URL)
	}
	secret := fragmentSecret(t, resp.Request.URL.String())
	if c := jar.Cookies(resp.Request.URL); len(c) != 1 || c[0].Value == testToken {
		t.Errorf("browser cookies = %v, want one that is not the token", c)
	}

	// The cookie alone doesn't open the stream; htmx sends the secret.
	resp, err = client.Get(srv.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("events with only the cookie = %d", resp.StatusCode)
	}
	req, _ := http.NewRequest("GET", srv.URL+"/events", nil)
	req.Header.Set(secretHeader, secret)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("events with the cookie and secret = %d %q", resp.StatusCode, resp.Header.Get("Content-Type"))
	}
	if line, _ := bufio.NewReader(resp.Body).ReadString('\n'); line != ": connected\n" {
		t.Errorf("events = %q", line)
	}

	// Without the cookie, the stream is refused before subscribing.
	resp2, err := http.Get(srv.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("events without the cookie = %d", resp2.StatusCode)
	}
}

// TestContainerCannotCreateSession is the regression test for a client
// inside a session container that reaches the dashboard through the host
// gateway and sends `Host: localhost`: it is refused before any docker call.
func TestContainerCannotCreateSession(t *testing.T) {
	r := &dockertest.Runner{}
	dir := t.TempDir()
	m := &session.Manager{
		Docker:      r.Client(),
		Secrets:     secrets.FileStore{Dir: filepath.Join(dir, "secrets")},
		SessionsDir: filepath.Join(dir, "sessions"),
		TTYDDir:     filepath.Join(dir, "ttyd"),
		NetworkDir:  filepath.Join(dir, "network"),
		CopyDir:     filepath.Join(dir, "copy"),
		Out:         io.Discard,
		PortFree:    func(int) bool { return true },
		Sleep:       func(time.Duration) {},
		OpenBrowser: func(string) error { return nil },
	}
	if err := m.Secrets.Set(secrets.ClaudeToken, "dummy-oauth"); err != nil {
		t.Fatal(err)
	}
	s, err := New(Options{Manager: m, Token: testToken, TokenFile: "unused"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)

	raw := func(host, auth string) string {
		t.Helper()
		conn, err := net.Dial("tcp", srv.Listener.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = conn.Close() }()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		body := `{"name":"v2","volume":"/:/host","secrets":"all","query":"dummy-q"}`
		req := "POST /api/create HTTP/1.1\r\nHost: " + host + "\r\nContent-Type: application/json\r\nConnection: close\r\n" + auth +
			"Content-Length: " + strconv.Itoa(len(body)) + "\r\n\r\n" + body
		if _, err := io.WriteString(conn, req); err != nil {
			t.Fatal(err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
		if err != nil {
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		return resp.Status
	}

	if got := raw("host.internal:7680", ""); got != "403 Forbidden" {
		t.Errorf("foreign Host = %s", got)
	}
	for _, auth := range []string{"", "Authorization: Bearer guess\r\n", "Cookie: safeclaw_dashboard_7680=guess\r\n"} {
		if got := raw("localhost", auth); got != "401 Unauthorized" {
			t.Errorf("Host: localhost with %q = %s", auth, got)
		}
	}
	if len(r.Calls) != 0 {
		t.Fatalf("unauthenticated create made docker calls: %v", r.Calls)
	}
}

func TestListenAndServeWritesTokenFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "dashboard")
	file := filepath.Join(dir, "7680.token")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(file, []byte("stale\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()

	s, err := New(Options{Sessions: &fakeSessions{}, Port: port, TokenFile: file})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	out := &syncBuffer{}
	done := make(chan error, 1)
	go func() { done <- s.ListenAndServe(ctx, out) }()
	for i := 0; i < 200 && !strings.Contains(out.String(), "API token"); i++ {
		time.Sleep(10 * time.Millisecond)
	}

	b, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "stale" || len(tok) < 40 || tok != s.token {
		t.Errorf("token file holds %q", tok)
	}
	for path, want := range map[string]os.FileMode{file: 0o600, dir: 0o700} {
		if fi, err := os.Stat(path); err != nil || fi.Mode().Perm() != want {
			t.Errorf("%s mode = %v, %v; want %v", path, fi.Mode().Perm(), err, want)
		}
	}
	want := "Dashboard: http://127.0.0.1:" + strconv.Itoa(port) + "/?token=" + tok + "\nAPI token: " + file + "\n"
	if out.String() != want {
		t.Errorf("printed %q, want %q", out.String(), want)
	}

	req, _ := http.NewRequest("GET", "http://127.0.0.1:"+strconv.Itoa(port)+"/api/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("bearer from the token file = %d", resp.StatusCode)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("token file left behind: %v", err)
	}
}

func TestRemoveTokenFileKeepsAnotherRunsToken(t *testing.T) {
	file := filepath.Join(t.TempDir(), "7680.token")
	if err := writeTokenFile(file, "newer"); err != nil {
		t.Fatal(err)
	}
	if err := removeTokenFile(file, "older"); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(file); string(b) != "newer\n" {
		t.Errorf("file = %q", b)
	}
}

func TestNewToken(t *testing.T) {
	a, err := NewToken()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewToken()
	if a == b || len(a) != 43 {
		t.Errorf("tokens %q %q", a, b)
	}
	s1, _ := New(Options{Sessions: &fakeSessions{}})
	s2, _ := New(Options{Sessions: &fakeSessions{}})
	if s1.token == "" || s1.token == s2.token {
		t.Errorf("servers share or lack a token: %q %q", s1.token, s2.token)
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}
