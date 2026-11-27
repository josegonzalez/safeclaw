package dashboard

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newClockServer is newAuthServer with a clock the test moves.
func newClockServer(t *testing.T) (http.Handler, *time.Time) {
	t.Helper()
	s, err := New(Options{Sessions: &fakeSessions{list: sampleSessions()}, Token: testToken, TokenFile: "/cfg/dashboard/7680.token"})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_000_000, 0)
	s.access.now = func() time.Time { return now }
	return s.Handler(), &now
}

func apiStatus(h http.Handler, hdr map[string]string) int {
	return send(h, "GET", "http://127.0.0.1:7680/api/sessions", "", hdr).Code
}

func logout(h http.Handler, hdr map[string]string) *httptest.ResponseRecorder {
	return send(h, "POST", "http://127.0.0.1:7680/logout", "", hdr)
}

func TestLogoutEndsOnlyItsLogin(t *testing.T) {
	h := newAuthServer(t, &fakeSessions{list: sampleSessions()})
	bearer := map[string]string{"Authorization": "Bearer " + testToken}
	a, b := browserLogin(t, h), browserLogin(t, h)
	const ws = "/sessions/work/terminal/ws"
	tk := mintTicket(t, h, a, ws)

	// Logging out needs the secret, and refuses other sites.
	if rec := logout(h, map[string]string{"Cookie": a["Cookie"]}); rec.Code != http.StatusUnauthorized {
		t.Errorf("logout with only the cookie = %d", rec.Code)
	}
	if rec := logout(h, with(a, "Sec-Fetch-Site", "cross-site")); rec.Code != http.StatusForbidden {
		t.Errorf("cross-site logout = %d", rec.Code)
	}
	if rec := logout(h, bearer); rec.Code != http.StatusBadRequest {
		t.Errorf("logout with the bearer token = %d", rec.Code)
	}
	if apiStatus(h, a) != http.StatusOK {
		t.Fatal("a refused logout logged a out")
	}

	rec := logout(h, a)
	if rec.Code != http.StatusNoContent || rec.Header().Get("HX-Trigger") != "logged-out" || rec.Header().Get("Cache-Control") != "no-store" {
		t.Errorf("logout = %d %v", rec.Code, rec.Header())
	}
	if c := rec.Result().Cookies(); len(c) != 1 || c[0].Name != "safeclaw_dashboard_7680" || c[0].Value != "" || c[0].MaxAge >= 0 {
		t.Errorf("logout cookies = %v", c)
	}

	// The old cookie and secret open nothing, not even the page shells,
	// and its ticket is gone.
	if code := apiStatus(h, a); code != http.StatusUnauthorized {
		t.Errorf("logged out cookie and secret = %d", code)
	}
	if rec := send(h, "GET", "http://127.0.0.1:7680/", "", map[string]string{"Cookie": a["Cookie"]}); rec.Code != http.StatusUnauthorized {
		t.Errorf("logged out cookie on the page shell = %d", rec.Code)
	}
	if rec := send(h, "GET", "http://127.0.0.1:7680"+ws+"?ticket="+tk, "", map[string]string{"Cookie": a["Cookie"]}); rec.Code != http.StatusUnauthorized {
		t.Errorf("logged out login's ticket = %d", rec.Code)
	}
	if rec := logout(h, a); rec.Code != http.StatusUnauthorized {
		t.Errorf("second logout = %d", rec.Code)
	}
	// Its secret doesn't work with another login's cookie either.
	if code := apiStatus(h, map[string]string{"Cookie": b["Cookie"], secretHeader: a[secretHeader]}); code != http.StatusUnauthorized {
		t.Errorf("a's secret with b's cookie = %d", code)
	}

	// Other logins and the bearer token are unaffected.
	if code := apiStatus(h, b); code != http.StatusOK {
		t.Errorf("other login after logout = %d", code)
	}
	if code := apiStatus(h, bearer); code != http.StatusOK {
		t.Errorf("bearer after logout = %d", code)
	}
}

func TestTicketsAreBoundToTheirLogin(t *testing.T) {
	h := newAuthServer(t, &fakeSessions{list: sampleSessions()})
	a, b := browserLogin(t, h), browserLogin(t, h)
	const ws = "/sessions/work/terminal/ws"
	tk := mintTicket(t, h, a, ws)
	if rec := send(h, "GET", "http://127.0.0.1:7680"+ws+"?ticket="+tk, "", map[string]string{"Cookie": b["Cookie"]}); rec.Code != http.StatusUnauthorized {
		t.Errorf("a's ticket with b's cookie = %d", rec.Code)
	}
	// A bearer ticket has no login, so any login's cookie can use it.
	tk = mintTicket(t, h, map[string]string{"Authorization": "Bearer " + testToken}, ws)
	if rec := send(h, "GET", "http://127.0.0.1:7680"+ws+"?ticket="+tk, "", map[string]string{"Cookie": b["Cookie"]}); rec.Code != http.StatusNotFound {
		t.Errorf("bearer ticket with a cookie = %d, want it past authentication", rec.Code)
	}
}

func TestLoginReplacesTheBrowsersOldLogin(t *testing.T) {
	h := newAuthServer(t, &fakeSessions{list: sampleSessions()})
	old := browserLogin(t, h)
	rec := send(h, "GET", "http://127.0.0.1:7680/?token="+testToken, "", map[string]string{"Cookie": old["Cookie"]})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("exchange = %d", rec.Code)
	}
	if code := apiStatus(h, old); code != http.StatusUnauthorized {
		t.Errorf("replaced login = %d", code)
	}
	c := rec.Result().Cookies()[0]
	fresh := map[string]string{"Cookie": c.Name + "=" + c.Value, secretHeader: fragmentSecret(t, rec.Header().Get("Location"))}
	if code := apiStatus(h, fresh); code != http.StatusOK {
		t.Errorf("new login = %d", code)
	}
}

func TestLoginExpiry(t *testing.T) {
	h, now := newClockServer(t)
	bearer := map[string]string{"Authorization": "Bearer " + testToken}

	// Idle: a login with no request for loginIdle ends.
	idle := browserLogin(t, h)
	*now = now.Add(loginIdle - time.Second)
	if code := apiStatus(h, idle); code != http.StatusOK {
		t.Fatalf("login before idling out = %d", code)
	}
	*now = now.Add(loginIdle)
	if code := apiStatus(h, idle); code != http.StatusUnauthorized {
		t.Errorf("idle login = %d", code)
	}
	if rec := send(h, "GET", "http://127.0.0.1:7680/", "", map[string]string{"Cookie": idle["Cookie"]}); rec.Code != http.StatusUnauthorized {
		t.Errorf("idle login's page shell = %d", rec.Code)
	}
	if code := apiStatus(h, bearer); code != http.StatusOK {
		t.Errorf("bearer after the login idled out = %d", code)
	}
}

// TestLoginLifetime checks that a login in steady use still ends after
// loginLifetime, which is the cookie's Max-Age.
func TestLoginLifetime(t *testing.T) {
	h, now := newClockServer(t)
	l := browserLogin(t, h)
	start := *now
	for now.Add(loginIdle / 2).Before(start.Add(loginLifetime)) {
		*now = now.Add(loginIdle / 2)
		if code := apiStatus(h, l); code != http.StatusOK {
			t.Fatalf("login %v after it started = %d", now.Sub(start), code)
		}
	}
	*now = start.Add(loginLifetime)
	if code := apiStatus(h, l); code != http.StatusUnauthorized {
		t.Errorf("login at its lifetime = %d", code)
	}
}

func TestRequestInFlightKeepsLoginFromIdling(t *testing.T) {
	a := NewAccess(testToken, 7680, "")
	now := time.Unix(1_000_000, 0)
	a.now = func() time.Time { return now }
	value, _ := a.newLogin(httptest.NewRequest("GET", "/", nil))
	r := httptest.NewRequest("GET", "/", nil)
	r.AddCookie(&http.Cookie{Name: a.cookie, Value: value})
	l := a.find(r)
	if l == nil {
		t.Fatal("new login not found")
	}
	a.acquire(l)
	now = now.Add(2 * loginIdle)
	if a.find(r) == nil {
		t.Fatal("login idled out with a request in flight")
	}
	a.release(l)
	now = now.Add(loginIdle)
	if a.find(r) != nil {
		t.Error("login kept after idling")
	}
}

func TestLoginLimit(t *testing.T) {
	h, now := newClockServer(t)
	var logins []map[string]string
	for range maxLogins {
		*now = now.Add(time.Second)
		logins = append(logins, browserLogin(t, h))
	}
	// Using the first makes the second the least recently used, which goes
	// when one more logs in.
	*now = now.Add(time.Second)
	if code := apiStatus(h, logins[0]); code != http.StatusOK {
		t.Fatalf("first login at the limit = %d", code)
	}
	*now = now.Add(time.Second)
	browserLogin(t, h)
	if code := apiStatus(h, logins[0]); code != http.StatusOK {
		t.Errorf("recently used login evicted = %d", code)
	}
	if code := apiStatus(h, logins[1]); code != http.StatusUnauthorized {
		t.Errorf("least recently used login kept = %d", code)
	}
	if code := apiStatus(h, logins[2]); code != http.StatusOK {
		t.Errorf("other login evicted = %d", code)
	}
}

// TestJunkCookieDoesNotHideTheLogin covers another 127.0.0.1 listener
// setting a cookie with the dashboard's name for a narrower path, which the
// browser sends before the real one.
func TestJunkCookieDoesNotHideTheLogin(t *testing.T) {
	h := newAuthServer(t, &fakeSessions{list: sampleSessions()})
	b := browserLogin(t, h)
	hdr := with(b, "Cookie", "safeclaw_dashboard_7680=junk; "+b["Cookie"])
	if code := apiStatus(h, hdr); code != http.StatusOK {
		t.Errorf("login behind a junk cookie = %d", code)
	}
}

func TestLogoutEndsStreams(t *testing.T) {
	s, err := New(Options{Sessions: &fakeSessions{list: sampleSessions()}, Token: testToken, TokenFile: "unused"})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)
	b := browserLogin(t, srv.Config.Handler)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "GET", srv.URL+"/events", nil)
	for k, v := range b {
		req.Header.Set(k, v)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	rd := bufio.NewReader(resp.Body)
	if line, err := rd.ReadString('\n'); err != nil || !strings.HasPrefix(line, ": connected") {
		t.Fatalf("stream = %q %v", line, err)
	}
	if rec := logout(srv.Config.Handler, b); rec.Code != http.StatusNoContent {
		t.Fatalf("logout = %d", rec.Code)
	}
	if _, err := io.ReadAll(rd); err != nil {
		t.Errorf("stream after logout: %v", err)
	}
	if ctx.Err() != nil {
		t.Error("stream outlived the logout")
	}
}

func TestLogoutClosesTerminals(t *testing.T) {
	srv, _, _ := newTerminalServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	b := browserLogin(t, srv.Config.Handler)
	tk := mintTicket(t, srv.Config.Handler, b, "/sessions/work/terminal/ws")
	h := http.Header{}
	h.Set("Origin", srv.URL)
	h.Set("Cookie", b["Cookie"])
	c, status, err := dialDashboard(ctx, srv, "/sessions/work/terminal/ws?ticket="+tk, h)
	if err != nil {
		t.Fatalf("dial = %d %v", status, err)
	}
	defer func() { _ = c.CloseNow() }()
	if rec := logout(srv.Config.Handler, b); rec.Code != http.StatusNoContent {
		t.Fatalf("logout = %d", rec.Code)
	}
	if _, _, err := c.Read(ctx); err == nil {
		t.Error("terminal read after logout succeeded")
	}
	if ctx.Err() != nil {
		t.Error("terminal outlived the logout")
	}
}
