package dashboard

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/josegonzalez/safeclaw/internal/dashproof"
)

// tokenParam is the query parameter carrying the launch token in the URL
// the dashboard prints.
const tokenParam = "token"

// cookieHost is the only host the session cookie is set for. Cookies are
// not scoped by port, so a cookie for localhost would also be sent to a
// session's web terminal at localhost:<port>, which is served from inside
// the container. Session URLs use [::1], or localhost for images whose
// ttyd refuses [::1], so a cookie for 127.0.0.1 never reaches them.
const cookieHost = "127.0.0.1"

// NewToken returns a random launch token.
func NewToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// secretHeader carries a browser login's second secret on every request
// its pages make.
const secretHeader = "Safeclaw-Secret"

// secretFragment names the second secret in the fragment of the URL the
// token exchange redirects to.
const secretFragment = "safeclaw-secret"

// ticketParam is the query parameter carrying a ticket on the routes a
// browser can't send headers to.
const ticketParam = "ticket"

// ticketTTL is how long a ticket can be redeemed for, and maxTickets bounds
// how many are outstanding at once.
const (
	ticketTTL  = 30 * time.Second
	maxTickets = 64
)

// pageRoutes are what a browser loads by navigating, which can't carry the
// second secret: the page shells and the static files. They serve only the
// dashboard's own code, never the state of a session or the host, so they
// need just the cookie. Everything they show is fetched by app.js, which
// sends the secret.
var pageRoutes = []string{"GET /{$}", "GET /static/", "GET /sessions/{name}/terminal"}

// ticketRoutes are opened by a browser API that can't set headers, the
// terminal WebSocket, so they take the cookie with a ticket in place of the
// secret.
var ticketRoutes = []string{"GET /sessions/{name}/terminal/ws"}

// loginIdle is how long a browser login lasts with no request in flight,
// loginLifetime how long it lasts at most, which is also its cookie's
// Max-Age, and maxLogins bounds how many are kept at once.
const (
	loginIdle     = 12 * time.Hour
	loginLifetime = 7 * 24 * time.Hour
	maxLogins     = 32
)

// Access authenticates dashboard callers. Browsers open the URL carrying
// the launch token once and get an HttpOnly, SameSite=Strict cookie in
// exchange, plus a second secret in the redirect's fragment, which app.js
// keeps in the origin's localStorage and sends in the Safeclaw-Secret header.
// Other clients send the token as `Authorization: Bearer`.
//
// Cookies are not scoped by port, so the browser also sends the cookie to
// anything else listening on 127.0.0.1, such as a session published there
// before sessions moved to [::1] or another local user's server, which can
// then replay it from any client with any headers. So the cookie alone only
// opens the page shells. Storage is scoped to the origin, port included, and
// no route returns the secret, so such a listener can't get it.
//
// Each exchange makes a login of its own, with its own cookie value and
// secret, so one browser logging out or expiring leaves the others working.
type Access struct {
	token  string
	cookie string
	// port is the dashboard's port, which its proofs are bound to.
	port int
	// file is where the token is stored for API callers, named in the 401
	// response.
	file string

	pages    *http.ServeMux
	ticketed *http.ServeMux

	mu sync.Mutex
	// logins are keyed by the SHA-256 of their cookie's value, so finding
	// one doesn't compare the value itself in variable time. They are only
	// kept in memory, so they stop working when the dashboard stops.
	logins  map[[sha256.Size]byte]*login
	tickets map[string]ticket
	now     func() time.Time
}

// login is one browser's login: the secret that must come with its cookie,
// and when it ends. ctx is canceled when it ends, which ends its requests
// still in flight, such as an SSE stream or a terminal WebSocket.
type login struct {
	secret  string
	expires time.Time
	used    time.Time
	// active counts its requests in flight. It doesn't idle out while any
	// are, so an open dashboard tab, whose SSE stream stays open, keeps it.
	active int
	ctx    context.Context
	cancel context.CancelFunc
}

// ticket lets the cookie of login open path once, until expires. A ticket
// minted with the bearer token has no login, and works with any.
type ticket struct {
	path    string
	login   *login
	expires time.Time
}

// loginKey is the request context key of the login a request came with.
type loginKey struct{}

// requestLogin returns the login r came with, or nil for the bearer token.
func requestLogin(r *http.Request) *login {
	l, _ := r.Context().Value(loginKey{}).(*login)
	return l
}

// NewAccess returns an Access for token. The cookie is named after port so
// dashboards on different ports don't overwrite each other's cookie.
func NewAccess(token string, port int, file string) *Access {
	return &Access{
		token:    token,
		cookie:   "safeclaw_dashboard_" + strconv.Itoa(port),
		port:     port,
		file:     file,
		pages:    routeSet(pageRoutes),
		ticketed: routeSet(ticketRoutes),
		logins:   map[[sha256.Size]byte]*login{},
		tickets:  map[string]ticket{},
		now:      time.Now,
	}
}

// routeMark is the handler routeSet registers, so a match can be told from
// the mux's own redirects and 404s.
type routeMark struct{}

func (*routeMark) ServeHTTP(http.ResponseWriter, *http.Request) {}

var mark = &routeMark{}

func routeSet(patterns []string) *http.ServeMux {
	m := http.NewServeMux()
	for _, p := range patterns {
		m.Handle(p, mark)
	}
	return m
}

// isRoute reports whether r is for one of the routes in m.
func isRoute(m *http.ServeMux, r *http.Request) bool {
	h, _ := m.Handler(r)
	return h == mark
}

// Middleware lets a request through to next only when it carries the token
// in its Authorization header, or a live login's cookie with that login's
// second secret in its Safeclaw-Secret header. The cookie alone is enough
// for pageRoutes, and with a ticket for ticketRoutes. A GET carrying the
// token in the query is answered with a new login's cookie and a redirect to
// the same URL without the token, with the secret in its fragment. A request
// for dashproof.Path is answered with the proof that this dashboard holds
// the token, with no login needed. Anything else gets 401 without reaching
// next.
//
// A request that came with a login ends with it: its context is canceled
// when the login logs out or expires.
//
// A handler behind it that forwards requests elsewhere, such as a session's
// web terminal, must drop the cookie and Authorization header first.
func (a *Access) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == dashproof.Path {
			a.prove(w, r)
			return
		}
		q := r.URL.Query()
		if q.Has(tokenParam) && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			a.exchange(w, r, q)
			return
		}
		l, ok := a.allowed(r)
		if !ok {
			a.unauthorized(w)
			return
		}
		if l == nil {
			next.ServeHTTP(w, r)
			return
		}
		// The deadline is the wall clock's, whatever a.now says.
		ctx, cancel := context.WithDeadline(r.Context(), time.Now().Add(a.acquire(l)))
		defer cancel()
		defer a.release(l)
		stop := context.AfterFunc(l.ctx, cancel)
		defer stop()
		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, loginKey{}, l)))
	})
}

// allowed reports whether r may reach the route it asks for, and the login
// it came with, which is nil for the bearer token. A bearer header decides
// on its own, so a cookie can't make up for a wrong token. Neither the token
// nor the cookie is accepted in place of the other.
func (a *Access) allowed(r *http.Request) (*login, bool) {
	if scheme, tok, ok := strings.Cut(r.Header.Get("Authorization"), " "); ok && strings.EqualFold(scheme, "Bearer") {
		return nil, equal(strings.TrimSpace(tok), a.token)
	}
	l := a.find(r)
	if l == nil {
		return nil, false
	}
	switch {
	case equal(r.Header.Get(secretHeader), l.secret):
		return l, true
	case isRoute(a.pages, r):
		return l, true
	case isRoute(a.ticketed, r):
		return l, a.redeem(r.URL.Query().Get(ticketParam), r.URL.Path, l)
	}
	return nil, false
}

func equal(got, want string) bool {
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

func cookieKey(v string) [sha256.Size]byte { return sha256.Sum256([]byte(v)) }

// find returns the live login whose cookie r carries, or nil. Every cookie
// with the dashboard's name is tried, so one that another 127.0.0.1
// listener set for a narrower path, which the browser sends first, doesn't
// hide the real one.
func (a *Access) find(r *http.Request) *login {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	for _, c := range r.CookiesNamed(a.cookie) {
		if c.Value == "" {
			continue
		}
		k := cookieKey(c.Value)
		l, ok := a.logins[k]
		if !ok {
			continue
		}
		if l.ended(now) {
			a.end(k, l)
			continue
		}
		return l
	}
	return nil
}

// ended reports whether l has expired by now, or idled out.
func (l *login) ended(now time.Time) bool {
	return !now.Before(l.expires) || (l.active == 0 && now.Sub(l.used) >= loginIdle)
}

// end forgets the login under k, ends its requests in flight, and drops its
// tickets. a.mu must be held.
func (a *Access) end(k [sha256.Size]byte, l *login) {
	delete(a.logins, k)
	l.cancel()
	for v, t := range a.tickets {
		if t.login == l {
			delete(a.tickets, v)
		}
	}
}

// acquire marks a request of l in flight and returns how long l has left.
func (a *Access) acquire(l *login) time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	l.active++
	l.used = now
	return l.expires.Sub(now)
}

// release marks a request of l done.
func (a *Access) release(l *login) {
	a.mu.Lock()
	defer a.mu.Unlock()
	l.active--
	l.used = a.now()
}

// newLogin makes a login and returns its cookie value and secret. It ends
// the login whose cookie r carries, since the browser replaces that cookie
// with the new one, and ends the least recently used login when maxLogins
// are kept.
func (a *Access) newLogin(r *http.Request) (value, secret string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	for _, c := range r.CookiesNamed(a.cookie) {
		k := cookieKey(c.Value)
		if l, ok := a.logins[k]; ok {
			a.end(k, l)
		}
	}
	var oldest *login
	var oldestKey [sha256.Size]byte
	for k, l := range a.logins {
		if l.ended(now) {
			a.end(k, l)
			continue
		}
		if oldest == nil || l.used.Before(oldest.used) {
			oldest, oldestKey = l, k
		}
	}
	if len(a.logins) >= maxLogins {
		a.end(oldestKey, oldest)
	}
	value, secret = rand.Text(), rand.Text()
	ctx, cancel := context.WithCancel(context.Background())
	a.logins[cookieKey(value)] = &login{secret: secret, expires: now.Add(loginLifetime), used: now, ctx: ctx, cancel: cancel}
	return value, secret
}

// logout ends l, if it is still live.
func (a *Access) logout(l *login) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for k, v := range a.logins {
		if v == l {
			a.end(k, l)
		}
	}
}

// sessionCookie returns the login cookie with value, kept for maxAge
// seconds.
func (a *Access) sessionCookie(value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     a.cookie,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	}
}

// exchange swaps the token in the query for a new login's cookie and
// redirects to the URL without it, so the token leaves the address bar and
// history. The redirect's fragment carries the login's second secret, which
// the browser never sends to a server or in a Referer; app.js stores it and
// removes it from the address bar. On any host other than 127.0.0.1 it
// first redirects there, keeping the token.
func (a *Access) exchange(w http.ResponseWriter, r *http.Request, q url.Values) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
	if !equal(q.Get(tokenParam), a.token) {
		a.unauthorized(w)
		return
	}
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil {
		host, port = r.Host, ""
	}
	if host != cookieHost {
		u := *r.URL
		u.Scheme, u.Host = "http", cookieHost
		if port != "" {
			u.Host = net.JoinHostPort(cookieHost, port)
		}
		http.Redirect(w, r, u.String(), http.StatusTemporaryRedirect)
		return
	}
	value, secret := a.newLogin(r)
	http.SetCookie(w, a.sessionCookie(value, int(loginLifetime/time.Second)))
	delete(q, tokenParam)
	// A path starting with // would redirect to another host.
	u := url.URL{Path: "/" + strings.TrimLeft(r.URL.Path, "/"), RawQuery: q.Encode()}
	http.Redirect(w, r, u.RequestURI()+"#"+secretFragment+"="+secret, http.StatusSeeOther)
}

// handleLogout ends the login the request came with, so its cookie and
// secret stop working and its streams and terminals close, and clears the
// cookie. It is behind Middleware like every route, and isn't a page or
// ticket route, so it needs the cookie with the secret, which a form on
// another site can't send, and CrossOriginProtection applies too. The
// bearer token has no login to end.
func (a *Access) handleLogout(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	l := requestLogin(r)
	if l == nil {
		http.Error(w, "only a browser login can log out", http.StatusBadRequest)
		return
	}
	a.logout(l)
	http.SetCookie(w, a.sessionCookie("", -1))
	w.Header().Set("HX-Trigger", "logged-out")
	w.WriteHeader(http.StatusNoContent)
}

// handleTicket answers with a ticket that lets the cookie open the path in
// the form once, within ticketTTL, which must be one of ticketRoutes. It is
// behind Middleware like every route, and isn't a page or ticket route, so
// only a caller with the secret or the token gets one.
func (a *Access) handleTicket(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	u, err := url.Parse(r.PostFormValue("path"))
	if err != nil || u.Scheme != "" || u.Host != "" || u.RawQuery != "" || u.Fragment != "" || !strings.HasPrefix(u.Path, "/") ||
		!isRoute(a.ticketed, &http.Request{Method: http.MethodGet, URL: &url.URL{Path: u.Path}, Host: r.Host}) {
		http.Error(w, "tickets are only for the terminal WebSocket", http.StatusBadRequest)
		return
	}
	t, ok := a.mint(u.Path, requestLogin(r))
	if !ok {
		http.Error(w, "too many outstanding tickets", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, t)
}

// mint returns a new ticket for path that l's cookie can use, or false when
// maxTickets are still outstanding. Expired tickets are dropped first.
func (a *Access) mint(path string, l *login) (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	now := a.now()
	for k, t := range a.tickets {
		if !now.Before(t.expires) {
			delete(a.tickets, k)
		}
	}
	if len(a.tickets) >= maxTickets {
		return "", false
	}
	v := rand.Text()
	a.tickets[v] = ticket{path: path, login: l, expires: now.Add(ticketTTL)}
	return v, true
}

// redeem reports whether v is an unexpired ticket for path that l's cookie
// can use, and uses it up whether or not it is.
func (a *Access) redeem(v, path string, l *login) bool {
	if v == "" {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	t, ok := a.tickets[v]
	if !ok {
		return false
	}
	delete(a.tickets, v)
	return t.path == path && (t.login == nil || t.login == l) && a.now().Before(t.expires)
}

// prove answers the nonce in r with the proof that this dashboard holds the
// token, so the CLI can tell it from another listener that took over the
// port of a stale token file without sending the token to it.
func (a *Access) prove(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	nonce := r.URL.Query().Get(dashproof.NonceParam)
	if !dashproof.ValidNonce(nonce) {
		http.Error(w, "bad nonce", http.StatusBadRequest)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set(dashproof.Header, dashproof.Sign(a.token, a.port, nonce))
	w.WriteHeader(http.StatusNoContent)
}

func (a *Access) unauthorized(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="safeclaw"`)
	msg := "unauthorized: open the URL printed by `safeclaw dashboard`"
	if a.file != "" {
		msg += ", or send `Authorization: Bearer` with the token in " + a.file
	}
	http.Error(w, msg, http.StatusUnauthorized)
}

// writeTokenFile stores token in path, readable only by the user, in a
// directory only the user can open. It replaces any file left by an earlier
// run.
func writeTokenFile(path, token string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".token-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer func() { _ = os.Remove(tmp) }()
	if err := f.Chmod(0o600); err != nil {
		_ = f.Close()
		return err
	}
	if _, err := io.WriteString(f, token+"\n"); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return fmt.Errorf("write dashboard token: %w", err)
	}
	return nil
}

// removeTokenFile removes path if it still holds token, so a dashboard that
// started on the same port meanwhile keeps its file.
func removeTokenFile(path, token string) error {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(b)) != token {
		return nil
	}
	return os.Remove(path)
}
