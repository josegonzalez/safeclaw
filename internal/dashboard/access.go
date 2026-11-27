package dashboard

import (
	"crypto/rand"
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
type Access struct {
	token string
	// session is the cookie's value and secret the value that must come
	// with it. Both are only kept in memory, so they stop working when the
	// dashboard stops.
	session string
	secret  string
	cookie  string
	// port is the dashboard's port, which its proofs are bound to.
	port int
	// file is where the token is stored for API callers, named in the 401
	// response.
	file string

	pages    *http.ServeMux
	ticketed *http.ServeMux

	mu      sync.Mutex
	tickets map[string]ticket
	now     func() time.Time
}

// ticket lets the cookie open path once, until expires.
type ticket struct {
	path    string
	expires time.Time
}

// NewAccess returns an Access for token. The cookie is named after port so
// dashboards on different ports don't overwrite each other's cookie.
func NewAccess(token string, port int, file string) *Access {
	return &Access{
		token:    token,
		session:  rand.Text(),
		secret:   rand.Text(),
		cookie:   "safeclaw_dashboard_" + strconv.Itoa(port),
		port:     port,
		file:     file,
		pages:    routeSet(pageRoutes),
		ticketed: routeSet(ticketRoutes),
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
// in its Authorization header, or the session cookie with the second secret
// in its Safeclaw-Secret header. The cookie alone is enough for pageRoutes,
// and with a ticket for ticketRoutes. A GET carrying the token in the query
// is answered with the cookie and a redirect to the same URL without the
// token, with the secret in its fragment. A request for dashproof.Path is
// answered with the proof that this dashboard holds the token, with no
// login needed. Anything else gets 401 without reaching next.
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
		if a.allowed(r) {
			next.ServeHTTP(w, r)
			return
		}
		a.unauthorized(w)
	})
}

// allowed reports whether r may reach the route it asks for. A bearer
// header decides on its own, so a cookie can't make up for a wrong token.
// Neither the token nor the cookie is accepted in place of the other.
func (a *Access) allowed(r *http.Request) bool {
	if scheme, tok, ok := strings.Cut(r.Header.Get("Authorization"), " "); ok && strings.EqualFold(scheme, "Bearer") {
		return equal(strings.TrimSpace(tok), a.token)
	}
	c, err := r.Cookie(a.cookie)
	if err != nil || !equal(c.Value, a.session) {
		return false
	}
	switch {
	case equal(r.Header.Get(secretHeader), a.secret):
		return true
	case isRoute(a.pages, r):
		return true
	case isRoute(a.ticketed, r):
		return a.redeem(r.URL.Query().Get(ticketParam), r.URL.Path)
	}
	return false
}

func equal(got, want string) bool {
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// exchange swaps the token in the query for the session cookie and
// redirects to the URL without it, so the token leaves the address bar and
// history. The redirect's fragment carries the second secret, which the
// browser never sends to a server or in a Referer; app.js stores it and
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
	http.SetCookie(w, &http.Cookie{
		Name:     a.cookie,
		Value:    a.session,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	delete(q, tokenParam)
	// A path starting with // would redirect to another host.
	u := url.URL{Path: "/" + strings.TrimLeft(r.URL.Path, "/"), RawQuery: q.Encode()}
	http.Redirect(w, r, u.RequestURI()+"#"+secretFragment+"="+a.secret, http.StatusSeeOther)
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
	t, ok := a.mint(u.Path)
	if !ok {
		http.Error(w, "too many outstanding tickets", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	_, _ = io.WriteString(w, t)
}

// mint returns a new ticket for path, or false when maxTickets are still
// outstanding. Expired tickets are dropped first.
func (a *Access) mint(path string) (string, bool) {
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
	a.tickets[v] = ticket{path: path, expires: now.Add(ticketTTL)}
	return v, true
}

// redeem reports whether v is an unexpired ticket for path, and uses it up
// whether or not it is.
func (a *Access) redeem(v, path string) bool {
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
	return t.path == path && a.now().Before(t.expires)
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
