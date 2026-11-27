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

// Access authenticates dashboard callers. Browsers open the URL carrying
// the launch token once and get an HttpOnly, SameSite=Strict cookie in
// exchange; other clients send the token as `Authorization: Bearer`.
//
// The cookie holds a separate random value, not the token. Cookies are not
// scoped by port, so the browser also sends it to anything else listening
// on 127.0.0.1, such as a session published there before sessions moved to
// [::1]. What such a listener gets is only good as this cookie, for this
// run of the dashboard: it is not the bearer token that the token file and
// the CLI use.
type Access struct {
	token string
	// session is the cookie's value. It is only kept in memory, so it stops
	// working when the dashboard stops.
	session string
	cookie  string
	// port is the dashboard's port, which its proofs are bound to.
	port int
	// file is where the token is stored for API callers, named in the 401
	// response.
	file string
}

// NewAccess returns an Access for token. The cookie is named after port so
// dashboards on different ports don't overwrite each other's cookie.
func NewAccess(token string, port int, file string) *Access {
	return &Access{token: token, session: rand.Text(), cookie: "safeclaw_dashboard_" + strconv.Itoa(port), port: port, file: file}
}

// Middleware lets a request through to next only when it carries the
// session cookie or the token in its Authorization header. A GET carrying
// the token in the query is answered with the cookie and a redirect to the
// same URL without the token. A request for dashproof.Path is answered with
// the proof that this dashboard holds the token, with no login needed.
// Anything else gets 401 without reaching next.
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
		if a.Authorized(r) {
			next.ServeHTTP(w, r)
			return
		}
		a.unauthorized(w)
	})
}

// Authorized reports whether r carries the token as a bearer token or the
// session value in the cookie. Neither is accepted in place of the other.
func (a *Access) Authorized(r *http.Request) bool {
	if scheme, tok, ok := strings.Cut(r.Header.Get("Authorization"), " "); ok && strings.EqualFold(scheme, "Bearer") {
		return equal(strings.TrimSpace(tok), a.token)
	}
	if c, err := r.Cookie(a.cookie); err == nil {
		return equal(c.Value, a.session)
	}
	return false
}

func equal(got, want string) bool {
	return got != "" && subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}

// exchange swaps the token in the query for the session cookie and
// redirects to the URL without it, so the token leaves the address bar and
// history. On any host other than 127.0.0.1 it first redirects there,
// keeping the token.
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
	http.Redirect(w, r, u.RequestURI(), http.StatusSeeOther)
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
