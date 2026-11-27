package dashboard

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/http"
	"os"

	"github.com/coder/websocket"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/session"
)

// ttydProtocol is the WebSocket subprotocol ttyd speaks.
const ttydProtocol = "tty"

// terminalReadLimit bounds a single WebSocket message in either direction,
// such as a large paste or a burst of output.
const terminalReadLimit = 1 << 20

// terminalCSP keeps the terminal page to the dashboard's own scripts and
// connections. xterm.js sets inline styles, so those are allowed. Only the
// dashboard's own pages may frame it.
const terminalCSP = "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; font-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'self'"

// Terminals finds a running session's web terminal. *session.Manager
// implements it.
type Terminals interface {
	Terminal(ctx context.Context, name string) (*session.Terminal, error)
}

// handleTerminal serves the dashboard's own terminal page for a session.
// Nothing on it comes from the session: the page, xterm.js, and the client
// script are the dashboard's, and only the WebSocket's terminal bytes come
// from ttyd, which xterm.js renders as text. So a session that replaced
// its ttyd can't run script on the dashboard's origin.
func (s *Server) handleTerminal(w http.ResponseWriter, r *http.Request) {
	name := config.SessionName(r.PathValue("name"))
	if err := session.ValidateName(name); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	// The dashboard's frames grid iframes this page, so it alone may be
	// framed, and only by the dashboard's own origin.
	allowSameOriginFraming(w, terminalCSP)
	w.Header().Set("Referrer-Policy", "no-referrer")
	s.render(w, http.StatusOK, "terminal", map[string]string{"Name": name})
}

// handleTerminalSocket proxies a WebSocket from the terminal page to the
// session's ttyd. It is a new connection, not a forwarded request, so the
// browser's dashboard cookie and Authorization header never reach the
// session. ttyd gets its credential twice, as it requires: in the
// Authorization header of the upgrade, and as the AuthToken of the first
// message, which the proxy sets whatever the browser sent.
func (s *Server) handleTerminalSocket(w http.ResponseWriter, r *http.Request) {
	name := config.SessionName(r.PathValue("name"))
	if s.terminals == nil {
		http.Error(w, "web terminals are unavailable", http.StatusNotFound)
		return
	}
	t, err := s.terminals.Terminal(r.Context(), name)
	starting := terminalStarting(err)
	if err != nil && !starting {
		status := http.StatusBadGateway
		if errors.Is(err, session.ErrNoTerminal) {
			status = http.StatusNotFound
		}
		http.Error(w, err.Error(), status)
		return
	}
	// Accept refuses an Origin other than the dashboard's own, so another
	// page on 127.0.0.1, which gets the SameSite cookie, can't open it.
	client, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{ttydProtocol}})
	if err != nil {
		return
	}
	defer func() { _ = client.CloseNow() }()
	if client.Subprotocol() != ttydProtocol {
		_ = client.Close(websocket.StatusPolicyViolation, "the tty subprotocol is required")
		return
	}
	// A browser can't see the status of a refused upgrade, so a terminal
	// that isn't up yet is reported after it, as a close with
	// StatusTryAgainLater, which the terminal page retries.
	if starting {
		_ = client.Close(websocket.StatusTryAgainLater, terminalStartingReason)
		return
	}
	client.SetReadLimit(terminalReadLimit)

	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	upstream, err := dialTerminal(ctx, t)
	if err != nil {
		// ttyd isn't listening yet, or was started with a credential
		// rotated after the lookup; either way, a retry looks it up again.
		log.Printf("terminal %s: %v", name, err)
		_ = client.Close(websocket.StatusTryAgainLater, "the session's terminal is not answering")
		return
	}
	defer func() { _ = upstream.CloseNow() }()
	upstream.SetReadLimit(terminalReadLimit)

	typ, msg, err := client.Read(ctx)
	if err != nil {
		return
	}
	msg, err = withAuthToken(msg, t.Credential.Token())
	if err != nil {
		_ = client.Close(websocket.StatusInvalidFramePayloadData, "the first message must be ttyd's JSON hello")
		return
	}
	if err := upstream.Write(ctx, typ, msg); err != nil {
		return
	}

	errc := make(chan error, 2)
	go func() { errc <- relay(ctx, upstream, client) }()
	go func() { errc <- relay(ctx, client, upstream) }()
	// A close frame from either side is the normal end; log anything else.
	if err := <-errc; websocket.CloseStatus(err) == -1 && r.Context().Err() == nil {
		log.Printf("terminal %s: %v", name, err)
	}
	cancel()
	_ = client.Close(websocket.StatusNormalClosure, "")
	_ = upstream.Close(websocket.StatusNormalClosure, "")
}

// terminalStartingReason is the close reason for a terminal that isn't up
// yet.
const terminalStartingReason = "the session's terminal is starting"

// terminalStarting reports whether a terminal lookup failed only because
// the session is still starting: its container is running with its port
// published, but its ttyd credential isn't written yet. A session's frame
// loads as soon as its container starts, before Ensure writes the
// credential and starts ttyd.
func terminalStarting(err error) bool {
	return err != nil && errors.Is(err, os.ErrNotExist) && !errors.Is(err, session.ErrNoTerminal)
}

// dialTerminal opens a WebSocket to the session's ttyd. It dials the address
// the port is published on, but names localhost:PORT as the Host and
// Origin, which is what ttyd's origin check compares.
func dialTerminal(ctx context.Context, t *session.Terminal) (*websocket.Conn, error) {
	dialer := &net.Dialer{}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, network, t.Addr)
		},
		Proxy: nil,
	}
	h := http.Header{}
	h.Set("Authorization", "Basic "+t.Credential.Token())
	h.Set("Origin", "http://"+t.Host)
	c, resp, err := websocket.Dial(ctx, "ws://"+t.Host+"/ws", &websocket.DialOptions{
		HTTPClient:   &http.Client{Transport: tr},
		HTTPHeader:   h,
		Subprotocols: []string{ttydProtocol},
	})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}
	return c, err
}

// withAuthToken returns ttyd's JSON hello with AuthToken set to token.
func withAuthToken(msg []byte, token string) ([]byte, error) {
	var hello map[string]any
	if err := json.Unmarshal(msg, &hello); err != nil {
		return nil, err
	}
	if hello == nil {
		return nil, errors.New("empty hello")
	}
	hello["AuthToken"] = token
	return json.Marshal(hello)
}

// relay copies messages from src to dst until either fails.
func relay(ctx context.Context, dst, src *websocket.Conn) error {
	for {
		typ, msg, err := src.Read(ctx)
		if err != nil {
			return err
		}
		if err := dst.Write(ctx, typ, msg); err != nil {
			return err
		}
	}
}

// terminalPath returns the path of a session's terminal page.
func terminalPath(name string) string {
	return sessionPath(config.SessionName(name), "terminal")
}
