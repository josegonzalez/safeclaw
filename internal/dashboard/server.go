// Package dashboard serves the web dashboard for managing sessions.
package dashboard

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/hangup"
	"github.com/josegonzalez/safeclaw/internal/session"
	"github.com/josegonzalez/safeclaw/internal/variant"
)

//go:embed templates static
var assets embed.FS

// Sessions is the session API the dashboard needs.
type Sessions interface {
	List(ctx context.Context) ([]session.Session, error)
	// ResolveName refuses a name while a container left from a mixed-case
	// name before names were lowercased shares its state.
	ResolveName(ctx context.Context, name string) (string, error)
	Ensure(ctx context.Context, opts session.Options) (*session.Result, error)
	Stop(ctx context.Context, name string) error
	Delete(ctx context.Context, name string, force bool) error
	NetOff(ctx context.Context, name string, opts session.NetOffOptions) (*session.NetResult, error)
	NetOn(ctx context.Context, name string, opts session.NetOnOptions) (*session.NetResult, error)
	Variants() (*variant.Set, error)
	SecretNames() ([]string, error)
	ClaudeTokenStatus(now time.Time) (session.TokenStatus, error)
}

// Options configures the dashboard.
type Options struct {
	// Manager provides sessions. If Sessions is nil it is used for both
	// sessions and docker events.
	Manager *session.Manager
	// Sessions overrides Manager for session operations (used in tests).
	Sessions Sessions
	// Events overrides the docker event stream (used in tests).
	Events EventSource
	// Terminals overrides Manager for reaching session terminals (used in
	// tests).
	Terminals Terminals
	// Port is the port to listen on.
	Port int
	// Dev serves templates and static files from disk.
	Dev bool
	// DevDir is the directory Dev reads from. Defaults to internal/dashboard.
	// It and its templates and static directories must be owned by the
	// current user and not be group- or world-writable, and symlinks out of
	// it are refused.
	DevDir string
	// Token is the launch token every request must carry. Defaults to a
	// random one.
	Token string
	// TokenFile is where ListenAndServe stores the token for API callers.
	// Defaults to config.DashboardTokenFile(Port).
	TokenFile string
}

// Server is the dashboard HTTP server.
type Server struct {
	sessions  Sessions
	events    EventSource
	terminals Terminals
	hub       *Hub
	port      int
	files     fs.FS
	dev       bool
	// devDir is the absolute directory dev reads from.
	devDir string
	tmpl   *template.Template
	// token is the launch token, kept in tokenFile while serving.
	token     string
	tokenFile string
	access    *Access
}

var tips = []string{
	"in a session, press q or scroll to the bottom to exit scroll mode and resume typing",
	"on this dashboard, press tab and enter to quickly create a new session",
	"run safeclaw env to manage environment variables",
}

// New builds a Server.
func New(opts Options) (*Server, error) {
	s := &Server{
		sessions:  opts.Sessions,
		events:    opts.Events,
		terminals: opts.Terminals,
		hub:       NewHub(),
		port:      opts.Port,
		dev:       opts.Dev,
	}
	if s.sessions == nil {
		if opts.Manager == nil {
			return nil, errors.New("dashboard: a session manager is required")
		}
		s.sessions = opts.Manager
	}
	if s.terminals == nil && opts.Manager != nil {
		s.terminals = opts.Manager
	}
	if s.events == nil && opts.Manager != nil {
		s.events = opts.Manager.Docker.Events
		s.hub.IsSession = isSession(opts.Manager.Docker)
	}
	if s.port == 0 {
		s.port = config.DashboardPort
	}
	s.token, s.tokenFile = opts.Token, opts.TokenFile
	if s.token == "" {
		tok, err := NewToken()
		if err != nil {
			return nil, fmt.Errorf("dashboard: generate token: %w", err)
		}
		s.token = tok
	}
	if s.tokenFile == "" {
		s.tokenFile = config.DashboardTokenFile(s.port)
	}
	s.access = NewAccess(s.token, s.port, s.tokenFile)
	if opts.Dev {
		dir := opts.DevDir
		if dir == "" {
			dir = defaultDevDir
		}
		root, abs, err := openDevDir(dir)
		if err != nil {
			return nil, err
		}
		s.files, s.devDir = root.FS(), abs
	} else {
		s.files = assets
	}
	t, err := s.parseTemplates()
	if err != nil {
		return nil, err
	}
	s.tmpl = t
	return s, nil
}

func (s *Server) parseTemplates() (*template.Template, error) {
	return template.New("").Funcs(template.FuncMap{
		"tip":  func() string { return tips[rand.IntN(len(tips))] },
		"join": strings.Join,
		"display": func(url string) string {
			return strings.TrimPrefix(url, "http://")
		},
		"action": func(name, kind, variant string) actionData {
			return actionData{Name: name, Kind: kind, Variant: buttonVariant(variant)}
		},
		"path":   sessionPath,
		"revert": revertPath,
		"vals":   hxVals,
		"busy": func(kind string) string {
			switch kind {
			case "start":
				return "starting"
			case "delete":
				return "deleting"
			case "offline":
				return "disconnecting"
			case "online":
				return "connecting"
			}
			return "stopping"
		},
		"holders":  holders,
		"terminal": terminalPath,
	}).ParseFS(s.files, "templates/*.html")
}

func (s *Server) templates() (*template.Template, error) {
	if s.dev {
		return s.parseTemplates()
	}
	return s.tmpl, nil
}

// Handler returns the dashboard's HTTP handler, with Host, authentication,
// and cross-origin protections applied. Every route, static files included,
// needs the launch token, and every route but the page shells and static
// files needs it as the bearer token or the cookie with its second secret
// (see Access).
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	static, _ := fs.Sub(s.files, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))

	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /fragments/sessions", s.handleFragment("sessions"))
	mux.HandleFunc("GET /fragments/frames", s.handleFragment("frames"))
	mux.HandleFunc("GET /fragments/auth", s.handleFragment("auth-banner"))
	mux.HandleFunc("GET /fragments/options", s.handleOptions)
	mux.HandleFunc("GET /events", s.handleEvents)

	mux.HandleFunc("POST /sessions", s.handleCreate)
	mux.HandleFunc("GET /sessions/validate", s.handleValidate)
	mux.HandleFunc("GET /sessions/{name}/info", s.handleInfo)
	mux.HandleFunc("GET /sessions/{name}/actions", s.handleActions)
	mux.HandleFunc("GET /sessions/{name}/terminal", s.handleTerminal)
	mux.HandleFunc("GET /sessions/{name}/terminal/ws", s.handleTerminalSocket)
	mux.HandleFunc("POST /sessions/{name}/start", s.handleStart)
	mux.HandleFunc("POST /sessions/{name}/stop", s.handleConfirmed("stop"))
	mux.HandleFunc("POST /sessions/{name}/delete", s.handleConfirmed("delete"))
	mux.HandleFunc("POST /sessions/{name}/offline", s.handleOffline)
	mux.HandleFunc("POST /sessions/{name}/online", s.handleOnline)

	mux.HandleFunc("GET /api/sessions", s.apiSessions)
	mux.HandleFunc("POST /api/start", s.apiStart)
	mux.HandleFunc("POST /api/stop", s.apiStop)
	mux.HandleFunc("POST /api/delete", s.apiDelete)
	mux.HandleFunc("POST /api/create", s.apiCreate)
	mux.HandleFunc("POST /api/net/off", s.apiNetOff)
	mux.HandleFunc("POST /api/net/on", s.apiNetOn)
	mux.HandleFunc("GET /api/events", s.apiEvents)

	mux.HandleFunc("POST /tickets", s.access.handleTicket)
	mux.HandleFunc("POST /logout", s.access.handleLogout)

	cop := http.NewCrossOriginProtection()
	return refuseFraming(s.checkHost(s.access.Middleware(cop.Handler(mux))))
}

// pageCSP is every response's policy but the terminal page's. Scripts,
// styles, and everything else come only from the dashboard's own origin,
// with no inline script or style and no eval, so markup that reached a
// page some other way couldn't run script. htmx's own indicator styles
// are a constructed stylesheet, which the policy doesn't cover, and the
// favicon is a data: URL. No other page may frame the dashboard.
const pageCSP = "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// refuseFraming tells the browser not to render any response inside a
// frame, so another page can't overlay the dashboard and pass clicks
// through to it, and sets pageCSP. CrossOriginProtection doesn't cover
// framing: a framed dashboard's own requests are same-origin. It wraps
// every other check, so refusals such as 401 and 403 carry the headers too.
//
// A handler whose page the dashboard frames itself replaces them with
// allowSameOriginFraming.
func refuseFraming(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", pageCSP)
		next.ServeHTTP(w, r)
	})
}

// allowSameOriginFraming lets only the dashboard's own pages frame the
// response, replacing refuseFraming's headers. csp is the page's full
// policy and must have a frame-ancestors 'self' directive: it replaces the
// default policy rather than adding a second one, since a browser enforces
// every policy it gets and the default's frame-ancestors 'none' would win.
func allowSameOriginFraming(w http.ResponseWriter, csp string) {
	w.Header().Set("X-Frame-Options", "SAMEORIGIN")
	w.Header().Set("Content-Security-Policy", csp)
}

// checkHost rejects requests whose Host is not one of the names the
// dashboard advertises, which blocks DNS rebinding: 127.0.0.1, which the
// printed URL uses, and localhost, which the API examples use and which is
// redirected to 127.0.0.1 before a browser gets the cookie. A request that
// reaches the [::1] listener through localhost is handled the same way, and
// ::1 itself is refused.
func (s *Server) checkHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		switch host {
		case "localhost", cookieHost:
			next.ServeHTTP(w, r)
		default:
			http.Error(w, "forbidden host", http.StatusForbidden)
		}
	})
}

// ListenAndServe serves until ctx is done. It holds the port on both
// loopback addresses, since localhost resolves to [::1] as well as
// 127.0.0.1 and many clients try [::1] first: another local user holding
// [::1]:PORT would get the launch token sent to localhost. Startup fails
// when something else holds it; a host without IPv6 loopback, where nothing
// can, gets a warning and 127.0.0.1 only.
//
// SIGHUP stops it too, as SIGINT and SIGTERM do through the CLI's context,
// so closing its terminal still removes the token file. A dashboard started
// with SIGHUP ignored, as under nohup, keeps ignoring it and keeps running.
func (s *Server) ListenAndServe(ctx context.Context, out io.Writer) error {
	if sigs := hangup.Signals(syscall.SIGHUP); len(sigs) > 0 {
		var stop context.CancelFunc
		ctx, stop = signal.NotifyContext(ctx, sigs...)
		defer stop()
	}
	port := strconv.Itoa(s.port)
	ln, err := net.Listen("tcp", net.JoinHostPort(cookieHost, port))
	if err != nil {
		return err
	}
	lns := []net.Listener{ln}
	closeAll := func() {
		for _, l := range lns {
			_ = l.Close()
		}
	}
	switch ln6, err := net.Listen("tcp", net.JoinHostPort("::1", port)); {
	case err == nil:
		lns = append(lns, ln6)
	case noIPv6Loopback(err):
		fmt.Fprintf(out, "Warning: listening on 127.0.0.1 only, since IPv6 loopback is unavailable (%v)\n", err)
	default:
		closeAll()
		return fmt.Errorf("dashboard must also hold [::1]:%s so localhost reaches only it: %w", port, err)
	}
	if err := writeTokenFile(s.tokenFile, s.token); err != nil {
		closeAll()
		return err
	}
	defer func() { _ = removeTokenFile(s.tokenFile, s.token) }()
	if s.events != nil {
		go s.hub.Run(ctx, s.events)
	}
	srv := &http.Server{
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	if s.dev {
		fmt.Fprintf(out, "Dev files: %s\n", s.devDir)
	}
	fmt.Fprintf(out, "Dashboard: %s\n", s.LaunchURL())
	fmt.Fprintf(out, "API token: %s\n", s.tokenFile)
	errc := make(chan error, len(lns))
	for _, l := range lns {
		go func() { errc <- srv.Serve(l) }()
	}
	var serveErr error
	for range lns {
		if err := <-errc; !errors.Is(err, http.ErrServerClosed) && serveErr == nil {
			serveErr = err
			_ = srv.Close()
		}
	}
	return serveErr
}

// noIPv6Loopback reports whether err from listening on [::1] means the host
// has no IPv6 loopback, as opposed to the port being taken.
func noIPv6Loopback(err error) bool {
	return errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.EAFNOSUPPORT) || errors.Is(err, syscall.EPROTONOSUPPORT)
}

// LaunchURL returns the URL that logs a browser in to the dashboard.
func (s *Server) LaunchURL() string {
	return fmt.Sprintf("http://%s/?%s=%s", net.JoinHostPort(cookieHost, strconv.Itoa(s.port)), tokenParam, s.token)
}

// view is the data the templates render.
type view struct {
	Sessions []session.Session
	Active   []session.Session
	Err      string
	// Variants lists the image variants for the new session form, base
	// included, and DefaultVariant is the one new sessions get by default.
	Variants       []string
	DefaultVariant string
	// VariantErr is set when the variants could not be loaded.
	VariantErr string
	// SecretNames lists the stored secrets for the new session form, and
	// SecretErr is set when they could not be read.
	SecretNames []string
	SecretErr   string
	// Token is the state of the stored Claude Code token, nil when it
	// could not be read, and TokenErr says why.
	Token    *session.TokenStatus
	TokenErr string
}

func (s *Server) load(ctx context.Context) view {
	list, err := s.sessions.List(ctx)
	v := view{Sessions: list}
	if err != nil {
		v.Err = err.Error()
	}
	s.loadOptions(&v)
	if st, err := s.sessions.ClaudeTokenStatus(time.Now()); err != nil {
		v.TokenErr = err.Error()
	} else {
		v.Token = &st
	}
	for _, x := range list {
		if x.Active && x.URL != "" {
			v.Active = append(v.Active, x)
		}
	}
	return v
}

// loadOptions loads the variants and secret names the new session form
// offers into v.
func (s *Server) loadOptions(v *view) {
	if set, err := s.sessions.Variants(); err != nil {
		v.VariantErr = err.Error()
	} else {
		v.Variants = append([]string{config.BaseVariant}, set.Names()...)
		v.DefaultVariant = variant.Label(set.DefaultFor(config.TypeSession))
	}
	if names, err := s.sessions.SecretNames(); err != nil {
		v.SecretErr = err.Error()
	} else {
		v.SecretNames = names
	}
}

func (s *Server) render(w http.ResponseWriter, status int, name string, data any) {
	t, err := s.templates()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, name, data); err != nil {
		log.Printf("render %s: %v", name, err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = buf.WriteTo(w)
}

// handleIndex serves the page shell, which a browser opens with only the
// cookie, so it shows no state: the sessions, frames, banner, and new
// session options are fetched by htmx, which sends the second secret.
func (s *Server) handleIndex(w http.ResponseWriter, _ *http.Request) {
	s.render(w, http.StatusOK, "page", nil)
}

func (s *Server) handleFragment(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.render(w, http.StatusOK, name, s.load(r.Context()))
	}
}

// handleOptions renders the new session form's variant and secrets
// pickers.
func (s *Server) handleOptions(w http.ResponseWriter, _ *http.Request) {
	var v view
	s.loadOptions(&v)
	s.render(w, http.StatusOK, "session-options", v)
}

// refresh tells the page to re-render the sessions table and frames.
func refresh(w http.ResponseWriter) {
	w.Header().Set("HX-Trigger", "sessions")
	w.WriteHeader(http.StatusNoContent)
}

// find returns the named session, or nil if it does not exist or the list
// fails.
func (s *Server) find(ctx context.Context, name string) *session.Session {
	list, err := s.sessions.List(ctx)
	if err != nil {
		return nil
	}
	c := config.ContainerName(name)
	for _, x := range list {
		if x.Container == c {
			return &x
		}
	}
	return nil
}

func (s *Server) exists(ctx context.Context, name string) bool {
	return s.find(ctx, name) != nil
}

// errNotManaged is returned for a container named like a session that is
// neither a session nor a sandbox.
var errNotManaged = errors.New("is not a safeclaw session or sandbox")

// taken returns the session or sandbox already using name, or nil. Unlike
// find, it returns the error when the list fails, so a create that can't
// check is refused rather than taken for a new name.
func (s *Server) taken(ctx context.Context, name string) (*session.Session, error) {
	list, err := s.sessions.List(ctx)
	if err != nil {
		return nil, err
	}
	c := config.ContainerName(name)
	for i := range list {
		if list[i].Container == c {
			return &list[i], nil
		}
	}
	return nil, nil
}

// checkLegacy refuses a valid session name, as the CLI does, while a
// container left from a mixed-case name before names were lowercased
// matches it case-insensitively, such as safeclaw-Work for `work`, since on
// a case-insensitive filesystem the two share the history directory, ttyd
// credential, and network state. The error wraps session.ErrLegacyName and
// names `docker rm -f` for each old container, with 409 as its status, or
// 500 if the containers can't be listed. An invalid name is left to the
// caller's own checks.
func (s *Server) checkLegacy(ctx context.Context, name string) (status int, err error) {
	if session.ValidateName(name) != nil {
		return http.StatusOK, nil
	}
	if _, err := s.sessions.ResolveName(ctx, name); err != nil {
		if errors.Is(err, session.ErrLegacyName) {
			return http.StatusConflict, err
		}
		return http.StatusInternalServerError, err
	}
	return http.StatusOK, nil
}

// target returns the session or sandbox a stop or delete acts on, with
// the checks the CLI makes: the name must be valid, no container left from
// a mixed-case name may share its state (see checkLegacy), and the
// container must exist and be a session or a sandbox. Both types are
// allowed, since the table offers stop and delete for both. On error,
// status is the HTTP status to answer with.
func (s *Server) target(ctx context.Context, name string) (x *session.Session, status int, err error) {
	if err := session.ValidateName(name); err != nil {
		return nil, http.StatusBadRequest, err
	}
	if status, err := s.checkLegacy(ctx, name); err != nil {
		return nil, status, err
	}
	list, err := s.sessions.List(ctx)
	if err != nil {
		return nil, http.StatusInternalServerError, err
	}
	c := config.ContainerName(name)
	for i := range list {
		if list[i].Container != c {
			continue
		}
		switch list[i].Type {
		case config.TypeSession, config.TypeSandbox:
			return &list[i], http.StatusOK, nil
		}
		return nil, http.StatusConflict, fmt.Errorf("%q %w", c, errNotManaged)
	}
	return nil, http.StatusNotFound, fmt.Errorf("session %q %w", name, session.ErrNotFound)
}

// buttonVariant returns an action button's style: "link" for the frame
// bar, or "" for the table. Anything else is the table style, so a value
// echoed from a request never reaches a template unchecked.
func buttonVariant(v string) string {
	if v == "link" {
		return v
	}
	return ""
}

// sessionPath returns the dashboard path for a session, with the name and
// each part path-escaped as one segment.
func sessionPath(name string, parts ...string) string {
	var b strings.Builder
	b.WriteString("/sessions/")
	b.WriteString(url.PathEscape(name))
	for _, p := range parts {
		b.WriteString("/")
		b.WriteString(url.PathEscape(p))
	}
	return b.String()
}

// revertPath returns the URL that fetches a session's normal action
// button, which reverts a confirm.
func revertPath(name, kind, variant string) string {
	q := url.Values{"kind": {kind}, "variant": {variant}}
	return sessionPath(name, "actions") + "?" + q.Encode()
}

// hxVals returns an hx-vals JSON object of key and value pairs. It is
// marshalled, not printed into a JSON template, so a quote in a value
// can't add a key once the attribute is decoded.
func hxVals(pairs ...string) (string, error) {
	if len(pairs)%2 != 0 {
		return "", errors.New("vals needs key and value pairs")
	}
	m := make(map[string]string, len(pairs)/2)
	for i := 0; i < len(pairs); i += 2 {
		m[pairs[i]] = pairs[i+1]
	}
	b, err := json.Marshal(m)
	return string(b), err
}

// sandboxError returns the error for an interactive-only action on a
// sandbox.
func sandboxError(name string) error {
	return fmt.Errorf("session %q %w", name, session.ErrIsSandbox)
}

// conflicts are the errors for actions refused because of the target's
// type or network state.
var conflicts = []error{
	session.ErrIsSandbox,
	session.ErrHostNetwork,
	session.ErrSharedNetwork,
	session.ErrNoNetwork,
	session.ErrHeld,
	session.ErrUnreadableState,
	session.ErrOffline,
}

// errStatus returns 409 for actions refused because of the target's type or
// network state, and fallback otherwise.
func errStatus(err error, fallback int) int {
	for _, c := range conflicts {
		if errors.Is(err, c) {
			return http.StatusConflict
		}
	}
	return fallback
}

// holders describes the holds on an offline session, with their reasons.
func holders(holds []session.Hold) string {
	parts := make([]string, len(holds))
	for i, h := range holds {
		parts[i] = h.Label()
		if h.Reason != "" {
			parts[i] += " (" + h.Reason + ")"
		}
	}
	return strings.Join(parts, ", ")
}

type hintData struct {
	Name   string
	Exists bool
}

func (s *Server) handleValidate(w http.ResponseWriter, r *http.Request) {
	name := session.NormalizeName(r.URL.Query().Get("name"))
	s.render(w, http.StatusOK, "name-hint", hintData{Name: name, Exists: s.exists(r.Context(), name)})
}

type createResult struct {
	URL     string `json:"url"`
	OpenTab bool   `json:"openTab"`
}

func (s *Server) handleCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.render(w, http.StatusUnprocessableEntity, "create-error", err.Error())
		return
	}
	// The name is checked in the form Ensure uses, so a name with the
	// container prefix can't pass as new and recreate the session it names.
	name := session.NormalizeName(r.PostForm.Get("name"))
	if err := session.ValidateNewName(name); err != nil {
		s.render(w, http.StatusUnprocessableEntity, "create-error", err.Error())
		return
	}
	if x, err := s.taken(r.Context(), name); err != nil {
		s.render(w, http.StatusUnprocessableEntity, "create-error", "could not check the name: "+err.Error())
		return
	} else if x != nil {
		s.render(w, http.StatusUnprocessableEntity, "create-error", fmt.Sprintf("session %q already seems to exist", name))
		return
	}
	set, err := formSecrets(r.PostForm.Get("secrets"), r.PostForm["secret"])
	if err != nil {
		s.render(w, http.StatusUnprocessableEntity, "create-error", err.Error())
		return
	}
	volume := strings.TrimSpace(r.PostForm.Get("volume"))
	warnings, err := checkVolume(volume)
	if err != nil {
		s.render(w, http.StatusUnprocessableEntity, "create-error", err.Error())
		return
	}
	res, err := s.sessions.Ensure(r.Context(), session.Options{
		Name:    name,
		Volume:  volume,
		Variant: strings.TrimSpace(r.PostForm.Get("variant")),
		Secrets: &set,
		Query:   strings.TrimSpace(r.PostForm.Get("query")),
		NoOpen:  true,
	})
	if err != nil {
		s.render(w, http.StatusUnprocessableEntity, "create-error", err.Error())
		return
	}
	// The dialog stays open on the warnings, with a link to the terminal,
	// rather than closing on its own and opening a tab before they are
	// read.
	if len(warnings) > 0 {
		w.Header().Set("HX-Trigger", `{"sessions":true}`)
		s.render(w, http.StatusOK, "create-warning", map[string]any{
			"Name":     res.Name,
			"URL":      terminalPath(res.Name),
			"Warnings": warnings,
		})
		return
	}
	trigger, _ := json.Marshal(map[string]any{
		"session-created": createResult{URL: terminalPath(res.Name), OpenTab: r.PostForm.Get("open_tab") != ""},
		"sessions":        true,
	})
	w.Header().Set("HX-Trigger", string(trigger))
	w.WriteHeader(http.StatusNoContent)
}

// checkVolume checks a create request's volume before the session is
// created, refusing one that would expose safeclaw's config directory and
// returning the warnings for one that exposes a container runtime socket.
// Ensure refuses the same volumes, but its warnings only reach its output.
func checkVolume(volume string) ([]string, error) {
	if volume == "" {
		return nil, nil
	}
	_, warnings, err := session.CheckVolume(volume)
	return warnings, err
}

// formSecrets returns the secret set the new session form picks: "all" (or
// nothing) for every secret, "none", or "only" for the checked names.
func formSecrets(mode string, checked []string) (session.SecretSet, error) {
	switch mode {
	case "", "all":
		return session.AllSecrets(), nil
	case "none":
		return session.NoSecrets(), nil
	case "only":
		if len(checked) == 0 {
			return session.SecretSet{}, errors.New("check at least one secret, or pick no secrets")
		}
		return session.OnlySecrets(checked...)
	}
	return session.SecretSet{}, fmt.Errorf("unknown secrets choice %q", mode)
}

func (s *Server) handleInfo(w http.ResponseWriter, r *http.Request) {
	name := config.SessionName(r.PathValue("name"))
	if err := session.ValidateName(name); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if x := s.find(r.Context(), name); x != nil && x.IsSandbox() {
		s.render(w, http.StatusConflict, "info-error", map[string]string{
			"Name":  name,
			"Error": sandboxError(name).Error(),
		})
		return
	}
	s.render(w, http.StatusOK, "info", map[string]string{
		"Name": name,
		// Not a raw `docker exec ... tmux attach`, which would pass the
		// session's clipboard writes and passthrough to the host terminal.
		"Command": "safeclaw attach " + name,
	})
}

// actionData renders a session's action button.
type actionData struct {
	Name    string
	Kind    string // stop, delete, start, offline, online
	Variant string // "" for the table button, "link" for the frame bar
	Confirm bool
	Failed  string
}

func (s *Server) handleActions(w http.ResponseWriter, r *http.Request) {
	name := config.SessionName(r.PathValue("name"))
	if err := session.ValidateName(name); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	q := r.URL.Query()
	s.render(w, http.StatusOK, "action", actionData{
		Name:    name,
		Kind:    kindOrDefault(q.Get("kind")),
		Variant: buttonVariant(q.Get("variant")),
	})
}

func kindOrDefault(k string) string {
	switch k {
	case "stop", "delete", "start", "offline", "online":
		return k
	}
	return "stop"
}

func (s *Server) handleStart(w http.ResponseWriter, r *http.Request) {
	name := config.SessionName(r.PathValue("name"))
	if _, err := s.sessions.Ensure(r.Context(), session.Options{Name: name, NoOpen: true}); err != nil {
		s.render(w, errStatus(err, http.StatusOK), "action", actionData{Name: name, Kind: "start", Failed: err.Error()})
		return
	}
	refresh(w)
}

// handleConfirmed implements the two-click confirm: the first POST returns
// the confirm button, the second (confirm=1) performs the action.
func (s *Server) handleConfirmed(kind string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := config.SessionName(r.PathValue("name"))
		_ = r.ParseForm()
		d := actionData{Name: name, Kind: kind, Variant: buttonVariant(r.Form.Get("variant"))}
		if _, status, err := s.target(r.Context(), name); err != nil {
			if status == http.StatusBadRequest {
				// An invalid name can't be rendered into the button's URLs.
				http.Error(w, err.Error(), status)
				return
			}
			d.Failed = err.Error()
			s.render(w, status, "action", d)
			return
		}
		if r.Form.Get("confirm") != "1" {
			d.Confirm = true
			s.render(w, http.StatusOK, "action", d)
			return
		}
		var err error
		if kind == "stop" {
			err = s.sessions.Stop(r.Context(), name)
		} else {
			err = s.sessions.Delete(r.Context(), name, false)
		}
		if err != nil {
			// A session held offline is refused, naming its holders.
			d.Failed = err.Error()
			s.render(w, errStatus(err, http.StatusOK), "action", d)
			return
		}
		refresh(w)
	}
}

// handleOffline takes a session offline with the unnamed hold.
func (s *Server) handleOffline(w http.ResponseWriter, r *http.Request) {
	name := config.SessionName(r.PathValue("name"))
	_ = r.ParseForm()
	d := actionData{Name: name, Kind: "offline", Variant: buttonVariant(r.Form.Get("variant"))}
	if status, err := s.checkLegacy(r.Context(), name); err != nil {
		d.Failed = err.Error()
		s.render(w, status, "action", d)
		return
	}
	if _, err := s.sessions.NetOff(r.Context(), name, session.NetOffOptions{}); err != nil {
		d.Failed = err.Error()
		s.render(w, errStatus(err, http.StatusOK), "action", d)
		return
	}
	refresh(w)
}

// forceData renders the force online dialog.
type forceData struct {
	Name  string
	Holds []session.Hold
}

// handleOnline releases the unnamed hold on a session. If other owners
// still hold it offline, it answers with a dialog listing them, retargeted
// to the info dialog, which asks for the session name to be typed before
// forcing it online. A force=1 request releases every hold, and is
// refused unless its confirm_name field is the session's name.
func (s *Server) handleOnline(w http.ResponseWriter, r *http.Request) {
	name := config.SessionName(r.PathValue("name"))
	_ = r.ParseForm()
	force := r.Form.Get("force") == "1"
	if force {
		if err := session.ValidateName(name); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if r.Form.Get("confirm_name") != name {
			s.render(w, http.StatusUnprocessableEntity, "dialog-error", fmt.Sprintf("type %q to force it online", name))
			return
		}
	}
	d := actionData{Name: name, Kind: "online", Variant: buttonVariant(r.Form.Get("variant"))}
	if status, err := s.checkLegacy(r.Context(), name); err != nil {
		if force {
			s.render(w, status, "dialog-error", err.Error())
			return
		}
		d.Failed = err.Error()
		s.render(w, status, "action", d)
		return
	}
	res, err := s.sessions.NetOn(r.Context(), name, session.NetOnOptions{Force: force})
	if err != nil && !errors.Is(err, session.ErrHeld) {
		if force {
			s.render(w, errStatus(err, http.StatusUnprocessableEntity), "dialog-error", err.Error())
			return
		}
		d.Failed = err.Error()
		s.render(w, errStatus(err, http.StatusOK), "action", d)
		return
	}
	if res != nil && len(res.Holds) > 0 {
		if force {
			s.render(w, http.StatusConflict, "dialog-error", "still held offline by "+holders(res.Holds))
			return
		}
		if err := session.ValidateName(name); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("HX-Retarget", "#session-info")
		w.Header().Set("HX-Reswap", "innerHTML")
		s.render(w, http.StatusOK, "force-online", forceData{Name: name, Holds: res.Holds})
		return
	}
	if force {
		trigger, _ := json.Marshal(map[string]bool{"sessions": true, "close-dialog": true})
		w.Header().Set("HX-Trigger", string(trigger))
		w.WriteHeader(http.StatusNoContent)
		return
	}
	refresh(w)
}

// handleEvents streams a "sessions" event whenever a safeclaw container changes.
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	s.stream(w, r, func(string) string { return "event: sessions\ndata: changed\n\n" }, ": connected\n\n")
}

func (s *Server) stream(w http.ResponseWriter, r *http.Request, format func(action string) string, hello string) {
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, hello)
	if err := rc.Flush(); err != nil {
		return
	}
	ch, unsubscribe := s.hub.Subscribe()
	defer unsubscribe()
	ping := time.NewTicker(30 * time.Second)
	defer ping.Stop()
	for {
		var msg string
		select {
		case <-r.Context().Done():
			return
		case action := <-ch:
			msg = format(action)
		case <-ping.C:
			msg = ": ping\n\n"
		}
		if _, err := io.WriteString(w, msg); err != nil {
			return
		}
		if err := rc.Flush(); err != nil {
			return
		}
	}
}
