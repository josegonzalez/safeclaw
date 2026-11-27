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
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/session"
	"github.com/josegonzalez/safeclaw/internal/variant"
)

//go:embed templates static
var assets embed.FS

// Sessions is the session API the dashboard needs.
type Sessions interface {
	List(ctx context.Context) ([]session.Session, error)
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
	tmpl      *template.Template
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
			dir = "internal/dashboard"
		}
		if _, err := os.Stat(dir + "/templates"); err != nil {
			return nil, fmt.Errorf("--dev needs %s/templates; run it from the repository root: %w", dir, err)
		}
		s.files = os.DirFS(dir)
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
			return actionData{Name: name, Kind: kind, Variant: variant}
		},
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
// needs the launch token.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	static, _ := fs.Sub(s.files, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))

	mux.HandleFunc("GET /{$}", s.handleIndex)
	mux.HandleFunc("GET /fragments/sessions", s.handleFragment("sessions"))
	mux.HandleFunc("GET /fragments/frames", s.handleFragment("frames"))
	mux.HandleFunc("GET /fragments/auth", s.handleFragment("auth-banner"))
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

	cop := http.NewCrossOriginProtection()
	return refuseFraming(s.checkHost(s.access.Middleware(cop.Handler(mux))))
}

// refuseFraming tells the browser not to render any response inside a
// frame, so another page can't overlay the dashboard and pass clicks
// through to it. CrossOriginProtection doesn't cover this: a framed
// dashboard's own requests are same-origin. It wraps every other check, so
// refusals such as 401 and 403 carry the headers too.
//
// A handler whose page the dashboard frames itself replaces them with
// allowSameOriginFraming.
func refuseFraming(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "frame-ancestors 'none'")
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

// checkHost rejects requests whose Host is not a loopback name, which blocks
// DNS rebinding.
func (s *Server) checkHost(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		switch strings.Trim(host, "[]") {
		case "localhost", "127.0.0.1", "::1":
			next.ServeHTTP(w, r)
		default:
			http.Error(w, "forbidden host", http.StatusForbidden)
		}
	})
}

// ListenAndServe serves until ctx is done.
func (s *Server) ListenAndServe(ctx context.Context, out io.Writer) error {
	addr := "127.0.0.1:" + strconv.Itoa(s.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if err := writeTokenFile(s.tokenFile, s.token); err != nil {
		_ = ln.Close()
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
	fmt.Fprintf(out, "Dashboard: %s\n", s.LaunchURL())
	fmt.Fprintf(out, "API token: %s\n", s.tokenFile)
	if err := srv.Serve(ln); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
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

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	s.render(w, http.StatusOK, "page", s.load(r.Context()))
}

func (s *Server) handleFragment(name string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		s.render(w, http.StatusOK, name, s.load(r.Context()))
	}
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
	name := session.NormalizeName(r.PostForm.Get("name"))
	if s.exists(r.Context(), name) {
		s.render(w, http.StatusUnprocessableEntity, "create-error", fmt.Sprintf("session %q already seems to exist", name))
		return
	}
	set, err := formSecrets(r.PostForm.Get("secrets"), r.PostForm["secret"])
	if err != nil {
		s.render(w, http.StatusUnprocessableEntity, "create-error", err.Error())
		return
	}
	res, err := s.sessions.Ensure(r.Context(), session.Options{
		Name:    name,
		Volume:  strings.TrimSpace(r.PostForm.Get("volume")),
		Variant: strings.TrimSpace(r.PostForm.Get("variant")),
		Secrets: &set,
		Query:   strings.TrimSpace(r.PostForm.Get("query")),
		NoOpen:  true,
	})
	if err != nil {
		s.render(w, http.StatusUnprocessableEntity, "create-error", err.Error())
		return
	}
	trigger, _ := json.Marshal(map[string]any{
		"session-created": createResult{URL: terminalPath(res.Name), OpenTab: r.PostForm.Get("open_tab") != ""},
		"sessions":        true,
	})
	w.Header().Set("HX-Trigger", string(trigger))
	w.WriteHeader(http.StatusNoContent)
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
	if x := s.find(r.Context(), name); x != nil && x.IsSandbox() {
		s.render(w, http.StatusConflict, "info-error", map[string]string{
			"Name":  name,
			"Error": sandboxError(name).Error(),
		})
		return
	}
	s.render(w, http.StatusOK, "info", map[string]string{
		"Name":    name,
		"Command": fmt.Sprintf("docker exec -it %s tmux attach -t %s", config.ContainerName(name), config.TmuxSession),
	})
}

// actionData renders a session's action button.
type actionData struct {
	Name    string
	Kind    string // stop, delete, start, offline, online
	Variant string // "" for the table button, "link" for the frame bar
	Confirm bool
	// Force makes the confirm button release every hold.
	Force bool
	// Title is the confirm button's tooltip.
	Title  string
	Failed string
}

func (s *Server) handleActions(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	s.render(w, http.StatusOK, "action", actionData{
		Name:    config.SessionName(r.PathValue("name")),
		Kind:    kindOrDefault(q.Get("kind")),
		Variant: q.Get("variant"),
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
		d := actionData{Name: name, Kind: kind, Variant: r.Form.Get("variant")}
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
			d.Failed = err.Error()
			s.render(w, http.StatusOK, "action", d)
			return
		}
		refresh(w)
	}
}

// handleOffline takes a session offline with the unnamed hold.
func (s *Server) handleOffline(w http.ResponseWriter, r *http.Request) {
	name := config.SessionName(r.PathValue("name"))
	_ = r.ParseForm()
	if _, err := s.sessions.NetOff(r.Context(), name, session.NetOffOptions{}); err != nil {
		s.render(w, errStatus(err, http.StatusOK), "action", actionData{Name: name, Kind: "offline", Variant: r.Form.Get("variant"), Failed: err.Error()})
		return
	}
	refresh(w)
}

// handleOnline releases the unnamed hold on a session. If other owners
// still hold it offline, it returns a confirm button that, clicked again
// with force=1, releases every hold.
func (s *Server) handleOnline(w http.ResponseWriter, r *http.Request) {
	name := config.SessionName(r.PathValue("name"))
	_ = r.ParseForm()
	d := actionData{Name: name, Kind: "online", Variant: r.Form.Get("variant")}
	res, err := s.sessions.NetOn(r.Context(), name, session.NetOnOptions{Force: r.Form.Get("force") == "1"})
	if err != nil && !errors.Is(err, session.ErrHeld) {
		d.Failed = err.Error()
		s.render(w, errStatus(err, http.StatusOK), "action", d)
		return
	}
	if res != nil && len(res.Holds) > 0 {
		d.Confirm, d.Force = true, true
		d.Title = "held offline by " + holders(res.Holds)
		s.render(w, http.StatusOK, "action", d)
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
