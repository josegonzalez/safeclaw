package dashboard

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/session"
)

// The JSON API mirrors upstream's /api endpoints for scripting.

type apiSession struct {
	Name   string  `json:"name"`
	Port   *string `json:"port"`
	URL    *string `json:"url"`
	Volume string  `json:"volume"`
	Active bool    `json:"active"`
	Type   string  `json:"type"`
	// Variant is the image variant, "" for the base image.
	Variant string `json:"variant"`
	// AutoRemove is set for one-off sandboxes, which are removed when
	// they stop.
	AutoRemove bool `json:"autoRemove"`
	// Secrets are the secrets the session receives: null for every secret,
	// otherwise the names, empty for none.
	Secrets *[]string `json:"secrets"`
}

type apiResult struct {
	Success bool   `json:"success"`
	URL     string `json:"url,omitempty"`
	Error   string `json:"error,omitempty"`
}

type apiRequest struct {
	Name    string     `json:"name"`
	Volume  string     `json:"volume"`
	Variant string     `json:"variant"`
	Secrets apiSecrets `json:"secrets"`
	Query   string     `json:"query"`
}

// apiSecrets is the secrets field of a create request: absent or null keeps
// the default, "all" or "none", or a list of names, empty for none.
type apiSecrets struct {
	set *session.SecretSet
}

func (a *apiSecrets) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		a.set = nil
		return nil
	}
	var set session.SecretSet
	var word string
	if err := json.Unmarshal(b, &word); err == nil {
		switch word {
		case "all":
			set = session.AllSecrets()
		case "none":
			set = session.NoSecrets()
		default:
			return fmt.Errorf(`secrets must be "all", "none", or a list of names, not %q`, word)
		}
		a.set = &set
		return nil
	}
	var names []string
	if err := json.Unmarshal(b, &names); err != nil {
		return errors.New(`secrets must be "all", "none", or a list of names`)
	}
	set, err := session.OnlySecrets(names...)
	if err != nil {
		return err
	}
	a.set = &set
	return nil
}

func writeJSON(w http.ResponseWriter, v any) {
	writeJSONStatus(w, http.StatusOK, v)
}

func writeJSONStatus(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func readRequest(r *http.Request) (apiRequest, error) {
	var req apiRequest
	r.Body = http.MaxBytesReader(nil, r.Body, 1<<20)
	err := json.NewDecoder(r.Body).Decode(&req)
	return req, err
}

func (s *Server) apiSessions(w http.ResponseWriter, r *http.Request) {
	list, err := s.sessions.List(r.Context())
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	out := make([]apiSession, 0, len(list))
	for _, x := range list {
		a := apiSession{Name: x.Container, Volume: x.Volume, Active: x.Active, Type: x.Type, Variant: x.Variant, AutoRemove: x.IsOneOff()}
		if !x.Secrets.All() {
			names := append([]string{}, x.Secrets.Names...)
			a.Secrets = &names
		}
		if x.Port > 0 {
			p := strconv.Itoa(x.Port)
			u := x.URL
			a.Port, a.URL = &p, &u
		}
		out = append(out, a)
	}
	writeJSON(w, out)
}

func (s *Server) apiStart(w http.ResponseWriter, r *http.Request) {
	req, err := readRequest(r)
	if err != nil {
		writeJSON(w, apiResult{Error: err.Error()})
		return
	}
	res, err := s.sessions.Ensure(r.Context(), session.Options{Name: config.SessionName(req.Name), NoOpen: true})
	if err != nil {
		writeJSONStatus(w, errStatus(err, http.StatusOK), apiResult{Error: err.Error()})
		return
	}
	writeJSON(w, apiResult{Success: true, URL: res.URL})
}

func (s *Server) apiStop(w http.ResponseWriter, r *http.Request) {
	req, err := readRequest(r)
	if err != nil {
		writeJSON(w, apiResult{Error: err.Error()})
		return
	}
	err = s.sessions.Stop(r.Context(), config.SessionName(req.Name))
	writeJSON(w, apiResult{Success: err == nil, Error: errString(err)})
}

func (s *Server) apiDelete(w http.ResponseWriter, r *http.Request) {
	req, err := readRequest(r)
	if err != nil {
		writeJSON(w, apiResult{Error: err.Error()})
		return
	}
	err = s.sessions.Delete(r.Context(), config.SessionName(req.Name), false)
	writeJSON(w, apiResult{Success: err == nil, Error: errString(err)})
}

func (s *Server) apiCreate(w http.ResponseWriter, r *http.Request) {
	req, err := readRequest(r)
	if err != nil {
		writeJSON(w, apiResult{Error: err.Error()})
		return
	}
	res, err := s.sessions.Ensure(r.Context(), session.Options{
		Name:    session.NormalizeName(req.Name),
		Volume:  req.Volume,
		Variant: req.Variant,
		Secrets: req.Secrets.set,
		Query:   req.Query,
		NoOpen:  true,
	})
	if err != nil {
		writeJSONStatus(w, errStatus(err, http.StatusOK), apiResult{Error: err.Error()})
		return
	}
	writeJSON(w, apiResult{Success: true, URL: res.URL})
}

// apiEvents streams raw docker actions in upstream's `data: <action>` format.
func (s *Server) apiEvents(w http.ResponseWriter, r *http.Request) {
	s.stream(w, r, func(action string) string { return "data: " + action + "\n\n" }, "data: connected\n\n")
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
