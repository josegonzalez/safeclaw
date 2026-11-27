package dashboard

import (
	"context"
	"errors"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/docker"
)

// watchedActions are the container events that change what the dashboard shows.
var watchedActions = map[string]bool{
	"create":  true,
	"start":   true,
	"stop":    true,
	"die":     true,
	"destroy": true,
}

// watchedNetworkActions are the network events that change a session's
// network status.
var watchedNetworkActions = map[string]bool{
	"connect":    true,
	"disconnect": true,
}

// EventSource streams docker container events until ctx ends or the stream fails.
type EventSource func(ctx context.Context, fn func(docker.Event)) error

// Hub fans docker events out to SSE clients.
type Hub struct {
	mu      sync.Mutex
	clients map[chan string]struct{}
	// IsSession reports whether a container ID belongs to a safeclaw
	// container, to filter network events. Nil publishes them all. An error
	// means it could not tell, and the answer is not cached.
	IsSession func(id string) (bool, error)

	// sessions caches IsSession answers by container ID. An entry is dropped
	// when its container is destroyed, and all of them when the event stream
	// restarts, since a destroy may have been missed.
	sessionsMu sync.Mutex
	sessions   map[string]bool
}

// NewHub returns an empty Hub.
func NewHub() *Hub {
	return &Hub{clients: map[chan string]struct{}{}, sessions: map[string]bool{}}
}

// Subscribe registers a client. Call the returned function to unsubscribe.
func (h *Hub) Subscribe() (<-chan string, func()) {
	ch := make(chan string, 16)
	h.mu.Lock()
	h.clients[ch] = struct{}{}
	h.mu.Unlock()
	return ch, func() {
		h.mu.Lock()
		delete(h.clients, ch)
		h.mu.Unlock()
	}
}

// Publish sends an action to every client, dropping it for clients that are
// too far behind.
func (h *Hub) Publish(action string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for ch := range h.clients {
		select {
		case ch <- action:
		default:
		}
	}
}

// Handle publishes an event if it is a watched action on a safeclaw
// container. Network events name the network, so their container is
// checked by ID.
func (h *Hub) Handle(ev docker.Event) {
	if ev.Type == "network" {
		if watchedNetworkActions[ev.Action] && h.isSession(ev.Container) {
			h.Publish(ev.Action)
		}
		return
	}
	if ev.Action == "destroy" {
		h.forget(ev.Container)
	}
	if !watchedActions[ev.Action] || !strings.HasPrefix(ev.Name, config.ContainerPrefix) {
		return
	}
	h.Publish(ev.Action)
}

// isSession answers IsSession for a container ID, from the cache when it can.
func (h *Hub) isSession(id string) bool {
	if h.IsSession == nil {
		return true
	}
	if id == "" {
		return false
	}
	h.sessionsMu.Lock()
	v, ok := h.sessions[id]
	h.sessionsMu.Unlock()
	if ok {
		return v
	}
	v, err := h.IsSession(id)
	if err != nil {
		return false
	}
	h.sessionsMu.Lock()
	h.sessions[id] = v
	h.sessionsMu.Unlock()
	return v
}

// forget drops a container's cached IsSession answer.
func (h *Hub) forget(id string) {
	h.sessionsMu.Lock()
	delete(h.sessions, id)
	h.sessionsMu.Unlock()
}

// forgetAll drops every cached IsSession answer.
func (h *Hub) forgetAll() {
	h.sessionsMu.Lock()
	clear(h.sessions)
	h.sessionsMu.Unlock()
}

// errNotInspectable is returned for a container that inspect cannot find,
// which may only mean it is not inspectable yet.
var errNotInspectable = errors.New("container not inspectable")

// isSession returns a Hub.IsSession that inspects the container.
func isSession(d *docker.Client) func(id string) (bool, error) {
	return func(id string) (bool, error) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		c, err := d.InspectOne(ctx, id)
		if err != nil {
			return false, err
		}
		if c == nil {
			return false, errNotInspectable
		}
		return strings.HasPrefix(c.ShortName(), config.ContainerPrefix), nil
	}
}

// Run consumes events until ctx is done, restarting the stream a second
// after it ends.
func (h *Hub) Run(ctx context.Context, events EventSource) {
	for ctx.Err() == nil {
		// Destroy events may have been missed while the stream was down.
		h.forgetAll()
		if err := events(ctx, h.Handle); err != nil && ctx.Err() == nil {
			log.Printf("docker events: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
}
