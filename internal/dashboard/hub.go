package dashboard

import (
	"context"
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

// EventSource streams docker container events until ctx ends or the stream fails.
type EventSource func(ctx context.Context, fn func(docker.Event)) error

// Hub fans docker events out to SSE clients.
type Hub struct {
	mu      sync.Mutex
	clients map[chan string]struct{}
}

// NewHub returns an empty Hub.
func NewHub() *Hub {
	return &Hub{clients: map[chan string]struct{}{}}
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

// Handle publishes an event if it is a watched action on a safeclaw container.
func (h *Hub) Handle(ev docker.Event) {
	if !watchedActions[ev.Action] || !strings.HasPrefix(ev.Name, config.ContainerPrefix) {
		return
	}
	h.Publish(ev.Action)
}

// Run consumes events until ctx is done, restarting the stream a second
// after it ends.
func (h *Hub) Run(ctx context.Context, events EventSource) {
	for ctx.Err() == nil {
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
