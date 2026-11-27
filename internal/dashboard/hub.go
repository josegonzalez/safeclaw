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

// RefreshAction is published when events may have been missed, because
// the event stream restarted or a line of it could not be read, so clients
// should fetch everything again.
const RefreshAction = "refresh"

const (
	// minRestartDelay and maxRestartDelay bound how long Run waits before
	// restarting the event stream. The delay doubles each time the stream
	// ends, and is reset once a stream lasts maxRestartDelay.
	minRestartDelay = time.Second
	maxRestartDelay = 30 * time.Second
	// maxLookups is how many IsSession lookups run at once.
	maxLookups = 4
	// maxPendingLookups is how many containers can wait for a lookup.
	// Past it, network events are published without one.
	maxPendingLookups = 256
)

// EventSource streams docker container events until ctx ends or the stream fails.
type EventSource func(ctx context.Context, fn func(docker.Event)) error

// Hub fans docker events out to SSE clients.
type Hub struct {
	mu      sync.Mutex
	clients map[chan string]struct{}
	// IsSession reports whether a container ID belongs to a safeclaw
	// container, to filter network events. Nil publishes them all. An error
	// means it could not tell, and the answer is not cached. It is called
	// off the event loop, so a slow inspect doesn't hold up other events.
	IsSession func(id string) (bool, error)

	// sessions caches IsSession answers by container ID. An entry is dropped
	// when its container is destroyed, and all of them when the event stream
	// restarts, since a destroy may have been missed. pending holds the
	// lookups running or waiting for a slot, by container ID.
	sessionsMu sync.Mutex
	sessions   map[string]bool
	pending    map[string]*lookup
	slots      chan struct{}
	lookups    sync.WaitGroup

	minDelay, maxDelay time.Duration
}

// lookup is an IsSession call for one container, with the actions of the
// network events waiting on its answer.
type lookup struct {
	actions []string
}

// NewHub returns an empty Hub.
func NewHub() *Hub {
	return &Hub{
		clients:  map[chan string]struct{}{},
		sessions: map[string]bool{},
		pending:  map[string]*lookup{},
		slots:    make(chan struct{}, maxLookups),
		minDelay: minRestartDelay,
		maxDelay: maxRestartDelay,
	}
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
// checked by ID. A line that could not be read publishes RefreshAction,
// since the event it held is lost.
func (h *Hub) Handle(ev docker.Event) {
	if ev.Err != nil {
		log.Printf("docker events: skipped an event: %v", ev.Err)
		h.Publish(RefreshAction)
		return
	}
	if ev.Type == "network" {
		if watchedNetworkActions[ev.Action] {
			h.publishIfSession(ev.Container, ev.Action)
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

// publishIfSession publishes action if the container is a session. An
// answer that isn't cached is looked up in the background, and the action
// published when it comes, so the event loop never waits on docker.
func (h *Hub) publishIfSession(id, action string) {
	if h.IsSession == nil {
		h.Publish(action)
		return
	}
	if id == "" {
		return
	}
	h.sessionsMu.Lock()
	if v, ok := h.sessions[id]; ok {
		h.sessionsMu.Unlock()
		if v {
			h.Publish(action)
		}
		return
	}
	if l, ok := h.pending[id]; ok {
		l.actions = append(l.actions, action)
		h.sessionsMu.Unlock()
		return
	}
	if len(h.pending) >= maxPendingLookups {
		h.sessionsMu.Unlock()
		// Too many lookups are stuck to wait for another; an extra
		// refresh is harmless.
		h.Publish(action)
		return
	}
	l := &lookup{actions: []string{action}}
	h.pending[id] = l
	h.lookups.Add(1)
	h.sessionsMu.Unlock()
	go h.lookup(id, l)
}

// lookup answers a pending lookup and publishes its actions if the
// container is a session.
func (h *Hub) lookup(id string, l *lookup) {
	defer h.lookups.Done()
	h.slots <- struct{}{}
	v, err := h.IsSession(id)
	<-h.slots
	h.sessionsMu.Lock()
	// The lookup was dropped if the container was destroyed or the stream
	// restarted meanwhile, and its answer may be stale.
	current := h.pending[id] == l
	if current {
		delete(h.pending, id)
		if err == nil {
			h.sessions[id] = v
		}
	}
	actions := l.actions
	h.sessionsMu.Unlock()
	if err != nil || !v {
		return
	}
	for _, a := range actions {
		h.Publish(a)
	}
}

// forget drops a container's cached IsSession answer.
func (h *Hub) forget(id string) {
	h.sessionsMu.Lock()
	delete(h.sessions, id)
	delete(h.pending, id)
	h.sessionsMu.Unlock()
}

// forgetAll drops every cached IsSession answer.
func (h *Hub) forgetAll() {
	h.sessionsMu.Lock()
	clear(h.sessions)
	clear(h.pending)
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

// Run consumes events until ctx is done. When the stream ends it is
// restarted after a delay that backs off while it keeps failing, and
// clients are told to refresh, since events may have been missed.
func (h *Hub) Run(ctx context.Context, events EventSource) {
	delay := h.minDelay
	for restarted := false; ctx.Err() == nil; restarted = true {
		// Destroy events may have been missed while the stream was down.
		h.forgetAll()
		if restarted {
			h.Publish(RefreshAction)
		}
		start := time.Now()
		err := events(ctx, h.Handle)
		if ctx.Err() != nil {
			return
		}
		if err != nil {
			log.Printf("docker events: %v", err)
		}
		if time.Since(start) >= h.maxDelay {
			delay = h.minDelay
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
		delay = min(delay*2, h.maxDelay)
	}
}
