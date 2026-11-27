package dashboard

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
)

func disconnect(id string) docker.Event {
	return docker.Event{Type: "network", Action: "disconnect", Name: "bridge", Container: id}
}

// counter counts IsSession calls by container ID.
type counter struct {
	mu    sync.Mutex
	calls map[string]int
}

func (c *counter) get(id string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls[id]
}

func countingHub(answer func(id string) (bool, error)) (*Hub, *counter) {
	h := NewHub()
	c := &counter{calls: map[string]int{}}
	h.IsSession = func(id string) (bool, error) {
		c.mu.Lock()
		c.calls[id]++
		c.mu.Unlock()
		return answer(id)
	}
	return h, c
}

// handle passes each event to the hub and waits for its lookups.
func handle(h *Hub, evs ...docker.Event) {
	for _, ev := range evs {
		h.Handle(ev)
		h.lookups.Wait()
	}
}

// next returns the next published action, failing after a while.
func next(t *testing.T, ch <-chan string) string {
	t.Helper()
	select {
	case a := <-ch:
		return a
	case <-time.After(10 * time.Second):
		t.Fatal("nothing published")
		return ""
	}
}

// quiet fails if anything is published soon.
func quiet(t *testing.T, ch <-chan string) {
	t.Helper()
	select {
	case a := <-ch:
		t.Fatalf("published %q, want nothing", a)
	case <-time.After(20 * time.Millisecond):
	}
}

func TestHubCachesSessionAnswers(t *testing.T) {
	h, c := countingHub(func(id string) (bool, error) { return id == "abc", nil })
	for range 3 {
		handle(h, disconnect("abc"), disconnect("other"))
	}
	if c.get("abc") != 1 || c.get("other") != 1 {
		t.Errorf("IsSession calls = %v, want one per ID", c.calls)
	}
}

func TestHubDoesNotCacheErrors(t *testing.T) {
	h, c := countingHub(func(string) (bool, error) { return false, errors.New("boom") })
	handle(h, disconnect("abc"), disconnect("abc"))
	if c.get("abc") != 2 || len(h.sessions) != 0 {
		t.Errorf("IsSession calls = %v, cache = %v; want errors left uncached", c.calls, h.sessions)
	}
}

func TestHubForgetsDestroyedContainers(t *testing.T) {
	h, c := countingHub(func(id string) (bool, error) { return true, nil })
	handle(h, disconnect("abc"), disconnect("def"))
	handle(h,
		docker.Event{Type: "container", Action: "destroy", Name: "safeclaw-x", Container: "abc"},
		docker.Event{Type: "container", Action: "destroy", Name: "not-a-session", Container: "def"})
	if len(h.sessions) != 0 {
		t.Errorf("cache = %v after destroy, want empty", h.sessions)
	}
	handle(h, disconnect("abc"))
	if c.get("abc") != 2 {
		t.Errorf("IsSession calls = %v, want abc asked again after destroy", c.calls)
	}
}

func TestHubKeepsCacheOnOtherContainerEvents(t *testing.T) {
	h, c := countingHub(func(id string) (bool, error) { return true, nil })
	handle(h, disconnect("abc"),
		docker.Event{Type: "container", Action: "die", Name: "safeclaw-x", Container: "abc"},
		disconnect("abc"))
	if c.get("abc") != 1 {
		t.Errorf("IsSession calls = %v, want the answer kept until destroy", c.calls)
	}
}

// blockingHub returns a hub whose IsSession answers true for IDs starting
// with "s" once release is closed.
func blockingHub() (h *Hub, c *counter, release func()) {
	gate := make(chan struct{})
	h, c = countingHub(func(id string) (bool, error) {
		<-gate
		return strings.HasPrefix(id, "s"), nil
	})
	return h, c, sync.OnceFunc(func() { close(gate) })
}

func TestHubLookupsDoNotBlockEvents(t *testing.T) {
	h, c, release := blockingHub()
	defer release()
	ch, unsubscribe := h.Subscribe()
	defer unsubscribe()
	h.Handle(disconnect("slow"))
	h.Handle(docker.Event{Type: "network", Action: "connect", Container: "slow"})
	h.Handle(docker.Event{Type: "container", Action: "start", Name: "safeclaw-x", Container: "x"})
	if a := next(t, ch); a != "start" {
		t.Fatalf("published %q first, want the container event while the inspect waits", a)
	}
	release()
	got := []string{next(t, ch), next(t, ch)}
	h.lookups.Wait()
	if got[0] != "disconnect" || got[1] != "connect" {
		t.Errorf("published %q after the inspect, want both network events", got)
	}
	if c.get("slow") != 1 {
		t.Errorf("IsSession calls = %v, want one lookup shared by both events", c.calls)
	}
	if v, ok := h.sessions["slow"]; !v || !ok {
		t.Errorf("cache = %v, want the answer kept", h.sessions)
	}
}

func TestHubBoundsLookups(t *testing.T) {
	gate := make(chan struct{})
	var mu sync.Mutex
	running, most := 0, 0
	h := NewHub()
	h.IsSession = func(string) (bool, error) {
		mu.Lock()
		running++
		most = max(most, running)
		mu.Unlock()
		<-gate
		mu.Lock()
		running--
		mu.Unlock()
		return false, nil
	}
	for i := range 3 * maxLookups {
		h.Handle(disconnect(fmt.Sprint(i)))
	}
	deadline := time.Now().Add(10 * time.Second)
	for {
		mu.Lock()
		r := running
		mu.Unlock()
		if r == maxLookups || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	close(gate)
	h.lookups.Wait()
	if most != maxLookups {
		t.Errorf("at most %d lookups ran at once, want %d", most, maxLookups)
	}
	if len(h.sessions) != 3*maxLookups || len(h.pending) != 0 {
		t.Errorf("cache = %d, pending = %d; want every answer kept", len(h.sessions), len(h.pending))
	}
}

func TestHubPublishesWhenLookupsBackUp(t *testing.T) {
	h, _, release := blockingHub()
	defer func() { release(); h.lookups.Wait() }()
	for i := range maxPendingLookups {
		h.Handle(disconnect(fmt.Sprint("n", i)))
	}
	ch, unsubscribe := h.Subscribe()
	defer unsubscribe()
	h.Handle(disconnect("one-too-many"))
	if a := next(t, ch); a != "disconnect" {
		t.Errorf("published %q, want the event passed through", a)
	}
}

func TestHubDropsLookupOfDestroyedContainer(t *testing.T) {
	h, _, release := blockingHub()
	ch, unsubscribe := h.Subscribe()
	defer unsubscribe()
	h.Handle(disconnect("sess"))
	h.Handle(docker.Event{Type: "container", Action: "destroy", Name: "safeclaw-x", Container: "sess"})
	if a := next(t, ch); a != "destroy" {
		t.Fatalf("published %q, want destroy", a)
	}
	release()
	if a := next(t, ch); a != "disconnect" {
		t.Errorf("published %q, want the network event still delivered", a)
	}
	h.lookups.Wait()
	if len(h.sessions) != 0 || len(h.pending) != 0 {
		t.Errorf("cache = %v, pending = %v; want the destroyed container's answer dropped", h.sessions, h.pending)
	}
}

func TestHubPublishesRefreshForUnreadableEvents(t *testing.T) {
	h := NewHub()
	ch, unsubscribe := h.Subscribe()
	defer unsubscribe()
	h.Handle(docker.Event{Err: docker.ErrEventTooLarge})
	if a := next(t, ch); a != RefreshAction {
		t.Errorf("published %q, want %q", a, RefreshAction)
	}
}

func TestHubRunClearsCacheOnRestart(t *testing.T) {
	h, c := countingHub(func(id string) (bool, error) { return true, nil })
	h.minDelay = time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runs := 0
	h.Run(ctx, func(_ context.Context, fn func(docker.Event)) error {
		runs++
		fn(disconnect("abc"))
		h.lookups.Wait()
		fn(disconnect("abc"))
		if runs == 2 {
			cancel()
		}
		return nil
	})
	h.lookups.Wait()
	if runs != 2 || c.get("abc") != 2 {
		t.Errorf("runs = %d, IsSession calls = %v; want one inspect per stream", runs, c.calls)
	}
}

func TestHubRunBacksOffAndRefreshes(t *testing.T) {
	h := NewHub()
	h.minDelay, h.maxDelay = 5*time.Millisecond, 20*time.Millisecond
	ch, unsubscribe := h.Subscribe()
	defer unsubscribe()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var starts []time.Time
	h.Run(ctx, func(context.Context, func(docker.Event)) error {
		starts = append(starts, time.Now())
		if len(starts) == 5 {
			cancel()
		}
		return errors.New("docker is down")
	})
	for i, want := range []time.Duration{5, 10, 20, 20} {
		if gap := starts[i+1].Sub(starts[i]); gap < want*time.Millisecond {
			t.Errorf("restart %d after %v, want at least %v", i+1, gap, want*time.Millisecond)
		}
	}
	for range 4 {
		if a := next(t, ch); a != RefreshAction {
			t.Errorf("published %q on restart, want %q", a, RefreshAction)
		}
	}
	quiet(t, ch)
}

func TestHubRunSurvivesOversizedEvent(t *testing.T) {
	huge := `{"Type":"container","Action":"start","Actor":{"Attributes":{"name":"safeclaw-` + strings.Repeat("x", docker.MaxEventLine) + `"}}}`
	r := &dockertest.Runner{Events: huge + "\n" +
		`{"Type":"container","Action":"start","Actor":{"ID":"a","Attributes":{"name":"safeclaw-a"}}}` + "\n" +
		`{"Type":"container","Action":"die","Actor":{"ID":"a","Attributes":{"name":"safeclaw-a"}}}` + "\n"}
	h := NewHub()
	h.minDelay = time.Hour
	ch, unsubscribe := h.Subscribe()
	defer unsubscribe()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		h.Run(ctx, r.Client().Events)
		close(done)
	}()
	var got []string
	for range 3 {
		got = append(got, next(t, ch))
	}
	cancel()
	<-done
	if want := []string{RefreshAction, "start", "die"}; strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("published %q, want %q", got, want)
	}
}

func TestIsSessionInspects(t *testing.T) {
	r := &dockertest.Runner{Handler: func(args []string, _ string) ([]byte, error) {
		switch args[len(args)-1] {
		case "abc":
			return []byte(`[{"Id":"abc","Name":"/safeclaw-work"}]`), nil
		case "def":
			return []byte(`[{"Id":"def","Name":"/postgres"}]`), nil
		}
		return nil, dockertest.NotFound(args)
	}}
	fn := isSession(r.Client())
	if v, err := fn("abc"); !v || err != nil {
		t.Errorf("isSession(abc) = %v, %v; want true", v, err)
	}
	if v, err := fn("def"); v || err != nil {
		t.Errorf("isSession(def) = %v, %v; want false", v, err)
	}
	if _, err := fn("gone"); err == nil {
		t.Error("isSession(gone) has no error, so its answer would be cached")
	}
}
