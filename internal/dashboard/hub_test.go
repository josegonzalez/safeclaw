package dashboard

import (
	"context"
	"errors"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
)

func disconnect(id string) docker.Event {
	return docker.Event{Type: "network", Action: "disconnect", Name: "bridge", Container: id}
}

func countingHub(answer func(id string) (bool, error)) (*Hub, map[string]int) {
	h := NewHub()
	calls := map[string]int{}
	h.IsSession = func(id string) (bool, error) {
		calls[id]++
		return answer(id)
	}
	return h, calls
}

func TestHubCachesSessionAnswers(t *testing.T) {
	h, calls := countingHub(func(id string) (bool, error) { return id == "abc", nil })
	for range 3 {
		h.Handle(disconnect("abc"))
		h.Handle(disconnect("other"))
	}
	if calls["abc"] != 1 || calls["other"] != 1 {
		t.Errorf("IsSession calls = %v, want one per ID", calls)
	}
}

func TestHubDoesNotCacheErrors(t *testing.T) {
	h, calls := countingHub(func(string) (bool, error) { return false, errors.New("boom") })
	h.Handle(disconnect("abc"))
	h.Handle(disconnect("abc"))
	if calls["abc"] != 2 || len(h.sessions) != 0 {
		t.Errorf("IsSession calls = %v, cache = %v; want errors left uncached", calls, h.sessions)
	}
}

func TestHubForgetsDestroyedContainers(t *testing.T) {
	h, calls := countingHub(func(id string) (bool, error) { return true, nil })
	h.Handle(disconnect("abc"))
	h.Handle(disconnect("def"))
	h.Handle(docker.Event{Type: "container", Action: "destroy", Name: "safeclaw-x", Container: "abc"})
	h.Handle(docker.Event{Type: "container", Action: "destroy", Name: "not-a-session", Container: "def"})
	if len(h.sessions) != 0 {
		t.Errorf("cache = %v after destroy, want empty", h.sessions)
	}
	h.Handle(disconnect("abc"))
	if calls["abc"] != 2 {
		t.Errorf("IsSession calls = %v, want abc asked again after destroy", calls)
	}
}

func TestHubKeepsCacheOnOtherContainerEvents(t *testing.T) {
	h, calls := countingHub(func(id string) (bool, error) { return true, nil })
	h.Handle(disconnect("abc"))
	h.Handle(docker.Event{Type: "container", Action: "die", Name: "safeclaw-x", Container: "abc"})
	h.Handle(disconnect("abc"))
	if calls["abc"] != 1 {
		t.Errorf("IsSession calls = %v, want the answer kept until destroy", calls)
	}
}

func TestHubRunClearsCacheOnRestart(t *testing.T) {
	h, calls := countingHub(func(id string) (bool, error) { return true, nil })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runs := 0
	h.Run(ctx, func(_ context.Context, fn func(docker.Event)) error {
		runs++
		fn(disconnect("abc"))
		fn(disconnect("abc"))
		if runs == 2 {
			cancel()
		}
		return nil
	})
	if runs != 2 || calls["abc"] != 2 {
		t.Errorf("runs = %d, IsSession calls = %v; want one inspect per stream", runs, calls)
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
