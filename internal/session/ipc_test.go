package session

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
)

func boolPtr(b bool) *bool { return &b }

func TestEnsureIPCNamespace(t *testing.T) {
	ctx := context.Background()
	// New sessions get docker's private IPC namespace.
	for _, hostIPC := range []*bool{nil, boolPtr(false)} {
		m, r := newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{}, native: true})
		if _, err := m.Ensure(ctx, Options{Name: "private", HostIPC: hostIPC, NoOpen: true}); err != nil {
			t.Fatal(err)
		}
		run, _ := r.Find("run ")
		if !strings.HasPrefix(run.String(), "run -d --name safeclaw-private ") || strings.Contains(run.String(), "--ipc") || strings.Contains(run.String(), "safeclaw.ipc") {
			t.Errorf("default run = %q", run.String())
		}
	}

	// Opting in shares the host's and records the choice.
	m, r := newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{}, native: true})
	if _, err := m.Ensure(ctx, Options{Name: "shared", HostIPC: boolPtr(true), NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	run, _ := r.Find("run ")
	if !strings.HasPrefix(run.String(), "run -d --ipc=host --label safeclaw.ipc=host --name safeclaw-shared ") {
		t.Errorf("opt-in run = %q", run.String())
	}
}

func TestEnsureIPCReuseAndRecreate(t *testing.T) {
	ctx := context.Background()
	existing := func(ipc string, labels map[string]string) *world {
		return &world{image: "img", containers: map[string]*fakeContainer{
			"safeclaw-p": {Running: true, Port: 7705, Image: "img", IpcMode: ipc, Labels: labels,
				Mounts: []string{"/hist:/home/sclaw/.claude/projects", "/proj:/home/sclaw/proj"}},
		}, native: true}
	}
	shared := func() *world {
		return existing("host", map[string]string{"safeclaw.ipc": "host", "safeclaw.secrets": ""})
	}

	// Without a choice, or with the same one, the container is kept.
	for _, tc := range []struct {
		w       func() *world
		hostIPC *bool
	}{
		{func() *world { return existing("", nil) }, nil},
		{func() *world { return existing("", nil) }, boolPtr(false)},
		{shared, nil},
		{shared, boolPtr(true)},
	} {
		w := tc.w()
		m, r := newTestManager(t, w)
		var out bytes.Buffer
		m.Out = &out
		if _, err := m.Ensure(ctx, Options{Name: "p", HostIPC: tc.hostIPC, NoOpen: true}); err != nil {
			t.Fatal(err)
		}
		if hasCall(r, "rm ") || hasCall(r, "run ") {
			t.Errorf("recreated: %v", r.Commands())
		}
		if strings.Contains(out.String(), "IPC") {
			t.Errorf("unexpected output: %s", out.String())
		}
	}

	// A different choice recreates it on the same port, keeping its mounts
	// and secrets.
	for _, tc := range []struct {
		w       func() *world
		hostIPC bool
		msg     string
	}{
		{func() *world { return existing("", map[string]string{"safeclaw.secrets": ""}) }, true, "Host IPC namespace requested"},
		{shared, false, "Private IPC namespace requested"},
	} {
		w := tc.w()
		m, r := newTestManager(t, w)
		var out bytes.Buffer
		m.Out = &out
		res, err := m.Ensure(ctx, Options{Name: "p", HostIPC: boolPtr(tc.hostIPC), NoOpen: true})
		if err != nil {
			t.Fatal(err)
		}
		if !hasCall(r, "rm -v -f safeclaw-p") || res.Port != 7705 || !strings.Contains(out.String(), tc.msg) {
			t.Errorf("host %v: not recreated on the old port: %d %v\n%s", tc.hostIPC, res.Port, r.Commands(), out.String())
		}
		run, _ := r.Find("run ")
		if strings.Contains(run.String(), "--ipc=host") != tc.hostIPC || strings.Contains(run.String(), "safeclaw.ipc=host") != tc.hostIPC {
			t.Errorf("host %v: run = %q", tc.hostIPC, run.String())
		}
		if !strings.Contains(run.String(), "-v /proj:/home/sclaw/proj ") || !strings.Contains(run.String(), "--label safeclaw.secrets= ") {
			t.Errorf("host %v: run lost mounts or secrets: %q", tc.hostIPC, run.String())
		}
	}

	// Other recreates keep the choice.
	w := shared()
	m, r := newTestManager(t, w)
	if _, err := m.Ensure(ctx, Options{Name: "p", Volume: "/new:/home/sclaw/new", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if run, _ := r.Find("run "); !strings.Contains(run.String(), "--ipc=host --label safeclaw.ipc=host ") {
		t.Errorf("volume recreate run = %q", run.String())
	}

	// An offline session is not recreated.
	w = existing("", nil)
	w.containers["safeclaw-p"].Offline = true
	m, r = newTestManager(t, w)
	if _, err := m.Ensure(ctx, Options{Name: "p", HostIPC: boolPtr(true), NoOpen: true}); !errors.Is(err, ErrOffline) || hasCall(r, "rm ") {
		t.Errorf("offline: err = %v, calls %v", err, r.Commands())
	}
}

func TestEnsureFailedIPCRecreateRestores(t *testing.T) {
	ctx := context.Background()
	w := &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-p": {Running: true, Port: 7705, Image: "img", IpcMode: "host", Labels: map[string]string{"safeclaw.ipc": "host"}},
	}, native: true, runErrs: []runErr{{err: errors.New("docker run failed")}}}
	m, r := newTestManager(t, w)
	if _, err := m.Ensure(ctx, Options{Name: "p", HostIPC: boolPtr(false), NoOpen: true}); err == nil {
		t.Fatal("no error")
	}
	c := w.containers["safeclaw-p"]
	if c == nil || c.IpcMode != "host" || c.Labels["safeclaw.ipc"] != "host" || c.Port != 7705 {
		t.Errorf("not restored with host IPC: %+v %v", c, r.Commands())
	}
}

func TestEnsureIPCUnrecordedHost(t *testing.T) {
	ctx := context.Background()
	// A container created with host IPC before the label existed.
	legacy := func() *world {
		return &world{image: "img", containers: map[string]*fakeContainer{
			"safeclaw-p": {Running: true, Port: 7705, Image: "img", IpcMode: "host"},
		}, native: true}
	}

	// It is kept, with a warning.
	m, r := newTestManager(t, legacy())
	var out bytes.Buffer
	m.Out = &out
	if _, err := m.Ensure(ctx, Options{Name: "p", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if hasCall(r, "rm ") || !strings.Contains(out.String(), "Warning: session p shares the host's IPC namespace") {
		t.Errorf("calls %v\n%s", r.Commands(), out.String())
	}

	// Either explicit choice recreates it: false to move it to a private
	// namespace, true to record the choice.
	for _, hostIPC := range []bool{false, true} {
		m, r := newTestManager(t, legacy())
		var out bytes.Buffer
		m.Out = &out
		if _, err := m.Ensure(ctx, Options{Name: "p", HostIPC: boolPtr(hostIPC), NoOpen: true}); err != nil {
			t.Fatal(err)
		}
		run, ok := r.Find("run ")
		if !hasCall(r, "rm -v -f safeclaw-p") || !ok || strings.Contains(run.String(), "safeclaw.ipc=host") != hostIPC {
			t.Errorf("host %v: calls %v", hostIPC, r.Commands())
		}
		if strings.Contains(out.String(), "Warning") {
			t.Errorf("host %v: warned: %s", hostIPC, out.String())
		}
	}

	// Any other recreate moves it to a private namespace without a warning.
	m, r = newTestManager(t, legacy())
	out.Reset()
	m.Out = &out
	if _, err := m.Ensure(ctx, Options{Name: "p", Volume: "/new:/home/sclaw/new", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if run, _ := r.Find("run "); strings.Contains(run.String(), "--ipc") || strings.Contains(out.String(), "Warning") {
		t.Errorf("volume recreate run = %q\n%s", run.String(), out.String())
	}
}
