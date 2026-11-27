package session

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// fakeDashboard serves the terminal page to requests carrying token, as
// the dashboard does, and writes its token file into dir.
func fakeDashboard(t *testing.T, dir, token string) (port int, hits *int) {
	t.Helper()
	hits = new(int)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*hits++
		if r.Header.Get("Authorization") != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/sessions/") || !strings.HasSuffix(r.URL.Path, "/terminal") {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write([]byte("<html>terminal</html>"))
	}))
	t.Cleanup(srv.Close)
	_, p, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ = strconv.Atoi(p)
	writeToken(t, dir, port, token)
	return port, hits
}

func writeToken(t *testing.T, dir string, port int, token string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, strconv.Itoa(port)+".token"), []byte(token+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// closedPort returns a loopback port nothing listens on.
func closedPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := l.Addr().(*net.TCPAddr).Port
	_ = l.Close()
	return port
}

func TestDashboardTerminalURL(t *testing.T) {
	m, _ := newTestManager(t, &world{containers: map[string]*fakeContainer{}})
	ctx := context.Background()
	if u, ok := m.DashboardTerminalURL(ctx, "work"); ok {
		t.Errorf("found a dashboard without token files: %s", u)
	}

	// A file left by a dashboard that exited, and one whose token the
	// dashboard on its port doesn't take, are skipped.
	writeToken(t, m.DashboardDir, closedPort(t), "stale")
	other, otherHits := fakeDashboard(t, t.TempDir(), "other")
	writeToken(t, m.DashboardDir, other, "wrong")
	if u, ok := m.DashboardTerminalURL(ctx, "work"); ok || *otherHits != 1 {
		t.Errorf("found a dashboard that refuses its token: %s, %d probes", u, *otherHits)
	}

	port, hits := fakeDashboard(t, m.DashboardDir, "secret")
	u, ok := m.DashboardTerminalURL(ctx, "safeclaw-work")
	want := "http://127.0.0.1:" + strconv.Itoa(port) + "/sessions/work/terminal"
	if !ok || u != want {
		t.Errorf("url = %q, %v, want %q", u, ok, want)
	}
	if *hits != 1 {
		t.Errorf("dashboard probed %d times, want 1", *hits)
	}
	if u, ok := m.DashboardTerminalURL(ctx, "../work"); ok {
		t.Errorf("accepted an invalid name: %s", u)
	}
}

func TestDashboardTokenFileMustBeRegular(t *testing.T) {
	m, _ := newTestManager(t, &world{containers: map[string]*fakeContainer{}})
	port, hits := fakeDashboard(t, t.TempDir(), "secret")
	target := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(target, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(m.DashboardDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(m.DashboardDir, strconv.Itoa(port)+".token")); err != nil {
		t.Fatal(err)
	}
	if u, ok := m.DashboardTerminalURL(context.Background(), "work"); ok || *hits != 0 {
		t.Errorf("followed a symlinked token file: %s, %d probes", u, *hits)
	}
}

func TestDashboardPortsDefaultFirst(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"9000.token", "7680.token", "8000.token", "x.token", "07680.token", "0.token", "70000.token", "8100.txt", ".token-tmp"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("t"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if got, want := dashboardPorts(dir), []int{7680, 8000, 9000}; !slices.Equal(got, want) {
		t.Errorf("ports = %v, want %v", got, want)
	}
	if got := dashboardPorts(filepath.Join(dir, "missing")); got != nil {
		t.Errorf("ports in a missing dir = %v", got)
	}
}

func TestOpenTerminal(t *testing.T) {
	m, _ := newTestManager(t, &world{containers: map[string]*fakeContainer{}})
	var opened []string
	m.OpenBrowser = func(u string) error { opened = append(opened, u); return nil }
	var out bytes.Buffer
	m.Out = &out
	ctx := context.Background()
	cred := "http://safeclaw:pw@[::1]:7681"

	if err := m.OpenTerminal(ctx, "work", cred); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(opened, []string{cred}) || !strings.Contains(out.String(), "Warning: opening the terminal URL with the session's credential") {
		t.Errorf("without a dashboard: opened %q, out %q", opened, out.String())
	}

	opened, out = nil, bytes.Buffer{}
	port, _ := fakeDashboard(t, m.DashboardDir, "secret")
	if err := m.OpenTerminal(ctx, "work", cred); err != nil {
		t.Fatal(err)
	}
	want := "http://127.0.0.1:" + strconv.Itoa(port) + "/sessions/work/terminal"
	if !slices.Equal(opened, []string{want}) || strings.Contains(out.String(), "pw") || strings.Contains(out.String(), "Warning") {
		t.Errorf("with a dashboard: opened %q, out %q", opened, out.String())
	}

	m.OpenBrowser = func(string) error { return errors.New("no opener") }
	if err := m.OpenTerminal(ctx, "work", cred); err == nil {
		t.Error("opener error was dropped")
	}
}

func TestEnsureOpensDashboardTerminal(t *testing.T) {
	w := &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-off": {Port: 7690, HostIP: "::1", Image: "img", Offline: true},
	}, native: true}
	m, _ := newTestManager(t, w)
	var opened []string
	m.OpenBrowser = func(u string) error { opened = append(opened, u); return nil }
	ctx := context.Background()

	res, err := m.Ensure(ctx, Options{Name: "work"})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(opened, []string{res.URL}) {
		t.Errorf("without a dashboard: opened %q, want the credential URL", opened)
	}

	opened = nil
	port, _ := fakeDashboard(t, m.DashboardDir, "secret")
	if _, err := m.Ensure(ctx, Options{Name: "work"}); err != nil {
		t.Fatal(err)
	}
	if want := "http://127.0.0.1:" + strconv.Itoa(port) + "/sessions/work/terminal"; !slices.Equal(opened, []string{want}) {
		t.Errorf("with a dashboard: opened %q, want %q", opened, want)
	}

	// An offline session's terminal is unreachable, so it isn't opened.
	opened = nil
	if _, err := m.Ensure(ctx, Options{Name: "off"}); err != nil {
		t.Fatal(err)
	}
	if len(opened) != 0 {
		t.Errorf("opened %q for an offline session", opened)
	}
}
