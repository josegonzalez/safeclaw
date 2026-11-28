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
	"time"

	"github.com/josegonzalez/safeclaw/internal/dashproof"
)

// fakeDashboard answers proof requests for token, as the dashboard does,
// and writes its token file into dir. It fails the test if a request
// carries credentials, which the probe must never send.
func fakeDashboard(t *testing.T, dir, token string) (port int, hits *int) {
	t.Helper()
	var p int
	port, hits = listen(t, func(w http.ResponseWriter, r *http.Request) {
		nonce := r.URL.Query().Get(dashproof.NonceParam)
		if r.URL.Path != dashproof.Path || !dashproof.ValidNonce(nonce) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set(dashproof.Header, dashproof.Sign(token, p, nonce))
		w.WriteHeader(http.StatusNoContent)
	})
	p = port
	writeToken(t, dir, port, token)
	return port, hits
}

// listen serves h on a loopback port, counting requests in hits and
// failing the test on any request that carries a token or cookie.
func listen(t *testing.T, h http.HandlerFunc) (port int, hits *int) {
	t.Helper()
	hits = new(int)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*hits++
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Errorf("probe sent credentials: %q", r.Header)
		}
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	_, ps, _ := net.SplitHostPort(srv.Listener.Addr().String())
	port, _ = strconv.Atoi(ps)
	return port, hits
}

func tokenExists(t *testing.T, dir string, port int) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(dir, strconv.Itoa(port)+".token"))
	return err == nil
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
	// dashboard on its port doesn't hold, are skipped and removed.
	closed := closedPort(t)
	writeToken(t, m.DashboardDir, closed, "stale")
	other, otherHits := fakeDashboard(t, t.TempDir(), "other")
	writeToken(t, m.DashboardDir, other, "wrong")
	if u, ok := m.DashboardTerminalURL(ctx, "work"); ok || *otherHits != 1 {
		t.Errorf("found a dashboard that doesn't hold its token: %s, %d probes", u, *otherHits)
	}
	if tokenExists(t, m.DashboardDir, closed) || tokenExists(t, m.DashboardDir, other) {
		t.Error("stale token files were kept")
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
	if !tokenExists(t, m.DashboardDir, port) {
		t.Error("the live dashboard's token file was removed")
	}
	if u, ok := m.DashboardTerminalURL(ctx, "../work"); ok {
		t.Errorf("accepted an invalid name: %s", u)
	}
}

// A listener that took over the port of a stale token file, answering
// every request with 200 or with a made-up proof, is never chosen, never
// gets the token, and the stale file is removed. The real dashboard is
// chosen once it runs.
func TestDashboardTerminalURLSkipsSquatter(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{
		"ok": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>terminal</html>")) },
		"fake proof": func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set(dashproof.Header, dashproof.Sign("guess", 1, "nonce"))
			w.WriteHeader(http.StatusNoContent)
		},
		"proof for another token": func(w http.ResponseWriter, r *http.Request) {
			_, p, _ := net.SplitHostPort(r.Host)
			port, _ := strconv.Atoi(p)
			w.Header().Set(dashproof.Header, dashproof.Sign("live", port, r.URL.Query().Get(dashproof.NonceParam)))
			w.WriteHeader(http.StatusNoContent)
		},
	} {
		t.Run(name, func(t *testing.T) {
			m, _ := newTestManager(t, &world{containers: map[string]*fakeContainer{}})
			squat, squatHits := listen(t, h)
			writeToken(t, m.DashboardDir, squat, "stale")
			ctx := context.Background()
			if u, ok := m.DashboardTerminalURL(ctx, "work"); ok {
				t.Errorf("chose the squatter: %s", u)
			}
			if *squatHits != 1 {
				t.Errorf("squatter probed %d times, want 1", *squatHits)
			}
			if tokenExists(t, m.DashboardDir, squat) {
				t.Error("the squatted stale token file was kept")
			}

			live, _ := fakeDashboard(t, m.DashboardDir, "live")
			u, ok := m.DashboardTerminalURL(ctx, "work")
			want := "http://127.0.0.1:" + strconv.Itoa(live) + "/sessions/work/terminal"
			if !ok || u != want {
				t.Errorf("url = %q, %v, want %q", u, ok, want)
			}
			if !tokenExists(t, m.DashboardDir, live) {
				t.Error("the live dashboard's token file was removed")
			}
		})
	}
}

// A stale file is only removed while it still holds the token that failed:
// one a new dashboard wrote meanwhile is kept.
func TestRemoveStaleTokenKeepsNewerFile(t *testing.T) {
	dir := t.TempDir()
	writeToken(t, dir, 7690, "new")
	removeStaleToken(filepath.Join(dir, "7690.token"), "old")
	if !tokenExists(t, dir, 7690) {
		t.Error("removed a file holding another run's token")
	}
	removeStaleToken(filepath.Join(dir, "7690.token"), "new")
	if tokenExists(t, dir, 7690) {
		t.Error("kept a file holding the stale token")
	}
}

// A port that doesn't answer in time keeps its file, since a busy
// dashboard may still be holding it.
func TestDashboardTerminalURLKeepsFileOnTimeout(t *testing.T) {
	m, _ := newTestManager(t, &world{containers: map[string]*fakeContainer{}})
	release := make(chan struct{})
	slow, _ := listen(t, func(http.ResponseWriter, *http.Request) { <-release })
	t.Cleanup(func() { close(release) })
	writeToken(t, m.DashboardDir, slow, "busy")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if u, ok := m.DashboardTerminalURL(ctx, "work"); ok {
		t.Errorf("chose a dashboard that never answered: %s", u)
	}
	if !tokenExists(t, m.DashboardDir, slow) {
		t.Error("removed the file of a port that didn't answer in time")
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
	// Without a dashboard, the URL is opened without the credential, which
	// the opener's command line would show other local users, and the
	// output says how to log in.
	if !slices.Equal(opened, []string{"http://[::1]:7681"}) || !strings.Contains(out.String(), "without its credential") || !strings.Contains(out.String(), "Log in as safeclaw with the password in the printed URL") || strings.Contains(out.String(), "pw") {
		t.Errorf("without a dashboard: opened %q, out %q", opened, out.String())
	}
	opened = nil
	if err := m.OpenTerminal(ctx, "work", "http://safeclaw:pw@[::1"); err == nil || strings.Contains(err.Error(), "pw") || len(opened) != 0 {
		t.Errorf("bad URL: err = %v, opened %q", err, opened)
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
	if want := "http://[::1]:" + strconv.Itoa(res.Port); !slices.Equal(opened, []string{want}) || !strings.Contains(res.URL, "@") {
		t.Errorf("without a dashboard: opened %q, want %q without the credential in %q", opened, want, res.URL)
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
