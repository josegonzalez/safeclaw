package dashboard

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/josegonzalez/safeclaw/internal/dashproof"
	"github.com/josegonzalez/safeclaw/internal/session"
)

func TestProofNeedsNoLogin(t *testing.T) {
	s, err := New(Options{Sessions: noSessions{t}, Port: 7690, Token: testToken, TokenFile: "unused"})
	if err != nil {
		t.Fatal(err)
	}
	h := s.Handler()
	nonce := dashproof.NewNonce()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:7690"+dashproof.Path+"?nonce="+nonce, nil))
	if rec.Code != http.StatusNoContent || !dashproof.Verify(testToken, 7690, nonce, rec.Header().Get(dashproof.Header)) {
		t.Errorf("proof = %d %q", rec.Code, rec.Header().Get(dashproof.Header))
	}
	if strings.Contains(rec.Body.String()+strings.Join(rec.Header().Values(dashproof.Header), ""), testToken) {
		t.Error("the proof response carries the token")
	}
	if len(rec.Result().Cookies()) != 0 {
		t.Error("the proof response sets a cookie")
	}

	for name, tc := range map[string]struct {
		method, url string
		want        int
	}{
		"no nonce":    {http.MethodGet, "http://127.0.0.1:7690" + dashproof.Path, http.StatusBadRequest},
		"bad nonce":   {http.MethodGet, "http://127.0.0.1:7690" + dashproof.Path + "?nonce=short", http.StatusBadRequest},
		"post":        {http.MethodPost, "http://127.0.0.1:7690" + dashproof.Path + "?nonce=" + nonce, http.StatusMethodNotAllowed},
		"rebind host": {http.MethodGet, "http://evil.example:7690" + dashproof.Path + "?nonce=" + nonce, http.StatusForbidden},
	} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(tc.method, tc.url, nil))
		if rec.Code != tc.want || rec.Header().Get(dashproof.Header) != "" {
			t.Errorf("%s: %d %q, want %d and no proof", name, rec.Code, rec.Header().Get(dashproof.Header), tc.want)
		}
	}
}

// The CLI chooses a running dashboard by its proof, and SIGHUP, as when its
// terminal closes, stops it and removes its token file.
func TestRunningDashboardIsChosenAndSIGHUPRemovesTokenFile(t *testing.T) {
	port := loopbackPort(t)
	dir := filepath.Join(t.TempDir(), "dashboard")
	file := filepath.Join(dir, strconv.Itoa(port)+".token")
	s, err := New(Options{Sessions: &fakeSessions{}, Port: port, TokenFile: file})
	if err != nil {
		t.Fatal(err)
	}
	out := &syncBuffer{}
	done := make(chan error, 1)
	go func() { done <- s.ListenAndServe(context.Background(), out) }()
	for i := 0; i < 200 && !strings.Contains(out.String(), "API token"); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(out.String(), "API token") {
		t.Fatalf("dashboard didn't start: %q", out.String())
	}

	m := &session.Manager{DashboardDir: dir}
	u, ok := m.DashboardTerminalURL(context.Background(), "work")
	if want := "http://127.0.0.1:" + strconv.Itoa(port) + "/sessions/work/terminal"; !ok || u != want {
		t.Errorf("url = %q, %v, want %q", u, ok, want)
	}

	if err := syscall.Kill(os.Getpid(), syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SIGHUP didn't stop the dashboard")
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("token file after SIGHUP: %v", err)
	}
}
