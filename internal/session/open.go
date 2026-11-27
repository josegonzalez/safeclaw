package session

import (
	"cmp"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/josegonzalez/safeclaw/internal/config"
	"github.com/josegonzalez/safeclaw/internal/dashproof"
)

// dashboardHost is the host dashboards listen on and set their cookie for,
// so it is the one their terminal pages are opened on.
const dashboardHost = "127.0.0.1"

// dashboardProbeTimeout bounds how long opening a terminal waits for each
// dashboard to answer.
const dashboardProbeTimeout = time.Second

// tokenSuffix ends the name of each running dashboard's token file, which
// starts with the dashboard's port.
const tokenSuffix = ".token"

func (m *Manager) dashboardDir() string {
	if m.DashboardDir != "" {
		return m.DashboardDir
	}
	return config.DashboardDir()
}

// DashboardTerminalURL returns the URL of a session's terminal page on a
// running dashboard, which needs the dashboard's login instead of the
// session's credential. Dashboards are found by their token files, the
// default port first. The listener on each file's port must prove it holds
// that file's token (see dashproof), which never sends the token to it, so
// a file left by a dashboard that has exited is skipped even when another
// local user took over its port. Such a file is removed when the port
// refuses the connection or answers without the proof. It reports false
// when no dashboard proves itself.
func (m *Manager) DashboardTerminalURL(ctx context.Context, name string) (string, bool) {
	name = config.SessionName(name)
	if ValidateName(name) != nil {
		return "", false
	}
	dir := m.dashboardDir()
	for _, port := range dashboardPorts(dir) {
		path := filepath.Join(dir, strconv.Itoa(port)+tokenSuffix)
		b, err := readRegular(path)
		if err != nil {
			continue
		}
		token := strings.TrimSpace(string(b))
		if token == "" {
			continue
		}
		switch probeDashboard(ctx, port, token) {
		case probeProved:
			u := url.URL{Scheme: "http", Host: net.JoinHostPort(dashboardHost, strconv.Itoa(port)), Path: "/sessions/" + name + "/terminal"}
			return u.String(), true
		case probeFailed:
			removeStaleToken(path, token)
		}
	}
	return "", false
}

// removeStaleToken removes the token file at path if it still holds token,
// so a dashboard that started on the same port meanwhile keeps its file.
func removeStaleToken(path, token string) {
	b, err := readRegular(path)
	if err != nil || strings.TrimSpace(string(b)) != token {
		return
	}
	_ = os.Remove(path)
}

// dashboardPorts returns the ports with a token file in dir, the default
// dashboard port first and the rest in order.
func dashboardPorts(dir string) []int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var ports []int
	for _, e := range entries {
		p, ok := strings.CutSuffix(e.Name(), tokenSuffix)
		if !ok {
			continue
		}
		port, err := strconv.Atoi(p)
		if err != nil || port < 1 || port > 65535 || strconv.Itoa(port) != p {
			continue
		}
		ports = append(ports, port)
	}
	slices.SortFunc(ports, func(a, b int) int {
		if (a == config.DashboardPort) != (b == config.DashboardPort) {
			if a == config.DashboardPort {
				return -1
			}
			return 1
		}
		return cmp.Compare(a, b)
	})
	return ports
}

// probeResult is what probing a token file's port found.
type probeResult int

const (
	// probeUnknown means the port didn't answer in time, so the file is
	// skipped but kept.
	probeUnknown probeResult = iota
	// probeFailed means nothing listens on the port or the listener can't
	// prove it holds the token, so the file is stale.
	probeFailed
	// probeProved means the dashboard holding the token listens there.
	probeProved
)

// probeDashboard asks the listener on port to prove it holds token, by
// answering a random nonce with dashproof.Sign. Only the nonce is sent,
// never the token, the request never goes through a proxy, and redirects
// are not followed.
func probeDashboard(ctx context.Context, port int, token string) probeResult {
	ctx, cancel := context.WithTimeout(ctx, dashboardProbeTimeout)
	defer cancel()
	nonce := dashproof.NewNonce()
	u := url.URL{
		Scheme:   "http",
		Host:     net.JoinHostPort(dashboardHost, strconv.Itoa(port)),
		Path:     dashproof.Path,
		RawQuery: url.Values{dashproof.NonceParam: {nonce}}.Encode(),
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return probeUnknown
	}
	tr := &http.Transport{Proxy: nil}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if errors.Is(err, syscall.ECONNREFUSED) {
		return probeFailed
	}
	if err != nil {
		return probeUnknown
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusNoContent || !dashproof.Verify(token, port, nonce, resp.Header.Get(dashproof.Header)) {
		return probeFailed
	}
	return probeProved
}

// OpenTerminal opens a session's terminal in the browser. When a dashboard
// is running it opens the dashboard's terminal page, so the session's
// credential stays out of the opener's command line, where other local
// users can see it, and out of the browser's history. Otherwise it opens
// credURL, the URL carrying the credential, and warns about that.
func (m *Manager) OpenTerminal(ctx context.Context, name, credURL string) error {
	if u, ok := m.DashboardTerminalURL(ctx, name); ok {
		m.printf("Opening the dashboard's terminal page: %s\n", u)
		m.printf("If it says unauthorized, log the browser in with the URL `safeclaw dashboard` printed\n")
		return m.openBrowser(u)
	}
	m.printf("Warning: opening the terminal URL with the session's credential in it, so other local users can see it in the process list and it stays in your browser history. With `safeclaw dashboard` running, the dashboard's terminal page is opened instead\n")
	return m.openBrowser(credURL)
}
