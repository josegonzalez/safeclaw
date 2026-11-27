package session

import (
	"cmp"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/josegonzalez/safeclaw/internal/config"
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
// default port first, and each is asked for the page with its token, so a
// file left by a dashboard that has exited is skipped. It reports false
// when no dashboard answers.
func (m *Manager) DashboardTerminalURL(ctx context.Context, name string) (string, bool) {
	name = config.SessionName(name)
	if ValidateName(name) != nil {
		return "", false
	}
	dir := m.dashboardDir()
	for _, port := range dashboardPorts(dir) {
		b, err := readRegular(filepath.Join(dir, strconv.Itoa(port)+tokenSuffix))
		if err != nil {
			continue
		}
		token := strings.TrimSpace(string(b))
		if token == "" {
			continue
		}
		u := url.URL{Scheme: "http", Host: net.JoinHostPort(dashboardHost, strconv.Itoa(port)), Path: "/sessions/" + name + "/terminal"}
		if probeDashboard(ctx, u.String(), token) {
			return u.String(), true
		}
	}
	return "", false
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

// probeDashboard reports whether the dashboard answers a GET of u with
// token. The request never goes through a proxy, so the token stays on
// loopback, and redirects are not followed.
func probeDashboard(ctx context.Context, u, token string) bool {
	ctx, cancel := context.WithTimeout(ctx, dashboardProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+token)
	tr := &http.Transport{Proxy: nil}
	defer tr.CloseIdleConnections()
	client := &http.Client{
		Transport:     tr,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	return resp.StatusCode == http.StatusOK
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
