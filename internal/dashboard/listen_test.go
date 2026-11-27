package dashboard

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// loopbackPort returns a port free on both 127.0.0.1 and [::1], skipping
// the test on a host without IPv6 loopback.
func loopbackPort(t *testing.T) int {
	t.Helper()
	for i := 0; i < 20; i++ {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		port := ln.Addr().(*net.TCPAddr).Port
		ln6, err := net.Listen("tcp", net.JoinHostPort("::1", strconv.Itoa(port)))
		_ = ln.Close()
		if err == nil {
			_ = ln6.Close()
			return port
		}
		if noIPv6Loopback(err) {
			t.Skipf("no IPv6 loopback: %v", err)
		}
	}
	t.Fatal("no port free on both loopback addresses")
	return 0
}

// viaIPv6 is a client that connects to [::1] whatever the URL's host is,
// as a client that tries ::1 first for localhost does.
func viaIPv6(port int) *http.Client {
	addr := net.JoinHostPort("::1", strconv.Itoa(port))
	return &http.Client{
		Transport: &http.Transport{
			Proxy: nil,
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, network, addr)
			},
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

func TestListenAndServeHoldsIPv6Loopback(t *testing.T) {
	port := loopbackPort(t)
	file := filepath.Join(t.TempDir(), "dashboard", "port.token")
	s, err := New(Options{Sessions: &fakeSessions{}, Port: port, TokenFile: file})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	out := &syncBuffer{}
	done := make(chan error, 1)
	go func() { done <- s.ListenAndServe(ctx, out) }()
	for i := 0; i < 200 && !strings.Contains(out.String(), "API token"); i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if strings.Contains(out.String(), "Warning") {
		t.Errorf("printed %q", out.String())
	}

	// Nothing else can take the [::1] side of localhost:PORT.
	if ln, err := net.Listen("tcp", net.JoinHostPort("::1", strconv.Itoa(port))); err == nil {
		_ = ln.Close()
		t.Error("[::1] port was free while the dashboard ran")
	}

	// localhost over [::1] is authorized and redirected as over 127.0.0.1.
	c := viaIPv6(port)
	base := fmt.Sprintf("http://localhost:%d", port)
	req, _ := http.NewRequest("GET", base+"/api/sessions", nil)
	req.Header.Set("Authorization", "Bearer "+s.token)
	if resp, err := c.Do(req); err != nil {
		t.Fatal(err)
	} else if _ = resp.Body.Close(); resp.StatusCode != http.StatusOK {
		t.Errorf("bearer to localhost over [::1] = %d", resp.StatusCode)
	}
	resp, err := c.Get(base + "/?token=" + s.token)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	want := fmt.Sprintf("http://127.0.0.1:%d/?token=%s", port, s.token)
	if resp.StatusCode != http.StatusTemporaryRedirect || resp.Header.Get("Location") != want || len(resp.Cookies()) != 0 {
		t.Errorf("token URL on localhost over [::1] = %d %q %v", resp.StatusCode, resp.Header.Get("Location"), resp.Cookies())
	}
	req, _ = http.NewRequest("GET", fmt.Sprintf("http://[::1]:%d/api/sessions", port), nil)
	req.Header.Set("Authorization", "Bearer "+s.token)
	if resp, err := c.Do(req); err != nil {
		t.Fatal(err)
	} else if _ = resp.Body.Close(); resp.StatusCode != http.StatusForbidden {
		t.Errorf("Host [::1] = %d", resp.StatusCode)
	}

	cancel()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"127.0.0.1", "::1"} {
		ln, err := net.Listen("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
		if err != nil {
			t.Errorf("%s port still held after shutdown: %v", host, err)
			continue
		}
		_ = ln.Close()
	}
}

func TestListenAndServeFailsWhenIPv6PortTaken(t *testing.T) {
	port := loopbackPort(t)
	squatter, err := net.Listen("tcp", net.JoinHostPort("::1", strconv.Itoa(port)))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = squatter.Close() }()
	file := filepath.Join(t.TempDir(), "dashboard", "port.token")
	s, err := New(Options{Sessions: &fakeSessions{}, Port: port, TokenFile: file})
	if err != nil {
		t.Fatal(err)
	}
	// A dashboard that starts anyway serves until the timeout and returns nil.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out := &syncBuffer{}
	err = s.ListenAndServe(ctx, out)
	if err == nil || !strings.Contains(err.Error(), "[::1]:"+strconv.Itoa(port)) {
		t.Fatalf("ListenAndServe = %v", err)
	}
	if out.String() != "" {
		t.Errorf("printed %q", out.String())
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("token file written: %v", err)
	}
	ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
	if err != nil {
		t.Fatalf("127.0.0.1 port still held: %v", err)
	}
	_ = ln.Close()
}

func TestNoIPv6Loopback(t *testing.T) {
	wrap := func(errno syscall.Errno) error {
		return &net.OpError{Op: "listen", Net: "tcp", Err: os.NewSyscallError("bind", errno)}
	}
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{wrap(syscall.EADDRNOTAVAIL), true},
		{wrap(syscall.EAFNOSUPPORT), true},
		{wrap(syscall.EADDRINUSE), false},
		{wrap(syscall.EACCES), false},
		{errors.New("other"), false},
	} {
		if got := noIPv6Loopback(tc.err); got != tc.want {
			t.Errorf("noIPv6Loopback(%v) = %v", tc.err, got)
		}
	}
}
