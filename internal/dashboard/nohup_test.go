package dashboard

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/josegonzalez/safeclaw/internal/session"
)

// nohupChildEnv, when set to PORT:TOKENFILE, makes
// TestDashboardUnderNohupKeepsRunningOnSIGHUP run the dashboard itself
// until SIGTERM, as the child its parent starts under nohup.
const nohupChildEnv = "SAFECLAW_TEST_NOHUP_DASHBOARD"

// A dashboard started under nohup keeps ignoring SIGHUP, so it keeps
// running, and keeps its token file, when its terminal closes.
func TestDashboardUnderNohupKeepsRunningOnSIGHUP(t *testing.T) {
	if v := os.Getenv(nohupChildEnv); v != "" {
		runNohupChild(t, v)
		return
	}
	nohup, err := exec.LookPath("nohup")
	if err != nil {
		t.Skip("nohup not found")
	}
	port := loopbackPort(t)
	dir := filepath.Join(t.TempDir(), "dashboard")
	file := filepath.Join(dir, strconv.Itoa(port)+".token")
	cmd := exec.Command(nohup, os.Args[0], "-test.run=^TestDashboardUnderNohupKeepsRunningOnSIGHUP$", "-test.timeout=60s")
	cmd.Env = append(os.Environ(), nohupChildEnv+"="+strconv.Itoa(port)+":"+file)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// exited is closed when the child exits, with its error in waitErr.
	exited := make(chan struct{})
	var waitErr error
	go func() { waitErr = cmd.Wait(); close(exited) }()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-exited
	})

	m := &session.Manager{DashboardDir: dir}
	running := func() bool {
		_, ok := m.DashboardTerminalURL(context.Background(), "work")
		return ok
	}
	for i := 0; i < 500 && !running(); i++ {
		select {
		case <-exited:
			t.Fatalf("dashboard exited before it started: %v\n%s", waitErr, out.String())
		case <-time.After(20 * time.Millisecond):
		}
	}
	if !running() {
		t.Fatal("dashboard didn't start")
	}

	if err := cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatal(err)
	}
	select {
	case <-exited:
		t.Fatalf("SIGHUP stopped the dashboard: %v\n%s", waitErr, out.String())
	case <-time.After(500 * time.Millisecond):
	}
	if !running() {
		t.Fatal("dashboard stopped answering after SIGHUP")
	}

	// It still stops cleanly, and removes its token file, on SIGTERM.
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case <-exited:
		if waitErr != nil {
			t.Fatalf("dashboard: %v\n%s", waitErr, out.String())
		}
	case <-time.After(10 * time.Second):
		t.Fatal("SIGTERM didn't stop the dashboard")
	}
	if _, err := os.Stat(file); !os.IsNotExist(err) {
		t.Errorf("token file after SIGTERM: %v", err)
	}
}

// runNohupChild serves the dashboard on the port and token file in v until
// SIGTERM.
func runNohupChild(t *testing.T, v string) {
	portStr, file, ok := strings.Cut(v, ":")
	port, err := strconv.Atoi(portStr)
	if !ok || err != nil {
		t.Fatalf("bad %s %q", nohupChildEnv, v)
	}
	if !signal.Ignored(syscall.SIGHUP) {
		t.Fatal("SIGHUP isn't ignored in the child")
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	s, err := New(Options{Sessions: &fakeSessions{}, Port: port, TokenFile: file})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ListenAndServe(ctx, &syncBuffer{}); err != nil {
		t.Fatal(err)
	}
}
