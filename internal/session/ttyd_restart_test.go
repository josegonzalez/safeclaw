package session

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
)

// fakeTTYD models the one ttyd a session container can run: it takes the
// credential file's contents when it starts, a second one can't bind the
// port while the first runs, and the scripts stopTTYD and
// checkTTYDAnswers run see it as a real container would. It wraps a
// world, serializing its handler so goroutines can share it.
type fakeTTYD struct {
	mu   sync.Mutex
	w    *world
	file string // the container's credential file
	cred string // what the running ttyd takes
	up   bool
	// stubborn ignores SIGTERM; deaf ignores SIGKILL too.
	stubborn, deaf bool
	// failKill makes pkill fail.
	failKill bool
	// answer, when set, is what every check that ttyd answers prints.
	answer string
	// starts counts ttyd starts, and checks the checks that it answers.
	starts, checks int
	// delay is slept outside the lock on every exec, so concurrent runs
	// interleave if nothing serializes them.
	delay time.Duration
}

func (f *fakeTTYD) handle(args []string, stdin string) ([]byte, error) {
	if f.delay > 0 && args[0] == "exec" {
		time.Sleep(f.delay)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	cmd := strings.Join(args, " ")
	switch {
	case args[0] != "exec":
	case strings.Contains(cmd, killTTYDScript):
		if f.failKill {
			return nil, errors.New("exit status 3")
		}
		kill := strings.HasSuffix(cmd, " -KILL")
		if !f.deaf && (kill || !f.stubborn) {
			f.up = false
		}
		return nil, nil
	case strings.Contains(cmd, ttydGoneScript):
		if f.up {
			return []byte("its process is still running\n"), nil
		}
		return nil, nil
	case strings.Contains(cmd, writeCredentialScript):
		f.file = stdin
		return nil, nil
	case strings.Contains(cmd, "exec ttyd --credential-file"):
		f.starts++
		// A second ttyd can't bind the port and exits.
		if !f.up {
			f.up, f.cred = true, f.file
		}
		return nil, nil
	case strings.Contains(cmd, ttydAnswersScript):
		f.checks++
		switch {
		case f.answer != "":
			return []byte(f.answer + "\n"), nil
		case !f.up:
			return []byte("000\n"), nil
		case stdin != `user = "`+f.cred+"\"\n":
			return []byte("401\n"), nil
		}
		return nil, nil
	}
	return f.w.handle(args, stdin)
}

func runningTTYD(t *testing.T) (*fakeTTYD, *Manager, *dockertest.Runner) {
	t.Helper()
	w := &world{image: "img", containers: map[string]*fakeContainer{
		"safeclaw-work": {Running: true, Port: 7690, HostIP: "::1", Image: "img"},
	}, native: true}
	f := &fakeTTYD{w: w, file: "safeclaw:old", cred: "safeclaw:old", up: true}
	m, r := newTestManager(t, w)
	r.Handler = f.handle
	if err := writePrivate(m.credentialPath("work"), "safeclaw:old\n"); err != nil {
		t.Fatal(err)
	}
	return f, m, r
}

// A failed pkill is an error, before the credential is rotated or a new
// ttyd started, so the host file keeps the credential the old ttyd takes.
func TestEnsureFailedPkillIsAnError(t *testing.T) {
	f, m, r := runningTTYD(t)
	f.failKill = true
	_, err := m.Ensure(context.Background(), Options{Name: "work", NoOpen: true})
	if !errors.Is(err, ErrTTYDRestart) || !strings.Contains(err.Error(), "stopping the old ttyd failed") {
		t.Fatalf("err = %v", err)
	}
	if hasCall(r, "exec -i --user sclaw safeclaw-work sh -c "+writeCredentialScript) || f.starts != 0 {
		t.Errorf("went on after pkill failed: %v", r.Commands())
	}
	if c, err := m.Credential("work"); err != nil || c.String() != "safeclaw:old" {
		t.Errorf("credential = %v, %v", c, err)
	}
}

// A ttyd that ignores SIGTERM gets SIGKILL, and the restart goes on.
func TestEnsureKillsStubbornTTYD(t *testing.T) {
	f, m, r := runningTTYD(t)
	f.stubborn = true
	if _, err := m.Ensure(context.Background(), Options{Name: "work", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	if !hasCall(r, "exec --user sclaw safeclaw-work sh -c "+killTTYDScript+" sh -KILL") {
		t.Errorf("no SIGKILL: %v", r.Commands())
	}
	c, err := m.Credential("work")
	if err != nil || c.String() != f.cred || c.String() == "safeclaw:old" {
		t.Errorf("credential = %v, %v; ttyd takes %q", c, err, f.cred)
	}
}

// A ttyd still running after SIGKILL is an error that says how to recover,
// and nothing is rotated or started.
func TestEnsureTTYDThatWontStop(t *testing.T) {
	f, m, r := runningTTYD(t)
	f.deaf = true
	var slept time.Duration
	m.Sleep = func(d time.Duration) { slept += d }
	_, err := m.Ensure(context.Background(), Options{Name: "work", NoOpen: true})
	if !errors.Is(err, ErrTTYDRestart) || !strings.Contains(err.Error(), "did not stop (its process is still running)") || !strings.Contains(err.Error(), "safeclaw stop work") {
		t.Fatalf("err = %v", err)
	}
	if f.starts != 0 || hasCall(r, "exec -i --user sclaw safeclaw-work sh -c "+writeCredentialScript) {
		t.Errorf("went on with the old ttyd running: %v", r.Commands())
	}
	if want := 2 * (ttydStopPolls - 1) * ttydPoll; slept != want {
		t.Errorf("waited %v, want %v", slept, want)
	}
	if c, err := m.Credential("work"); err != nil || c.String() != "safeclaw:old" {
		t.Errorf("credential = %v, %v", c, err)
	}
}

// A new ttyd that refuses the new credential is an error right away.
func TestStartTTYDRefused(t *testing.T) {
	f, m, _ := runningTTYD(t)
	f.answer = "401"
	_, err := m.Ensure(context.Background(), Options{Name: "work", NoOpen: true})
	if !errors.Is(err, ErrTTYDRestart) || !strings.Contains(err.Error(), "refused the new credential") || f.checks != 1 {
		t.Errorf("err = %v after %d checks", err, f.checks)
	}
}

// A new ttyd that never answers is an error once the checks run out.
func TestStartTTYDNeverAnswers(t *testing.T) {
	f, m, _ := runningTTYD(t)
	f.answer = "000"
	_, err := m.Ensure(context.Background(), Options{Name: "work", NoOpen: true})
	if !errors.Is(err, ErrTTYDRestart) || !strings.Contains(err.Error(), "did not answer on port 7681 (HTTP status 000)") || f.checks != ttydStartPolls {
		t.Errorf("err = %v after %d checks", err, f.checks)
	}
}

// The check that ttyd answers sends the credential on stdin, never in argv.
func TestStartTTYDCheckKeepsCredentialOffArgv(t *testing.T) {
	f, m, r := runningTTYD(t)
	if _, err := m.Ensure(context.Background(), Options{Name: "work", NoOpen: true}); err != nil {
		t.Fatal(err)
	}
	pass := strings.TrimPrefix(f.cred, "safeclaw:")
	for _, c := range r.Commands() {
		if strings.Contains(c, pass) {
			t.Errorf("credential in argv: %q", c)
		}
	}
	if call, ok := r.Find("exec -i --user sclaw safeclaw-work sh -c " + ttydAnswersScript); !ok || call.Stdin != `user = "`+f.cred+"\"\n" {
		t.Errorf("check = %+v, %v", call, ok)
	}
}

// Concurrent runs of one session, from separate Managers as the CLI and the
// dashboard are, leave the host credential equal to the one the running
// ttyd took, and none of them fails.
func TestEnsureConcurrentRunsAgree(t *testing.T) {
	f, m, r := runningTTYD(t)
	f.delay = time.Millisecond
	const runs = 6
	var wg sync.WaitGroup
	errs := make([]error, runs)
	for i := range runs {
		mi := m
		if i%2 == 1 {
			// Another process: its own Manager, sharing the host's files.
			mi = &Manager{Docker: r.Client(), Secrets: m.Secrets, SessionsDir: m.SessionsDir, TTYDDir: m.TTYDDir, DashboardDir: m.DashboardDir,
				NetworkDir: m.NetworkDir, CopyDir: m.CopyDir, PortFree: m.PortFree, Sleep: m.Sleep, OpenBrowser: m.OpenBrowser, PromptTimeout: m.PromptTimeout}
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = mi.Ensure(context.Background(), Options{Name: "work", NoOpen: true})
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("run %d: %v", i, err)
		}
	}
	c, err := m.Credential("work")
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if !f.up || c.String() != f.cred || f.starts != runs {
		t.Errorf("host credential %q, ttyd takes %q (up %v) after %d starts", c, f.cred, f.up, f.starts)
	}
}

// A run waiting for another run of the same session gives up when its
// context ends.
func TestEnsureLockHonorsContext(t *testing.T) {
	_, m, r := runningTTYD(t)
	release, err := m.ensureLock(context.Background(), "work")
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx, cancel := context.WithTimeout(context.Background(), 3*lockRetry)
	defer cancel()
	_, err = m.Ensure(ctx, Options{Name: "work", NoOpen: true})
	if !errors.Is(err, context.DeadlineExceeded) || len(r.Calls) != 0 {
		t.Errorf("err = %v, commands = %v", err, r.Commands())
	}
	// Another session isn't held up.
	other, err := m.ensureLock(context.Background(), "other")
	if err != nil {
		t.Fatal(err)
	}
	other()
}
