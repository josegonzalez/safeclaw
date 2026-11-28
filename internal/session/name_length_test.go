package session

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/josegonzalez/safeclaw/internal/config"
)

// The longest name leaves the longest host file named after it exactly
// 255 bytes: a session's history directory moved aside.
func TestMaxName(t *testing.T) {
	if MaxName != 230 {
		t.Errorf("MaxName = %d, want 230", MaxName)
	}
	name := strings.Repeat("a", MaxName)
	archived := name + ".old-" + time.Now().UTC().Format(archiveTime)
	if len(archived) != 255 {
		t.Errorf("archived history name is %d bytes, want 255", len(archived))
	}
	if MaxNamePrefix != MaxName-len("-"+prefixTime)-len("-9") {
		t.Errorf("MaxNamePrefix = %d, not lined up with MaxName", MaxNamePrefix)
	}
}

func TestValidateNewName(t *testing.T) {
	longest := strings.Repeat("a", MaxName)
	if err := ValidateNewName(longest); err != nil {
		t.Errorf("a %d character name: %v", MaxName, err)
	}
	err := ValidateNewName(longest + "a")
	if !errors.Is(err, ErrNameTooLong) || !strings.Contains(err.Error(), "at most 230 characters") {
		t.Errorf("a %d character name: %v, want ErrNameTooLong naming the limit", MaxName+1, err)
	}
	// Existing containers are still named by ValidateName alone.
	if err := ValidateName(longest + "a"); err != nil {
		t.Errorf("ValidateName should accept a long existing name: %v", err)
	}
	// The other rules still come first.
	if err := ValidateNewName("Work"); !errors.Is(err, ErrLegacyName) {
		t.Errorf("ValidateNewName(Work) = %v, want ErrLegacyName", err)
	}
}

// Every host file safeclaw names after a session or sandbox can be made
// for a name of MaxName characters.
func TestMaxNameHostFiles(t *testing.T) {
	ctx := context.Background()
	m, _ := newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{}})
	m.ChoicesDir = filepath.Join(filepath.Dir(m.SessionsDir), "choices")
	name := strings.Repeat("a", MaxName)
	if _, err := m.historyDir(name); err != nil {
		t.Fatalf("history dir: %v", err)
	}
	if _, err := m.archiveHistory(name); err != nil {
		t.Errorf("archive history: %v", err)
	}
	if err := m.writeState(name, &netState{}); err != nil {
		t.Errorf("network state: %v", err)
	}
	if _, err := m.rotateCredential(name); err != nil {
		t.Errorf("ttyd credential: %v", err)
	}
	if err := writePrivate(m.choicesPath(name), "{}\n"); err != nil {
		t.Errorf("choices: %v", err)
	}
	release, err := m.ensureLock(ctx, name)
	if err != nil {
		t.Errorf("ensure lock: %v", err)
	} else {
		release()
	}
	unlock, err := lockFileCtx(ctx, m.copyDir(), config.ContainerName(name)+".lock")
	if err != nil {
		t.Errorf("cp-in lock: %v", err)
	} else {
		unlock()
	}
}

func TestEnsureNameLength(t *testing.T) {
	ctx := context.Background()
	longest := strings.Repeat("a", MaxName)
	t.Run("at the limit", func(t *testing.T) {
		m, r := newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{}})
		if _, err := m.Ensure(ctx, Options{Name: longest, NoOpen: true}); err != nil {
			t.Fatal(err)
		}
		if !hasCall(r, "run -d --name "+config.ContainerName(longest)+" ") {
			t.Errorf("not created: %v", r.Commands())
		}
	})
	t.Run("past the limit", func(t *testing.T) {
		m, r := newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{}})
		_, err := m.Ensure(ctx, Options{Name: longest + "a", NoOpen: true})
		if !errors.Is(err, ErrNameTooLong) {
			t.Fatalf("err = %v, want ErrNameTooLong", err)
		}
		if hasCall(r, "run ") {
			t.Errorf("created anyway: %v", r.Commands())
		}
		if _, err := os.Stat(filepath.Join(m.ttydDir(), ".ensure")); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("the session lock was taken: %v", err)
		}
	})
	// A session made with a longer name by an earlier version still starts,
	// but is never recreated under that name.
	existing := func() *world {
		return &world{image: "img", containers: map[string]*fakeContainer{
			config.ContainerName(longest + "a"): {Running: true, Port: 7690, Image: "img"},
		}}
	}
	t.Run("existing", func(t *testing.T) {
		m, r := newTestManager(t, existing())
		if _, err := m.Ensure(ctx, Options{Name: longest + "a", NoOpen: true}); err != nil {
			t.Fatal(err)
		}
		if hasCall(r, "run ") || hasCall(r, "rm ") {
			t.Errorf("should not create or remove: %v", r.Commands())
		}
	})
	t.Run("existing recreated", func(t *testing.T) {
		m, r := newTestManager(t, existing())
		_, err := m.Ensure(ctx, Options{Name: longest + "a", NoOpen: true, FreshHistory: true})
		if !errors.Is(err, ErrNameTooLong) {
			t.Fatalf("err = %v, want ErrNameTooLong", err)
		}
		if hasCall(r, "run ") || hasCall(r, "rm ") {
			t.Errorf("should not remove or create: %v", r.Commands())
		}
	})
	t.Run("existing removed", func(t *testing.T) {
		m, r := newTestManager(t, existing())
		if err := m.Stop(ctx, longest+"a"); err != nil {
			t.Errorf("stop: %v", err)
		}
		if err := m.DeleteWith(ctx, longest+"a", DeleteOptions{}); err != nil {
			t.Errorf("rm: %v", err)
		}
		if !hasCall(r, "rm ") {
			t.Errorf("not removed: %v", r.Commands())
		}
	})
}

func TestEnsureSandboxNameLength(t *testing.T) {
	ctx := context.Background()
	longest := strings.Repeat("a", MaxName)
	for _, remove := range []bool{false, true} {
		m, r := newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{}})
		if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: longest, Remove: remove}); err != nil {
			t.Errorf("remove=%v at the limit: %v", remove, err)
		}
		if !hasCall(r, "run ") {
			t.Errorf("remove=%v not created at the limit: %v", remove, r.Commands())
		}
		m, r = newTestManager(t, &world{image: "img", containers: map[string]*fakeContainer{}})
		_, err := m.EnsureSandbox(ctx, SandboxOptions{Name: longest + "a", Remove: remove})
		if !errors.Is(err, ErrNameTooLong) {
			t.Errorf("remove=%v past the limit: %v, want ErrNameTooLong", remove, err)
		}
		if hasCall(r, "run ") {
			t.Errorf("remove=%v created anyway: %v", remove, r.Commands())
		}
	}

	long := longest + "a"
	existing := func() *world {
		return &world{image: "img", containers: map[string]*fakeContainer{
			config.ContainerName(long): {Image: "img", Labels: sandboxLabels},
		}}
	}
	m, r := newTestManager(t, existing())
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: long}); err != nil {
		t.Errorf("existing: %v", err)
	}
	if !hasCall(r, "start "+config.ContainerName(long)) || hasCall(r, "rm ") {
		t.Errorf("existing not started as it is: %v", r.Commands())
	}
	m, r = newTestManager(t, existing())
	if _, err := m.EnsureSandbox(ctx, SandboxOptions{Name: long, Recreate: true}); !errors.Is(err, ErrNameTooLong) {
		t.Errorf("existing recreated: %v, want ErrNameTooLong", err)
	}
	if hasCall(r, "rm ") || hasCall(r, "run ") {
		t.Errorf("existing removed or replaced: %v", r.Commands())
	}
	m, r = newTestManager(t, existing())
	if _, err := m.DeleteSandbox(ctx, long, SandboxStopOptions{Force: true}); err != nil {
		t.Errorf("rm: %v", err)
	}
	if !hasCall(r, "rm ") {
		t.Errorf("not removed: %v", r.Commands())
	}
}

// The longest prefix makes a name of MaxName characters, the longest a
// one-off sandbox can be created with.
func TestNamePrefixAtMaxName(t *testing.T) {
	m, r, _ := newPrefixManager(t, &world{image: "img", containers: map[string]*fakeContainer{}})
	res, err := m.EnsureSandbox(context.Background(), SandboxOptions{Remove: true, NamePrefix: strings.Repeat("a", MaxNamePrefix)})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Name) != MaxName-len("-9") || !hasCall(r, "run ") {
		t.Errorf("name %q, %d characters: %v", res.Name, len(res.Name), r.Commands())
	}
}
