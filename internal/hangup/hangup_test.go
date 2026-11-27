package hangup

import (
	"os"
	"slices"
	"syscall"
	"testing"
)

func TestFilter(t *testing.T) {
	sigs := []os.Signal{syscall.SIGINT, syscall.SIGHUP, syscall.SIGTERM}
	if got := filter(false, sigs); !slices.Equal(got, sigs) {
		t.Errorf("not ignored: %v, want %v", got, sigs)
	}
	want := []os.Signal{syscall.SIGINT, syscall.SIGTERM}
	if got := filter(true, sigs); !slices.Equal(got, want) {
		t.Errorf("ignored: %v, want %v", got, want)
	}
	if got := filter(true, []os.Signal{syscall.SIGHUP}); len(got) != 0 {
		t.Errorf("ignored, SIGHUP only: %v, want none", got)
	}
}

// The test binary isn't started under nohup, so SIGHUP is kept.
func TestSignalsKeepsSIGHUPWhenNotIgnored(t *testing.T) {
	if ignoredAtStart {
		t.Skip("SIGHUP was ignored when the tests started")
	}
	if got := Signals(syscall.SIGHUP); !slices.Equal(got, []os.Signal{syscall.SIGHUP}) {
		t.Errorf("Signals(SIGHUP) = %v", got)
	}
}
