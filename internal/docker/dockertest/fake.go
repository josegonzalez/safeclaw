// Package dockertest provides a fake docker Runner for tests.
package dockertest

import (
	"bytes"
	"context"
	"io"
	"strings"
	"sync"

	"github.com/josegonzalez/safeclaw/internal/docker"
)

// Call is one recorded docker invocation.
type Call struct {
	Args  []string
	Stdin string
}

// String joins the args with spaces.
func (c Call) String() string { return strings.Join(c.Args, " ") }

// Handler returns canned output for a call.
type Handler func(args []string, stdin string) ([]byte, error)

// Runner records calls and answers them with Handler.
type Runner struct {
	mu      sync.Mutex
	Calls   []Call
	Handler Handler
	// Events is returned by Stream when Handler gives no output.
	Events string
	// StreamHandler, when set, answers Stream calls in place of Handler
	// and Events, for streams that block or fail partway.
	StreamHandler func(ctx context.Context, args []string) (io.ReadCloser, func() error, error)
}

// Output implements docker.Runner.
func (r *Runner) Output(_ context.Context, stdin io.Reader, args ...string) ([]byte, error) {
	in := ""
	if stdin != nil {
		b, _ := io.ReadAll(stdin)
		in = string(b)
	}
	r.mu.Lock()
	r.Calls = append(r.Calls, Call{Args: append([]string(nil), args...), Stdin: in})
	h := r.Handler
	r.mu.Unlock()
	if h == nil {
		return nil, nil
	}
	return h(args, in)
}

// Passthrough implements docker.Runner.
func (r *Runner) Passthrough(ctx context.Context, args ...string) error {
	_, err := r.Output(ctx, nil, args...)
	return err
}

// Stream implements docker.Runner. It returns StreamHandler's answer when
// it is set. Otherwise it returns Handler's output, or Events when there is
// none, and the wait function returns Handler's error.
func (r *Runner) Stream(ctx context.Context, args ...string) (io.ReadCloser, func() error, error) {
	r.mu.Lock()
	sh := r.StreamHandler
	if sh != nil {
		r.Calls = append(r.Calls, Call{Args: append([]string(nil), args...)})
	}
	r.mu.Unlock()
	if sh != nil {
		return sh(ctx, args)
	}
	out, err := r.Output(ctx, nil, args...)
	if out == nil {
		out = []byte(r.Events)
	}
	return io.NopCloser(bytes.NewReader(out)), func() error { return err }, nil
}

// Commands returns each recorded call as a space-joined string.
func (r *Runner) Commands() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.Calls))
	for i, c := range r.Calls {
		out[i] = c.String()
	}
	return out
}

// Find returns the first call whose space-joined args start with prefix.
func (r *Runner) Find(prefix string) (Call, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, c := range r.Calls {
		if strings.HasPrefix(c.String(), prefix) {
			return c, true
		}
	}
	return Call{}, false
}

// NotFound returns the error docker gives for a missing object.
func NotFound(args []string) error {
	return &docker.Error{Args: args, Stderr: "Error: No such object", Err: io.EOF}
}

// Client returns a docker.Client backed by r.
func (r *Runner) Client() *docker.Client {
	return &docker.Client{R: r}
}
