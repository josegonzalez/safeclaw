// Package dockertest provides a fake docker Runner for tests.
package dockertest

import (
	"bytes"
	"context"
	"io"
	"slices"
	"strings"
	"sync"

	"github.com/josegonzalez/safeclaw/internal/docker"
)

// Call is one recorded docker invocation.
type Call struct {
	// Args leave out the wrapper docker.ExecOptions.Input adds to bound
	// the command's stdin, so they name the command itself. Raw has them
	// as given.
	Args  []string
	Raw   []string
	Stdin string
	// Input is set for an exec given docker.ExecOptions.Input.
	Input bool
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
	// ExecHandler, when set, answers Output calls in place of Handler with
	// the call's context and its stdin unread, for commands that read
	// their stdin as a process would or outlive their context.
	ExecHandler func(ctx context.Context, args []string, stdin io.Reader) ([]byte, error)
}

// Output implements docker.Runner. Handler gets the args without the
// wrapper docker.ExecOptions.Input adds, like Call.Args. When ExecHandler
// is set, it answers instead, with the call's context and stdin.
func (r *Runner) Output(ctx context.Context, stdin io.Reader, args ...string) ([]byte, error) {
	cmd, input := docker.UnwrapInput(args)
	call := Call{Args: slices.Clone(cmd), Raw: slices.Clone(args), Input: input}
	r.mu.Lock()
	eh := r.ExecHandler
	r.mu.Unlock()
	if eh != nil {
		r.record(call)
		return eh(ctx, cmd, stdin)
	}
	if stdin != nil {
		b, _ := io.ReadAll(stdin)
		call.Stdin = string(b)
	}
	r.record(call)
	r.mu.Lock()
	h := r.Handler
	r.mu.Unlock()
	if h == nil {
		return nil, nil
	}
	return h(cmd, call.Stdin)
}

func (r *Runner) record(c Call) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Calls = append(r.Calls, c)
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
