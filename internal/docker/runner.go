// Package docker wraps the docker CLI. Every command is run with an argument
// slice, never through a shell.
package docker

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
)

// Runner runs docker CLI commands.
type Runner interface {
	// Output runs docker with args, feeding stdin if non-nil, and returns stdout.
	// A non-zero exit returns an *Error carrying stderr.
	Output(ctx context.Context, stdin io.Reader, args ...string) ([]byte, error)
	// Passthrough runs docker with args attached to the current stdio.
	Passthrough(ctx context.Context, args ...string) error
	// Stream starts docker with args and returns its stdout. Calling the
	// returned function waits for the process to exit, returning an *Error
	// carrying stderr on a non-zero exit.
	Stream(ctx context.Context, args ...string) (io.ReadCloser, func() error, error)
}

// Error is returned when a docker command exits non-zero.
type Error struct {
	Args   []string
	Stderr string
	Err    error
}

func (e *Error) Error() string {
	msg := strings.TrimSpace(e.Stderr)
	if msg == "" {
		msg = e.Err.Error()
	}
	return fmt.Sprintf("docker %s: %s", firstArg(e.Args), msg)
}

func (e *Error) Unwrap() error { return e.Err }

func firstArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}

// ExecRunner runs the real docker binary.
type ExecRunner struct {
	// Binary is the docker executable. Defaults to "docker".
	Binary string
}

func (r ExecRunner) bin() string {
	if r.Binary != "" {
		return r.Binary
	}
	return "docker"
}

// Output implements Runner.
func (r ExecRunner) Output(ctx context.Context, stdin io.Reader, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, r.bin(), args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if stdin != nil {
		cmd.Stdin = stdin
	}
	if err := cmd.Run(); err != nil {
		return stdout.Bytes(), &Error{Args: args, Stderr: stderr.String(), Err: err}
	}
	return stdout.Bytes(), nil
}

// Passthrough implements Runner.
func (r ExecRunner) Passthrough(ctx context.Context, args ...string) error {
	cmd := exec.CommandContext(ctx, r.bin(), args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return &Error{Args: args, Err: err}
	}
	return nil
}

// Stream implements Runner.
func (r ExecRunner) Stream(ctx context.Context, args ...string) (io.ReadCloser, func() error, error) {
	cmd := exec.CommandContext(ctx, r.bin(), args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, nil, err
	}
	wait := func() error {
		if err := cmd.Wait(); err != nil {
			return &Error{Args: args, Stderr: stderr.String(), Err: err}
		}
		return nil
	}
	return out, wait, nil
}

// IsNotFound reports whether err came from docker failing to find an object.
func IsNotFound(err error) bool {
	var de *Error
	if !errors.As(err, &de) {
		return false
	}
	s := strings.ToLower(de.Stderr)
	return strings.Contains(s, "no such") || strings.Contains(s, "not found")
}
