package totext

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// Runner runs the document tools. Exec is the real one; tests use fakes.
type Runner interface {
	// Run runs tool, one of pdfinfo, pdftotext, pdftoppm, or tesseract,
	// with args, writing its stdout to stdout. Once ctx is done it must
	// stop the tool and everything it started, and return. A tool that
	// exits non-zero returns an *ExitError.
	Run(ctx context.Context, stdout io.Writer, tool string, args ...string) error
}

// ExitError is a tool that exited non-zero.
type ExitError struct {
	Tool string
	Code int
	// Stderr is the start of what the tool wrote to stderr.
	Stderr string
}

func (e *ExitError) Error() string {
	msg := oneLine(e.Stderr)
	if msg == "" {
		return fmt.Sprintf("%s exited with status %d", e.Tool, e.Code)
	}
	return fmt.Sprintf("%s exited with status %d: %s", e.Tool, e.Code, msg)
}

// toolPackages names the package each tool comes from, for the error when
// it is missing.
var toolPackages = map[string]string{
	"pdfinfo":   "poppler-utils",
	"pdftotext": "poppler-utils",
	"pdftoppm":  "poppler-utils",
	"tesseract": "tesseract-ocr",
}

// maxStderr is how much of a tool's stderr is kept.
const maxStderr = 4 << 10

// Exec runs the tools from PATH, each in a process group of its own with
// stdin from /dev/null, never through a shell. When the context is done
// the whole group is killed, so a tool that forked can't outlive its
// timeout. tesseract gets OMP_THREAD_LIMIT=1, so it doesn't start a thread
// per CPU.
type Exec struct {
	// WaitDelay is how long Run waits for a killed tool's output to close.
	// Defaults to 2 seconds.
	WaitDelay time.Duration
}

// Run runs tool.
func (x Exec) Run(ctx context.Context, stdout io.Writer, tool string, args ...string) error {
	path, err := exec.LookPath(tool)
	if err != nil {
		return fmt.Errorf("%s not found on PATH; it is in the sandbox image variant (the %s package)", tool, toolPackages[tool])
	}
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdout = stdout
	stderr := &capped{max: maxStderr}
	cmd.Stderr = stderr
	cmd.Env = os.Environ()
	if tool == "tesseract" {
		cmd.Env = append(cmd.Env, "OMP_THREAD_LIMIT=1")
	}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		// The group's id is the tool's pid, since Setpgid made it the
		// leader.
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = x.WaitDelay
	if cmd.WaitDelay <= 0 {
		cmd.WaitDelay = 2 * time.Second
	}
	err = cmd.Run()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return &ExitError{Tool: tool, Code: ee.ExitCode(), Stderr: stderr.String()}
	}
	return err
}

// capped keeps the first max bytes written to it and drops the rest.
type capped struct {
	max int
	b   strings.Builder
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.b.Len(); room > 0 {
		c.b.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

func (c *capped) String() string { return c.b.String() }

// oneLine joins the non-blank lines of s with "; ".
func oneLine(s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" {
			out = append(out, l)
		}
	}
	return strings.Join(out, "; ")
}
