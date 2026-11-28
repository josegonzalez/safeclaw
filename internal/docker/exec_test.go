package docker_test

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/josegonzalez/safeclaw/internal/docker"
	"github.com/josegonzalez/safeclaw/internal/docker/dockertest"
)

// fakeDocker stands in for `docker exec`: it drops "exec", its flags and
// the container name, and runs the command on the host with docker's
// stdin, which the command reads to EOF like a process in a container.
const fakeDocker = `#!/bin/sh
shift
while :; do case $1 in -i|-d) shift ;; --user|--workdir) shift 2 ;; *) break ;; esac; done
shift
exec "$@"
`

// holdingDocker is fakeDocker for a docker that never passes on the close
// of its stdin: the command gets docker's stdin through a fifo that a
// holder keeps open after copying it, as the hang in #167 looked from
// inside the container. It returns once the command exits, as docker does.
const holdingDocker = `#!/bin/sh
shift
while :; do case $1 in -i|-d) shift ;; --user|--workdir) shift 2 ;; *) break ;; esac; done
shift
fifo="$(mktemp -d)/stdin"
mkfifo "$fifo"
# A background job's stdin is /dev/null, and dash keeps it so even with
# <&0, so the holder gets docker's stdin through a saved descriptor.
exec 3<&0
sh -c 'cat; exec sleep 30' <&3 3<&- >"$fifo" 2>/dev/null &
exec 3<&-
holder=$!
"$@" <"$fifo"
s=$?
kill "$holder" 2>/dev/null
exit "$s"
`

func fakeClient(t *testing.T, script string) *docker.Client {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "docker")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return &docker.Client{R: docker.ExecRunner{Binary: bin, WaitDelay: 100 * time.Millisecond}}
}

func TestExecClosesStdin(t *testing.T) {
	c := fakeClient(t, fakeDocker)
	// cat only exits on EOF, so it returns only if Exec closes its stdin
	// once the input is written, whether the input is a reader that ends
	// or a pipe its writer closes.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := c.Exec(ctx, "safeclaw-a", docker.ExecOptions{Stdin: strings.NewReader("hi\n")}, "cat")
	if err != nil || string(out) != "hi\n" {
		t.Errorf("reader: %q, %v", out, err)
	}
	pr, pw := io.Pipe()
	go func() {
		_, _ = io.WriteString(pw, "piped\n")
		_ = pw.Close()
	}()
	out, err = c.Exec(ctx, "safeclaw-a", docker.ExecOptions{Stdin: pr}, "cat")
	if err != nil || string(out) != "piped\n" {
		t.Errorf("pipe: %q, %v", out, err)
	}
}

func TestExecInputEndsWithoutClose(t *testing.T) {
	c := fakeClient(t, holdingDocker)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Trailing newlines, quotes, and format verbs come through unchanged.
	in := "export A='x\\ny'\nexport B='%s'\n\n"
	start := time.Now()
	out, err := c.Exec(ctx, "safeclaw-a", docker.ExecOptions{Input: in, User: "root"}, "cat")
	if err != nil || string(out) != in {
		t.Errorf("Input: %q, %v, want %q", out, err, in)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("Input took %s, so cat waited for EOF", d)
	}
	// A command that doesn't read its input still succeeds, and its exit
	// status is the run's.
	if _, err := c.Exec(ctx, "safeclaw-a", docker.ExecOptions{Input: in}, "true"); err != nil {
		t.Errorf("unread Input: %v", err)
	}
	if _, err := c.Exec(ctx, "safeclaw-a", docker.ExecOptions{Input: in}, "sh", "-c", "cat >/dev/null; exit 3"); err == nil {
		t.Error("failed command succeeded")
	}

	// Streamed through Stdin, the same input never ends, so only the
	// context stops it.
	sctx, scancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer scancel()
	if _, err := c.Exec(sctx, "safeclaw-a", docker.ExecOptions{Stdin: strings.NewReader(in)}, "cat"); err == nil || !errors.Is(sctx.Err(), context.DeadlineExceeded) {
		t.Errorf("Stdin = %v, want it stopped by its context", err)
	}
}

func TestExecInputArgs(t *testing.T) {
	r := &dockertest.Runner{}
	c := r.Client()
	ctx := context.Background()
	if _, err := c.Exec(ctx, "safeclaw-a", docker.ExecOptions{Input: "abc", User: "root"}, "sh", "-c", "cat > f"); err != nil {
		t.Fatal(err)
	}
	call := r.Calls[0]
	if got := strings.Join(call.Raw[:7], " "); got != "exec -i --user root safeclaw-a /bin/sh -c" {
		t.Errorf("raw = %q", got)
	}
	if got := strings.Join(call.Raw[8:], " "); got != "3 sh -c cat > f" {
		t.Errorf("raw tail = %q", got)
	}
	if call.String() != "exec -i --user root safeclaw-a sh -c cat > f" || !call.Input || call.Stdin != "abc" {
		t.Errorf("call = %q, input %v, stdin %q", call.String(), call.Input, call.Stdin)
	}
	if args, ok := docker.UnwrapInput(call.Raw); !ok || strings.Join(args, " ") != call.String() {
		t.Errorf("UnwrapInput = %q, %v", args, ok)
	}

	// No input runs without -i, so the command's stdin is empty.
	if _, err := c.Exec(ctx, "safeclaw-a", docker.ExecOptions{Input: ""}, "cat"); err != nil {
		t.Fatal(err)
	}
	if call := r.Calls[1]; call.String() != "exec safeclaw-a cat" || call.Input {
		t.Errorf("empty input = %q, input %v", call.String(), call.Input)
	}

	for _, o := range []docker.ExecOptions{
		{Input: "x", Stdin: strings.NewReader("x")},
		{Input: "a\x00b"},
		{Input: "x", MaxOutput: 1},
	} {
		if _, err := c.Exec(ctx, "safeclaw-a", o, "cat"); err == nil {
			t.Errorf("%+v should be refused", o)
		}
	}
	if len(r.Calls) != 2 {
		t.Errorf("refused execs ran: %v", r.Commands())
	}
}
