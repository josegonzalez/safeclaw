package cli

import (
	"errors"
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/session"
)

func TestSandboxFlagsOptions(t *testing.T) {
	f := sandboxFlags{session: "box", volume: "/in:/in", variant: "base", memory: "2g", pidsLimit: 64, cpus: "0.5"}
	none := func(string) bool { return false }
	// Unset limits are left for the defaults, or a recreated sandbox's own.
	want := session.SandboxOptions{Name: "box", Volume: "/in:/in", Variant: "base"}
	if got := f.options(none); !reflect.DeepEqual(got, want) {
		t.Errorf("options = %+v, want %+v", got, want)
	}
	all := func(string) bool { return true }
	want = session.SandboxOptions{Name: "box", Volume: "/in:/in", Variant: "base", Memory: "2g", PidsLimit: 64, CPUs: "0.5", Recreate: true}
	if got := f.options(all); !reflect.DeepEqual(got, want) {
		t.Errorf("options = %+v, want %+v", got, want)
	}
	for _, flag := range limitFlags {
		got := f.options(func(name string) bool { return name == flag })
		if !got.Recreate {
			t.Errorf("setting --%s should recreate", flag)
		}
	}
	if f.options(func(name string) bool { return name == "volume" }).Recreate {
		t.Error("--volume recreates through Volume, not Recreate")
	}
	f.remove = true
	if !f.options(none).Remove {
		t.Error("--rm should set Remove")
	}
}

func TestSandboxRunFlags(t *testing.T) {
	cmd := newSandboxRunCommand()
	if err := cmd.ParseFlags([]string{"-s", "box", "--memory", "2g"}); err != nil {
		t.Fatal(err)
	}
	if !cmd.Flags().Changed("memory") || cmd.Flags().Changed("cpus") {
		t.Error("changed flags wrong")
	}
	if got := cmd.Flags().Lookup("pids-limit").DefValue; got != "256" {
		t.Errorf("pids-limit default = %q", got)
	}
	cmd = newSandboxRunCommand()
	cmd.SetArgs([]string{})
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	if err := cmd.Execute(); !errors.Is(err, session.ErrSandboxName) {
		t.Errorf("sandbox run without -s or --rm: err = %v, want ErrSandboxName", err)
	}
	cmd = newSandboxRunCommand()
	if err := cmd.ParseFlags([]string{"--rm"}); err != nil {
		t.Fatal(err)
	}
	if err := cmd.ValidateRequiredFlags(); err != nil {
		t.Errorf("--rm without -s: %v", err)
	}
	if rm, _ := cmd.Flags().GetBool("rm"); !rm {
		t.Error("--rm not parsed")
	}
}

func TestSandboxExecArgs(t *testing.T) {
	cases := []struct {
		flags []string
		args  []string
		err   string
	}{
		{nil, []string{"box", "ls"}, ""},
		{nil, []string{"box"}, "a sandbox name and command are required"},
		{[]string{"--ephemeral"}, []string{"ls"}, ""},
		{[]string{"--ephemeral", "-s", "job", "-v", "/in:/in", "--memory", "2g"}, []string{"ls", "/in"}, ""},
		{[]string{"--ephemeral"}, nil, "a command is required"},
		{[]string{"-s", "job"}, []string{"box", "ls"}, "--session can only be used with --ephemeral"},
		{[]string{"-v", "/in:/in"}, []string{"box", "ls"}, "--volume can only be used with --ephemeral"},
		{[]string{"--cpus", "2"}, []string{"box", "ls"}, "--cpus can only be used with --ephemeral"},
		{[]string{"--variant", "base"}, []string{"box", "ls"}, "--variant can only be used with --ephemeral"},
		{[]string{"--ephemeral", "--variant", "base"}, []string{"ls"}, ""},
		{[]string{"-i", "-t"}, []string{"box", "ls"}, ""},
	}
	for _, tc := range cases {
		cmd := newSandboxExecCommand()
		if err := cmd.ParseFlags(tc.flags); err != nil {
			t.Fatal(err)
		}
		err := cmd.Args(cmd, tc.args)
		switch {
		case tc.err == "" && err != nil:
			t.Errorf("%v %v: %v", tc.flags, tc.args, err)
		case tc.err != "" && (err == nil || !strings.Contains(err.Error(), tc.err)):
			t.Errorf("%v %v: err = %v, want %q", tc.flags, tc.args, err, tc.err)
		}
	}
}

func TestWriteSandboxes(t *testing.T) {
	list := []session.Session{
		{Name: "job", Status: "running", Volume: "-", Type: "sandbox", Variant: "sandbox", AutoRemove: true, Network: "none"},
		{Name: "box", Status: "exited", Volume: "/in:/in", Type: "sandbox", Network: "none"},
		{Name: "work", Status: "running", Volume: "-", Type: "session", Network: "online"},
		{Name: "triage", Status: "running", Volume: "-", Type: "session", Network: "offline", Holds: []session.Hold{{Owner: "job"}, {}}},
	}
	var b strings.Builder
	if err := writeSandboxes(&b, list); err != nil {
		t.Fatal(err)
	}
	want := "SANDBOX   VARIANT   STATUS    ONE-OFF   VOLUME\n" +
		"job       sandbox   running   yes       -\n" +
		"box       -         exited    -         /in:/in\n"
	if b.String() != want {
		t.Errorf("sandbox ls =\n%s\nwant\n%s", b.String(), want)
	}

	b.Reset()
	if err := writeSessions(&b, list); err != nil {
		t.Fatal(err)
	}
	want = "SESSION   TYPE                VARIANT   STATUS    NETWORK                  URL   VOLUME\n" +
		"job       sandbox (one-off)   sandbox   running   none                     -     -\n" +
		"box       sandbox             -         exited    none                     -     /in:/in\n" +
		"work      session             -         running   online                   -     -\n" +
		"triage    session             -         running   offline (job, unnamed)   -     -\n"
	if b.String() != want {
		t.Errorf("ls =\n%s\nwant\n%s", b.String(), want)
	}
}

func TestSandboxExecArgv(t *testing.T) {
	cases := []struct {
		i, t bool
		want []string
	}{
		{false, false, []string{"docker", "exec", "--user", "sandbox", "--workdir", "/sandbox", "safeclaw-box", "pdftotext", "-", "-"}},
		{true, false, []string{"docker", "exec", "-i", "--user", "sandbox", "--workdir", "/sandbox", "safeclaw-box", "pdftotext", "-", "-"}},
		{true, true, []string{"docker", "exec", "-i", "-t", "--user", "sandbox", "--workdir", "/sandbox", "safeclaw-box", "pdftotext", "-", "-"}},
	}
	for _, tc := range cases {
		if got := sandboxExecArgv("box", tc.i, tc.t, []string{"pdftotext", "-", "-"}); !slices.Equal(got, tc.want) {
			t.Errorf("argv = %v, want %v", got, tc.want)
		}
	}
}
