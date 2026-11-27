package cli

import (
	"errors"
	"io"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/josegonzalez/safeclaw/internal/session"
)

func TestSandboxFlagsOptions(t *testing.T) {
	f := sandboxFlags{session: "box", volumes: []string{"/in:/in", "/tools:/tools"}, variant: "base", memory: "2g", pidsLimit: 64, cpus: "0.5", disk: "4g"}
	none := func(string) bool { return false }
	// Unset limits are left for the defaults, or a recreated sandbox's own.
	want := session.SandboxOptions{Name: "box", Volumes: []string{"/in:/in", "/tools:/tools"}, Variant: "base"}
	if got := f.options(none); !reflect.DeepEqual(got, want) {
		t.Errorf("options = %+v, want %+v", got, want)
	}
	all := func(string) bool { return true }
	want = session.SandboxOptions{Name: "box", Volumes: []string{"/in:/in", "/tools:/tools"}, Variant: "base", Memory: "2g", PidsLimit: 64, CPUs: "0.5", Disk: "4g", Recreate: true}
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
		t.Error("--volume recreates through Volumes, not Recreate")
	}
	f.remove = true
	if !f.options(none).Remove {
		t.Error("--rm should set Remove")
	}
}

func TestSandboxVolumeFlagRepeats(t *testing.T) {
	for _, cmd := range []*cobra.Command{newSandboxRunCommand(), newSandboxExecCommand()} {
		if err := cmd.ParseFlags([]string{"-v", "/a:/a", "--volume", "/b,c:/b"}); err != nil {
			t.Fatal(err)
		}
		// StringArray, not StringSlice, so a comma in a path is kept.
		if got, _ := cmd.Flags().GetStringArray("volume"); !slices.Equal(got, []string{"/a:/a", "/b,c:/b"}) {
			t.Errorf("%s: volumes = %q", cmd.Name(), got)
		}
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
	for flag, want := range map[string]string{"pids-limit": "256", "memory": "2g", "disk": "1g"} {
		if got := cmd.Flags().Lookup(flag).DefValue; got != want {
			t.Errorf("%s default = %q, want %q", flag, got, want)
		}
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
		{[]string{"--disk", "2g"}, []string{"box", "ls"}, "--disk can only be used with --ephemeral"},
		{[]string{"--ephemeral", "--disk", "2g"}, []string{"ls"}, ""},
		{[]string{"--variant", "base"}, []string{"box", "ls"}, "--variant can only be used with --ephemeral"},
		{[]string{"--ephemeral", "--variant", "base"}, []string{"ls"}, ""},
		{[]string{"-i", "-t"}, []string{"box", "ls"}, ""},
		{[]string{"--escape-controls", "-i"}, []string{"box", "ls"}, ""},
		{[]string{"--ephemeral", "--escape-controls"}, []string{"ls"}, ""},
		{[]string{"--escape-controls", "-t"}, []string{"box", "ls"}, "--escape-controls can't be used with -t"},
		{[]string{"--ephemeral", "--escape-controls", "-it"}, []string{"ls"}, "--escape-controls can't be used with -t"},
		{[]string{"--timeout", "30s", "-e", "A=1", "--env", "B"}, []string{"box", "ls"}, ""},
		{[]string{"--ephemeral", "--timeout", "1m", "-e", "A=1", "-v", "/a:/a", "-v", "/b:/b"}, []string{"ls"}, ""},
		{[]string{"--timeout", "0s"}, []string{"box", "ls"}, "invalid --timeout"},
		{[]string{"--ephemeral", "--timeout", "-1s"}, []string{"ls"}, "invalid --timeout"},
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

func TestSandboxCopyCommands(t *testing.T) {
	in := newSandboxCopyInCommand()
	if err := in.Args(in, []string{"box"}); err == nil {
		t.Error("cp-in without files should fail")
	}
	if err := in.Args(in, []string{"box", "a", "b"}); err != nil {
		t.Errorf("cp-in NAME FILE FILE: %v", err)
	}
	if got := in.Flags().Lookup("to").DefValue; got != session.DefaultCopyDest {
		t.Errorf("--to default = %q", got)
	}

	out := newSandboxCopyOutCommand()
	for _, args := range [][]string{{"box"}, {"box", "/sandbox/out"}, {"box", "a", "b", "c"}} {
		if err := out.Args(out, args); err == nil {
			t.Errorf("cp-out %v should fail", args)
		}
	}
	if err := out.Args(out, []string{"box", "/sandbox/out", "."}); err != nil {
		t.Errorf("cp-out NAME DIR DIR: %v", err)
	}
	if err := out.ParseFlags([]string{"--only", "*.txt", "--only", "a,b"}); err != nil {
		t.Fatal(err)
	}
	// --only is an array, so globs with commas are kept whole.
	if got, _ := out.Flags().GetStringArray("only"); !slices.Equal(got, []string{"*.txt", "a,b"}) {
		t.Errorf("--only = %v", got)
	}
	if got := out.Flags().Lookup("max-size").DefValue; got != session.DefaultCopyMaxSize {
		t.Errorf("--max-size default = %q", got)
	}
	if got := out.Flags().Lookup("max-files").DefValue; got != strconv.Itoa(session.DefaultCopyMaxFiles) {
		t.Errorf("--max-files default = %q", got)
	}

	out = newSandboxCopyOutCommand()
	out.SetArgs([]string{"box", "/sandbox/out", "."})
	out.SetOut(io.Discard)
	out.SetErr(io.Discard)
	if err := out.Execute(); err == nil || !strings.Contains(err.Error(), `"only" not set`) {
		t.Errorf("cp-out without --only: err = %v", err)
	}
	out = newSandboxCopyOutCommand()
	out.SetArgs([]string{"box", "/sandbox/out", ".", "--only", "*", "--max-size", "lots"})
	out.SetOut(io.Discard)
	out.SetErr(io.Discard)
	if err := out.Execute(); err == nil || !strings.Contains(err.Error(), "--max-size") {
		t.Errorf("bad --max-size: err = %v", err)
	}
}

func TestWritePaths(t *testing.T) {
	var buf strings.Builder
	paths := []string{"/sandbox/in/1-report.zip", "/sandbox/in/2-a\nb.txt", "/sandbox/in/3-\x1b[31mred", "/sandbox/in/4-\xff"}
	if err := writePaths(&buf, paths); err != nil {
		t.Fatal(err)
	}
	want := "/sandbox/in/1-report.zip\n" +
		`"/sandbox/in/2-a\nb.txt"` + "\n" +
		`"/sandbox/in/3-\x1b[31mred"` + "\n" +
		`"/sandbox/in/4-\xff"` + "\n"
	if got := buf.String(); got != want {
		t.Errorf("output = %q, want %q", got, want)
	}
}
