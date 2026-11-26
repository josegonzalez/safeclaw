package cli

import (
	"slices"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/session"
)

func TestSandboxFlagsOptions(t *testing.T) {
	f := sandboxFlags{session: "box", volume: "/in:/in", memory: "1g", pidsLimit: 256, cpus: "1"}
	none := func(string) bool { return false }
	want := session.SandboxOptions{Name: "box", Volume: "/in:/in", Memory: "1g", PidsLimit: 256, CPUs: "1"}
	if got := f.options(none); got != want {
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
	if err := cmd.Execute(); err == nil {
		t.Error("sandbox run without -s should fail")
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
