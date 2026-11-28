package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/session"
)

func TestSandboxRunInputFlagsRefused(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-s", "box", "--keep-inputs", "d"}, "--keep-inputs can only be used with --rm"},
		{[]string{"-s", "box", "--restore-from", "d"}, "--restore-from can only be used with --rm"},
		{[]string{"--rm", "--keep-inputs", ""}, "--keep-inputs can't be empty"},
		{[]string{"--rm", "--restore-from", ""}, "--restore-from can't be empty"},
		{[]string{"--rm", "--keep-inputs", "a", "--restore-from", "b"}, "can't be used together"},
	} {
		fakeContainers(t, map[string]string{}, nil)
		_, _, err := runStderr(append([]string{"sandbox", "run"}, tc.args...)...)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: err = %v, want %q", tc.args, err, tc.want)
		}
	}
}

func TestWriteReplay(t *testing.T) {
	var out bytes.Buffer
	writeReplay(&out, "job", nil)
	if out.Len() != 0 {
		t.Errorf("no opens printed %q", out.String())
	}
	writeReplay(&out, "job", [][]string{
		{"--hold=mail-archives", "--skip=1-a b.zip"},
		{},
		{"--release=it's.zip", `--unskip=1-\x1b.zip`},
	})
	want := "The record has 3 sandbox open run(s). To rebuild /sandbox/tree, run them again in order, adding --password-env where one needed a password:\n" +
		"  safeclaw sandbox open job --hold=mail-archives '--skip=1-a b.zip'\n" +
		"  safeclaw sandbox open job\n" +
		`  safeclaw sandbox open job '--release=it'\''s.zip' '--unskip=1-\x1b.zip'` + "\n"
	if out.String() != want {
		t.Errorf("replay =\n%s\nwant\n%s", out.String(), want)
	}
}

// keptContainer is a running sandbox's inspect JSON with a keep-inputs
// label for dir.
func keptContainer(name, dir string) string {
	label, _ := json.Marshal(dir)
	return `{"Id":"id","Name":"/` + name + `","State":{"Status":"running","Running":true},` +
		`"Config":{"Image":"safeclaw","User":"sandbox","Labels":{"safeclaw.type":"sandbox","safeclaw.keep-inputs":` + string(label) + `}},` +
		`"HostConfig":{"NetworkMode":"none","Memory":1048576,"AutoRemove":true}}`
}

func TestSandboxOpenRecordsRuns(t *testing.T) {
	w := newOpenWorld(t)
	dir := filepath.Join(t.TempDir(), "rec")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	record := filepath.Join(dir, session.InputsFile)
	if err := os.WriteFile(record, []byte(`{"schema":1,"verify":false,"files":[],"opens":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	w.containers["safeclaw-kept"] = keptContainer("safeclaw-kept", dir)
	opens := func() [][]string {
		t.Helper()
		var rec struct {
			Opens []struct {
				Args []string `json:"args"`
			} `json:"opens"`
		}
		data, err := os.ReadFile(record)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(data, &rec); err != nil {
			t.Fatal(err)
		}
		var out [][]string
		for _, o := range rec.Opens {
			out = append(out, o.Args)
		}
		return out
	}

	// A finished run is recorded, packed containers or not, without the
	// password or safeclaw-totext's flags.
	w.helper(t, "expand", packedOut, "0")
	w.helper(t, "totext", "tree\tok\t0\t0\tfolded\t-\n", "0")
	t.Setenv("TRIAGE_PASSWORD", "hunter2")
	_, _, err := runStderr("sandbox", "open", "kept", "--hold", "mail-archives", "--skip", "1-a.zip", "--password-env", "TRIAGE_PASSWORD", "--text", "--max-pages", "3")
	if exit, ok := err.(exitCodeError); !ok || exit.code != openLeftPacked {
		t.Fatalf("err = %v, want exit %d", err, openLeftPacked)
	}
	want := [][]string{{"--hold=mail-archives", "--skip=1-a.zip"}}
	if got := opens(); !reflect.DeepEqual(got, want) {
		t.Errorf("opens = %v, want %v", got, want)
	}
	if data, _ := os.ReadFile(record); bytes.Contains(data, []byte("hunter2")) {
		t.Error("the password was recorded")
	}

	// A plan and a failed run are not.
	_, _, _ = runStderr("sandbox", "open", "kept", "--hold", "mail-archives", "--plan")
	w.helper(t, "expand", "", "1")
	_, _, _ = runStderr("sandbox", "open", "kept", "--hold", "mail-archives", "--release", "1-a.eml.unpacked/1-b.zip")
	if got := opens(); !reflect.DeepEqual(got, want) {
		t.Errorf("after a plan and a failed run, opens = %v, want %v", got, want)
	}

	// A record that can't be written fails the run before safeclaw-totext.
	w.helper(t, "expand", openedOut, "0")
	if err := os.WriteFile(record, []byte(`{"schema":9}`), 0o600); err != nil {
		t.Fatal(err)
	}
	before := strings.Count(w.read("ran"), "totext")
	_, _, err = runStderr("sandbox", "open", "kept", "--text")
	if err == nil || !strings.Contains(err.Error(), "could not be recorded") {
		t.Errorf("err = %v", err)
	}
	if strings.Count(w.read("ran"), "totext") != before {
		t.Error("converted after the run could not be recorded")
	}
}
