package secrets

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
)

func TestStoreRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), ".secrets")
	s := Store{Dir: dir}

	if keys, err := s.Keys(); err != nil || len(keys) != 0 {
		t.Fatalf("Keys on missing dir = %v, %v", keys, err)
	}
	path, err := s.Set("GH_TOKEN", "abc\n")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Set("A_KEY", "x"); err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Errorf("file mode = %v, want 0600", info.Mode().Perm())
	}
	dinfo, _ := os.Stat(dir)
	if dinfo.Mode().Perm() != 0o700 {
		t.Errorf("dir mode = %v, want 0700", dinfo.Mode().Perm())
	}
	if v, _ := s.Get("GH_TOKEN"); v != "abc" {
		t.Errorf("Get = %q, want trailing newline trimmed", v)
	}
	keys, _ := s.Keys()
	if !reflect.DeepEqual(keys, []string{"A_KEY", "GH_TOKEN"}) {
		t.Errorf("Keys = %v", keys)
	}
	if !s.Has("A_KEY") || s.Has("NOPE") {
		t.Error("Has is wrong")
	}
	if err := s.Delete("A_KEY"); err != nil || s.Has("A_KEY") {
		t.Errorf("Delete: %v", err)
	}
	if err := s.Delete("../escape"); err == nil {
		t.Error("Delete should reject invalid names")
	}
}

func TestAllSkipsInvalidNames(t *testing.T) {
	dir := t.TempDir()
	_ = os.WriteFile(filepath.Join(dir, "GOOD"), []byte("1"), 0o600)
	_ = os.WriteFile(filepath.Join(dir, "bad-name"), []byte("2"), 0o600)
	_ = os.Mkdir(filepath.Join(dir, "SUBDIR"), 0o700)
	all, err := Store{Dir: dir}.All()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(all, []Secret{{Name: "GOOD", Value: "1"}}) {
		t.Errorf("All = %+v", all)
	}
}

func TestValidateName(t *testing.T) {
	for _, ok := range []string{"A", "_x", "OPENAI_API_KEY", "a1"} {
		if ValidateName(ok) != nil {
			t.Errorf("%q should be valid", ok)
		}
	}
	for _, bad := range []string{"", "1A", "A-B", "A B", "../x"} {
		if ValidateName(bad) == nil {
			t.Errorf("%q should be invalid", bad)
		}
	}
}

func TestRenderEnvIsShellSafe(t *testing.T) {
	values := []Secret{
		{Name: "PLAIN", Value: "abc"},
		{Name: "QUOTES", Value: `it's "quoted" $HOME`},
		{Name: "MULTI", Value: "line1\nline2"},
	}
	env := RenderEnv(values)
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	script := env + `printf '%s|%s|%s' "$PLAIN" "$QUOTES" "$MULTI"`
	out, err := exec.Command(sh, "-c", script).Output()
	if err != nil {
		t.Fatal(err)
	}
	if want := "abc|it's \"quoted\" $HOME|line1\nline2"; string(out) != want {
		t.Errorf("sourced values = %q, want %q", out, want)
	}
}
