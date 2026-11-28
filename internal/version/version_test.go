package version

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestParseRelease(t *testing.T) {
	for in, want := range map[string]Release{
		"0.3.0":    {0, 3, 0},
		"v0.3.0":   {0, 3, 0},
		"1.20.300": {1, 20, 300},
		"v10.0.1":  {10, 0, 1},
		"0.0.0":    {0, 0, 0},
	} {
		got, err := ParseRelease(in)
		if err != nil {
			t.Errorf("ParseRelease(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseRelease(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestParseReleaseRefuses(t *testing.T) {
	for _, in := range []string{
		"", "v", "dev", "0.3", "0.3.0.1", "1", "0.3.x", "0..3", ".0.3", "0.3.",
		"vv0.3.0", "V0.3.0", " 0.3.0", "0.3.0 ", "+1.0.0", "-1.0.0", "01.0.0", "0.03.0",
		"0.3.0-rc.1", "0.3.0+build", "v0.3.0-5-g8d41adf", "v0.3.0-dirty", "0.3.1-SNAPSHOT-8d41adf",
		"99999999999999999999.0.0",
	} {
		if r, err := ParseRelease(in); err == nil {
			t.Errorf("ParseRelease(%q) = %v, want an error", in, r)
		}
	}
}

func TestCompare(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"0.3.0", "0.3.0", 0},
		{"v0.3.0", "0.3.0", 0},
		{"0.2.9", "0.3.0", -1},
		{"0.3.0", "0.2.9", 1},
		{"0.3.1", "0.3.0", 1},
		{"0.10.0", "0.9.0", 1},
		{"1.0.0", "0.99.99", 1},
		{"0.3.0", "1.0.0", -1},
	} {
		a, err := ParseRelease(c.a)
		if err != nil {
			t.Fatal(err)
		}
		b, err := ParseRelease(c.b)
		if err != nil {
			t.Fatal(err)
		}
		if got := a.Compare(b); got != c.want {
			t.Errorf("%s.Compare(%s) = %d, want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestRequire(t *testing.T) {
	required := Release{0, 3, 0}
	for _, v := range []string{"0.3.0", "v0.3.0", "0.3.1", "v1.0.0", "0.10.0"} {
		if err := Require(v, required); err != nil {
			t.Errorf("Require(%q, 0.3.0): %v", v, err)
		}
	}
	err := Require("v0.2.9", required)
	if err == nil {
		t.Fatal("Require(v0.2.9, 0.3.0) passed")
	}
	if want := "safeclaw 0.2.9 is older than the required 0.3.0"; err.Error() != want {
		t.Errorf("error = %q, want %q", err, want)
	}
}

func TestRequireDevBuild(t *testing.T) {
	for _, v := range []string{"dev", "", "none", "v0.3.0-5-g8d41adf", "v0.3.0-dirty", "8d41adf", "0.4.0-SNAPSHOT-8d41adf", "1.0.0-rc.1"} {
		err := Require(v, Release{0, 0, 0})
		if err == nil {
			t.Errorf("Require(%q, 0.0.0) passed, want a development build error", v)
			continue
		}
		if !strings.Contains(err.Error(), "development build") || !strings.Contains(err.Error(), "required 0.0.0") {
			t.Errorf("Require(%q) error = %q", v, err)
		}
	}
}

func TestInfoJSON(t *testing.T) {
	old := [3]string{Version, Commit, Date}
	t.Cleanup(func() { Version, Commit, Date = old[0], old[1], old[2] })
	Version, Commit, Date = "0.3.0", "8d41adf", "2026-11-28T11:18:28Z"

	b, err := json.Marshal(Get())
	if err != nil {
		t.Fatal(err)
	}
	want := `{"schema":1,"version":"0.3.0","commit":"8d41adf","built":"2026-11-28T11:18:28Z"}`
	if string(b) != want {
		t.Errorf("JSON = %s, want %s", b, want)
	}
}
