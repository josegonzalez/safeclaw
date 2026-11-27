package cli

import "testing"

func TestRunNoMemoryFlag(t *testing.T) {
	cases := []struct {
		args []string
		want string // "" keeps the session's choice
	}{
		{nil, ""},
		{[]string{"--no-memory"}, "true"},
		{[]string{"--no-memory=true"}, "true"},
		{[]string{"--no-memory=false"}, "false"},
	}
	for _, tc := range cases {
		opts, err := parseRunFlags(t, tc.args...)
		if err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		got := ""
		if opts.NoMemory != nil {
			got = map[bool]string{true: "true", false: "false"}[*opts.NoMemory]
		}
		if got != tc.want {
			t.Errorf("%v: NoMemory = %q, want %q", tc.args, got, tc.want)
		}
	}
}
