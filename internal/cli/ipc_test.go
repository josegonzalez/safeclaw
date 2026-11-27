package cli

import "testing"

func TestRunHostIPCFlag(t *testing.T) {
	cases := []struct {
		args []string
		want string // "" keeps the session's choice
	}{
		{nil, ""},
		{[]string{"--host-ipc"}, "true"},
		{[]string{"--host-ipc=true"}, "true"},
		{[]string{"--host-ipc=false"}, "false"},
	}
	for _, tc := range cases {
		opts, err := parseRunFlags(t, tc.args...)
		if err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		got := ""
		if opts.HostIPC != nil {
			got = map[bool]string{true: "true", false: "false"}[*opts.HostIPC]
		}
		if got != tc.want {
			t.Errorf("%v: HostIPC = %q, want %q", tc.args, got, tc.want)
		}
	}
}
