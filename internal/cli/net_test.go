package cli

import (
	"testing"
)

func TestNetCommands(t *testing.T) {
	root := NewRootCommand()
	off, _, err := root.Find([]string{"net", "off"})
	if err != nil || off.Name() != "off" {
		t.Fatalf("net off: %v", err)
	}
	for _, f := range []string{"owner", "reason"} {
		if off.Flags().Lookup(f) == nil {
			t.Errorf("net off lacks --%s", f)
		}
	}
	on, _, err := root.Find([]string{"net", "on"})
	if err != nil || on.Name() != "on" {
		t.Fatalf("net on: %v", err)
	}
	for _, f := range []string{"owner", "force"} {
		if on.Flags().Lookup(f) == nil {
			t.Errorf("net on lacks --%s", f)
		}
	}
	if err := on.Args(on, nil); err == nil {
		t.Error("net on accepted no name")
	}
}
