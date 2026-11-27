package config

import "testing"

// Every session name maps to one container, and SessionName undoes
// ContainerName.
func TestContainerName(t *testing.T) {
	for in, want := range map[string]string{
		"work":          "safeclaw-work",
		"safeclaw-work": "safeclaw-safeclaw-work",
	} {
		if got := ContainerName(in); got != want {
			t.Errorf("ContainerName(%q) = %q, want %q", in, got, want)
		}
		if got := SessionName(ContainerName(in)); got != in {
			t.Errorf("SessionName(ContainerName(%q)) = %q", in, got)
		}
	}
	for in, want := range map[string]string{"safeclaw-work": "work", "work": "work", "safeclaw-safeclaw-work": "safeclaw-work"} {
		if got := SessionName(in); got != want {
			t.Errorf("SessionName(%q) = %q, want %q", in, got, want)
		}
	}
}
