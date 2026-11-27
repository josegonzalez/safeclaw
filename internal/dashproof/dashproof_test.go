package dashproof

import (
	"strings"
	"testing"
)

func TestSignVerify(t *testing.T) {
	nonce := NewNonce()
	if !ValidNonce(nonce) {
		t.Fatalf("NewNonce gave an invalid nonce %q", nonce)
	}
	proof := Sign("token", 7680, nonce)
	if !Verify("token", 7680, nonce, proof) {
		t.Error("a correct proof was refused")
	}
	for name, ok := range map[string]bool{
		"other token": Verify("other", 7680, nonce, proof),
		"other port":  Verify("token", 7681, nonce, proof),
		"other nonce": Verify("token", 7680, NewNonce(), proof),
		"empty proof": Verify("token", 7680, nonce, ""),
		"empty token": Verify("", 7680, nonce, Sign("", 7680, nonce)),
	} {
		if ok {
			t.Errorf("%s: proof accepted", name)
		}
	}
}

func TestValidNonce(t *testing.T) {
	for nonce, want := range map[string]bool{
		"":                       false,
		"short":                  false,
		"abcdefghijklmnop":       true,
		"ABC-def_0123456789":     true,
		"abcdefghijklmnop!":      false,
		"abcdefgh ijklmnop":      false,
		strings.Repeat("a", 128): true,
		strings.Repeat("a", 129): false,
	} {
		if got := ValidNonce(nonce); got != want {
			t.Errorf("ValidNonce(%q) = %v, want %v", nonce, got, want)
		}
	}
}
