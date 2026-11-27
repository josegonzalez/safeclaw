// Package dashproof lets a client check that the listener on a port is the
// dashboard holding a token, without sending the token to it.
//
// The client sends a random nonce to Path, and the dashboard answers with
// HMAC-SHA256 of its port and the nonce, keyed by its token, in Header. A
// listener without the token can't compute the answer, and a dashboard on
// another port can't answer for this one, so a token file whose port was
// taken over by something else is never trusted.
package dashproof

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strconv"
)

const (
	// Path is the dashboard route that answers a nonce. It needs no login.
	Path = "/dashboard-proof"
	// NonceParam is the query parameter carrying the nonce.
	NonceParam = "nonce"
	// Header carries the proof in the response.
	Header = "Safeclaw-Proof"
	// label separates these MACs from any other use of the token.
	label = "safeclaw-dashboard-proof"
	// minNonce and maxNonce bound the length of a nonce the dashboard
	// answers.
	minNonce, maxNonce = 16, 128
)

// NewNonce returns a random nonce.
func NewNonce() string {
	return rand.Text()
}

// ValidNonce reports whether nonce is one the dashboard answers: 16 to 128
// letters, digits, `-` or `_`.
func ValidNonce(nonce string) bool {
	if len(nonce) < minNonce || len(nonce) > maxNonce {
		return false
	}
	for _, c := range []byte(nonce) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '_':
		default:
			return false
		}
	}
	return true
}

// Sign returns the proof that the dashboard on port holds token, for nonce.
func Sign(token string, port int, nonce string) string {
	mac := hmac.New(sha256.New, []byte(token))
	mac.Write([]byte(label + "\x00" + strconv.Itoa(port) + "\x00" + nonce))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// Verify reports, in constant time, whether proof is Sign(token, port,
// nonce).
func Verify(token string, port int, nonce, proof string) bool {
	return token != "" && hmac.Equal([]byte(proof), []byte(Sign(token, port, nonce)))
}
