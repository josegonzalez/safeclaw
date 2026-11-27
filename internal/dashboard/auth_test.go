package dashboard

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/josegonzalez/safeclaw/internal/session"
)

func TestAuthBanner(t *testing.T) {
	exp := time.Date(2026, 12, 10, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name  string
		f     *fakeSessions
		wants []string
	}{
		{"missing", &fakeSessions{token: session.TokenStatus{State: session.TokenMissing}}, []string{"No Claude Code token", "<code>safeclaw auth login</code>", "<code>safeclaw auth set</code>"}},
		{"expiring", &fakeSessions{token: session.TokenStatus{State: session.TokenExpiring, ExpiresAt: exp, DaysLeft: 13}}, []string{"expires on 2026-12-10 (in 13 days)", "<code>safeclaw auth login</code>"}},
		{"expired", &fakeSessions{token: session.TokenStatus{State: session.TokenExpired, ExpiresAt: exp, DaysLeft: -2}}, []string{"expired on 2026-12-10", "<code>safeclaw auth login</code>"}},
		{"error", &fakeSessions{tokenErr: errors.New("keychain locked")}, []string{"could not read the Claude Code token: keychain locked"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestServer(t, tc.f)
			page := do(h, "GET", "/", nil, nil).Body.String()
			frag := do(h, "GET", "/fragments/auth", nil, nil).Body.String()
			for _, want := range tc.wants {
				if !strings.Contains(page, want) {
					t.Errorf("page lacks %q", want)
				}
				if !strings.Contains(frag, want) {
					t.Errorf("fragment lacks %q", want)
				}
			}
			if !strings.Contains(page, `<div id="auth-banner" hx-get="/fragments/auth" hx-trigger="sessions from:body"`) {
				t.Error("banner does not refresh on the sessions trigger")
			}
		})
	}

	h := newTestServer(t, &fakeSessions{})
	if frag := do(h, "GET", "/fragments/auth", nil, nil).Body.String(); strings.Contains(frag, "auth-banner") {
		t.Errorf("valid token shows a banner: %q", frag)
	}
}
