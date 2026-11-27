package dashboard

import (
	"encoding/json"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/session"
)

func onlySecrets(t *testing.T, names ...string) session.SecretSet {
	t.Helper()
	s, err := session.OnlySecrets(names...)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSecretsPicker(t *testing.T) {
	h := newTestServer(t, &fakeSessions{secretNames: []string{"CLAUDE_CODE_OAUTH_TOKEN", "GH_TOKEN"}})
	body := fullPage(h)
	for _, want := range []string{
		`<select id="session-secrets" name="secrets">`,
		`<option value="all">all secrets</option>`,
		`<option value="none">no secrets</option>`,
		`<option value="only">only checked</option>`,
		`<input type="checkbox" id="session-secret-0" name="secret" value="CLAUDE_CODE_OAUTH_TOKEN">`,
		`<label for="session-secret-1">GH_TOKEN</label>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}

	// Without stored secrets there is nothing to check.
	h = newTestServer(t, &fakeSessions{secretErr: errors.New("permission denied")})
	body = fullPage(h)
	if strings.Contains(body, `value="only"`) || strings.Contains(body, `class="secret-list"`) || !strings.Contains(body, "could not read secrets: permission denied") {
		t.Errorf("picker without secrets is wrong")
	}
}

func TestCreateWithSecrets(t *testing.T) {
	cases := []struct {
		form url.Values
		want string
	}{
		{url.Values{}, "all"},
		{url.Values{"secrets": {"all"}, "secret": {"GH_TOKEN"}}, "all"},
		{url.Values{"secrets": {"none"}}, "none"},
		{url.Values{"secrets": {"only"}, "secret": {"GH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"}}, "CLAUDE_CODE_OAUTH_TOKEN,GH_TOKEN"},
	}
	for _, tc := range cases {
		f := &fakeSessions{}
		h := newTestServer(t, f)
		tc.form.Set("name", "s")
		rec := do(h, "POST", "/sessions", tc.form, nil)
		if rec.Code != 204 || len(f.ensured) != 1 || f.ensured[0].Secrets == nil || f.ensured[0].Secrets.String() != tc.want {
			t.Errorf("%v: %d %+v", tc.form, rec.Code, f.ensured)
		}
	}

	for _, tc := range []struct {
		form url.Values
		want string
	}{
		{url.Values{"secrets": {"only"}}, "check at least one secret"},
		{url.Values{"secrets": {"only"}, "secret": {"bad-name"}}, "invalid secret name"},
		{url.Values{"secrets": {"some"}}, "unknown secrets choice"},
	} {
		f := &fakeSessions{}
		h := newTestServer(t, f)
		tc.form.Set("name", "s")
		rec := do(h, "POST", "/sessions", tc.form, nil)
		if rec.Code != 422 || !strings.Contains(rec.Body.String(), tc.want) || len(f.ensured) != 0 {
			t.Errorf("%v: %d %s", tc.form, rec.Code, rec.Body)
		}
	}
}

func TestSecretsBadgeAndAPI(t *testing.T) {
	list := []session.Session{
		{Container: "safeclaw-all", Name: "all", Volume: "-", Type: "session"},
		{Container: "safeclaw-none", Name: "none", Volume: "-", Type: "session", Secrets: session.NoSecrets()},
		{Container: "safeclaw-one", Name: "one", Volume: "-", Type: "session", Secrets: onlySecrets(t, "GH_TOKEN")},
		{Container: "safeclaw-two", Name: "two", Volume: "-", Type: "session", Secrets: onlySecrets(t, "A", "B")},
		{Container: "safeclaw-box", Name: "box", Volume: "-", Type: "sandbox", Secrets: session.NoSecrets()},
	}
	h := newTestServer(t, &fakeSessions{list: list})
	body := do(h, "GET", "/fragments/sessions", nil, nil).Body.String()
	for _, want := range []string{
		`hx-target="#session-info">all</a></td>`,
		`hx-target="#session-info">none</a> <span class="badge" title="receives no secrets">no secrets</span></td>`,
		`hx-target="#session-info">one</a> <span class="badge" title="receives only GH_TOKEN">1 secret</span></td>`,
		`hx-target="#session-info">two</a> <span class="badge" title="receives only A, B">2 secrets</span></td>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("sessions fragment lacks %q\n%s", want, body)
		}
	}
	if strings.Count(body, ">no secrets</span>") != 1 {
		t.Errorf("sandbox shows a secrets badge:\n%s", body)
	}

	var got []struct {
		Secrets *[]string `json:"secrets"`
	}
	raw := do(h, "GET", "/api/sessions", nil, nil).Body.Bytes()
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatal(err)
	}
	if got[0].Secrets != nil || got[1].Secrets == nil || len(*got[1].Secrets) != 0 ||
		strings.Join(*got[3].Secrets, ",") != "A,B" || got[4].Secrets == nil || len(*got[4].Secrets) != 0 {
		t.Errorf("api secrets = %s", raw)
	}
	if !strings.Contains(string(raw), `"secrets":null`) || !strings.Contains(string(raw), `"secrets":[]`) {
		t.Errorf("api encoding = %s", raw)
	}
}

func TestAPICreateSecrets(t *testing.T) {
	cases := []struct {
		body string
		want string // "" for no set
	}{
		{`{"name":"x"}`, ""},
		{`{"name":"x","secrets":null}`, ""},
		{`{"name":"x","secrets":"all"}`, "all"},
		{`{"name":"x","secrets":"none"}`, "none"},
		{`{"name":"x","secrets":[]}`, "none"},
		{`{"name":"x","secrets":["GH_TOKEN","A"]}`, "A,GH_TOKEN"},
	}
	for _, tc := range cases {
		f := &fakeSessions{}
		h := newTestServer(t, f)
		rec := doJSON(h, "/api/create", tc.body)
		if rec.Code != 200 || len(f.ensured) != 1 {
			t.Fatalf("%s: %d %s", tc.body, rec.Code, rec.Body)
		}
		got := ""
		if s := f.ensured[0].Secrets; s != nil {
			got = s.String()
		}
		if got != tc.want {
			t.Errorf("%s: secrets = %q, want %q", tc.body, got, tc.want)
		}
	}

	for _, body := range []string{`{"name":"x","secrets":"some"}`, `{"name":"x","secrets":3}`, `{"name":"x","secrets":["bad-name"]}`} {
		f := &fakeSessions{}
		h := newTestServer(t, f)
		rec := doJSON(h, "/api/create", body)
		if !strings.Contains(rec.Body.String(), `"success":false`) || len(f.ensured) != 0 {
			t.Errorf("%s: %d %s", body, rec.Code, rec.Body)
		}
	}
}
