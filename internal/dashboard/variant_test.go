package dashboard

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/session"
	"github.com/josegonzalez/safeclaw/internal/variant"
)

func TestVariantPicker(t *testing.T) {
	set, err := variant.Parse([]byte("defaults:\n  session: docs\nvariants:\n  docs:\n    packages: [pandoc]\n"))
	if err != nil {
		t.Fatal(err)
	}
	h := newTestServer(t, &fakeSessions{variants: set})
	body := do(h, "GET", "/", nil, nil).Body.String()
	for _, want := range []string{
		`<select id="session-variant" name="variant">`,
		`<option value="">default (docs)</option>`,
		`<option value="base">base</option>`,
		`<option value="docs">docs</option>`,
		`<option value="sandbox">sandbox</option>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("page lacks %q", want)
		}
	}

	h = newTestServer(t, &fakeSessions{variantErr: errors.New("bad config")})
	body = do(h, "GET", "/", nil, nil).Body.String()
	if !strings.Contains(body, "could not load variants: bad config") || !strings.Contains(body, `<option value="">default</option>`) {
		t.Errorf("variant error not shown")
	}
}

func TestCreateWithVariant(t *testing.T) {
	f := &fakeSessions{}
	h := newTestServer(t, f)
	rec := do(h, "POST", "/sessions", url.Values{"name": {"docs"}, "variant": {" sandbox "}}, nil)
	if rec.Code != 204 {
		t.Fatalf("status %d: %s", rec.Code, rec.Body)
	}
	if len(f.ensured) != 1 || f.ensured[0].Variant != "sandbox" {
		t.Errorf("ensured = %+v", f.ensured)
	}

	f = &fakeSessions{ensureFn: func(o session.Options) (*session.Result, error) {
		return nil, errors.New("image 'safeclaw:sandbox' not found")
	}}
	h = newTestServer(t, f)
	rec = do(h, "POST", "/sessions", url.Values{"name": {"docs"}, "variant": {"sandbox"}}, nil)
	if rec.Code != 422 || !strings.Contains(rec.Body.String(), "safeclaw:sandbox") {
		t.Errorf("missing image: %d %s", rec.Code, rec.Body)
	}

	f = &fakeSessions{}
	h = newTestServer(t, f)
	rec = doJSON(h, "/api/create", `{"name":"x","variant":"sandbox"}`)
	if rec.Code != 200 || len(f.ensured) != 1 || f.ensured[0].Variant != "sandbox" {
		t.Errorf("api create: %d %+v", rec.Code, f.ensured)
	}
}

func TestVariantBadgeAndAPI(t *testing.T) {
	list := []session.Session{
		{Container: "safeclaw-docs", Name: "docs", Active: true, Port: 7681, URL: "http://localhost:7681", Volume: "-", Type: "session", Variant: "docs"},
		{Container: "safeclaw-plain", Name: "plain", Volume: "-", Type: "session"},
		{Container: "safeclaw-box", Name: "box", Volume: "-", Type: "sandbox", Variant: "sandbox"},
	}
	h := newTestServer(t, &fakeSessions{list: list})
	body := do(h, "GET", "/fragments/sessions", nil, nil).Body.String()
	for _, want := range []string{
		`hx-target="#session-info">docs</a> <span class="badge" title="runs the safeclaw:docs image variant">docs</span>`,
		`hx-target="#session-info">plain</a></td>`,
		`<span class="badge" title="runs the safeclaw:sandbox image variant">sandbox</span>`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("sessions fragment lacks %q\n%s", want, body)
		}
	}

	rec := do(h, "GET", "/api/sessions", nil, nil)
	var got []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got[0]["variant"] != "docs" || got[1]["variant"] != "" || got[2]["variant"] != "sandbox" {
		t.Errorf("api variants = %v, %v, %v", got[0]["variant"], got[1]["variant"], got[2]["variant"])
	}
}

func doJSON(h http.Handler, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", "http://localhost:7680"+path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
