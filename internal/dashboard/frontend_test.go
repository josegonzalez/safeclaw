package dashboard

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"regexp"
	"slices"
	"strings"
	"testing"
)

// vendorRow matches a file's row in VENDOR.md: its path in backticks,
// package, version, source URL, and SHA-256 in backticks.
var vendorRow = regexp.MustCompile("^\\| `(static/[^`]+)` \\| `([^`]+)` \\| ([^ |]+) \\| (https://[^ |]+) \\| `([0-9a-f]{64})` \\|$")

// TestVendoredFiles checks every vendored file embedded in the binary is
// listed in VENDOR.md, with its source, and still has the SHA-256 recorded
// there, so a vendored file can't change, or a new one appear, without
// the manifest saying where it came from.
func TestVendoredFiles(t *testing.T) {
	manifest, err := os.ReadFile("VENDOR.md")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{}
	for line := range strings.SplitSeq(string(manifest), "\n") {
		if !strings.HasPrefix(line, "| `static/") {
			continue
		}
		m := vendorRow.FindStringSubmatch(line)
		if m == nil {
			t.Errorf("VENDOR.md: malformed row %q", line)
			continue
		}
		path, pkg, version, source, sum := m[1], m[2], m[3], m[4], m[5]
		if !strings.Contains(source, pkg+"@"+version+"/") {
			t.Errorf("VENDOR.md: %s source %s is not %s@%s", path, source, pkg, version)
		}
		if _, dup := want[path]; dup {
			t.Errorf("VENDOR.md: %s listed twice", path)
		}
		want[path] = sum
	}
	if len(want) == 0 {
		t.Fatal("VENDOR.md lists no files")
	}

	// Only these static files are the dashboard's own.
	own := []string{"static/app.js", "static/style.css"}
	seen := map[string]bool{}
	err = fs.WalkDir(assets, "static", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || slices.Contains(own, path) {
			return err
		}
		seen[path] = true
		sum, ok := want[path]
		if !ok {
			t.Errorf("%s is embedded but not listed in VENDOR.md", path)
			return nil
		}
		b, err := fs.ReadFile(assets, path)
		if err != nil {
			return err
		}
		if got := sha256.Sum256(b); hex.EncodeToString(got[:]) != sum {
			t.Errorf("%s SHA-256 = %x, VENDOR.md says %s", path, got, sum)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for path := range want {
		if !seen[path] {
			t.Errorf("VENDOR.md lists %s, which isn't embedded", path)
		}
	}
}

// cspDirectives splits a policy into its directives' sources.
func cspDirectives(t *testing.T, policy string) map[string][]string {
	t.Helper()
	d := map[string][]string{}
	for part := range strings.SplitSeq(policy, ";") {
		f := strings.Fields(part)
		if len(f) == 0 {
			continue
		}
		if _, dup := d[f[0]]; dup {
			t.Errorf("policy %q repeats %s", policy, f[0])
		}
		d[f[0]] = f[1:]
	}
	return d
}

// TestPagePolicyIsStrict checks the policy every page but the terminal
// gets allows only the dashboard's own scripts and styles, with no inline
// script or eval, and no framing.
func TestPagePolicyIsStrict(t *testing.T) {
	h := newAuthServer(t, &fakeSessions{list: sampleSessions()})
	rec := send(h, "GET", "http://127.0.0.1:7680/", "", map[string]string{"Authorization": "Bearer " + testToken})
	if rec.Code != 200 {
		t.Fatalf("GET / = %d", rec.Code)
	}
	policy := rec.Header().Get("Content-Security-Policy")
	d := cspDirectives(t, policy)
	for name, want := range map[string][]string{
		"default-src":     {"'self'"},
		"script-src":      {"'self'"},
		"style-src":       {"'self'"},
		"object-src":      {"'none'"},
		"base-uri":        {"'none'"},
		"frame-ancestors": {"'none'"},
	} {
		if !slices.Equal(d[name], want) {
			t.Errorf("%s = %q, want %q (policy %q)", name, d[name], want, policy)
		}
	}
	for _, bad := range []string{"'unsafe-inline'", "'unsafe-eval'", "'unsafe-hashes'", "*", "data:"} {
		for _, name := range []string{"default-src", "script-src", "style-src"} {
			if slices.Contains(d[name], bad) {
				t.Errorf("%s allows %s", name, bad)
			}
		}
	}
}

var (
	// scriptElement matches a script element, its attributes and content.
	scriptElement = regexp.MustCompile(`<script\b([^>]*)>([^<]*)</script>`)
	// inlineAttr matches an event handler or style attribute, htmx's
	// hx-on, which htmx runs with Function, and a javascript: URL.
	inlineAttr = regexp.MustCompile(`\s(on[a-z]+|style)\s*=|hx-on|javascript:`)
)

// inlineCode returns the first piece of markup in b that the page policy
// would refuse to run or apply, or "".
func inlineCode(b string) string {
	for _, m := range scriptElement.FindAllStringSubmatch(b, -1) {
		if !strings.Contains(m[1], " src=") || strings.TrimSpace(m[2]) != "" {
			return m[0]
		}
	}
	return inlineAttr.FindString(b)
}

// TestTemplatesHaveNoInlineCode checks no template has inline script or
// style, which the page and terminal policies would refuse.
func TestTemplatesHaveNoInlineCode(t *testing.T) {
	files, err := fs.Glob(assets, "templates/*.html")
	if err != nil || len(files) == 0 {
		t.Fatalf("templates: %v %v", files, err)
	}
	for _, f := range files {
		b, err := fs.ReadFile(assets, f)
		if err != nil {
			t.Fatal(err)
		}
		if m := inlineCode(string(b)); m != "" {
			t.Errorf("%s has inline code the policy refuses: %q", f, m)
		}
	}
}

func TestInlineCode(t *testing.T) {
	for _, s := range []string{
		`<script>alert(1)</script>`,
		`<script type="module">x()</script>`,
		`<script src="/static/app.js">x()</script>`,
		`<div onclick="x()">`,
		`<p style="color:red">`,
		`<button hx-on:click="x()">`,
		`<a href="javascript:x()">`,
	} {
		if inlineCode(s) == "" {
			t.Errorf("inlineCode misses %q", s)
		}
	}
	for _, s := range []string{
		`<script src="/static/app.js" defer></script>`,
		`<script src="/static/htmx.min.js"></script>`,
		`<div data-open-dialog="x">`,
		`<link rel="stylesheet" href="/static/style.css">`,
	} {
		if m := inlineCode(s); m != "" {
			t.Errorf("inlineCode flags %q in %q", m, s)
		}
	}
}
