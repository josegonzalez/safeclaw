package safeclaw

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/josegonzalez/safeclaw/internal/config"
)

func TestBuildContextHasEverythingTheDockerfileNeeds(t *testing.T) {
	for _, path := range []string{
		"Dockerfile",
		".dockerignore",
		"go.mod",
		"go.sum",
		"setup/.bashrc",
		"setup/CLAUDE.md",
		"setup/settings.json",
		"setup/managed-mcp.json",
		"setup/safeclaw-session.json",
		"setup/skills/gdoc/SKILL.md",
		"cmd/safeclaw/main.go",
		"internal/cli/root.go",
		"internal/dashboard/static/htmx.min.js",
	} {
		if _, err := fs.Stat(BuildContext, path); err != nil {
			t.Errorf("embedded build context is missing %s: %v", path, err)
		}
	}
}

// fetchingFiles returns the Dockerfile and every skill, the files whose
// commands fetch build or runtime inputs.
func fetchingFiles(t *testing.T) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := fs.WalkDir(BuildContext, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path != "Dockerfile" && (d.IsDir() || !strings.HasPrefix(path, "setup/skills/")) {
			return nil
		}
		b, err := fs.ReadFile(BuildContext, path)
		if err != nil {
			return err
		}
		files[path] = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestDockerfilePinsBaseImagesByDigest(t *testing.T) {
	b, err := fs.ReadFile(BuildContext, "Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	matches := regexp.MustCompile(`(?m)^FROM\s+(\S+)`).FindAllStringSubmatch(string(b), -1)
	if len(matches) == 0 {
		t.Fatal("Dockerfile has no FROM lines")
	}
	pinned := regexp.MustCompile(`^[^@\s]+:[^@\s]+@sha256:[0-9a-f]{64}$`)
	for _, m := range matches {
		if !pinned.MatchString(m[1]) {
			t.Errorf("FROM %s is not pinned by tag and digest", m[1])
		}
	}
}

func TestBuildInputsAreFetchedSafely(t *testing.T) {
	curl := regexp.MustCompile(`curl\s+(-\S+)`)
	for path, body := range fetchingFiles(t) {
		for _, m := range curl.FindAllStringSubmatch(body, -1) {
			if !strings.Contains(m[1], "f") {
				t.Errorf("%s: %q does not fail on HTTP errors (-f)", path, m[0])
			}
		}
		for _, bad := range []string{"releases/latest", "/main/", "chmod -R 777"} {
			if strings.Contains(body, bad) {
				t.Errorf("%s contains %q", path, bad)
			}
		}
	}
}

// TestDockerfilePinsClaudeCodeTipsByCommit checks that claude-code-tips, the
// source of the status line script and the dx plugin, is fetched by commit
// SHA rather than by a tag, and that the status line script is checksummed.
func TestDockerfilePinsClaudeCodeTipsByCommit(t *testing.T) {
	b, err := fs.ReadFile(BuildContext, "Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	dockerfile := string(b)
	if !regexp.MustCompile(`(?m)^ARG CLAUDE_CODE_TIPS_COMMIT=[0-9a-f]{40}$`).MatchString(dockerfile) {
		t.Error("Dockerfile does not pin CLAUDE_CODE_TIPS_COMMIT to a 40-hex commit SHA")
	}
	if !regexp.MustCompile(`(?m)^ARG CONTEXT_BAR_SHA256=[0-9a-f]{64}$`).MatchString(dockerfile) {
		t.Error("Dockerfile does not pin CONTEXT_BAR_SHA256 to a SHA-256")
	}
	for _, want := range []string{
		"https://raw.githubusercontent.com/ykdojo/claude-code-tips/${CLAUDE_CODE_TIPS_COMMIT}/scripts/context-bar.sh",
		`echo "${CONTEXT_BAR_SHA256}  /home/sclaw/.claude/scripts/context-bar.sh" | sha256sum -c -`,
		"claude plugin marketplace add https://github.com/ykdojo/claude-code-tips.git#${CLAUDE_CODE_TIPS_COMMIT}",
		`test "$(git -C /home/sclaw/.claude/plugins/marketplaces/ykdojo rev-parse HEAD)" = "${CLAUDE_CODE_TIPS_COMMIT}"`,
	} {
		if !strings.Contains(dockerfile, want) {
			t.Errorf("Dockerfile is missing %q", want)
		}
	}
	// Every fetch of claude-code-tips names the pinned commit.
	ref := regexp.MustCompile(`ykdojo/claude-code-tips(?:\.git#|/)(\S+?)[/\s]`)
	for _, m := range ref.FindAllStringSubmatch(dockerfile, -1) {
		if m[1] != "${CLAUDE_CODE_TIPS_COMMIT}" {
			t.Errorf("Dockerfile fetches claude-code-tips at %q, not ${CLAUDE_CODE_TIPS_COMMIT}", m[1])
		}
	}
}

// TestDockerfileBuildsPatchedTTYD checks that ttyd is built from a pinned
// commit with the patches that let its origin check accept a bracketed IPv6
// Host, make it refuse framing and let it read its credential from a file,
// rather than installed from apt, and that the image carries the labels
// safeclaw reads to name [::1] in session URLs and to start ttyd with
// --credential-file.
func TestDockerfileBuildsPatchedTTYD(t *testing.T) {
	b, err := fs.ReadFile(BuildContext, "Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	dockerfile := string(b)
	if !regexp.MustCompile(`(?m)^ARG TTYD_COMMIT=[0-9a-f]{40}$`).MatchString(dockerfile) {
		t.Error("Dockerfile does not pin TTYD_COMMIT to a 40-hex commit SHA")
	}
	for _, want := range []string{
		"COPY setup/ttyd/bracketed-ipv6-origin.patch /tmp/bracketed-ipv6-origin.patch\n",
		`git fetch -q --depth 1 https://github.com/tsl0922/ttyd.git "${TTYD_COMMIT}"`,
		`test "$(git rev-parse HEAD)" = "${TTYD_COMMIT}"`,
		"git apply /tmp/bracketed-ipv6-origin.patch",
		"COPY setup/ttyd/refuse-framing.patch /tmp/refuse-framing.patch\n",
		"git apply /tmp/refuse-framing.patch",
		"COPY setup/ttyd/credential-file.patch /tmp/credential-file.patch\n",
		"git apply /tmp/credential-file.patch",
		"COPY --from=ttyd /out/ttyd /usr/local/bin/ttyd\n",
		"LABEL " + config.LabelBracketedHostTTYD + `="1"` + "\n",
		"LABEL " + config.LabelCredentialFileTTYD + `="1"` + "\n",
	} {
		if !strings.Contains(dockerfile, want) {
			t.Errorf("Dockerfile is missing %q", want)
		}
	}
	if regexp.MustCompile(`apt-get install[^\n]*\sttyd(\s|$)`).MatchString(dockerfile) {
		t.Error("Dockerfile installs ttyd from apt, which refuses a bracketed IPv6 Host")
	}
	patch, err := fs.ReadFile(BuildContext, "setup/ttyd/bracketed-ipv6-origin.patch")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(patch), "+++ b/src/protocol.c") || !strings.Contains(string(patch), `"[%s]:%d"`) {
		t.Errorf("patch does not bracket IPv6 origins in src/protocol.c:\n%s", patch)
	}
	framing, err := fs.ReadFile(BuildContext, "setup/ttyd/refuse-framing.patch")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"+++ b/src/http.c",
		`"x-frame-options:"`,
		`"DENY"`,
		`"content-security-policy:"`,
		`"frame-ancestors 'none'"`,
	} {
		if !strings.Contains(string(framing), want) {
			t.Errorf("refuse-framing patch is missing %q:\n%s", want, framing)
		}
	}
	// Every response ttyd builds headers for gets them: the index (built in
	// and -I), /token, the base-path redirect, and the 401.
	if n := strings.Count(string(framing), "add_frame_headers(wsi, &p, end)"); n != 5 {
		t.Errorf("refuse-framing patch adds the headers to %d responses, want 5", n)
	}
	credFile, err := fs.ReadFile(BuildContext, "setup/ttyd/credential-file.patch")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"+++ b/src/server.c",
		`{"credential-file", required_argument, NULL, OPT_CREDENTIAL_FILE}`,
		"read_credential_file(optarg)",
		// ttyd no longer logs the encoded credential at startup.
		`-  if (server->credential != NULL) lwsl_notice("  credential: %s\n", server->credential);`,
	} {
		if !strings.Contains(string(credFile), want) {
			t.Errorf("credential-file patch is missing %q:\n%s", want, credFile)
		}
	}
	if regexp.MustCompile(`(?m)^\+.*lwsl_\w+\([^\n]*server->credential`).Match(credFile) {
		t.Errorf("credential-file patch logs the credential:\n%s", credFile)
	}
}

// TestDockerfileRootOwnsWhatClaudeCodeLoads checks that the files and folders
// Claude Code and the shell load are made root-owned, so the agent cannot
// rewrite them, and that MCP servers come only from the managed config.
func TestDockerfileRootOwnsWhatClaudeCodeLoads(t *testing.T) {
	b, err := fs.ReadFile(BuildContext, "Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	dockerfile := string(b)
	owned := map[string]bool{}
	for _, m := range regexp.MustCompile(`chown -R root:root ([^&]+)&&`).FindAllStringSubmatch(dockerfile, -1) {
		for _, p := range strings.Fields(m[1]) {
			owned[p] = true
		}
	}
	for _, p := range []string{
		// in ~/.claude
		"CLAUDE.md", "AGENTS.md", "settings.json", "settings.local.json", "scripts", "skills",
		"agents", "commands", "output-styles", "rules", "workflows", "routines", "plugins",
		// in the home folder
		".bashrc", ".profile", ".bash_profile", ".bash_logout", "CLAUDE.local.md",
		"AGENTS.override.md", "bin", ".local/bin", ".local/share/claude",
	} {
		if !owned[p] {
			t.Errorf("Dockerfile does not root-own %s", p)
		}
	}
	if strings.Contains(dockerfile, "claude mcp add") {
		t.Error("Dockerfile adds an MCP server to ~/.claude.json, which sclaw can write; use setup/managed-mcp.json")
	}
	if !strings.Contains(dockerfile, "COPY setup/managed-mcp.json /etc/claude-code/managed-mcp.json") {
		t.Error("Dockerfile does not install setup/managed-mcp.json")
	}
}

// TestDockerfileRootOwnsSessionSettings checks that the managed settings
// file safeclaw writes each session's settings to is created root-owned and
// read-only for sclaw, and starts out setting nothing.
func TestDockerfileRootOwnsSessionSettings(t *testing.T) {
	b, err := fs.ReadFile(BuildContext, "Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	dockerfile := string(b)
	for _, want := range []string{
		"COPY setup/safeclaw-session.json " + config.SessionSettingsFile + "\n",
		"chmod 755 /etc/claude-code " + config.ManagedSettingsDir + " ",
		"chmod 644 /etc/claude-code/managed-mcp.json " + config.SessionSettingsFile + "\n",
	} {
		if !strings.Contains(dockerfile, want) {
			t.Errorf("Dockerfile is missing %q", want)
		}
	}
	settings, err := fs.ReadFile(BuildContext, "setup/safeclaw-session.json")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(settings)) != "{}" {
		t.Errorf("setup/safeclaw-session.json sets something: %s", settings)
	}
}

// TestDockerfileRootOwnsSecretsAndGitConfig checks that the env file every
// bash sources, and the git config files git reads, are root-owned, with the
// env file readable by sclaw and nobody else.
func TestDockerfileRootOwnsSecretsAndGitConfig(t *testing.T) {
	b, err := fs.ReadFile(BuildContext, "Dockerfile")
	if err != nil {
		t.Fatal(err)
	}
	dockerfile := string(b)
	for _, want := range []string{
		"ENV BASH_ENV=" + config.EnvFile + "\n",
		"install -o root -g sclaw -m 640 /dev/null " + config.EnvFile,
		"install -o root -g root -m 644 /dev/null /etc/gitconfig",
		"install -o root -g root -m 644 /dev/null .gitconfig",
		"install -d -o root -g sclaw -m 1770 .config",
		"install -d -o root -g root -m 755 .config/git",
	} {
		if !strings.Contains(dockerfile, want) {
			t.Errorf("Dockerfile is missing %q", want)
		}
	}
	if strings.Contains(dockerfile, config.LegacyEnvFile) {
		t.Errorf("Dockerfile still uses %s", config.LegacyEnvFile)
	}
	bashrc, err := fs.ReadFile(BuildContext, "setup/.bashrc")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(bashrc), ". "+config.EnvFile+"\n") || strings.Contains(string(bashrc), config.LegacyEnvFile) {
		t.Errorf("setup/.bashrc does not source %s:\n%s", config.EnvFile, bashrc)
	}
}
