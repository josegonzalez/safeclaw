package safeclaw

import (
	"encoding/json"
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
		"setup/apt/nodesource.asc",
		"setup/apt/githubcli-archive-keyring.gpg",
		"setup/apt/verify-keyring.sh",
		"setup/npm/package.json",
		"setup/npm/package-lock.json",
		"setup/playwright/archives.sha256",
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
		// dx's source is the pinned marketplace checkout itself, and the
		// installed plugin records the pinned commit.
		`jq -e '[.plugins[] | select(.name == "dx")] | length == 1 and .[0].source == "./"' /home/sclaw/.claude/plugins/marketplaces/ykdojo/.claude-plugin/marketplace.json`,
		`jq -e --arg commit "${CLAUDE_CODE_TIPS_COMMIT}" '.plugins["dx@ykdojo"] | length == 1 and .[0].gitCommitSha == $commit' /home/sclaw/.claude/plugins/installed_plugins.json`,
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

func readBuildContext(t *testing.T, path string) string {
	t.Helper()
	b, err := fs.ReadFile(BuildContext, path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// TestDockerfilePinsAptKeyrings checks that the nodesource and GitHub CLI apt
// keyrings are committed rather than fetched, and that the build checks them
// against recorded primary key fingerprints.
func TestDockerfilePinsAptKeyrings(t *testing.T) {
	dockerfile := readBuildContext(t, "Dockerfile")
	for _, arg := range []string{"NODESOURCE_APT_FINGERPRINTS", "GH_CLI_APT_FINGERPRINTS"} {
		re := regexp.MustCompile(`(?m)^ARG ` + arg + `=("?)[0-9A-F]{40}( [0-9A-F]{40})*("?)$`)
		m := re.FindStringSubmatch(dockerfile)
		if m == nil || m[1] != m[3] {
			t.Errorf("Dockerfile does not pin %s to 40-hex fingerprints", arg)
		}
	}
	for _, want := range []string{
		"COPY setup/apt/nodesource.asc /etc/apt/keyrings/nodesource.asc\n",
		"COPY setup/apt/githubcli-archive-keyring.gpg /usr/share/keyrings/githubcli-archive-keyring.gpg\n",
		"sh /tmp/verify-keyring.sh /etc/apt/keyrings/nodesource.asc ${NODESOURCE_APT_FINGERPRINTS} &&",
		"sh /tmp/verify-keyring.sh /usr/share/keyrings/githubcli-archive-keyring.gpg ${GH_CLI_APT_FINGERPRINTS} &&",
		"signed-by=/etc/apt/keyrings/nodesource.asc]",
		"signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg]",
	} {
		if !strings.Contains(dockerfile, want) {
			t.Errorf("Dockerfile is missing %q", want)
		}
	}
	for _, bad := range []string{"gpgkey", "githubcli-archive-keyring.gpg |", "gpg --dearmor"} {
		if strings.Contains(dockerfile, bad) {
			t.Errorf("Dockerfile fetches an apt keyring (%q)", bad)
		}
	}
	if !strings.HasPrefix(readBuildContext(t, "setup/apt/nodesource.asc"), "-----BEGIN PGP PUBLIC KEY BLOCK-----") {
		t.Error("setup/apt/nodesource.asc is not an armored public key")
	}
	// A binary keyring starts with a public key packet: tag 6 in the old
	// (0x98, 0x99) or new (0xc6) packet format.
	gh := readBuildContext(t, "setup/apt/githubcli-archive-keyring.gpg")
	if gh == "" || (gh[0] != 0x98 && gh[0] != 0x99 && gh[0] != 0xc6) {
		t.Error("setup/apt/githubcli-archive-keyring.gpg is not a binary OpenPGP keyring")
	}
}

// TestDockerfilePinsClaudeCodeBinary checks that the Claude Code binary is
// fetched for the pinned version directly, not through install.sh, and is
// checked against a pinned SHA-256 for each architecture before and after it
// installs itself.
func TestDockerfilePinsClaudeCodeBinary(t *testing.T) {
	dockerfile := readBuildContext(t, "Dockerfile")
	if !regexp.MustCompile(`(?m)^ARG CLAUDE_CODE_VERSION=\d+\.\d+\.\d+$`).MatchString(dockerfile) {
		t.Error("Dockerfile does not pin CLAUDE_CODE_VERSION to an exact version")
	}
	for _, arch := range []string{"X64", "ARM64"} {
		if !regexp.MustCompile(`(?m)^ARG CLAUDE_CODE_SHA256_LINUX_` + arch + `=[0-9a-f]{64}$`).MatchString(dockerfile) {
			t.Errorf("Dockerfile does not pin CLAUDE_CODE_SHA256_LINUX_%s to a SHA-256", arch)
		}
	}
	for _, want := range []string{
		"x86_64) platform=linux-x64 sum=${CLAUDE_CODE_SHA256_LINUX_X64} ;;",
		"aarch64) platform=linux-arm64 sum=${CLAUDE_CODE_SHA256_LINUX_ARM64} ;;",
		`"https://downloads.claude.ai/claude-code-releases/${CLAUDE_CODE_VERSION}/${platform}/claude"`,
		`echo "${sum}  /tmp/claude-install/claude" | sha256sum -c -`,
		`./claude install "${CLAUDE_CODE_VERSION}"`,
		`echo "${sum}  /home/sclaw/.local/share/claude/versions/${CLAUDE_CODE_VERSION}" | sha256sum -c -`,
	} {
		if !strings.Contains(dockerfile, want) {
			t.Errorf("Dockerfile is missing %q", want)
		}
	}
	if regexp.MustCompile(`install\.sh\s*\|`).MatchString(dockerfile) {
		t.Error("Dockerfile runs claude.ai/install.sh, which fetches the latest binary")
	}
}

// TestDockerfileInstallsNpmPackagesFromLockfile checks that the image's npm
// packages, yarn included, are installed with npm ci from the committed
// lockfile at exact versions with integrity hashes, never with npm install.
func TestDockerfileInstallsNpmPackagesFromLockfile(t *testing.T) {
	dockerfile := readBuildContext(t, "Dockerfile")
	if regexp.MustCompile(`npm (install|i)\s`).MatchString(dockerfile) {
		t.Error("Dockerfile runs npm install; install from setup/npm/package-lock.json with npm ci")
	}
	for _, want := range []string{
		"COPY setup/npm/package.json setup/npm/package-lock.json /opt/safeclaw/npm/\n",
		"npm ci --ignore-scripts --no-audit --no-fund &&",
		"ENV NODE_PATH=/opt/safeclaw/npm/node_modules\n",
		"ln -s /opt/safeclaw/npm/node_modules/.bin/yarn /usr/local/bin/yarn &&",
		"ln -s /opt/safeclaw/npm/node_modules/.bin/playwright-mcp /usr/local/bin/playwright-mcp &&",
	} {
		if !strings.Contains(dockerfile, want) {
			t.Errorf("Dockerfile is missing %q", want)
		}
	}

	var pkg struct {
		Dependencies map[string]string `json:"dependencies"`
	}
	if err := json.Unmarshal([]byte(readBuildContext(t, "setup/npm/package.json")), &pkg); err != nil {
		t.Fatal(err)
	}
	exact := regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	for _, name := range []string{"@playwright/mcp", "node-lief", "yarn"} {
		if !exact.MatchString(pkg.Dependencies[name]) {
			t.Errorf("setup/npm/package.json does not pin %s to an exact version: %q", name, pkg.Dependencies[name])
		}
	}

	var lock struct {
		LockfileVersion int `json:"lockfileVersion"`
		Packages        map[string]struct {
			Version      string            `json:"version"`
			Resolved     string            `json:"resolved"`
			Integrity    string            `json:"integrity"`
			Dependencies map[string]string `json:"dependencies"`
		} `json:"packages"`
	}
	if err := json.Unmarshal([]byte(readBuildContext(t, "setup/npm/package-lock.json")), &lock); err != nil {
		t.Fatal(err)
	}
	if lock.LockfileVersion != 3 {
		t.Errorf("package-lock.json has lockfileVersion %d, want 3", lock.LockfileVersion)
	}
	for name, version := range pkg.Dependencies {
		if lock.Packages[""].Dependencies[name] != version {
			t.Errorf("package-lock.json is out of date with package.json for %s", name)
		}
		if got := lock.Packages["node_modules/"+name].Version; got != version {
			t.Errorf("package-lock.json installs %s %q, want %q", name, got, version)
		}
	}
	for path, p := range lock.Packages {
		if path == "" {
			continue
		}
		if !strings.HasPrefix(p.Resolved, "https://registry.npmjs.org/") {
			t.Errorf("package-lock.json resolves %s from %q, not the npm registry", path, p.Resolved)
		}
		if !strings.HasPrefix(p.Integrity, "sha512-") {
			t.Errorf("package-lock.json has no sha512 integrity for %s", path)
		}
	}
}

// TestDockerfileChecksumsPlaywrightBrowsers checks that every Playwright
// browser archive is checked, before it is unzipped, against a SHA-256
// recorded for its URL, for both architectures the image is built for.
func TestDockerfileChecksumsPlaywrightBrowsers(t *testing.T) {
	dockerfile := readBuildContext(t, "Dockerfile")
	for _, want := range []string{
		"COPY setup/playwright/archives.sha256 /tmp/pw-archives.sha256\n",
		`sum=$(awk -v u="$url" '$2 == u { print $1 }' /tmp/pw-archives.sha256);`,
		`[ -n "$sum" ] || {`,
		"echo \"$sum  /tmp/pw.zip\" | sha256sum -c - || exit 1; \\\n        unzip -q -o /tmp/pw.zip",
	} {
		if !strings.Contains(dockerfile, want) {
			t.Errorf("Dockerfile is missing %q", want)
		}
	}
	line := regexp.MustCompile(`^[0-9a-f]{64}  https://\S+\.zip$`)
	seen := map[string]bool{}
	for _, l := range strings.Split(strings.TrimSpace(readBuildContext(t, "setup/playwright/archives.sha256")), "\n") {
		if !line.MatchString(l) {
			t.Errorf("setup/playwright/archives.sha256 has a bad line: %q", l)
			continue
		}
		url := strings.Fields(l)[1]
		if seen[url] {
			t.Errorf("setup/playwright/archives.sha256 lists %s twice", url)
		}
		seen[url] = true
	}
	for _, want := range []string{
		"/linux64/chrome-linux64.zip",
		"/linux64/chrome-headless-shell-linux64.zip",
		"/ffmpeg-linux.zip",
		"/linux-arm64/chrome-linux-arm64.zip",
		"/linux-arm64/chrome-headless-shell-linux-arm64.zip",
		"/ffmpeg-linux-arm64.zip",
	} {
		found := false
		for url := range seen {
			found = found || strings.HasSuffix(url, want)
		}
		if !found {
			t.Errorf("setup/playwright/archives.sha256 has no checksum for *%s", want)
		}
	}
}

// TestDockerfileRootOwnsPlaywright checks that the browsers and npm packages
// the managed MCP config launches are root-owned and not writable by sclaw.
func TestDockerfileRootOwnsPlaywright(t *testing.T) {
	dockerfile := readBuildContext(t, "Dockerfile")
	for _, want := range []string{
		"chown -R root:root /opt/safeclaw /ms-playwright &&",
		"chmod -R a+rX,go-w /opt/safeclaw /ms-playwright\n",
	} {
		if !strings.Contains(dockerfile, want) {
			t.Errorf("Dockerfile is missing %q", want)
		}
	}
	if regexp.MustCompile(`chown[^\n]*sclaw[^\n]*(/ms-playwright|/opt/safeclaw)`).MatchString(dockerfile) {
		t.Error("Dockerfile gives sclaw /ms-playwright or /opt/safeclaw")
	}
	var mcp struct {
		MCPServers map[string]struct {
			Command string `json:"command"`
		} `json:"mcpServers"`
	}
	if err := json.Unmarshal([]byte(readBuildContext(t, "setup/managed-mcp.json")), &mcp); err != nil {
		t.Fatal(err)
	}
	if got := mcp.MCPServers["playwright"].Command; got != "/usr/local/bin/playwright-mcp" {
		t.Errorf("managed MCP config runs %q, want the root-owned /usr/local/bin/playwright-mcp", got)
	}
}

// TestDockerignoreExcludesLocalState checks that a `--context .` build does
// not send Claude Code's local state and worktrees, the built binary or
// secrets to the docker daemon.
func TestDockerignoreExcludesLocalState(t *testing.T) {
	lines := map[string]bool{}
	for _, l := range strings.Split(readBuildContext(t, ".dockerignore"), "\n") {
		lines[strings.TrimSpace(l)] = true
	}
	for _, want := range []string{".git", ".claude", "safeclaw", "tmp", "dist", "**/.env", "**/*.pem"} {
		if !lines[want] {
			t.Errorf(".dockerignore does not exclude %s", want)
		}
	}
}
