# === BUILD the in-container safeclaw binary ===

FROM golang:1.27@sha256:5f1b98fa02fe396ebce2a0227a0e08309e11792915b9dd2e1f71053d7e7e6666 AS build

ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath \
      -ldflags "-s -w \
        -X github.com/josegonzalez/safeclaw/internal/version.Version=${VERSION} \
        -X github.com/josegonzalez/safeclaw/internal/version.Commit=${COMMIT} \
        -X github.com/josegonzalez/safeclaw/internal/version.Date=${DATE}" \
      -o /out/safeclaw ./cmd/safeclaw

# === BUILD ttyd, patched to accept a bracketed IPv6 Host and refuse framing ===

FROM ubuntu:26.04@sha256:d66b366dac61b575bee2aef07e9c26e8070096fbe84a3d4d3eb0da069b5d76db AS ttyd

ARG DEBIAN_FRONTEND=noninteractive
# ttyd is pinned by commit (tag 1.7.7), not by tag, so a moved tag can't
# change what the build fetches
ARG TTYD_COMMIT=40e79c706be14029b391f369bee6613c31667abb

RUN apt-get update && \
    apt-get install -y --no-install-recommends ca-certificates git build-essential cmake \
      libjson-c-dev libwebsockets-dev libuv1-dev zlib1g-dev libssl-dev && \
    rm -rf /var/lib/apt/lists/*
COPY setup/ttyd/bracketed-ipv6-origin.patch /tmp/bracketed-ipv6-origin.patch
COPY setup/ttyd/refuse-framing.patch /tmp/refuse-framing.patch
# Session URLs name [::1]:PORT, and ttyd's -O origin check otherwise never
# matches a bracketed Host. Every response says X-Frame-Options DENY and
# frame-ancestors 'none', so no other page can frame a logged-in terminal
# and pass the user's keystrokes through
RUN git init -q /src && cd /src && \
    git fetch -q --depth 1 https://github.com/tsl0922/ttyd.git "${TTYD_COMMIT}" && \
    git checkout -q FETCH_HEAD && \
    test "$(git rev-parse HEAD)" = "${TTYD_COMMIT}" && \
    git apply /tmp/bracketed-ipv6-origin.patch && \
    git apply /tmp/refuse-framing.patch && \
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build -j "$(nproc)" && \
    install -D -m 755 build/ttyd /out/ttyd

# === RUNTIME image ===

FROM ubuntu:26.04@sha256:d66b366dac61b575bee2aef07e9c26e8070096fbe84a3d4d3eb0da069b5d76db

ARG DEBIAN_FRONTEND=noninteractive
ARG TZ=America/Los_Angeles
ARG NODE_VERSION=26
ARG PLAYWRIGHT_MCP_VERSION=0.0.86
ARG CLAUDE_CODE_VERSION=2.1.332
ARG NODE_LIEF_VERSION=1.3.2
# claude-code-tips is pinned by commit (tag v0.26.39), not by tag, so a moved
# tag can't change what the build fetches
ARG CLAUDE_CODE_TIPS_COMMIT=ed25f97beae8fa1755c6ba90cc670944316e21ae
ARG CONTEXT_BAR_SHA256=3b7644b94eaa82c5df46bbf34ffa61d5b2bc4f12976576d966676cfc2c61761f
ARG YT_DLP_VERSION=2026.11.23
ARG YT_DLP_SHA256=e8665ed64d6b9172773e812f891fb707a0cb1ee8d9ef4fc1acb00cabee4c5256

ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

# === INSTALL Node.js ===

RUN apt-get update && \
    # Install Node.js
    apt-get install -y curl wget gpg ca-certificates && \
    mkdir -p /etc/apt/keyrings && \
    curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg && \
    echo "deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_${NODE_VERSION}.x nodistro main" >> /etc/apt/sources.list.d/nodesource.list && \
    apt-get update && \
    apt-get install -y nodejs && \
    # Install GitHub CLI
    curl -fsSL https://cli.github.com/packages/githubcli-archive-keyring.gpg | dd of=/usr/share/keyrings/githubcli-archive-keyring.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" > /etc/apt/sources.list.d/github-cli.list && \
    apt-get update && \
    apt-get install -y gh && \
    apt-get install -y --no-install-recommends git openssh-client jq tmux vim python3-pip unzip && \
    # ttyd's libraries; ttyd itself is built above
    apt-get install -y --no-install-recommends libjson-c5 libwebsockets-evlib-uv libuv1t64 zlib1g libssl3t64 && \
    npm install -g yarn && \
    # clean apt cache
    rm -rf /var/lib/apt/lists/* && \
    # Create the sclaw user, with a home only it can read
    useradd --create-home --shell /bin/bash sclaw && \
    chmod 700 /home/sclaw && \
    # Create the unprivileged, non-login user sandboxes run as
    useradd --uid 2000 --user-group --no-create-home --home-dir /sandbox --shell /usr/sbin/nologin sandbox && \
    mkdir -m 700 /sandbox && \
    chown sandbox:sandbox /sandbox

# === INSTALL Playwright MCP + browsers ===

ENV PLAYWRIGHT_BROWSERS_PATH=/ms-playwright

# Install MCP globally, then prefetch the Chromium browser artifacts with curl.
# Playwright's own downloader has no stall timeout: on some networks the CDN
# connection establishes but then stops sending data mid-transfer, and the
# install hangs forever. curl's --speed-time aborts a stalled transfer and
# --retry reconnects until one succeeds. We fetch each artifact (URLs/paths come
# from --dry-run, so this stays version-agnostic) into Playwright's browser dir
# and mark it INSTALLATION_COMPLETE, so `playwright install` finds them already
# present and skips its download. The final install is a fast no-op verification
# (timeout-guarded so a missed artifact fails the build instead of hanging).
RUN npm install -g @playwright/mcp@${PLAYWRIGHT_MCP_VERSION} && \
    mkdir -p /ms-playwright && \
    PW=/usr/lib/node_modules/@playwright/mcp/node_modules/.bin/playwright && \
    "$PW" install-deps chromium && \
    "$PW" install --dry-run chromium | \
        awk '/Install location:/{loc=$3} /Download url:/{print loc, $3}' | \
        sort -u > /tmp/pw-pairs.txt && \
    while read -r loc url; do \
        echo "prefetching $loc"; \
        mkdir -p "$loc" || exit 1; \
        curl -fL --retry 8 --retry-all-errors --retry-delay 2 --connect-timeout 20 \
             --speed-limit 50000 --speed-time 15 -o /tmp/pw.zip "$url" || exit 1; \
        unzip -q -o /tmp/pw.zip -d "$loc" || exit 1; \
        touch "$loc/INSTALLATION_COMPLETE"; \
        rm -f /tmp/pw.zip; \
    done < /tmp/pw-pairs.txt && \
    timeout 300 "$PW" install chromium && \
    rm -f /tmp/pw-pairs.txt && \
    rm -rf /var/lib/apt/lists/* && \
    rm -rf ~/.npm/ && \
    chown -R sclaw:sclaw /ms-playwright && \
    chmod -R go-w /ms-playwright

# === INSTALL node-lief ===

RUN npm install -g node-lief@${NODE_LIEF_VERSION}
ENV NODE_PATH=/usr/lib/node_modules

# === INSTALL yt-dlp ===

RUN curl -fsSLo /usr/local/bin/yt-dlp \
      https://github.com/yt-dlp/yt-dlp/releases/download/${YT_DLP_VERSION}/yt-dlp && \
    echo "${YT_DLP_SHA256}  /usr/local/bin/yt-dlp" | sha256sum -c - && \
    chmod 755 /usr/local/bin/yt-dlp

# === INSTALL safeclaw (ttyd wrapper) ===

COPY --from=build /out/safeclaw /usr/local/bin/safeclaw

# === INSTALL ttyd ===

COPY --from=ttyd /out/ttyd /usr/local/bin/ttyd
RUN ttyd --version
# safeclaw names [::1] in the URLs of sessions made from images with this
LABEL io.github.josegonzalez.safeclaw.ttyd-bracketed-host="1"

# === INSTALL Claude Code (native binary) ===

USER sclaw
WORKDIR /home/sclaw

ENV PATH="/home/sclaw/.local/bin:${PATH}"
ENV DISABLE_AUTOUPDATER=1
# The env file safeclaw writes the session's secrets to, as root. It is
# created root:sclaw 0640 below.
ENV BASH_ENV=/etc/safeclaw/env

# Auth: set these env vars for cloud deployment (no interactive login needed)
# - CLAUDE_CODE_OAUTH_TOKEN: run `safeclaw auth login` (or `claude setup-token`) to generate
# - GH_TOKEN: run `gh auth token` locally to print current token

# Bake Claude config into image. These are made root-owned and read-only at
# the end of the build, once Claude Code has finished writing to them.
COPY --chown=sclaw:sclaw setup/CLAUDE.md /home/sclaw/.claude/CLAUDE.md
COPY --chown=sclaw:sclaw setup/settings.json /home/sclaw/.claude/settings.json

# Install scripts (context bar status line), from the same claude-code-tips
# commit as the dx plugin
RUN mkdir -p /home/sclaw/.claude/scripts && \
    curl -fsSLo /home/sclaw/.claude/scripts/context-bar.sh \
      https://raw.githubusercontent.com/ykdojo/claude-code-tips/${CLAUDE_CODE_TIPS_COMMIT}/scripts/context-bar.sh && \
    echo "${CONTEXT_BAR_SHA256}  /home/sclaw/.claude/scripts/context-bar.sh" | sha256sum -c - && \
    chmod +x /home/sclaw/.claude/scripts/context-bar.sh

RUN curl -fsSL https://claude.ai/install.sh | bash -s -- ${CLAUDE_CODE_VERSION}

# === SETUP Claude Code ===

# Install DX plugin. The marketplace is checked out at the pinned commit, and
# dx's source is that same checkout ("./" in its marketplace.json).
RUN claude plugin marketplace add https://github.com/ykdojo/claude-code-tips.git#${CLAUDE_CODE_TIPS_COMMIT} && \
    test "$(git -C /home/sclaw/.claude/plugins/marketplaces/ykdojo rev-parse HEAD)" = "${CLAUDE_CODE_TIPS_COMMIT}" && \
    claude plugin install dx@ykdojo

# The Playwright MCP server is the only MCP server. Claude Code's managed MCP
# config takes exclusive control of the server list, so servers added to
# ~/.claude.json or a .mcp.json (which sclaw can write) are refused or ignored.
COPY setup/managed-mcp.json /etc/claude-code/managed-mcp.json

# Managed settings take precedence over every other settings file, the
# --settings flag and the environment. safeclaw writes each session's own
# managed settings, such as auto memory off for `run --no-memory`, to this
# drop-in as root. Sessions drop every capability, so root can't chown
# there: the file is created here root-owned, and only its contents are
# rewritten.
COPY setup/safeclaw-session.json /etc/claude-code/managed-settings.d/safeclaw-session.json

# Skip onboarding so CLAUDE_CODE_OAUTH_TOKEN works in interactive mode
# See: https://github.com/anthropics/claude-code/issues/8938
# Newer Claude Code versions also ask to trust the home folder and to accept
# bypass permissions mode on every start; the container is the sandbox, so
# pre-accept both.
RUN { [ -f /home/sclaw/.claude.json ] || echo '{}' > /home/sclaw/.claude.json; } && \
    jq '. + {hasCompletedOnboarding: true, autoCompactEnabled: false, bypassPermissionsModeAccepted: true} | .projects["/home/sclaw"].hasTrustDialogAccepted = true' /home/sclaw/.claude.json > /tmp/.claude.json.tmp && \
    mv /tmp/.claude.json.tmp /home/sclaw/.claude.json

# Set default model (must be after plugin install which rewrites settings.json).
# Without this, the Claude API account defaults to Sonnet, not Opus.
RUN jq '. + {model: "claude-opus-5-5", skipDangerousModePermissionPrompt: true}' /home/sclaw/.claude/settings.json > /tmp/settings.json.tmp && \
    mv /tmp/settings.json.tmp /home/sclaw/.claude/settings.json

# Shell aliases and shortcuts
COPY --chown=sclaw:sclaw setup/.bashrc /tmp/.bashrc
RUN cat /tmp/.bashrc >> /home/sclaw/.bashrc && rm /tmp/.bashrc

# Skills
COPY setup/skills /home/sclaw/.claude/skills

# === LOCK DOWN Claude Code config ===

# Make the settings, CLAUDE.md, status line script and skills root-owned and
# read-only, so the agent cannot rewrite its own config, hooks or skills. An
# empty settings.local.json and empty agents and commands folders are created
# the same way, so the agent cannot add them to override the settings or add
# its own agents and commands.
# The same goes for the empty output-styles, rules, workflows and routines
# folders and AGENTS.md that Claude Code also reads from ~/.claude, and the
# plugins (whose hooks and skills Claude Code runs) are root-owned too.
# ~/.claude and the home folder become root-owned, group-writable and sticky:
# sclaw can still create, edit and replace its own files there, but cannot
# delete or rename the root-owned ones (or ~/.claude itself) to swap them out.
USER root
RUN cd /home/sclaw/.claude && \
    echo '{}' > settings.local.json && \
    touch AGENTS.md && \
    mkdir -p agents commands output-styles rules workflows routines && \
    chown -R root:root CLAUDE.md AGENTS.md settings.json settings.local.json scripts skills agents commands output-styles rules workflows routines plugins && \
    chmod -R u=rwX,go=rX CLAUDE.md AGENTS.md settings.json settings.local.json scripts skills agents commands output-styles rules workflows routines plugins && \
    chmod 755 scripts/context-bar.sh && \
    chown root:sclaw /home/sclaw /home/sclaw/.claude && \
    chmod 1770 /home/sclaw /home/sclaw/.claude && \
    chmod 755 /etc/claude-code /etc/claude-code/managed-settings.d && \
    chmod 644 /etc/claude-code/managed-mcp.json /etc/claude-code/managed-settings.d/safeclaw-session.json

# Lock down the Claude Code install and the shell's startup files, so the
# agent cannot replace the claude binary or what each shell runs. Claude Code's
# auto-updater is disabled, so it never needs to write its install. ~/.local
# and ~/.local/share stay open to sclaw like the home folder, for other tools'
# data, but ~/.local/bin, which is early in PATH, is root-owned so nothing can
# shadow claude, node or the other commands Claude Code runs. Empty, root-owned
# project instructions are created in the home folder, Claude Code's working
# directory, so the agent cannot add its own. ~/.bash_profile only sources
# ~/.profile, and is there so the agent cannot add one that login shells would
# read instead, and ~/bin, which ~/.profile adds to PATH, is root-owned and
# empty.
RUN cd /home/sclaw && \
    printf '%s\n' '[ -f "$HOME/.profile" ] && . "$HOME/.profile"' > .bash_profile && \
    touch CLAUDE.md CLAUDE.local.md AGENTS.md AGENTS.override.md && \
    mkdir -p bin && \
    chown -R root:root .bashrc .profile .bash_profile .bash_logout CLAUDE.md CLAUDE.local.md AGENTS.md AGENTS.override.md bin .local/bin .local/share/claude && \
    chmod -R u=rwX,go=rX .bashrc .profile .bash_profile .bash_logout CLAUDE.md CLAUDE.local.md AGENTS.md AGENTS.override.md bin .local/bin .local/share/claude && \
    chown root:sclaw .local .local/share && \
    chmod 1770 .local .local/share

# Lock down the secrets env file and git config, which every shell and git
# command loads. safeclaw writes both as root with `docker exec -u root`, but
# sessions drop every capability, so root can't chown there: the env file is
# created here as root:sclaw 0640 and only its contents are rewritten. The git
# identity goes to the system config, /etc/gitconfig. An empty, root-owned
# ~/.gitconfig and ~/.config/git keep the agent from adding a global config
# with options such as core.fsmonitor or core.pager that run commands, and
# ~/.config is root:sclaw 1770 like the home folder so other tools can still
# keep their config there.
RUN mkdir -p /etc/safeclaw && \
    install -o root -g sclaw -m 640 /dev/null /etc/safeclaw/env && \
    install -o root -g root -m 644 /dev/null /etc/gitconfig && \
    cd /home/sclaw && \
    install -o root -g root -m 644 /dev/null .gitconfig && \
    install -d -o root -g sclaw -m 1770 .config && \
    install -d -o root -g root -m 755 .config/git
USER sclaw
