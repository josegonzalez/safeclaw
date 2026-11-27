# SafeClaw

Run multiple Claude Code sessions, each in its own container, with a dashboard to manage them all.

This is a Go reimplementation of [ykdojo/safeclaw](https://github.com/ykdojo/safeclaw). It ships as a single `safeclaw` binary, and the dashboard uses [htmx](https://htmx.org) with only a few lines of hand-written JavaScript. It is compatible with upstream installs: same image name, container names, ports, and `~/.config/safeclaw` layout.

See [docs/](docs/README.md) for design details.

## Why a container?

- **Isolated** - Claude Code runs with bypass permissions, but can't touch your host machine.
- **Lightweight** - Spin up, stop, or delete sessions in seconds. Much faster than a full VM.
- **Portable** - Works on any machine with Docker. Same environment everywhere.

This lets you run Claude Code with `--dangerously-skip-permissions` safely and fast.

## One session per container

Each Claude Code session runs in its own container. Spin up as many as you need - they're isolated from each other and start in seconds. Conversation history is stored on your host machine via a volume mount.

## Install

```bash
brew install josegonzalez/repo/safeclaw
# or
go install github.com/josegonzalez/safeclaw/cmd/safeclaw@latest
```

## Quickstart

```bash
# Build the image (once, or after upgrading), or pull the published one.
# --variant sandbox also fetches the image sandboxes use by default.
safeclaw build --variant sandbox
safeclaw pull --variant sandbox

# Start a container and web terminal
safeclaw run

# Mount a local project (host_path:container_path)
safeclaw run -v ~/myproject:/home/sclaw/myproject

# Run multiple sessions with -s
safeclaw run -s work        # safeclaw-work on the next available port
safeclaw run -s research    # safeclaw-research on the next available port
```

On first run, `safeclaw run` prompts you to set up authentication tokens, offering to sign in to Claude Code for you. It then starts a web terminal at http://localhost:7681 and opens it in your browser. The terminal needs a credential made for each session, so the printed URL carries it, like `http://safeclaw:PASSWORD@localhost:7681`; the dashboard adds it for you. `safeclaw url NAME` prints that URL again without restarting anything. When a dashboard is running, `run` and `safeclaw url NAME --open` open its terminal page instead, which keeps the credential out of the process list and your browser history; otherwise they open the URL with the credential and warn about it.

## Dashboard

```bash
safeclaw dashboard
```

Prints a URL like `http://127.0.0.1:7680/?token=...` to open. The token is made fresh each time the dashboard starts, and every page and API call needs it, so code in a session container can't drive the dashboard. Scripts can send it as `Authorization: Bearer` from `~/.config/safeclaw/dashboard/7680.token`; see [the dashboard docs](docs/dashboard.md#routes). The dashboard has:

- Create new sessions with volume mounts, image variants, secrets, and initial queries
- All sessions listed with start/stop/delete and offline/online controls
- Live iframe views of active sessions, updated as containers change

## Sandboxes for untrusted files

A sandbox is a headless container for opening untrusted files, such as PDFs, archives, or emails that haven't been checked. It gets no secrets, git config, web terminal, or Claude Code, has no network, and runs as an unprivileged user that can't read `/home/sclaw`. See [architecture](docs/architecture.md#sandboxes) for the full list of defaults.

Sandboxes run the `sandbox` [image variant](#image-variants) by default, which adds document extraction tools: `pdftotext`, `pdfinfo`, and `pdftoppm` from poppler-utils, `tesseract` with English language data, `7z`, and `file`. Fetch it once with `safeclaw pull --variant sandbox` (or `safeclaw build --variant sandbox`), or pass `--variant base` to use the base image.

```bash
# Create a sandbox, mounting host directories read-only (-v repeats)
safeclaw sandbox run -s triage -v ~/inbox:/in -v ~/triage-tools:/opt/tools

# Run commands as the sandbox user
safeclaw sandbox exec triage -- pdftotext /in/report.pdf -
safeclaw sandbox exec triage -- unzip -l /in/report.zip
safeclaw sandbox exec -i triage -- python3 - < extract.py

# Escape control characters in the output, so escape sequences in file names
# or tool errors never reach your terminal
safeclaw sandbox exec --escape-controls triage -- 7z l /in/archive.7z

# Stop a command that hangs on a crafted file, exiting 124
safeclaw sandbox exec --timeout 2m triage -- pdftotext /in/report.pdf -

# Pass a value in the environment instead of the arguments, where ps shows it
ARCHIVE_PASSWORD=... safeclaw sandbox exec -e ARCHIVE_PASSWORD triage -- python3 /opt/tools/unpack.py /in/archive.zip

# Copy files in, owned by the sandbox user and numbered so names never collide
safeclaw sandbox cp-in triage ~/Downloads/report.zip   # prints /sandbox/in/1-report.zip
safeclaw sandbox exec triage -- unzip -d /sandbox/out /sandbox/in/1-report.zip

# Copy only the matching regular files back out, dropping links and directories
safeclaw sandbox cp-out triage /sandbox/out ./results --only '*.txt'

# Remove it
safeclaw sandbox rm -f triage
```

`/sandbox` is a tmpfs of `--disk` bytes (default `1g`), so an extractor writing past it fails instead of filling the host's disk. Its files count toward `--memory` (default `2g`), so raise both together, and they are lost when the sandbox stops. See [sandbox disk](docs/architecture.md#sandbox-disk).

A one-off sandbox lives for exactly one job, so jobs never share files, locks, or cleanup. Without `-s` it gets a random name, and a name that already exists is refused.

```bash
# Run one command in a new sandbox that is removed when the command exits
safeclaw sandbox exec --ephemeral -i -- python3 - < extract.py
safeclaw sandbox exec --ephemeral -v ~/inbox:/in -- unzip -l /in/report.zip
safeclaw sandbox exec --ephemeral -v ~/inbox:/in -- tesseract /in/scan.png -
safeclaw sandbox exec --ephemeral --timeout 5m -v ~/inbox:/in -- pdftotext /in/report.pdf -

# Or keep one around for a job with several steps; it is removed when stopped
name=$(safeclaw sandbox run --rm -v ~/inbox:/in)
safeclaw sandbox exec "$name" -- unzip -d /sandbox/out /in/report.zip
safeclaw sandbox cp-out "$name" /sandbox/out ./results --only '*.pdf'
safeclaw sandbox stop "$name"
```

Scripts that drive a sandbox can check it before handing it untrusted files, without relying on container names, labels, or `docker inspect`:

```bash
safeclaw sandbox inspect triage   # its isolation settings, limits, and mounts as JSON
safeclaw sandbox verify triage    # checks each isolation guarantee, exits non-zero naming any that fail
```

## Taking a session offline

While an interactive session handles something untrusted, take it offline. `safeclaw net off` saves the session's networks and disconnects it from them, and `safeclaw net on` reconnects it to exactly those networks. Its web terminal is unreachable while it is offline, and it stays offline across restarts.

```bash
safeclaw net off work --owner triage --reason "opening an emailed pdf"
safeclaw ls                      # NETWORK shows: offline (triage)
safeclaw net on work --owner triage
```

Each `net off` records a hold for its `--owner` (or one shared unnamed hold without it), and the session is reconnected only once every hold is released, so one job can't bring a session back online while another still relies on it being offline. `--force` releases every hold. The saved state is tied to the container, so a session recreated under the same name starts online. See [architecture](docs/architecture.md#offline-sessions) for details.

## Image variants

An image variant is the `safeclaw` image with extra apt packages or setup steps, tagged `safeclaw:NAME`. The built-in `sandbox` variant is published alongside each release. Define more, or override `sandbox`, in `~/.config/safeclaw/config.yaml`:

```yaml
defaults:
  session: base      # the variant new sessions use (default: base)
  sandbox: sandbox   # the variant new sandboxes use (default: sandbox)
variants:
  research:
    packages: [pandoc]
    run:
      - pip install --break-system-packages markitdown
```

`run` commands run as root with `/bin/sh -c`, one line each, and the image switches back to the `sclaw` user after them whatever they contain. A variant defined in the config file replaces a built-in one with the same name.

```bash
safeclaw variant ls                          # variants, their images, and defaults
safeclaw build --variant research            # build the base image, then the variant
safeclaw run -s notes --variant research     # a session on safeclaw:research
safeclaw sandbox exec --ephemeral --variant base -- ls
```

`safeclaw build` and `safeclaw pull` also refresh every variant already present locally, so no variant is left on an older base image. Passing `--variant` to an existing session or sandbox with a different variant recreates it, keeping its mounts and limits.

## What's included

- Ubuntu 26.04
- Node.js 26 (LTS)
- Claude Code 2.1.332
- GitHub CLI with auto-configured git user and https credentials
- Playwright MCP 0.0.86 with Chromium
- yt-dlp 2026.11.23
- [DX plugin](https://github.com/ykdojo/claude-code-tips#tip-44-install-the-dx-plugin), [custom status line](https://github.com/ykdojo/claude-code-tips#tip-0-customize-your-status-line), [shell aliases](#aliases)
- ttyd web terminal + tmux
- In the `sandbox` variant: poppler-utils, tesseract-ocr with English, 7zip, and file

## Sensible defaults

- Claude Code version pinned (currently 2.1.332)
- `autoCompactEnabled: false` - prevents automatic context compaction
- `promptSuggestionEnabled: false` - disables prompt suggestions
- `--dangerously-skip-permissions` enabled (because it's containerized), with the home folder trust and bypass permissions prompts pre-accepted
- Claude Code's install, settings, instructions, skills, plugins, MCP servers, and the shell's startup files are root-owned, so the agent can't change them (see [architecture](docs/architecture.md#image))

## Conversation history and memory

Each session's data persists locally at:

```
~/.config/safeclaw/sessions/<session-name>/
```

This maps to `/home/sclaw/.claude/projects/` inside the container and includes:

- **Conversations** - JSONL files (one per conversation)
- **Memory** - Auto memory at `-home-sclaw/memory/MEMORY.md`, loaded into the system prompt each conversation

`~/.config/safeclaw` and the history directories in it are readable only by you (mode 0700). safeclaw restricts one that is open to others, and refuses to run with one owned by another user; see [config directory](docs/architecture.md#config-directory).

Rebuilding containers or restarting sessions won't affect your history or memory. A session created again with a different set of secrets keeps it too, with a warning. To start a session with an empty history, pass `--fresh-history` to `run` or `new`, which moves the old one aside to `<session-name>.old-<timestamp>` and recreates the container:

```bash
safeclaw run -s work --no-secrets --fresh-history
```

Image variants and their defaults are configured in `~/.config/safeclaw/config.yaml`, see [image variants](#image-variants).

## Authentication

Tokens and other secrets are stored in the system keychain (the macOS keychain, Secret Service on Linux, or the Windows credential manager) under the `safeclaw` service, and injected as env vars on each run. Each secret's name is the env var name. Where no keychain is available, such as a Linux server without Secret Service, they are stored as files in `~/.config/safeclaw/.secrets/` instead, with a warning. Secrets left in that directory by earlier versions are moved into the keychain the next time safeclaw runs.

| Secret | How to generate |
|--------|-----------------|
| `CLAUDE_CODE_OAUTH_TOKEN` | `safeclaw auth login`, or `claude setup-token` (valid 1 year) |
| `GH_TOKEN` | `gh auth token` or create a PAT at github.com/settings/tokens |

`safeclaw auth login` runs `claude setup-token` in a short-lived container, so Claude Code doesn't need to be installed on the host. Open the URL it prints, sign in, and paste the code back. To store a token without a terminal, pipe it in:

```bash
printf '%s' "$TOKEN" | safeclaw auth set
gh auth token | safeclaw env set GH_TOKEN
```

`safeclaw auth status` shows when the token was set and when it expires, and exits non-zero when there is none or it has expired. It, `safeclaw run`, and the dashboard warn in the last 30 days of the token's year. You can add any other secret with `safeclaw env set NAME` or the `safeclaw env` menu.

Without a terminal, `safeclaw run` doesn't prompt, so it fails like `safeclaw new` when the Claude token is missing.

### Choosing which secrets a session receives

Every bash process in a session can read the secrets it receives. By default a new session receives every secret, including ones added later, but you can limit it:

```bash
safeclaw run -s chat --secrets CLAUDE_CODE_OAUTH_TOKEN    # only the listed secrets
safeclaw run -s offline --no-secrets                      # none
safeclaw run -s chat --all-secrets                        # back to every secret
```

The choice is remembered for the session, so rerunning `safeclaw run -s chat` or starting it from the dashboard keeps it. It is kept with the container, so give it again after `safeclaw rm`. Giving a different set recreates the container, keeping its port, mounts, and variant. Listed secrets must exist. A session that does not receive `CLAUDE_CODE_OAUTH_TOKEN` starts Claude Code logged out, and one that does not receive `GH_TOKEN` gets no git configuration. Sandboxes never receive secrets.

### Sharing the host's IPC namespace

Sessions get a private IPC namespace and `/dev/shm`, so they can't reach the docker host's shared memory. If something in a session needs the host's, opt in with `--host-ipc`:

```bash
safeclaw run -s work --host-ipc          # share the host's IPC namespace
safeclaw run -s work --host-ipc=false    # back to a private one
```

The choice is remembered for the session like its secrets, and changing it recreates the container. See [architecture](docs/architecture.md#ipc-namespace) for details.

## Commands

| Command | Description |
|---------|-------------|
| `safeclaw build` | Build the image from the build context embedded in the binary (`--context .` for a checkout), then each `--variant` and every variant already built. Warns about sessions on an older image; `--recreate` removes them, skipping offline sessions. |
| `safeclaw pull` | Pull `ghcr.io/josegonzalez/safeclaw` for this version and tag it `safeclaw`, then fetch each `--variant` and every variant already present |
| `safeclaw run` | Start/reuse a container, inject auth, start ttyd. `-s name` for named sessions, `-v` for volumes, `--variant` for an image variant, `--secrets`, `--no-secrets`, or `--all-secrets` to choose the secrets it receives, `--host-ipc` to share the host's IPC namespace, `--fresh-history` to move its history aside and start with an empty one, `-n` to skip opening the browser, `-q "question"` to start with a query. |
| `safeclaw new` | Same as `run` but never prompts (used by the dashboard) |
| `safeclaw dashboard` | Web dashboard for managing sessions |
| `safeclaw auth login` | Sign in with `claude setup-token` in a container and store the token |
| `safeclaw auth set` | Store a Claude Code token from stdin (hidden prompt on a terminal) |
| `safeclaw auth status` | Show when the token was set and expires. Exits non-zero when it is missing or expired. |
| `safeclaw auth logout` | Delete the stored Claude Code token |
| `safeclaw env` | Manage secrets in an interactive menu (list, add, delete) |
| `safeclaw env set NAME` | Store a secret from stdin (hidden prompt on a terminal) |
| `safeclaw env ls` | List secret names |
| `safeclaw env rm NAME` | Delete a secret |
| `safeclaw ls` | List sessions and sandboxes |
| `safeclaw url NAME` | Print a running session's terminal URL with its credential. `--open` also opens it, through the dashboard when one is running |
| `safeclaw stop NAME` | Stop a session |
| `safeclaw rm NAME` | Delete a session container (history is kept) |
| `safeclaw attach NAME` | Attach to a session's tmux session in this terminal |
| `safeclaw net off NAME` | Save a session's networks and disconnect it from them. `--owner` names the hold and `--reason` says why. |
| `safeclaw net on NAME` | Release the hold for `--owner` (or the unnamed hold) and reconnect the session once none remain. `--force` releases every hold. |
| `safeclaw sandbox run -s NAME` | Create or start a headless sandbox for untrusted files. `-v` mounts a host directory read-only and can be repeated, `--variant` picks the image variant, `--memory`, `--pids-limit`, `--cpus`, and `--disk` (the size of `/sandbox`) set limits. |
| `safeclaw sandbox run --rm [-s NAME]` | Create a one-off sandbox that is removed when it stops, and print its name |
| `safeclaw sandbox exec NAME -- CMD` | Run a command in a sandbox as the sandbox user (`-i` for stdin, `-t` for a TTY, `--escape-controls` to escape control characters in its output, `--timeout DUR` to stop it after DUR and exit 124, `-e NAME=VALUE` or `-e NAME` to set an environment variable for the command without putting the value in docker's arguments) |
| `safeclaw sandbox exec --ephemeral [-s NAME] -- CMD` | Run a command in a new one-off sandbox that is removed when it exits, returning its exit code. Takes the same `-v`, `--variant`, and limit flags as `sandbox run`, and the same `--timeout` and `-e` as `sandbox exec`. |
| `safeclaw sandbox cp-in NAME FILE...` | Copy regular host files into a running sandbox as `N-name`, owned by the sandbox user, refusing links and other file types. `--to` picks a directory under `/sandbox` (default `/sandbox/in`). |
| `safeclaw sandbox cp-out NAME DIR HOST_DIR --only GLOB` | Copy the regular files directly in a sandbox directory that match an `--only` glob into an existing host directory, dropping links, directories, sparse files, and nested files. Names that are not printable UTF-8 or start with `-` refuse the copy, and hidden files only match a glob starting with `.`. Existing files are refused unless `--force` is given, `--max-size` (default `1g`) caps the total, and `--max-files` (default `1000`) caps the number of files. |
| `safeclaw sandbox ls` | List sandboxes |
| `safeclaw sandbox inspect NAME` | Print a sandbox's status, variant, network, user, capabilities, read-only root, limits including `--disk`, mounts, and safeclaw labels as JSON with a versioned schema |
| `safeclaw sandbox verify NAME` | Check a sandbox's configuration and, when it is running, what the sandbox user sees inside it against the sandbox's isolation guarantees, exiting non-zero and naming the failed checks. `--json` prints the report as JSON. |
| `safeclaw sandbox stop NAME` | Stop a sandbox, emptying its `/sandbox` |
| `safeclaw sandbox rm NAME` | Delete a sandbox |
| `safeclaw variant ls` | List image variants, whether their images exist, and which session types default to them |
| `safeclaw variant dockerfile NAME` | Print the Dockerfile that builds a variant |
| `safeclaw completion SHELL` | Shell completions |
| `safeclaw version` | Version information |

## Aliases

Inside each container, these aliases are available:

| Alias | Command |
|-------|---------|
| `c` | `claude` |
| `cs` | `claude --dangerously-skip-permissions` |

## Skills

Defined in `setup/skills/`.

| Skill | Description |
|-------|-------------|
| yt-dlp | Download YouTube videos, audio, and subtitles/transcripts |
| gdoc | Read publicly shared Google Docs |

## Credits

Originally created by [YK Sugi](https://github.com/ykdojo) as [ykdojo/safeclaw](https://github.com/ykdojo/safeclaw). MIT licensed.
