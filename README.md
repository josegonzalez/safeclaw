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
brew install --cask josegonzalez/repo/safeclaw
# or
go install github.com/josegonzalez/safeclaw/cmd/safeclaw@latest
```

## Quickstart

```bash
# Build the image (once, or after upgrading), or pull the published one
safeclaw build
safeclaw pull

# Start a container and web terminal
safeclaw run

# Mount a local project (host_path:container_path)
safeclaw run -v ~/myproject:/home/sclaw/myproject

# Run multiple sessions with -s
safeclaw run -s work        # safeclaw-work on the next available port
safeclaw run -s research    # safeclaw-research on the next available port
```

On first run, `safeclaw run` prompts you to set up authentication tokens. It then starts a web terminal at http://localhost:7681 and opens it in your browser.

## Dashboard

```bash
safeclaw dashboard
```

Opens at http://localhost:7680 with:

- Create new sessions with volume mounts and initial queries
- All sessions listed with start/stop/delete controls
- Live iframe views of active sessions, updated as containers change

## What's included

- Ubuntu 26.04
- Node.js 26 (LTS)
- Claude Code 2.1.332
- GitHub CLI with auto-configured git user
- Playwright MCP 0.0.86 with Chromium
- [DX plugin](https://github.com/ykdojo/claude-code-tips#tip-44-install-the-dx-plugin), [custom status line](https://github.com/ykdojo/claude-code-tips#tip-0-customize-your-status-line), [shell aliases](#aliases)
- ttyd web terminal + tmux

## Sensible defaults

- Claude Code version pinned (currently 2.1.332)
- `autoCompactEnabled: false` - prevents automatic context compaction
- `promptSuggestionEnabled: false` - disables prompt suggestions
- `--dangerously-skip-permissions` enabled (because it's containerized), with the home folder trust and bypass permissions prompts pre-accepted

## Conversation history and memory

Each session's data persists locally at:

```
~/.config/safeclaw/sessions/<session-name>/
```

This maps to `/home/sclaw/.claude/projects/` inside the container and includes:

- **Conversations** - JSONL files (one per conversation)
- **Memory** - Auto memory at `-home-sclaw/memory/MEMORY.md`, loaded into the system prompt each conversation

Rebuilding containers or restarting sessions won't affect your history or memory.

## Authentication

Tokens are stored in `~/.config/safeclaw/.secrets/` and injected as env vars on each run. The filename becomes the env var name.

| File | How to generate |
|------|-----------------|
| `CLAUDE_CODE_OAUTH_TOKEN` | `claude setup-token` (valid 1 year) |
| `GH_TOKEN` | `gh auth token` or create a PAT at github.com/settings/tokens |

You can add any additional secrets with `safeclaw env` or by creating files in the `.secrets/` directory.

## Commands

| Command | Description |
|---------|-------------|
| `safeclaw build` | Build the image from the build context embedded in the binary (`--context .` for a checkout). Warns about sessions on an older image; `--recreate` removes them. |
| `safeclaw pull` | Pull `ghcr.io/josegonzalez/safeclaw` for this version and tag it `safeclaw` |
| `safeclaw run` | Start/reuse a container, inject auth, start ttyd. `-s name` for named sessions, `-v` for volumes, `-n` to skip opening the browser, `-q "question"` to start with a query. |
| `safeclaw new` | Same as `run` but never prompts (used by the dashboard) |
| `safeclaw dashboard` | Web dashboard for managing sessions |
| `safeclaw env` | Manage environment variables (list, add, delete) |
| `safeclaw ls` | List sessions |
| `safeclaw stop NAME` | Stop a session |
| `safeclaw rm NAME` | Delete a session container (history is kept) |
| `safeclaw attach NAME` | Attach to a session's tmux session in this terminal |
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
