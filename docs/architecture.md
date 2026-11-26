# Architecture

## Overview

SafeClaw runs Claude Code inside a sandboxed Docker container, accessible via a web terminal. All authentication is handled via environment variables, making it easy to deploy locally or in the cloud.

Everything on the host is one Go binary, `safeclaw`. It talks to Docker by running the `docker` CLI with argument lists (never through a shell), so it works with any Docker-compatible CLI. The same binary is compiled into the image, where ttyd runs its hidden `safeclaw ttyd-wrapper` subcommand.

## Web terminal

The user interacts with Claude Code through a browser, not a local terminal. This gives full access to the native Claude Code UI rather than building a custom one on top of the Agent SDK.

- **ttyd** serves a web terminal over HTTP/WebSocket on port 7681 inside the container, published on `127.0.0.1` at the first free port from 7681 up
- **tmux** manages the Claude Code session inside the container (session `main`)
- `safeclaw ttyd-wrapper` creates the tmux session and starts `claude --dangerously-skip-permissions` if it doesn't exist, then attaches
- One port, one ttyd process, one tmux session per container

Containers created from the upstream image don't contain the `safeclaw` binary, so `run` falls back to their `/home/sclaw/ttyd-wrapper.sh`.

## Session lifecycle

`safeclaw run` (and the dashboard's create and start) all go through the same code path:

1. Check the image exists and the Claude token is present (prompting for it only in `run`)
2. Reuse the container's existing port, or pick the lowest port no `safeclaw-*` container reserves and nothing on the host is listening on
3. Create, start, or refresh the container. With `-v`, an existing container is recreated with the new mount. A running container has ttyd and tmux restarted so new env vars take effect
4. Write `/home/sclaw/.env` from the secrets directory
5. Configure git from the GitHub account if `GH_TOKEN` is set
6. Start ttyd, and with `-q`, wait for Claude Code's input prompt before sending the query

## Sandboxes

`safeclaw sandbox run -s NAME` creates a headless container for opening untrusted files with `docker exec`, for example extracting text from PDFs, archives, or emails that have not been checked. It shares the `safeclaw-NAME` namespace with interactive sessions and is marked with the `safeclaw.type=sandbox` label. Containers without the label are interactive sessions.

A sandbox is created with none of what an interactive session gets: no secrets are written and no Claude token is needed, there is no git configuration, no ttyd, tmux, or Claude Code, no published port, no `--ipc=host`, and no history mount. Instead it runs with:

- `--network none`, so loopback is the only interface
- `--user sandbox`, an unprivileged, non-login user (uid 2000) whose home and working directory is `/sandbox`. `/home/sclaw` is mode 700, so it can't be read
- `--cap-drop ALL` and `--security-opt no-new-privileges`
- `--read-only`, with a 256 MB tmpfs at `/tmp` and an anonymous volume at `/sandbox`. `docker cp` works into the volume, and removing the sandbox removes the volume too
- `--memory 1g`, `--pids-limit 256`, and `--cpus 1` by default, changeable with flags of the same name
- `HOME=/sandbox`, an empty `BASH_ENV`, and a `PATH` without sclaw's `~/.local/bin`

With `-v`, a host directory is mounted read-only, whatever options the spec carries. Rerunning `sandbox run` starts a stopped sandbox or leaves a running one alone, and `-v` or any limit flag recreates it.

The two types are kept apart. `safeclaw run`, the dashboard's start, and the API refuse a sandbox name, `safeclaw stop`, `rm`, and `attach` refuse sandboxes, and the `safeclaw sandbox` commands refuse interactive sessions. `safeclaw ls` lists both with a TYPE column, and `safeclaw sandbox ls` lists only sandboxes.

## Authentication

All secrets are stored on the host in `~/.config/safeclaw/.secrets/`. Each file becomes an environment variable (filename = env var name).

### How env vars are passed

1. `safeclaw run` renders every secret as `export NAME='value'` (shell-quoted) and pipes it into the container over stdin, writing `/home/sclaw/.env` with mode 600. Secret values never appear in process arguments.
2. `BASH_ENV=/home/sclaw/.env` (set in the Dockerfile) ensures every bash invocation sources it
3. `.bashrc` also sources `.env` for interactive shells

This means env vars are available everywhere - interactive shells, Claude's bash commands, and `docker exec bash -c` commands.

### Claude Code

The token from `claude setup-token` is stored as `CLAUDE_CODE_OAUTH_TOKEN`. The Dockerfile sets `hasCompletedOnboarding: true` in `.claude.json` to skip the onboarding flow. Without this, interactive mode ignores the token and shows the login screen ([known issue](https://github.com/anthropics/claude-code/issues/8938)). It also pre-accepts the home folder trust prompt and the bypass permissions prompt, which newer Claude Code versions show on every start.

Known limitation: the token from `setup-token` has limited scopes (`user:inference` only), so `/usage` doesn't work and the status bar shows "Claude API" instead of the subscription name ([#11985](https://github.com/anthropics/claude-code/issues/11985)). Chat works fine.

### GitHub CLI

`GH_TOKEN` is used for GitHub CLI authentication. On container start, `run` also configures the git user (name and email) from the GitHub account.

We recommend creating a separate GitHub account for SafeClaw so you can scope its permissions independently.

## Image

The image has two users: `sclaw`, who runs Claude Code and owns `/home/sclaw` (mode 700), and `sandbox`, the non-login user sandboxes run as. The Dockerfile is multi-stage. The first stage builds the `safeclaw` binary from the Go source; the second is the runtime image. The Dockerfile, `setup/`, and the Go source are embedded in the binary, so `safeclaw build` works from any directory. Tagged releases also publish a multi-arch image to `ghcr.io/josegonzalez/safeclaw`, which `safeclaw pull` fetches and tags locally as `safeclaw`.
