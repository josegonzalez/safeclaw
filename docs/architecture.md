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

## Dashboard access

The dashboard listens on `127.0.0.1`, but that only keeps other machines out: code inside a session container can reach host loopback through the runtime's host gateway on some runtimes (observed on OrbStack via `host.docker.internal`), and any local process can connect too. Every route therefore needs a token that `safeclaw dashboard` makes with `crypto/rand` each time it starts:

- The printed URL, `http://127.0.0.1:PORT/?token=...`, swaps the token for an HttpOnly, SameSite=Strict cookie named `safeclaw_dashboard_PORT` and redirects to the same URL without it, so the token leaves the address bar and history
- API clients send `Authorization: Bearer TOKEN`, reading the token from `~/.config/safeclaw/dashboard/PORT.token` (honoring `XDG_CONFIG_HOME`). The directory is 0700 and the file 0600; it is replaced on start and removed on exit
- Anything else, static files included, gets 401 before any session or docker call. Tokens are compared in constant time

The cookie is only ever set for `127.0.0.1`, and the token URL on `localhost` or `::1` first redirects there. Cookies aren't scoped by port, and session terminals are served from inside their containers at `localhost:PORT`, so a cookie for `localhost` would be sent to every session's ttyd. Restarting the dashboard makes a new token, so open the newly printed URL again.

The `Host` check (against DNS rebinding) and `http.CrossOriginProtection` (against other websites driving the dashboard from your browser) still apply on top of the token.

## Session lifecycle

`safeclaw run` (and the dashboard's create and start) all go through the same code path:

1. Pick the [image variant](#image-variants) and check its image exists, pick the [secrets](#choosing-secrets) the session receives, then check that the Claude token is present if the session receives it (prompting for it only in `run`) and that every listed secret exists
2. Reuse the container's existing port, or pick the lowest port no `safeclaw-*` container reserves and nothing on the host is listening on
3. Create, start, or refresh the container. With `-v`, a `--variant` other than the container's, a different set of secrets, or a different [`--host-ipc`](#ipc-namespace) choice, an existing container is recreated, keeping its port and whichever of its mount, variant, secrets, and IPC choice were not given again. Every volume is checked before the old container is removed, and if the new one can't be created, the old one is created again with its port, mounts, variant, secrets, and IPC choice, so a failed recreate never loses the session's secret set. A running container has ttyd and tmux restarted so new env vars take effect. An [offline](#offline-sessions) session is never recreated, and starting it keeps it offline
4. Write `/home/sclaw/.env` from the secrets the session receives
5. Configure git from the GitHub account if the session receives `GH_TOKEN`
6. Start ttyd, and with `-q`, wait for Claude Code's input prompt before sending the query

### IPC namespace

A session gets docker's default private IPC namespace and its own `/dev/shm`, so code Claude Code runs can't see or attach to the docker host's shared memory, semaphores, or message queues. On a native Linux docker host that is the real host's; on Docker Desktop or OrbStack it is the Linux VM's. No `--shm-size` is set: Playwright starts Chromium with `--disable-dev-shm-usage`, so the browser works with docker's default 64 MB `/dev/shm`.

`--host-ipc` on `run` or `new` opts a session into `--ipc=host`, recorded in the `safeclaw.ipc=host` label so recreates keep it, and `--host-ipc=false` moves it back to a private namespace. Sessions created before private namespaces became the default share the host's without the label: `run` keeps them as they are with a warning, `--host-ipc=false` or `--host-ipc` recreates them with that choice, and any other recreate gives them a private namespace.

## Sandboxes

`safeclaw sandbox run -s NAME` creates a headless container for opening untrusted files with `docker exec`, for example extracting text from PDFs, archives, or emails that have not been checked. It shares the `safeclaw-NAME` namespace with interactive sessions and is marked with the `safeclaw.type=sandbox` label. Containers without the label are interactive sessions.

A sandbox is created with none of what an interactive session gets: no secrets are written and no Claude token is needed, there is no git configuration, no ttyd, tmux, or Claude Code, no published port, no option to share the host's IPC namespace, and no history mount. Instead it runs with:

- `--network none`, so loopback is the only interface
- `--user sandbox`, an unprivileged, non-login user (uid 2000) whose home and working directory is `/sandbox`. `/home/sclaw` is mode 700, so it can't be read
- `--cap-drop ALL` and `--security-opt no-new-privileges`
- `--read-only`, with a 256 MB tmpfs at `/tmp` and an anonymous volume at `/sandbox`. Files are copied into the volume with [`sandbox cp-in`](#copying-files), and removing the sandbox removes the volume too
- `--memory 1g`, `--pids-limit 256`, and `--cpus 1` by default, changeable with flags of the same name
- `HOME=/sandbox`, an empty `BASH_ENV`, and a `PATH` without sclaw's `~/.local/bin`

`safeclaw sandbox exec`, with or without `--ephemeral`, runs its command as `/bin/sh -c 'umask 022; exec "$@"' sh CMD...`, so files it creates are not world-writable whatever umask docker gives the command. Some Docker versions start `docker exec` processes with a umask of `0000` instead of the container's. The command and its arguments are passed to the shell as positional parameters, so they reach the command exactly as given.

With `-v`, a host directory is mounted read-only, whatever options the spec carries. Rerunning `sandbox run` starts a stopped sandbox or leaves a running one alone, and `-v`, any limit flag, or a `--variant` other than the sandbox's recreates it. The new sandbox keeps whichever of the old one's mount, variant, and limits were not given again.

Sandboxes run the `sandbox` [image variant](#image-variants) unless the config file or `--variant` says otherwise, so the document extraction tools are already installed and never need the network or root.

The two types are kept apart. `safeclaw run`, the dashboard's start, and the API refuse a sandbox name, `safeclaw stop`, `rm`, and `attach` refuse sandboxes, and the `safeclaw sandbox` commands refuse interactive sessions. `safeclaw ls` lists both with a TYPE column, and `safeclaw sandbox ls` lists only sandboxes.

### Copying files

`safeclaw sandbox cp-in` and `safeclaw sandbox cp-out` move files into and out of a running sandbox without `docker cp`, which runs as root on the daemon side, leaves root-owned files with the host's mode, and copies whatever it is pointed at. Both stream a tar that safeclaw writes or reads itself through `docker exec --user sandbox` and the image's `/usr/bin/tar`, so a copy can only read and write what the sandbox user can, and a symlink planted by the untrusted side can't make it read `/home/sclaw` or anything else root can. A stopped sandbox is refused.

The sandbox side also controls what those commands write to stderr, and part of their stdout. Only the last 64 KiB of any docker command's stderr is kept, a command whose stdout safeclaw buffers (rather than streams, as cp-out's tar is) fails once it passes 64 MiB, and docker errors and every error the CLI prints have control characters escaped: anything `unicode.IsPrint` rejects other than newline and tab, including raw 8-bit C1 bytes, is written as a Go escape such as `\x1b`, so container output never reaches the terminal as escape sequences.

`cp-in NAME FILE...` checks every file before sending any: symbolic links and anything that is not a regular file are refused, and each file is opened without following links and checked to be the same file that was inspected. Files land in `--to` (default `/sandbox/in`, and always under `/sandbox`) as `N-name`, with N continuing after the highest number already there, so files with the same name from different folders never overwrite each other. The numbers are picked under a lock file in `~/.config/safeclaw/copy/`, and tar's `-k` refuses to overwrite anything regardless. Since the sandbox user extracts them, the files are owned by uid 2000, with mode 644. Each container path is printed, in the order given, and a path that is not printable text (a host file name with a newline or terminal escape, say) is printed as a Go-quoted string so it stays on one line and never reaches the terminal as escapes.

`cp-out NAME DIR HOST_DIR --only GLOB` keeps only the regular files directly in DIR whose names match one of the (repeatable) `--only` globs. Symbolic links, hard links, directories, devices, and anything in a subdirectory are dropped, and a name that appears twice is an error. GNU sparse entries are dropped too, since the tar reader would expand them to their logical size, so a tiny stream can't fill the host disk even with `--max-size 0`; the image's tar never writes them, since it isn't given `--sparse`. Since the names come from the untrusted side, a kept file whose name is not valid UTF-8, contains anything `unicode.IsPrint` rejects (control characters such as newlines and terminal escapes, format characters such as bidi overrides, and spaces other than a plain space), or starts with `-` refuses the whole copy, with an error naming it quoted. As in a shell, a name starting with `.` only matches a glob that starts with `.` too, so `--only '*'` never brings back hidden files such as `.envrc` - ask for them with a glob such as `.envrc` or `.*`. HOST_DIR must exist. Files are written to a temporary directory inside it with mode 644 (less the umask), and nothing is moved into place until the whole stream has arrived, stays within `--max-size` (default `1g`, `0` for no limit) and `--max-files` (default `1000`, `0` for no limit; empty files are free against `--max-size`, so this is what stops a sandbox from planting any number of them), and none of the names already exist. Without `--force` each file is moved with a rename that refuses to replace, so a file created in the meantime is never overwritten. `--force` replaces existing files, and a symlink itself rather than its target, but never a directory. Each host path written is printed, quoted like cp-in's when it is not printable.

### One-off sandboxes

A one-off sandbox lives for exactly one job, so callers sharing the host need no locking, no detection of a sandbox recreated under the same name, and no per-job cleanup. If something removes one mid-job, the job is simply run again. One-off sandboxes are created with docker's `--rm`, so docker itself removes the container and its `/sandbox` volume when it stops, and they get the same isolation, limits, and read-only `-v` as any other sandbox. Without `-s` they get a random `tmp-<8 hex>` name, and a name any container already has is refused rather than reused.

- `safeclaw sandbox exec --ephemeral -- CMD` checks the image and name, then replaces itself with `docker run --rm --init` in the foreground. Cleanup does not depend on safeclaw staying alive, the command's exit code is returned as is, `--init` forwards signals to the command instead of leaving it as PID 1, and nothing but the command writes to stdout
- `safeclaw sandbox run --rm` creates a detached one-off sandbox for jobs with several steps (`sandbox cp-in`, several `sandbox exec` calls, then `sandbox cp-out`). Progress goes to stderr and only its name to stdout, and `safeclaw sandbox stop` removes it

`safeclaw sandbox ls` marks them in a ONE-OFF column, and `safeclaw ls` lists their type as `sandbox (one-off)`.

## Offline sessions

`safeclaw net off NAME` takes an interactive session off the network while it handles something untrusted, and `safeclaw net on NAME` brings it back. Taking a session offline disconnects it from every network it is attached to, which also takes down its ttyd web terminal, since the published port belongs to the container's network. Claude Code keeps running but can't reach the API until the session is back.

The networks are saved before anything is disconnected, along with any aliases, static addresses, and links (leaving out the aliases docker adds itself), so `net on` restores exactly those. The state is kept in `~/.config/safeclaw/network/NAME.json` (honoring `XDG_CONFIG_HOME`), not in the session's history directory, because that directory is mounted into the container. It records the container ID, so state left by a session that was removed and recreated under the same name, for example by `safeclaw rm` or `safeclaw build --recreate`, is ignored and deleted rather than applied to the new container. Without saved state, for example after a raw `docker network disconnect`, `net on` reconnects the session to the network it was created with (`bridge`).

Each `net off` records a hold with its `--owner`, an optional `--reason`, and when it was taken. Without `--owner` it takes the unnamed hold, which every caller without an owner shares. Taking an offline session offline again adds a hold, or updates the same owner's, and keeps the saved networks. `net on` releases only the hold for its `--owner` (or the unnamed one), fails if other owners hold the session and it holds nothing, and reconnects the session only once no holds remain, so one job can't bring a session back online while another still relies on it being offline. `--force` releases every hold. Every network change and state write happens under one lock file in that directory, so concurrent safeclaw processes don't interleave.

The status comes from docker: a session attached to no network is offline. `safeclaw ls` shows it in a NETWORK column (`online`, `offline` with its holders, `none` for sandboxes, or `host`), and the dashboard shows an `offline` badge.

While a session is offline:

- `run` and the dashboard's start still start or refresh it, warning that the web terminal is unreachable, and a started session is disconnected again if docker attached any network
- `run` refuses to recreate it for a new `-v`, `--variant`, set of secrets, or `--host-ipc` choice, so it can't come back online as a new container
- `safeclaw build --recreate` skips it, and the stale report marks it `(offline)`
- `safeclaw rm` removes its saved state along with the container

Sessions using host networking, or sharing another container's network, can't be disconnected, so `net off` refuses them. Sandboxes always run with `--network none`, so the `net` commands refuse them too.

## Image variants

An image variant is the base `safeclaw` image with extra apt packages or `run` commands, tagged `safeclaw:NAME`. Variants come from two places:

- built in: `sandbox` adds poppler-utils, tesseract-ocr and tesseract-ocr-eng, 7zip, and file
- `~/.config/safeclaw/config.yaml` (honoring `XDG_CONFIG_HOME`), whose `variants` map adds variants or replaces a built-in of the same name, and whose `defaults` pick the variant each session type uses when none is given (`base` for sessions and `sandbox` for sandboxes unless set)

The config file is decoded strictly, so unknown keys are errors. Names are lowercase and may not be `base`, which means the base image, or `latest`. Package names are checked, and `run` commands are one line each and run as root. The file is read whenever a variant is resolved, so the dashboard sees edits without a restart, and commands that don't resolve variants, like `ls`, `stop`, and `rm`, don't read it.

Each variant is built from a generated Dockerfile (`safeclaw variant dockerfile NAME`) that starts `FROM` the image in its `BASE` build argument, the local `safeclaw` image by default, installs the packages and runs the commands as root, then switches back to `sclaw` and labels the image `safeclaw.variant=NAME`. `safeclaw build` builds the base image, then each `--variant` and every variant already present locally, so no variant is left on an older base. `safeclaw pull` does the same with the published images: the unmodified built-ins are pulled from `ghcr.io/josegonzalez/safeclaw:<version>-NAME` (`:NAME` for latest), and variants from the config file are built on the pulled base.

Containers on a variant carry the `safeclaw.variant=NAME` label; containers without it run the base image. An existing container keeps its variant unless `--variant` names a different one, which recreates it. A missing variant image is an error naming the `pull` and `build` commands that fetch it, and after a build or pull, containers whose variant image changed or no longer exists are reported as stale.

## Authentication

All secrets are stored on the host, and each becomes an environment variable of the same name.

### Where secrets are stored

Secrets are kept in the system keychain with [go-keyring](https://github.com/zalando/go-keyring): the macOS keychain, Secret Service on Linux, or the Windows credential manager. Each secret is an item under the `safeclaw` service, with the env var name as its account. The keychain can't list items or say when they were written, so a reserved `.index` item holds each secret's name and the time it was set. `~/.config/safeclaw/secrets.lock` is locked while the index changes, so the CLI and dashboard don't lose each other's writes. On macOS, values are passed to `security` on stdin, not in its arguments.

If the keychain can't be read, such as on a Linux server without Secret Service, secrets fall back to files in `~/.config/safeclaw/.secrets/` (one 0600 file per secret, named after it, with its modification time as the set time), with a warning. Only regular files are secrets: the store checks each name itself and opens files with `O_NOFOLLOW`, so a symlink, directory, or FIFO in the directory is treated as not set, and a name like `../x` is refused. A secret is written to a new 0600 temp file in the directory and renamed into place, so it never takes an older file's mode and replaces a symlink rather than writing through it. The directory is created with mode 700, and an existing one with looser permissions is tightened to 700 when the store is opened or written. When the keychain is available, files left there by earlier versions are moved into it with their modification times, deleted, and the directory removed once empty. Files whose names aren't valid env var names are left in place.

### How env vars are passed

1. `safeclaw run` renders each secret the session receives as `export NAME='value'` (shell-quoted) and pipes it into the container over stdin, writing `/home/sclaw/.env` with mode 600. Secret values never appear in process arguments.
2. `BASH_ENV=/home/sclaw/.env` (set in the Dockerfile) ensures every bash invocation sources it
3. `.bashrc` also sources `.env` for interactive shells

This means env vars are available everywhere - interactive shells, Claude's bash commands, and `docker exec bash -c` commands.

### Choosing secrets

Because every bash process in a session can read `.env`, each session can be limited to the secrets it needs. `--secrets A,B` writes only the listed secrets, `--no-secrets` writes none, and `--all-secrets` writes every secret, including ones added later. New sessions get every secret unless told otherwise.

The choice is recorded in the `safeclaw.secrets` container label as comma-separated names, so the container itself can't change it. Containers without the label, including ones created before it existed, get every secret, and an empty label means none. Without a flag, `run` and the dashboard's start keep the container's set; a different one recreates the container, since labels can't change. The choice lives only in the label, so a session whose container was removed (for example by `safeclaw rm` or `safeclaw build --recreate`) gets every secret when it is created again without a flag, with a warning when its history directory shows it existed before.

`.env` is replaced on every run, so secrets left out of the set are removed from it. Names given on a run must be stored secrets, by the same rule used when `.env` is written, so an entry the store doesn't count as a secret fails the run instead of being skipped (after prompting for the Claude and GitHub tokens, if the session receives them). A remembered name that has since been deleted is skipped with a warning, so the session still starts. Tokens the session doesn't receive are neither required nor prompted for. Without `CLAUDE_CODE_OAUTH_TOKEN`, a warning says Claude Code won't be logged in.

Sandboxes never receive secrets, whatever their labels say.

### Claude Code

The token from `claude setup-token` is stored as `CLAUDE_CODE_OAUTH_TOKEN`. `safeclaw auth login` creates it without Claude Code on the host: it starts a container from the base image with no secrets, mounts, or ports, labeled `safeclaw.auth` with the PID of the safeclaw process, and runs `claude setup-token` there under `script`, attached to the terminal. The sign-in can't call back to the host, so Claude Code prints a URL and asks for the code shown after signing in. Once it exits, the recording is read back and deleted from the container right away, terminal escapes are stripped, the last `sk-ant-oat01-` token is stored, and the container is removed. A login killed before cleaning up leaves its container behind; every `safeclaw auth` command removes containers whose PID is no longer running, with one `docker ps`. `safeclaw auth set` and `safeclaw env set NAME` read a value from stdin (or a hidden prompt on a terminal), so values never appear in process arguments.

Tokens are valid for a year, and the token doesn't say when it was made, so the expiry is estimated from when it was stored. `auth status`, `run` (for sessions that receive the token), and a dashboard banner warn in the last 30 days, and once it has expired. `run` only prompts for missing tokens when stdin is a terminal; otherwise it fails like `new`, with an error naming `safeclaw auth login` and `safeclaw auth set`.

The Dockerfile sets `hasCompletedOnboarding: true` in `.claude.json` to skip the onboarding flow. Without this, interactive mode ignores the token and shows the login screen ([known issue](https://github.com/anthropics/claude-code/issues/8938)). It also pre-accepts the home folder trust prompt and the bypass permissions prompt, which newer Claude Code versions show on every start.

Known limitation: the token from `setup-token` has limited scopes (`user:inference` only), so `/usage` doesn't work and the status bar shows "Claude API" instead of the subscription name ([#11985](https://github.com/anthropics/claude-code/issues/11985)). Chat works fine.

### GitHub CLI

`GH_TOKEN` is used for GitHub CLI authentication. On container start, `run` also configures the git user (name and email) from the GitHub account.

We recommend creating a separate GitHub account for SafeClaw so you can scope its permissions independently.

## Image

The image has two users: `sclaw`, who runs Claude Code and owns `/home/sclaw` (mode 700), and `sandbox`, the non-login user sandboxes run as. The Dockerfile is multi-stage. The first stage builds the `safeclaw` binary from the Go source; the second is the runtime image. The Dockerfile, `setup/`, and the Go source are embedded in the binary, so `safeclaw build` works from any directory. Tagged releases also publish a multi-arch image to `ghcr.io/josegonzalez/safeclaw`, which `safeclaw pull` fetches and tags locally as `safeclaw`, along with the built-in [variants](#image-variants), built on top of it.
