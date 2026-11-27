# Architecture

## Overview

SafeClaw runs Claude Code inside a sandboxed Docker container, accessible via a web terminal. All authentication is handled via environment variables, making it easy to deploy locally or in the cloud.

Everything on the host is one Go binary, `safeclaw`. It talks to Docker by running the `docker` CLI with argument lists (never through a shell), so it works with any Docker-compatible CLI. The same binary is compiled into the image, where ttyd runs its hidden `safeclaw ttyd-wrapper` subcommand.

## Web terminal

The user interacts with Claude Code through a browser, not a local terminal. This gives full access to the native Claude Code UI rather than building a custom one on top of the Agent SDK.

- **ttyd** serves a web terminal over HTTP/WebSocket on port 7681 inside the container, published on `[::1]` at the first free port from 7681 up
- **tmux** manages the Claude Code session inside the container (session `main`)
- `safeclaw ttyd-wrapper` creates the tmux session and starts `claude --dangerously-skip-permissions` if it doesn't exist, then attaches
- One port, one ttyd process, one tmux session per container

Containers created from the upstream image don't contain the `safeclaw` binary, so `run` falls back to their `/home/sclaw/ttyd-wrapper.sh`.

### Umask

Some Docker versions start `docker exec` processes with a umask of `0000` instead of the container's, and safeclaw starts everything in a session with `docker exec`. So ttyd is started under `umask 022`, and `safeclaw ttyd-wrapper` sets it again before it runs tmux, which covers `run -q` starting the tmux session without ttyd. The tmux server, every shell in it, and Claude Code inherit it, so files they create, including in the history mount on the host, are not world-writable. `safeclaw attach` only runs a tmux client, so its shells come from the same server. The legacy tmux script and the git config script run under `umask 022` too, and the env file and the terminal credential are written under `umask 077`. A running session picks this up on its next `run`, which restarts ttyd and tmux.

### Attaching from the host

`safeclaw attach NAME` runs `docker exec -it safeclaw-NAME tmux attach -t main`, but not on the host terminal. The tmux server runs as `sclaw`, the same user as Claude Code and everything it starts, so code in the session can change any tmux option and make tmux send attached clients anything, such as an OSC 52 clipboard write from `tmux set-buffer -w` or a pane's sequence wrapped in tmux passthrough. So `attach` puts the host terminal in raw mode, runs docker on a pseudo-terminal of its own, copies keystrokes to it, resizes it when the host terminal is resized, and passes its output to the host terminal through a filter that drops:

- OSC sequences other than window titles (0, 1, 2), hyperlinks (8), and default and cursor colours (10, 11, 12, and the resets 104, 110, 111, 112), which drops OSC 52 clipboard writes and reads. An allowed OSC is dropped too when it is longer than 8 KiB or holds a control character
- DCS, SOS, PM, and APC strings, which drops tmux passthrough, terminal capability queries, and graphics and terminal-specific commands carried in them
- CSI `t` window operations other than the size reports and the title stack (14, 15, 16, 18, 19, 22, 23), so the session can't move, resize, or iconify the host window or read its title
- C1 control bytes, raw or UTF-8 encoded

Text, colours, cursor movement, the alternate screen, mouse and bracketed paste modes, and queries whose replies go back to the session pass through unchanged. The session can't set the host clipboard, so tmux copy mode only copies into tmux's own buffers. The dashboard's session info dialog gives the `safeclaw attach NAME` command for the same reason, rather than the raw `docker exec`, which would connect the host terminal to tmux directly.

`safeclaw ttyd-wrapper` also starts the tmux server with `set-clipboard off` and `allow-passthrough off`, so programs that leave those options alone don't send clipboard writes or passthrough to any client, including the web terminal. That is not the control: code in the session can turn both back on.

### Terminal credential

The published port is not private to the session's owner: other session containers can reach it through the runtime's host gateway or the default bridge, and so can any local process or a browser page allowed to open a WebSocket to loopback. So ttyd runs with `-c` and `-O`:

- `-c` requires a per-session credential, user `safeclaw` and a password made with `crypto/rand` the first time the session starts. It is kept in `~/.config/safeclaw/ttyd/NAME` (honoring `XDG_CONFIG_HOME`), a 0600 file in a 0700 directory, outside the history directory that is mounted into the container. It is never followed through a symlink, survives ttyd and container restarts, and is removed with `safeclaw rm`. Every new container for the name gets a new one, including a recreate and a run after `safeclaw build --recreate`: the old container's processes could read the credential from its file in the container, and a recreate can give the session wider secrets, so the old credential must not open the new terminal. It is replaced only once no container has the name, before the new container's ttyd starts, so the file never disagrees with a running ttyd, and a container restored after a failed recreate gets the new one when its ttyd next starts
- The credential reaches ttyd without appearing on a host command line: it is written to `/home/sclaw/.ttyd-credential` in the container on stdin, and ttyd is started through `sh -c` reading that file
- `-O` refuses WebSocket clients whose `Origin` doesn't match the `Host` they connected to

ttyd checks the credential twice: as basic auth on every HTTP request and the WebSocket upgrade, and as the `AuthToken` in the WebSocket's first message, which its own page fetches from `/token`.

Once a browser has opened the URL with the credential, it keeps sending that credential to the session's port, and the page it gets passes `-O` because the page's own origin is the session's. Any other page on loopback, such as another session that replaced its own ttyd, could otherwise frame it invisibly and pass the user's keystrokes through to the session. So the image's ttyd is built from source with `setup/ttyd/refuse-framing.patch`, which makes every response it sends headers for, the index page, `/token`, the base-path redirect and the 401 alike, carry `X-Frame-Options: DENY` and `Content-Security-Policy: frame-ancestors 'none'`. The browser then refuses to render the terminal inside a frame on any page, without relying on the page's script. The patch needs no flag, so the same ttyd arguments work with older images, whose ttyd lacks it until the image is updated and the session recreated. Nothing needs to frame ttyd: the dashboard's frames show its own terminal page and relay the WebSocket, see [dashboard access](#dashboard-access).

`safeclaw run` prints the session URL with the credential in it, `http://safeclaw:PASSWORD@[::1]:PORT`, so the browser logs in to ttyd directly, and `safeclaw url NAME` prints it again for a running, online session without touching it. `safeclaw ls` shows the URL without it.

Opening a browser hands the URL to `open` or `xdg-open`, whose command line other local users can read, and the browser keeps it in its history. So `run` and `safeclaw url NAME --open` first look for a running dashboard: for each token file in `~/.config/safeclaw/dashboard/` (the default port first, read without following symlinks), they send `http://127.0.0.1:PORT/dashboard-proof` a random nonce, never the token, with a one second timeout and no proxy, and check that the answer is HMAC-SHA256 of the port and nonce keyed by the file's token. The first dashboard that proves it holds its file's token has its terminal page, `http://127.0.0.1:PORT/sessions/NAME/terminal`, opened, which carries no credential and needs the dashboard's own login, so a browser that isn't logged in gets the dashboard's 401 page. A file left by a dashboard that has exited fails the proof, even when another local user took over its port, and is skipped and removed. See [finding the dashboard](dashboard.md#finding-the-dashboard). With no dashboard answering, they open the URL with the credential and print a warning. `run` doesn't open an offline session's terminal, which is unreachable. The dashboard never sends the browser to the session's port; it proxies the terminal instead, see [dashboard access](#dashboard-access).

Sessions are published on `[::1]` rather than `127.0.0.1` because `127.0.0.1` is where the dashboard's cookie is set, and cookies aren't scoped by port. Code in a session runs as the same user as its ttyd, so it can replace ttyd with any server on that port; if the browser were ever sent to `http://127.0.0.1:PORT`, that server would get the dashboard's cookie. With the port on `[::1]`, nothing a session controls listens on `127.0.0.1`. Session URLs name `[::1]` too, rather than `localhost`: a browser sends a page on `localhost` every cookie other local web apps set for `localhost`, and may connect to `127.0.0.1` for it, where nothing holds the session's port and another local user could listen. The image's ttyd is also built with `setup/ttyd/bracketed-ipv6-origin.patch`, because upstream ttyd's origin check strips the brackets from `Origin` but not from `Host`, so it never passes for `[::1]:PORT`. The image carries the label `io.github.josegonzalez.safeclaw.ttyd-bracketed-host`; sessions made from an image without it keep `localhost` URLs, and `run` warns about them until the image is updated and the session recreated. Sessions created before terminals moved to `[::1]` keep `127.0.0.1`, which their URLs name, until they are recreated, and `run` warns about them.

## Dashboard access

The dashboard listens on `127.0.0.1`, and holds `[::1]` on the same port too so no other local user can take the `[::1]` side of `localhost:PORT`, but that only keeps other machines out: code inside a session container can reach host loopback through the runtime's host gateway on some runtimes (observed on OrbStack via `host.docker.internal`), and any local process can connect too. Every route therefore needs a token that `safeclaw dashboard` makes with `crypto/rand` each time it starts:

- The printed URL, `http://127.0.0.1:PORT/?token=...`, swaps the token for an HttpOnly, SameSite=Strict cookie named `safeclaw_dashboard_PORT` and redirects to the same URL without it, so the token leaves the address bar and history. The cookie holds a separate random value that the dashboard keeps in memory, not the token, so it only works as that cookie and only until the dashboard stops
- API clients send `Authorization: Bearer TOKEN`, reading the token from `~/.config/safeclaw/dashboard/PORT.token` (honoring `XDG_CONFIG_HOME`). The directory is 0700 and the file 0600; it is replaced on start and removed on exit, including on SIGHUP
- Anything else, static files included, gets 401 before any session or docker call. Tokens are compared in constant time

The cookie is only ever set for `127.0.0.1`, and the token URL on `localhost` first redirects there. Any other `Host`, `::1` included, is refused. Cookies aren't scoped by port, and session terminals are served from inside their containers at `[::1]:PORT` (or `localhost:PORT` for an older image), so no name a session can serve on gets the cookie. Restarting the dashboard makes a new token, so open the newly printed URL again.

The dashboard shows each session's terminal through itself rather than framing ttyd:

- `GET /sessions/NAME/terminal` is the dashboard's own page: vendored xterm.js and the client in `static/app.js`, with a `Content-Security-Policy` allowing only the dashboard's own scripts and connections. The iframe and the `open` link point at it
- Its WebSocket, `GET /sessions/NAME/terminal/ws`, is behind the token like every route, and only accepts an `Origin` equal to the dashboard's own, since other pages on `127.0.0.1` are the same site and get the SameSite cookie. The dashboard opens a new WebSocket to the session's published port, so the browser's cookie and `Authorization` header never reach it, and adds ttyd's credential as basic auth and as the first message's `AuthToken`, sending `localhost:PORT` as the `Host` and `Origin` so `-O` passes for patched and older ttyd alike. These headers never come from or reach a browser, so they carry no cookies. Then it relays messages both ways

Nothing the session's port returns is ever served as a page: only the terminal bytes on the WebSocket come from ttyd, and xterm.js renders them as text. A session that replaced its ttyd therefore can't run script on the dashboard's origin, which would have the dashboard's full authority. Terminal links open in a new tab, except links to the dashboard's own host.

The `Host` check (against DNS rebinding) and `http.CrossOriginProtection` (against other websites driving the dashboard from your browser) still apply on top of the token.

## Session lifecycle

### Session names

Session names are lowercase letters, numbers, `.`, `_`, and `-`, starting with a letter or number, and may not start with `safeclaw-`. Each session is the container `safeclaw-NAME`, the history directory `~/.config/safeclaw/sessions/NAME`, and the state files named after it, so one name never reaches another session's container with different history or state, including on a case-insensitive filesystem. Commands also accept the container name, with its one `safeclaw-` prefix removed, and the CLI lowercases names like the dashboard's create dialog does, so `Work` is the session `work`. The API and the dashboard's session routes refuse names that aren't already lowercase.

Earlier versions accepted uppercase letters. If a container was created with exactly the mixed-case name given, such as `safeclaw-Work`, the CLI refuses the name instead of acting on `work`, and names `docker rm -f safeclaw-Work` to remove it, since `safeclaw rm` would remove the credential and network state that `work` shares with it on a case-insensitive filesystem. It can then be created again as `work`.

### Creating, starting, and refreshing

`safeclaw run` (and the dashboard's create and start) all go through the same code path:

1. Pick the [image variant](#image-variants) and check its image exists and carries no [safeclaw labels](#labels) of its own, pick the [secrets](#choosing-secrets) the session receives, then check that the Claude token is present if the session receives it (prompting for it only in `run`) and that every listed secret exists
2. Reuse the container's existing port, or pick the lowest port no `safeclaw-*` container reserves and nothing on the host is listening on, on `[::1]` or `127.0.0.1`
3. Create, start, or refresh the container. With `-v`, a `--variant` other than the container's, a different set of secrets, a different [`--host-ipc`](#ipc-namespace) or [`--no-memory`](#auto-memory) choice, or [`--fresh-history`](#reused-history), an existing container is recreated, keeping its port and whichever of its mount, variant, secrets, IPC, and auto memory choices were not given again. Every volume is checked before the old container is removed, and if the new one can't be created, the old one is created again with its port, mounts, variant, secrets, IPC, and auto memory choices, so a failed recreate never loses the session's secret set. A running container has ttyd and tmux restarted so new env vars take effect. An [offline](#offline-sessions) session is never recreated, and starting it keeps it offline
4. Write the env file, `/etc/safeclaw/env`, from the secrets the session receives
5. Configure git from the GitHub account if the session receives `GH_TOKEN`
6. Write the session's [auto memory](#auto-memory) choice to its managed settings file, before Claude Code starts
7. Start ttyd with the session's [terminal credential](#terminal-credential), and with `-q`, wait for Claude Code's input prompt before sending the query, typed literally with `tmux send-keys -l --` so a query starting with `-` isn't read as options

### Labels

safeclaw records what it decided about a container in `safeclaw.*` labels: its type (`safeclaw.type`), [variant](#image-variants), [secrets](#choosing-secrets), [IPC namespace](#ipc-namespace), [auto memory](#auto-memory), and whether it is a [sign-in container](#claude-code) (`safeclaw.auth`). Docker copies an image's labels onto every container made from it, so before creating a session, sandbox, or sign-in container, and before reusing a session or sandbox, safeclaw refuses an image that carries any `safeclaw.*` label other than the `safeclaw.variant` label naming its own variant. The error names the label, and the image has to be rebuilt without it. Every `safeclaw.*` label on a container safeclaw creates is then one safeclaw wrote, so an image can't make a session look like a sandbox, change its secrets, IPC, or auto memory choice, or get it removed as a stale sign-in container. Every session is labeled `safeclaw.type=session` and every sandbox `safeclaw.type=sandbox`; containers without the label, created by versions that left it off sessions, are interactive sessions.

### IPC namespace

A session gets docker's default private IPC namespace and its own `/dev/shm`, so code Claude Code runs can't see or attach to the docker host's shared memory, semaphores, or message queues. On a native Linux docker host that is the real host's; on Docker Desktop or OrbStack it is the Linux VM's. No `--shm-size` is set: Playwright starts Chromium with `--disable-dev-shm-usage`, so the browser works with docker's default 64 MB `/dev/shm`.

`--host-ipc` on `run` or `new` opts a session into `--ipc=host`, recorded in the `safeclaw.ipc=host` label so recreates keep it, and `--host-ipc=false` moves it back to a private namespace. Sessions created before private namespaces became the default share the host's without the label: `run` keeps them as they are with a warning, `--host-ipc=false` or `--host-ipc` recreates them with that choice, and any other recreate gives them a private namespace.

### Auto memory

Claude Code's auto memory lives in the session's [history directory](#reused-history), so what one conversation writes to `MEMORY.md` is loaded into every later one, including after the container is recreated. It stays on by default. `--no-memory` on `run` or `new` turns it off for a session, recorded in the `safeclaw.memory=off` label so recreates keep it, and `--no-memory=false` turns it back on. Changing the choice recreates the container, like `--host-ipc`.

The choice is set through Claude Code's managed settings, which take precedence over every other settings file, the `--settings` flag, and the environment, so the agent can't turn it back on. The image creates `/etc/claude-code/managed-settings.d/safeclaw-session.json` root:root 0644 with `{}` (from `setup/safeclaw-session.json`), and on every run, before Claude Code starts, safeclaw rewrites its contents as root, like the env file. With auto memory off it holds `autoMemoryEnabled: false` and sets `CLAUDE_CODE_DISABLE_AUTO_MEMORY=1` in its `env`, since that variable set to `0` in the environment would otherwise turn auto memory back on; managed `env` wins over the environment. With auto memory on it holds `{}` again, leaving Claude Code's default. In containers from images without the file, root creates it to turn auto memory off, which needs no capability since root owns `/etc`, and leaves it absent otherwise. If it can't be written, the run fails before ttyd starts. Memory already in the history directory is kept but neither loaded nor written while auto memory is off; use [`--fresh-history`](#reused-history) to move it aside.

### Privileges

Sessions run with `--cap-drop ALL` and `--security-opt no-new-privileges`, like sandboxes. Everything in a session, apart from the env file, git identity, and auto memory setting writes below, runs as the unprivileged `sclaw` user, which needs no capabilities: Claude Code, git, gh, tmux, and ttyd don't, Playwright starts Chromium with `--no-sandbox` so it needs no user namespaces, and the terminal credential write is a file sclaw owns. The image has no sudo, and with `no-new-privileges` the setuid and setgid binaries it does have (`su`, `passwd`, `mount`, `ssh-agent`, and the like) run without gaining privileges, so even a `root` process started with `docker exec -u root` has no capabilities. safeclaw writes the env file, git identity, and auto memory setting that way, as root from the host, which works because root owns those files: without `CAP_CHOWN`, `CAP_FOWNER` or `CAP_DAC_OVERRIDE` it can write and create files it owns but can't chown them, so the image creates the env file with its owner and mode and safeclaw only rewrites its contents.

The history directory is mounted with plain bind-mount options: docker's `-v` and `--mount type=bind` take no `nosuid` or `nodev`, and a bind volume made with the `local` driver's `o=bind,nosuid,nodev` doesn't carry the flags into the container. The same protections come from the flags above: setuid bits are ignored under `no-new-privileges`, and nothing can make a device node without `CAP_MKNOD`.

Sessions created before this keep docker's default capabilities. `run` keeps them as they are with a warning, and any recreate, for example with `-v` or after `safeclaw rm`, drops them.

### Config directory

Before any command runs, safeclaw checks `~/.config/safeclaw` (honoring `XDG_CONFIG_HOME`, and following a symlink to its target). One owned by another user is refused, since they could read or replace the history, credentials, and tokens kept there; the error suggests removing it or setting `XDG_CONFIG_HOME`. One owned by the user but open to others, for example one made with `mkdir -p` to write `config.yaml`, is restricted to 0700 with a note. Directories safeclaw creates there are 0700, including `sessions/` and each session's history directory, and ones created open to others by earlier versions are restricted when a container is created for them.

## Sandboxes

`safeclaw sandbox run -s NAME` creates a headless container for opening untrusted files with `docker exec`, for example extracting text from PDFs, archives, or emails that have not been checked. It shares the `safeclaw-NAME` namespace with interactive sessions and is marked with the `safeclaw.type=sandbox` label, where interactive sessions get `safeclaw.type=session` (see [labels](#labels)).

A sandbox is created with none of what an interactive session gets: no secrets are written and no Claude token is needed, there is no git configuration, no ttyd, tmux, or Claude Code, no published port, no option to share the host's IPC namespace, and no history mount. Instead it runs with:

- `--network none`, so loopback is the only interface
- `--user sandbox`, an unprivileged, non-login user (uid 2000) whose home and working directory is `/sandbox`. `/home/sclaw` is mode 1770 with group `sclaw`, so it can't be read
- `--cap-drop ALL` and `--security-opt no-new-privileges`
- `--log-driver none`, whatever the daemon's default driver, so docker keeps no log of the container's main stdout and stderr. Any sandbox process can write to PID 1's stdout through `/proc/1/fd/1`, and for `sandbox exec --ephemeral` the command's own output is that stream, so a log would store untrusted bytes on the Docker host's disk outside `--disk` and `--memory`. Nothing is lost: a named sandbox's PID 1 is `sleep infinity`, `sandbox exec` output comes back over `docker exec`, and a one-off sandbox's output reaches the caller attached rather than through `docker logs`
- `--read-only`, with a 256 MB tmpfs at `/tmp` and a tmpfs at `/sandbox` (see [sandbox disk](#sandbox-disk)). Files are copied into `/sandbox` with [`sandbox cp-in`](#copying-files)
- `--memory 2g`, `--pids-limit 256`, `--cpus 1`, and `--disk 1g` by default, changeable with flags of the same name
- `HOME=/sandbox`, an empty `BASH_ENV`, and a `PATH` without sclaw's `~/.local/bin`

`safeclaw sandbox exec`, with or without `--ephemeral`, runs its command as `/bin/sh -c 'umask 022; exec "$@"' sh CMD...`, so files it creates are not world-writable whatever umask docker gives the command. Some Docker versions start `docker exec` processes with a umask of `0000` instead of the container's. The command and its arguments are passed to the shell as positional parameters, so they reach the command exactly as given.

By default `sandbox exec` replaces itself with docker, so the command's output reaches the terminal byte for byte, including any escape sequences that came from the untrusted files: file names in an archive tool's messages, or errors from `pdftotext` or a script that failed on a crafted file. With `--escape-controls`, safeclaw instead runs docker as a child and passes its stdout and stderr, kept apart, through the same escaping as docker errors (see [copying files](#copying-files)): anything `unicode.IsPrint` rejects other than newline and tab, carriage return and invalid UTF-8 included, is written as a Go escape such as `\x1b`. Escaping rather than dropping keeps what the command said visible. A UTF-8 character split across reads is held back until it is whole. safeclaw returns docker's exit code, or 128 plus the signal number when a signal killed docker, and forwards SIGINT, SIGTERM, SIGHUP, and SIGQUIT to it. Docker runs in its own process group so a Ctrl-C reaches it once, through safeclaw, except with `-i` and a terminal on stdin, where it must stay in the foreground group to read it; there the terminal signals it directly and only SIGTERM and SIGHUP are forwarded. `--escape-controls` is refused with `-t`, since a TTY merges stdout and stderr and the programs that want one need their control characters. The flag is opt-in because escaping changes the bytes, so binary output should be piped without it.

With `-v`, which can be repeated, each host directory is mounted read-only, whatever options its spec carries. Two mounts at the same container path, or one at `/sandbox` or `/tmp`, are refused before docker runs. Rerunning `sandbox run` starts a stopped sandbox or leaves a running one alone, and `-v`, any limit flag, or a `--variant` other than the sandbox's recreates it. The new sandbox keeps whichever of the old one's mounts, variant, and limits were not given again: any `-v` replaces all of the old mounts with exactly the ones given, and without `-v` every old mount is kept. `sandbox inspect` lists every mount, and `sandbox verify` checks each one.

### Command timeouts

`sandbox exec --timeout DUR`, with or without `--ephemeral`, runs the command under coreutils `timeout` inside the container: it gets SIGTERM after DUR and SIGKILL 5 seconds later, and `timeout` signals the command's whole process group, so children it started go too. With `-t`, `timeout` has to leave the command in the terminal's foreground group (`--foreground`), so only the command itself is timed out. Enforcing the limit inside the container means it holds even if safeclaw is killed, and killing the `docker exec` client alone would leave the command running in the sandbox.

Without `--timeout` (or `--escape-controls`), `sandbox exec` replaces itself with docker, but then nothing would be left to say why the command ended, so with `--timeout` safeclaw runs docker as a child instead, as `--escape-controls` does, with the same signal forwarding. Output still passes through byte for byte unless `--escape-controls` is also given. When the command was timed out, safeclaw prints `Error: the command timed out after DUR` and exits 124, as `timeout` does, whether it ended with SIGTERM or SIGKILL. A command that exits 124 on its own before DUR is reported with its own exit code. A command running with the sandbox user's privileges can still escape `timeout` (by leaving its process group, or killing `timeout` itself), so if docker is still running 5 seconds after the SIGKILL, safeclaw stops it: a one-off sandbox is removed, which ends everything in it, and for a named sandbox the `docker exec` client is killed and the error says the command may still be running there, since its other commands can't be told apart. `safeclaw sandbox stop` ends it.

### Command environment

`sandbox exec -e NAME=VALUE`, or `-e NAME` to take the value from safeclaw's environment, sets an environment variable for that command only, so a value such as an archive password needn't be a command argument, where `ps` on the host and in the container shows it. safeclaw writes the variables to a pipe and passes its read end to docker, which reads them with `--env-file /dev/fd/N`, so the values are never in docker's arguments, its environment, or a file on disk. They can still be read from inside the container by the sandbox user (from the command's `/proc/PID/environ`), which is the point, and, for `--ephemeral`, by anyone who can `docker inspect` the one-off container while it runs, since there they are part of the container's configuration. This needs Docker 23 or later, whose `docker exec` has `--env-file`.

Names must be letters, digits, and `_`, not starting with a digit, and each may be given once. `-e NAME` for a variable that isn't set is refused rather than left unset, so a missing password is an error instead of a prompt or a silent failure. Values must be UTF-8 without newlines, carriage returns, or NUL bytes, which an env file can't hold, and all of them together must fit in 8 KiB, so the pipe holds them before docker starts. Since sandboxes never receive secrets, the names of stored secrets, `CLAUDE_CODE_OAUTH_TOKEN`, and `GH_TOKEN` are refused, which stops `-e GH_TOKEN` from passing the caller's token in by mistake; pass a value meant for the sandbox under another name. Errors name the variable but never print its value.

### Sandbox disk

`/sandbox` is a tmpfs of `--disk` bytes (default `1g`), mode 0700 and owned by the sandbox user, so a tool that extracts an untrusted archive there gets "No space left on device" once it reaches the limit, whether or not the archive records or tells the truth about its uncompressed size, and a zip bomb can't fill the Docker host's disk. `--disk 0` is refused, since a tmpfs of size 0 has no limit. A docker volume would keep files across a stop, but volume size quotas only work on a few storage drivers (overlay2 on xfs with project quotas, for one) and not on Docker Desktop or OrbStack, so a tmpfs is the limit that works everywhere. This has three consequences:

- tmpfs pages count toward `--memory`, which is why its default is 2g: a full `/sandbox` and `/tmp` still leave about 750 MB for processes. When a sandbox's files and processes together go past `--memory`, the kernel swaps if the host allows it and otherwise kills the process that is writing, so the limit holds either way. Raise `--memory` along with `--disk`
- Stopping a sandbox empties `/sandbox`, as stopping a one-off sandbox removes it. Its size is kept, and it is still empty, mode 0700, and owned by the sandbox user when the sandbox starts again
- `docker cp` into `/sandbox` is refused, since docker writes it to the read-only root filesystem rather than the tmpfs. `sandbox cp-in` works

The limit counts blocks actually written, not a file's apparent size, so a sandbox can still create a sparse file far larger than `--disk` (`truncate -s 8E` works, as it does on `/tmp`). Reading such a file only yields zeros, and [`cp-out`](#copying-files) checks each file's declared size against `--max-size` before copying anything, so it never streams one to the host.

Sandboxes run the `sandbox` [image variant](#image-variants) unless the config file or `--variant` says otherwise, so the document extraction tools are already installed and never need the network or root.

The two types are kept apart. `safeclaw run`, the dashboard's start, and the API refuse a sandbox name, `safeclaw stop`, `rm`, and `attach` refuse sandboxes, and the `safeclaw sandbox` commands refuse interactive sessions. `safeclaw ls` lists both with a TYPE column, and `safeclaw sandbox ls` lists only sandboxes.

### Copying files

`safeclaw sandbox cp-in` and `safeclaw sandbox cp-out` move files into and out of a running sandbox without `docker cp`, which runs as root on the daemon side, leaves root-owned files with the host's mode, and copies whatever it is pointed at. Both stream a tar that safeclaw writes or reads itself through `docker exec --user sandbox` and the image's `/usr/bin/tar`, so a copy can only read and write what the sandbox user can, and a symlink planted by the untrusted side can't make it read `/home/sclaw` or anything else root can. A stopped sandbox is refused.

The sandbox side also controls what those commands write to stderr, and part of their stdout. Only the last 64 KiB of any docker command's stderr is kept, a command whose stdout safeclaw buffers (rather than streams, as cp-out's tar is) fails once it passes 64 MiB, and docker errors and every error the CLI prints have control characters escaped: anything `unicode.IsPrint` rejects other than newline and tab, including raw 8-bit C1 bytes, is written as a Go escape such as `\x1b`, so container output never reaches the terminal as escape sequences.

`cp-in NAME FILE...` checks every file before sending any: symbolic links and anything that is not a regular file are refused, and each file is opened without following links and checked to be the same file that was inspected. Files land in `--to` (default `/sandbox/in`, and always under `/sandbox`) as `N-name`, with N continuing after the highest number already there, so files with the same name from different folders never overwrite each other. The numbers are picked under a lock file in `~/.config/safeclaw/copy/`, and tar's `-k` refuses to overwrite anything regardless. Since the sandbox user extracts them, the files are owned by uid 2000, with mode 644. Like `sandbox exec`, cp-in's `mkdir`, `ls`, and `tar -x`, and cp-out's `tar -c`, run under `umask 022`, so the directories cp-in creates are mode 755 rather than world-writable on Docker versions whose `docker exec` gives a umask of `0000`. Each container path is printed, in the order given, and a path that is not printable text (a host file name with a newline or terminal escape, say) is printed as a Go-quoted string so it stays on one line and never reaches the terminal as escapes.

`cp-out NAME DIR HOST_DIR --only GLOB` keeps only the regular files directly in DIR whose names match one of the (repeatable) `--only` globs. Symbolic links, hard links, directories, devices, and anything in a subdirectory are dropped, and a name that appears twice is an error. GNU sparse entries are dropped too, since the tar reader would expand them to their logical size, so a tiny stream can't fill the host disk even with `--max-size 0`; the image's tar never writes them, since it isn't given `--sparse`. Since the names come from the untrusted side, a kept file whose name is not valid UTF-8, contains anything `unicode.IsPrint` rejects (control characters such as newlines and terminal escapes, format characters such as bidi overrides, and spaces other than a plain space), or starts with `-` refuses the whole copy, with an error naming it quoted. As in a shell, a name starting with `.` only matches a glob that starts with `.` too, so `--only '*'` never brings back hidden files such as `.envrc` - ask for them with a glob such as `.envrc` or `.*`. HOST_DIR must exist. Files are written to a temporary directory inside it with mode 644 (less the umask), and nothing is moved into place until the whole stream has arrived, stays within `--max-size` (default `1g`, `0` for no limit) and `--max-files` (default `1000`, `0` for no limit; empty files are free against `--max-size`, so this is what stops a sandbox from planting any number of them), and none of the names already exist. Without `--force` each file is moved with a rename that refuses to replace, so a file created in the meantime is never overwritten. `--force` replaces existing files, and a symlink itself rather than its target, but never a directory. Each host path written is printed, quoted like cp-in's when it is not printable.

### Inspecting and verifying

`safeclaw sandbox inspect NAME` and `safeclaw sandbox verify NAME` let a script confirm that a container really is an isolated sandbox, and whether it is running, without relying on the `safeclaw-` prefix, the labels, or `docker inspect` templates. Neither changes the sandbox. Both refuse interactive sessions and missing names.

`inspect` prints the sandbox's docker configuration as JSON and runs nothing inside it. `schema` is the version of the output: fields may be added within a version, but are never renamed, removed, or given a new meaning without a new one. Lists are never `null`.

| Field | Meaning |
|---|---|
| `schema` | `1` |
| `name`, `container`, `id` | The sandbox name, its container name, and the container ID |
| `status`, `running` | docker's status (`running`, `exited`, ...) and whether it is running |
| `one_off` | Whether docker removes it when it stops |
| `variant` | Its image variant, `base` for the base image |
| `image`, `image_id` | The image name it was created from and that image's ID |
| `network_mode`, `networks` | docker's network mode (`none`) and the networks it is attached to |
| `user` | The user it runs as (`sandbox`) |
| `read_only_root`, `privileged` | `--read-only` and `--privileged` |
| `cap_drop`, `cap_add` | The capabilities dropped and added |
| `no_new_privileges` | Whether `no-new-privileges` is set |
| `ipc_mode`, `pid_mode` | docker's IPC and PID namespace modes |
| `log_driver` | docker's logging driver (`none`) |
| `limits` | `memory_bytes`, `cpus`, `pids`, and `disk_bytes` (the size of `/sandbox`), each `0` for none |
| `tmpfs` | Each tmpfs as `path`, `options`, and `size_bytes`, sorted by path |
| `mounts` | Each bind mount or volume as `type`, `source`, `destination`, and `read_only` |
| `labels` | Its `safeclaw.*` labels |

`verify` checks the guarantees above, first from the docker configuration: `network` (mode `none`, attached to nothing else), `user` (`sandbox`), `capabilities` (`ALL` dropped, none added, not privileged), `no-new-privileges`, `read-only-root`, `mounts-read-only`, `no-secrets` (no env var named after a stored secret, `CLAUDE_CODE_OAUTH_TOKEN`, or `GH_TOKEN`), `namespaces` (no host IPC or PID namespace), `limits` (memory, CPU, and process limits set), `logs` (log driver `none`, which sandboxes created before it was set fail until they are recreated, for example with `sandbox rm` and `sandbox run`), `disk` (a sized `/sandbox` tmpfs, mode 0700 and owned by uid 2000), and `tmp` (a sized `/tmp` tmpfs). Then `running`, and, for a running sandbox, a read-only probe run with `docker exec --user sandbox` that checks what the sandbox user actually gets: `live-user` (uid 2000), `live-home` (`/home/sclaw` can't be read or entered), `live-network` (only `lo`), `live-capabilities` (every capability set in `/proc/self/status` empty and `NoNewPrivs` on), `live-read-only-root` and `live-mounts` (`/` and each mount are `ro` in `/proc/self/mounts`), and `live-disk` (`/sandbox` is a tmpfs no larger than `--disk`). A stopped sandbox fails `running`, and its live checks are skipped, which also fails the verify. Each check is printed as `ok`, `FAIL`, or `SKIP` with what was found, and the command exits 1 with an error naming the failed checks. `--json` prints the report as `{"schema", "name", "container", "ok", "checks": [{"name", "ok", "skipped", "detail"}]}` instead, still exiting 1 when `ok` is false. Check names are stable within a schema version, and `detail` is for people, not parsing.

### One-off sandboxes

A one-off sandbox lives for exactly one job, so callers sharing the host need no locking, no detection of a sandbox recreated under the same name, and no per-job cleanup. If something removes one mid-job, the job is simply run again. One-off sandboxes are created with docker's `--rm`, so docker itself removes the container when it stops, and they get the same isolation, limits, and read-only `-v` as any other sandbox. Without `-s` they get a random `tmp-<8 hex>` name, and a name any container already has is refused rather than reused.

- `safeclaw sandbox exec --ephemeral -- CMD` checks the image and name, then replaces itself with `docker run --rm --init` in the foreground (or, with `--escape-controls`, runs it as a child as described [above](#sandboxes)). Cleanup does not depend on safeclaw staying alive, the command's exit code is returned as is, `--init` forwards signals to the command instead of leaving it as PID 1, and nothing but the command writes to stdout
- `safeclaw sandbox run --rm` creates a detached one-off sandbox for jobs with several steps (`sandbox cp-in`, several `sandbox exec` calls, then `sandbox cp-out`). Progress goes to stderr and only its name to stdout, and `safeclaw sandbox stop` removes it

`safeclaw sandbox ls` marks them in a ONE-OFF column, and `safeclaw ls` lists their type as `sandbox (one-off)`.

## Offline sessions

`safeclaw net off NAME` takes an interactive session off the network while it handles something untrusted, and `safeclaw net on NAME` brings it back. Taking a session offline disconnects it from every network it is attached to, which also takes down its ttyd web terminal, since the published port belongs to the container's network. Claude Code keeps running but can't reach the API until the session is back.

The networks are saved before anything is disconnected, along with any aliases, static addresses, and links (leaving out the aliases docker adds itself), so `net on` restores exactly those. The state is kept in `~/.config/safeclaw/network/NAME.json` (honoring `XDG_CONFIG_HOME`), not in the session's history directory, because that directory is mounted into the container. It records the container ID, so state left by a session that was removed and recreated under the same name, for example by `safeclaw rm` or `safeclaw build --recreate`, is ignored and deleted rather than applied to the new container. Without saved state, for example after a raw `docker network disconnect`, `net on` reconnects the session to the network it was created with (`bridge`).

Each `net off` records a hold with its `--owner`, an optional `--reason`, and when it was taken. Without `--owner` it takes the unnamed hold, which every caller without an owner shares. Taking an offline session offline again adds a hold, or updates the same owner's, and keeps the saved networks. `net on` releases only the hold for its `--owner` (or the unnamed one), fails if other owners hold the session and it holds nothing, and reconnects the session only once no holds remain, so one job can't bring a session back online while another still relies on it being offline. `--force` releases every hold. Every network change and state write happens under one lock file in that directory, so concurrent safeclaw processes don't interleave.

If a disconnect fails, `net off` still tries the session's other networks, then retries the failed ones once. If the session is still attached after that, the hold is kept rather than rolled back, since rolling back would bring the session online while its owner expects it offline, and `net off` fails naming the networks still attached, so it can be run again.

The status comes from docker: a session attached to no network is offline. `safeclaw ls` shows it in a NETWORK column (`online`, `offline` with its holders, `none` for sandboxes, or `host`), and the dashboard shows an `offline` badge. A held session that is still attached shows as `online` with its holders.

While a session is offline, or held offline but still attached:

- `run` and the dashboard's start still start or refresh it, warning that the web terminal is unreachable, and a started or running held session is disconnected again from any network attached to it
- `run` refuses to recreate it for a new `-v`, `--variant`, set of secrets, `--host-ipc` or `--no-memory` choice, or `--fresh-history`, so it can't come back online as a new container
- `safeclaw build --recreate` skips it, checking under the network lock just before each removal, and the stale report marks it `(offline)`
- `safeclaw rm` removes its saved state along with the container

Sessions using host networking, or sharing another container's network, can't be disconnected, so `net off` refuses them. Sandboxes always run with `--network none`, so the `net` commands refuse them too.

## Image variants

An image variant is the base `safeclaw` image with extra apt packages or `run` commands, tagged `safeclaw:NAME`. Variants come from two places:

- built in: `sandbox` adds poppler-utils, tesseract-ocr and tesseract-ocr-eng, 7zip, and file
- `~/.config/safeclaw/config.yaml` (honoring `XDG_CONFIG_HOME`), whose `variants` map adds variants or replaces a built-in of the same name, and whose `defaults` pick the variant each session type uses when none is given (`base` for sessions and `sandbox` for sandboxes unless set)

The config file is decoded strictly, so unknown keys are errors. Names are lowercase and may not be `base`, which means the base image, or `latest`. Package names are checked, and `run` commands are one line each and run as root. The file is read whenever a variant is resolved, so the dashboard sees edits without a restart, and commands that don't resolve variants, like `ls`, `stop`, and `rm`, don't read it.

Each variant is built from a generated Dockerfile (`safeclaw variant dockerfile NAME`) that starts `FROM` the image in its `BASE` build argument, the local `safeclaw` image by default, installs the packages and runs the commands as root, then switches back to `sclaw` and labels the image `safeclaw.variant=NAME`. Each command is written as an exec-form `RUN ["/bin/sh","-c","..."]` with `<` escaped, so a trailing backslash or a heredoc in a command can't continue into the `USER sclaw` line and leave the image running as root. `safeclaw build` builds the base image, then each `--variant` and every variant already present locally, so no variant is left on an older base. `safeclaw pull` does the same with the published images: the unmodified built-ins are pulled from `ghcr.io/josegonzalez/safeclaw:<version>-NAME` (`:NAME` for latest), and variants from the config file are built on the pulled base.

Containers on a variant carry the `safeclaw.variant=NAME` label; containers without it run the base image. An existing container keeps its variant unless `--variant` names a different one, which recreates it. A missing variant image is an error naming the `pull` and `build` commands that fetch it, and after a build or pull, containers whose variant image changed or no longer exists are reported as stale.

## Authentication

All secrets are stored on the host, and each becomes an environment variable of the same name.

### Where secrets are stored

Secrets are kept in the system keychain with [go-keyring](https://github.com/zalando/go-keyring): the macOS keychain, Secret Service on Linux, or the Windows credential manager. Each secret is an item under the `safeclaw` service, with the env var name as its account. The keychain can't list items or say when they were written, so a reserved `.index` item holds each secret's name and the time it was set. `~/.config/safeclaw/secrets.lock` is locked while the index changes, so the CLI and dashboard don't lose each other's writes. On macOS, values are passed to `security` on stdin, not in its arguments.

If the keychain can't be read, such as on a Linux server without Secret Service, secrets fall back to files in `~/.config/safeclaw/.secrets/` (one 0600 file per secret, named after it, with its modification time as the set time), with a warning. Only regular files are secrets: the store checks each name itself and opens files with `O_NOFOLLOW`, so a symlink, directory, or FIFO in the directory is treated as not set, and a name like `../x` is refused. A secret is written to a new 0600 temp file in the directory and renamed into place, so it never takes an older file's mode and replaces a symlink rather than writing through it. The directory is created with mode 700, and an existing one with looser permissions is tightened to 700 when the store is opened or written. When the keychain is available, files left there by earlier versions are moved into it with their modification times, deleted, and the directory removed once empty. Files whose names aren't valid env var names are left in place.

### How env vars are passed

1. `safeclaw run` renders each secret the session receives as `export NAME='value'` (shell-quoted) and pipes it into the container over stdin, as root, into `/etc/safeclaw/env`. Secret values never appear in process arguments.
2. `BASH_ENV=/etc/safeclaw/env` (set in the Dockerfile) ensures every bash invocation sources it
3. `.bashrc` also sources it for interactive shells, which don't read `BASH_ENV`

This means env vars are available everywhere - interactive shells, Claude's bash commands, and `docker exec bash -c` commands.

The env file is created by the image owned by root with group `sclaw` and mode 640, so sclaw can read it but not change it, and the `sandbox` user can't read it. safeclaw rewrites its contents in place with `docker exec -u root` and never chowns it, since root has no capabilities in a session. Between runs, the agent can't add to it, for example an `export CLAUDE_CONFIG_DIR=...` that every later shell and Claude Code itself would pick up. The agent can still set `BASH_ENV` or any other variable in a shell it starts, but that only changes its own processes, which already run as sclaw: ttyd, tmux, Claude Code and every `docker exec` get `BASH_ENV` from the image, and nothing safeclaw runs reads a file sclaw controls.

Containers from images that predate the root-owned env file are told apart by whether `/etc/safeclaw/env` exists, and keep getting sclaw's `~/.env`, written as sclaw with mode 600, and the git identity in `~/.gitconfig`, until they are recreated from a current image. A failed check fails the run, rather than writing secrets to a file the container doesn't source.

### Choosing secrets

Because every bash process in a session can read the env file, each session can be limited to the secrets it needs. `--secrets A,B` writes only the listed secrets, `--no-secrets` writes none, and `--all-secrets` writes every secret, including ones added later. New sessions get every secret unless told otherwise.

The choice is recorded in the `safeclaw.secrets` container label as comma-separated names, so the container itself can't change it. Containers without the label, including ones created before it existed, get every secret, and an empty label means none. Without a flag, `run` and the dashboard's start keep the container's set; a different one recreates the container, since labels can't change. The choice lives only in the label, so a session whose container was removed (for example by `safeclaw rm` or `safeclaw build --recreate`) gets every secret when it is created again without a flag, with a warning when its history directory shows it existed before.

The env file is replaced on every run, so secrets left out of the set are removed from it. Names given on a run must be stored secrets, by the same rule used when the env file is written, so an entry the store doesn't count as a secret fails the run instead of being skipped (after prompting for the Claude and GitHub tokens, if the session receives them). A remembered name that has since been deleted is skipped with a warning, so the session still starts. Tokens the session doesn't receive are neither required nor prompted for. Without `CLAUDE_CODE_OAUTH_TOKEN`, a warning says Claude Code won't be logged in.

Sandboxes never receive secrets, whatever their labels say.

### Reused history

A session's history directory is kept when its container is removed or recreated, and it holds Claude Code's transcripts and the memory loaded into its system prompt. So a session whose secrets change keeps what its previous container wrote with the old set: a narrowed session can read transcripts written with more secrets, and a session with none can leave memory for a later one with every secret. When a container is created over existing history with a different set of secrets than the container it replaces, or with a chosen set where no earlier container's set is known, `run` prints a warning naming `--fresh-history`.

`--fresh-history` on `run` or `new` renames the history directory to `NAME.old-TIMESTAMP` next to it, with the time in UTC as `20261127T150405+0000`, and recreates an existing container, so the new one starts with an empty history. Nothing is deleted. The `+` and uppercase `T` can't appear in a session name, so a moved directory is never another session's history. If the new container can't be created, the history is moved back before the old container is restored. Like other recreates, it is refused while the session is offline.

### Claude Code

The token from `claude setup-token` is stored as `CLAUDE_CODE_OAUTH_TOKEN`. `safeclaw auth login` creates it without Claude Code on the host: it starts a container from the base image with no secrets, mounts, or ports, named `safeclaw.auth.` and a random suffix and labeled `safeclaw.auth` with the PID of the safeclaw process, and runs `claude setup-token` there under `script`, attached to the terminal. The sign-in can't call back to the host, so Claude Code prints a URL and asks for the code shown after signing in. Once it exits, the recording is read back and deleted from the container right away, terminal escapes are stripped, the last `sk-ant-oat01-` token is stored, and the container is removed. A login killed before cleaning up leaves its container behind; every `safeclaw auth` command removes containers with both the name and the label whose PID is no longer running, with one `docker ps`. Sign-in containers left by versions that didn't name them are not removed, and can be removed with `docker rm`. `safeclaw auth set` and `safeclaw env set NAME` read a value from stdin (or a hidden prompt on a terminal), so values never appear in process arguments.

Tokens are valid for a year, and the token doesn't say when it was made, so the expiry is estimated from when it was stored. `auth status`, `run` (for sessions that receive the token), and a dashboard banner warn in the last 30 days, and once it has expired. `run` only prompts for missing tokens when stdin is a terminal; otherwise it fails like `new`, with an error naming `safeclaw auth login` and `safeclaw auth set`.

The Dockerfile sets `hasCompletedOnboarding: true` in `.claude.json` to skip the onboarding flow. Without this, interactive mode ignores the token and shows the login screen ([known issue](https://github.com/anthropics/claude-code/issues/8938)). It also pre-accepts the home folder trust prompt and the bypass permissions prompt, which newer Claude Code versions show on every start.

Known limitation: the token from `setup-token` has limited scopes (`user:inference` only), so `/usage` doesn't work and the status bar shows "Claude API" instead of the subscription name ([#11985](https://github.com/anthropics/claude-code/issues/11985)). Chat works fine.

### GitHub CLI

`GH_TOKEN` is used for GitHub CLI authentication. On container start, `run` also configures the git user (name and email) from the GitHub account. It does this as root, reading `GH_TOKEN` from the env file, so `gh` uses root's home rather than sclaw's gh config, and writes the identity to the system config, `/etc/gitconfig`, along with `gh auth git-credential` as git's credential helper for `https://github.com`, so git uses `GH_TOKEN` to push and pull over https. `~/.gitconfig` is an empty root-owned file and `~/.config/git` an empty root-owned folder, so the agent can't add a global git config with options such as `core.fsmonitor` or `core.pager` that run commands. `git config --global` fails with a permission error, so tools that write the global config, such as `gh auth setup-git`, don't work, and aren't needed for GitHub; a repository's own `.git/config` can still be changed. `~/.config` is root:sclaw 1770 like the home folder, so other tools can still keep their config there.

We recommend creating a separate GitHub account for SafeClaw so you can scope its permissions independently.

## Image

The image has two users: `sclaw`, who runs Claude Code, and `sandbox`, the non-login user sandboxes run as. The Dockerfile is multi-stage. The first stage builds the `safeclaw` binary from the Go source; the second is the runtime image. The Dockerfile, `setup/`, and the Go source are embedded in the binary, so `safeclaw build` works from any directory. Tagged releases also publish a multi-arch image to `ghcr.io/josegonzalez/safeclaw`, which `safeclaw pull` fetches and tags locally as `safeclaw`, along with the built-in [variants](#image-variants), built on top of it.

Build inputs are pinned: the `golang` and `ubuntu` base images by digest (kept current by Dependabot), and the Claude Code, Playwright MCP, Node.js, node-lief, and yt-dlp versions by `ARG`, and claude-code-tips by commit SHA (`CLAUDE_CODE_TIPS_COMMIT`) rather than by tag, so a moved tag can't change the build. The status line script is fetched from the same claude-code-tips commit as the DX plugin, the build checks that the plugin marketplace is checked out at that commit, and the status line script and yt-dlp are checked against pinned SHA-256s.

Claude Code's own config is root-owned and read-only, so the agent can't rewrite its settings, status line, skills, or instructions for the life of the container: `~/.claude/settings.json`, `~/.claude/CLAUDE.md`, `~/.claude/scripts/`, and `~/.claude/skills/`. An empty `~/.claude/settings.local.json`, `~/.claude/AGENTS.md`, and empty `~/.claude/agents/`, `commands/`, `output-styles/`, `rules/`, `workflows/` and `routines/` are created the same way, so the agent can't add them to override the settings or add its own instructions, agents and commands. The plugins in `~/.claude/plugins`, whose hooks and skills Claude Code runs, are root-owned too. `/home/sclaw` and `~/.claude` are owned by root with group `sclaw` and mode 1770, so sclaw can still create and change its own files there (history, `.claude.json`, cloned repos) but the sticky bit stops it from deleting or renaming the root-owned files, or `~/.claude` itself, to replace them.

The Claude Code install is root-owned as well: `~/.local/bin`, which is early in `PATH`, and the binary in `~/.local/share/claude`. Claude Code's auto-updater is disabled, so it never writes to its install. `~/.local` and `~/.local/share` are root:sclaw 1770 like the home folder, so other tools can still keep data there, but nothing can be added to `~/.local/bin` to shadow `claude`, `node` or the other commands Claude Code runs. The shell's startup files are root-owned: `~/.bashrc`, `~/.profile`, `~/.bash_logout`, and a `~/.bash_profile` that only sources `~/.profile`, which is there so the agent can't add one that login shells would read instead. `~/bin`, which `~/.profile` adds to `PATH`, is an empty root-owned folder.

The home folder is Claude Code's working directory, so it is also the project folder. Empty, root-owned `CLAUDE.md`, `CLAUDE.local.md`, `AGENTS.md` and `AGENTS.override.md` there keep the agent from adding project instructions. The project's `.claude/` is `~/.claude` itself.

The only MCP server, Playwright, is defined in Claude Code's managed MCP config at `/etc/claude-code/managed-mcp.json` (from `setup/managed-mcp.json`), with the full path to `playwright-mcp`. A managed MCP config takes exclusive control of the server list: `claude mcp add` is refused, and servers written into `~/.claude.json` or a `.mcp.json` are ignored, even with `CLAUDE_CONFIG_DIR` pointed elsewhere. An allowlist of server commands in `settings.json` would not be enough, since Claude Code still reads each server's `env` from `~/.claude.json`. Having a managed config has two side effects. Claude Code turns on its built-in `cc-plugin-sec-default` plugin, which keeps managed hooks, prompt content, settings and tool policy out of reach of the plugins a person installs. It also leaves out its built-in Artifacts MCP server. `~/.claude.json` itself stays owned by sclaw, since Claude Code rewrites it on every start (by writing a temp file and renaming it over the old one), and with the MCP servers moved out it only holds Claude Code's own state.

The env file every bash sources and git's config are root-owned too; see [how env vars are passed](#how-env-vars-are-passed) and [GitHub CLI](#github-cli). Auto memory in `~/.claude/projects` is meant to persist, and is mounted from the host, unless the session [turns it off](#auto-memory). `/ms-playwright`, where Chromium lives, is owned by sclaw and not writable by anyone else.
