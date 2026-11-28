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

Sessions share one docker network, `safeclaw`, which safeclaw creates with traffic between its containers off, so a dev server or other service one session runs can't be reached from the others. Docker enforces that with its firewall rules on native Linux and Docker Desktop, but OrbStack, and docker with `"iptables": false`, let the traffic through anyway. Sessions created by earlier versions stay on docker's default bridge, where they can reach each other, and `run` warns about them until they are recreated, for example with `-v` or after `safeclaw rm`. See [session network](docs/architecture.md#session-network).

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

On first run, `safeclaw run` prompts you to set up authentication tokens, offering to sign in to Claude Code for you. It then starts a web terminal at http://[::1]:7681 and opens it in your browser. The terminal needs a credential, made anew each time the session starts or is run again, so the printed URL carries it, like `http://safeclaw:PASSWORD@[::1]:7681`; the dashboard adds it for you. `safeclaw url NAME` prints that URL again without restarting anything. When a dashboard is running, `run` and `safeclaw url NAME --open` open its terminal page instead, which keeps the credential out of the process list and your browser history; otherwise they open the URL without the credential, so the browser asks you to log in as `safeclaw` with the password in the printed URL. Sessions need an image whose ttyd accepts `[::1]` URLs and reads its credential from a file rather than its command line, which other local users can read on a Linux host: `run` refuses to create one from an older image, including every published image up to v0.2.0, and asks you to update it with `safeclaw pull` or `safeclaw build`. A session made from such an image by an earlier version is recreated from the updated image the next time you run it, keeping its port, mounts, and history.

`-v` takes docker's `host_path:container_path[:options]`, with a leading `~` or `./` expanded. Keep these in mind when mounting:

- A host path that is the safeclaw config directory (`~/.config/safeclaw`, honoring `XDG_CONFIG_HOME`), contains it, like `~` or `~/.config`, or is inside it is refused, after resolving symlinks. It holds every session's terminal credential, the dashboard's API token, and secrets kept in files. Mount the project directory instead.
- A host path that is or contains the docker socket, or another container runtime's socket, is mounted with a warning, since it gives the session control of docker and so of the host.
- A read-write mount lets the agent change anything in the project, including `.git/config` and `.git/hooks`. Git on the host reads that config and runs those hooks the next time you run git in the directory there, for example through `core.fsmonitor`, `core.hooksPath`, or a `pre-commit` hook. Check them before running git on the host in a directory a session could write, or mount it `:ro`.
- The `z` and `Z` options make docker relabel the host directory for SELinux, on hosts that enforce it, and the label stays after the session is gone. `Z` gives it a label only this container can use, so other containers and host services can lose access to it. Don't use them on a directory such as your home or a system path.

See [volume mounts](docs/architecture.md#volume-mounts).

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

Sandboxes run the `sandbox` [image variant](#image-variants) by default, which adds document extraction tools: `pdftotext`, `pdfinfo`, and `pdftoppm` from poppler-utils, `tesseract` with English language data, `7z`, `file`, and ClamAV's `clamscan` and `freshclam` for [malware scanning](#scanning-for-malware). Fetch it once with `safeclaw pull --variant sandbox` (or `safeclaw build --variant sandbox`), or pass `--variant base` to use the base image.

The `sandbox` variant also has `safeclaw-unpack`, which lists and extracts untrusted archives with `7z` more safely than running `7z x` or `unzip` yourself: it refuses archives with links, special files, or unsafe paths (absolute, a drive letter, a `..` segment, or control characters), checks a size limit before, during, and after extracting, deletes any link 7z made and checks every extracted path stays inside the destination, and unpacks nested archives up to a depth limit. See [unpacking archives](docs/architecture.md#unpacking-archives).

```bash
# Print the archive format a file starts like (zip, 7z, rar, tar, gzip, bzip2, xz, or zstd), or none
safeclaw sandbox exec --ephemeral -v ~/inbox:/in -- safeclaw-unpack detect /in/report.zip

# One entry per line: type, size, escaped path, and flags such as ENCRYPTED, LINK, and UNSAFE-PATH
safeclaw sandbox exec --ephemeral -v ~/inbox:/in -- safeclaw-unpack list /in/report.zip

# Extract into a new or empty directory; --json prints one JSON object instead
safeclaw sandbox exec triage -- safeclaw-unpack extract /in/report.zip /sandbox/out/report

# Leave out the bad entries instead of rejecting the archive, with a password from the environment
SAFECLAW_UNPACK_PASSWORD=... safeclaw sandbox exec -e SAFECLAW_UNPACK_PASSWORD triage -- safeclaw-unpack extract --drop-bad /in/sample.7z /sandbox/out/sample

# Keep the good files when a nested archive fails, leaving that archive packed and flagged
safeclaw sandbox exec triage -- safeclaw-unpack extract --nested keep-going /in/report.zip /sandbox/out/report
```

`safeclaw-unpack` exits 0 on success, 1 when it failed (7z failed, or the archive is corrupt), 2 when the archive was rejected for links or unsafe paths, 3 when it needs a password (none or the wrong one was given), 4 when it is over `--max-size` (default `512m`), and 5 when the file is not an archive: `detect` found no archive format, or 7z can't open it for `list` or `extract` and it doesn't start like an archive `detect` knows. `detect` uses the same check `extract` uses to find nested archives, so callers can ask it instead of keeping their own list of archive types. The password comes from `SAFECLAW_UNPACK_PASSWORD`, or the variable `--password-env` names, and reaches 7z on its stdin rather than its arguments. `--depth` (default `3`) limits how many levels of nested archives are unpacked, each into `NAME.unpacked` next to it. By default a nested archive that fails fails the whole extraction. With `--nested keep-going`, it is left packed and flagged `REJECTED`, `NEEDS-PASSWORD`, `TOO-LARGE`, or `FAILED` instead, nothing it extracted is kept, and the run exits 0 as long as the outer archive itself extracted.

It also has `safeclaw-totext`, which turns an untrusted PDF, image, or text file into text that is safe to read, instead of each caller writing its own script around `pdftotext` and `tesseract`. It detects the type from the file's first bytes, writes one file per PDF page (`p001.txt`, `p002.txt`, and so on), OCRs pages with almost no text and image files, copies text files, and removes control characters from all of them. Every tool runs under its own timeout and is killed with everything it started when the timeout passes. See [extracting text](docs/architecture.md#extracting-text).

```bash
# One file per page in a new or empty directory, then a report: type, page lines, and skipped lines
safeclaw sandbox exec --ephemeral -v ~/inbox:/in -- safeclaw-totext /in/report.pdf /sandbox/out/report

# The report as JSON with a versioned schema, for building an index of the pages
safeclaw sandbox exec triage -- safeclaw-totext --json --max-pages 20 --ocr-lang eng /in/scan.pdf /sandbox/out/scan
```

`safeclaw-totext` exits 0 when every page was converted, 1 when it failed (a tool failed on the whole file, or the file is corrupt), 3 when the PDF is encrypted, 5 when the file is not a supported type, 6 when it wrote text but skipped something (pages over `--max-pages`, default `100`, or a page whose extraction or OCR timed out or failed), and 7 when a tool timed out before anything was written. `--ocr-threshold` (default `10`) is the number of characters below which a PDF page is OCR'd, `--ocr-dpi` (default `300`) and `--ocr-lang` (default `eng`) set how, and `--timeout` (default `1m`) limits each tool run.

With `--recursive`, it converts every regular file under a folder, without following links, into one flat OUTDIR, named `NNN-<safe path>.p001.txt`, `.ocr.txt`, or `.text.txt` so names never collide and `cp-out --only '*.txt'` gets them all, and writes `manifest.txt` there mapping each output to its original with its type, size, pages, characters per page, OCR pages, and anything skipped, including files that were unsupported, encrypted, failed, or links. When the folder was opened by `safeclaw-expand`, its manifest is folded in, listing each email and archive with its outcome and flags. `--max-files` (default `10000`) and `--max-output` (default `512m`) limit the whole run. It exits 0 when everything converted, 6 when anything wasn't converted in full (a file that was partial, unsupported, encrypted, or failed, a link, a file past a limit, or a container `safeclaw-expand` left packed), and 1 when the run failed. See [converting a folder](docs/architecture.md#converting-a-folder).

```bash
# Open an email and its attachments, then turn everything in it into text with one manifest
safeclaw sandbox exec --ephemeral -v ~/inbox:/in -- sh -c 'safeclaw-expand /in/report.eml /sandbox/tree && safeclaw-totext --recursive /sandbox/tree /sandbox/out/text'
```

The `sandbox` variant also has `safeclaw-mail`, which opens untrusted emails (`.eml` files) without a decoder of your own: it writes the headers and the text of every body part, forwarded messages included, to `body.txt`, preferring `text/plain` in a `multipart/alternative` and otherwise turning HTML into text without its scripts or styles, and writes each attachment under a safe, numbered name. It decodes transfer encodings, charsets, and encoded words, strips control characters from everything it prints, and limits the number of parts, their nesting, the size of headers, and the size of what it writes. See [reading emails](docs/architecture.md#reading-emails).

```bash
# The main headers, then one part per line: part, type, size, escaped name, and flags such as ATTACHMENT, NESTED-MESSAGE, and UNSAFE-NAME
safeclaw sandbox exec --ephemeral -v ~/inbox:/in -- safeclaw-mail list /in/invoice.eml

# Write body.txt and the attachments into a new or empty directory; --json prints one JSON object instead
safeclaw sandbox exec triage -- safeclaw-mail extract /in/invoice.eml /sandbox/out/invoice
```

`safeclaw-mail` uses `safeclaw-unpack`'s exit codes where they mean the same thing: 0 on success, 1 when it failed, 2 when the message was rejected for going over a limit on its structure, 4 when what it would write is over `--max-size` (default `512m`), and 5 when the file is not a message. It never exits 3. `--depth` (default `3`) limits how many levels of nested messages are followed; one past it is written as an attachment.

For a report that mixes the two, such as an email carrying a zip that holds a forwarded `.eml` carrying another zip, the `sandbox` variant also has `safeclaw-expand`, which opens the whole tree in one call. It copies each input into DEST, opens every email and archive it finds into `NAME.unpacked` next to it, the same way `safeclaw-mail extract` and `safeclaw-unpack extract` do, with one `--depth` and one `--max-size` for the whole tree, and writes `manifest.json` into DEST with every container's path, kind, outcome, flags, and the directory it was opened into. A container that fails at any level, the inputs included, is left packed and flagged `REJECTED`, `NEEDS-PASSWORD`, `TOO-LARGE`, `FAILED`, or `DEPTH-LIMIT`, and the rest is kept. See [opening a tree of emails and archives](docs/architecture.md#opening-a-tree-of-emails-and-archives).

```bash
# One line per container: kind, escaped path, flags, and the directory it was opened into
safeclaw sandbox exec --ephemeral -v ~/inbox:/in -- safeclaw-expand /in/report.eml /in/logs.zip /sandbox/out

# Print the manifest instead, with a password for every encrypted archive, and leave emails as plain files
SAFECLAW_UNPACK_PASSWORD=... safeclaw sandbox exec -e SAFECLAW_UNPACK_PASSWORD triage -- safeclaw-expand --json --no-mail /in/dump.tar.gz /sandbox/out
```

Running it again on the same DEST resumes from the manifest, which is checked first so code in the sandbox can't make it trust a path outside DEST. Containers already opened, rejected, skipped, or past `--depth` are kept, the ones left `NEEDS-PASSWORD`, `TOO-LARGE`, or `FAILED` are tried again with the new run's password and `--max-size`, which counts what is already in DEST, and new inputs are opened as usual. `--skip PATH`, with the path as the lines print it, leaves a container packed and flagged `SKIPPED` on that run and later ones, and `--unskip PATH` opens it on a later run. `--plan` prints the containers not opened yet with their entries or parts, and the rejected ones one line each, without opening anything.

```bash
# Open what opens, leaving a zip to decide on later
safeclaw sandbox exec triage -- safeclaw-expand --skip 2-logs.zip /in/report.eml /in/logs.zip /sandbox/out

# See what is still packed, then try again with the password the email gave
safeclaw sandbox exec triage -- safeclaw-expand --plan /sandbox/out
SAFECLAW_UNPACK_PASSWORD=... safeclaw sandbox exec -e SAFECLAW_UNPACK_PASSWORD triage -- safeclaw-expand /sandbox/out
```

`safeclaw-expand` exits 0 when the run finished, even with containers left packed, since the manifest and the flags say what was; and 1 when the run itself failed: a usage or I/O error, an input that is missing or not a regular file, a DEST that isn't missing or empty and has no manifest, a manifest that was refused, or an interrupt. A first run that fails empties DEST, and a rerun that fails leaves it as it was.

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

# Fetch them again after another run: overwrite, and remove the .txt files that are gone
safeclaw sandbox cp-out triage /sandbox/out ./results --only '*.txt' --replace

# Check files for malware inside the sandbox (advisory; cp-out scans again on the way out)
safeclaw sandbox scan triage /sandbox/in/1-report.zip /sandbox/out

# Remove it
safeclaw sandbox rm -f triage
```

Each `-v` is mounted recursively read-only: any filesystem mounted below the host directory is read-only in the sandbox too. This needs Docker Engine 25 or later on Linux 5.12 or later, and docker refuses to create the sandbox where it can't do it, rather than leave those filesystems writable. SELinux relabeling (`z`, `Z`), propagation modes other than `rprivate`, and `nocopy` are refused, since a recursively read-only mount can't take them. See [sandboxes](docs/architecture.md#sandboxes).

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
safeclaw sandbox status triage                    # running, stopped, or missing, exiting 0, 3, or 4 (5 for an interactive session)
safeclaw sandbox inspect triage                   # its isolation settings, limits, and mounts as JSON
safeclaw sandbox inspect triage --field running   # one field: strings as plain text, anything else as JSON
safeclaw sandbox verify triage                    # checks each isolation guarantee, exits non-zero naming any that fail
```

Only the checks `verify` makes from the docker configuration are authoritative. Its live checks run inside the sandbox as the sandbox user, so code already running there can make them report anything: treat them as advisory. See [inspecting and verifying](docs/architecture.md#inspecting-and-verifying).

To get a sandbox that passed those checks or none at all, pass `--verify` when creating it. If any check fails, the report goes to stderr, the sandbox it just created is removed (an existing named sandbox is left alone), and it exits non-zero naming the failed checks. With `exec --ephemeral`, the command only starts once every check has passed:

```bash
name=$(safeclaw sandbox run --rm --verify -v ~/inbox:/in)
safeclaw sandbox exec --ephemeral --verify -v ~/inbox:/in -- pdftotext /in/report.pdf -
```

### Scanning for malware

`cp-out` scans every file it copies with ClamAV before placing any of them, and refuses the whole copy when a file is flagged as infected or could not be scanned (over clamscan's size limits, or an encrypted archive or document), naming each file and the reason, so `HOST_DIR` is left as it was, with `--force` and `--replace` too. `--allow-flagged` copies them anyway, and `--no-scan` skips the scan, for files your own script wrote. Each file's result and the signatures' date go to stderr, and the copied paths to stdout as before. The scan runs in a fresh container of the `sandbox` variant with no network that sees only the copied files and the signatures, never in the sandbox, so nothing the untrusted files left running there can change it.

Signatures are kept in `~/.cache/safeclaw/clamav` (`$XDG_CACHE_HOME/safeclaw/clamav`), which every sandbox mounts read-only at `/var/lib/clamav`. Download them, and later refresh them, with `update-signatures`; until then `cp-out` refuses to copy without `--no-scan`:

```bash
safeclaw sandbox update-signatures   # about 110 MB the first time, then only what changed; prints the date and version
safeclaw sandbox scan triage /sandbox/out --json   # clean, infected with the signature name, or error, for each file
```

`update-signatures` runs freshclam in a short-lived container with network access but no secrets, web terminal, or mount other than a staging directory in the cache, and keeps the old signatures when it fails. Each scan loads the whole database, which takes about 8 seconds and 1.1 GB of memory, so a scan container gets the sandbox's CPU and process limits and at least 3 GB of memory. `sandbox scan` is advisory, since it runs inside the sandbox where the untrusted files are. It exits 1 when a file is infected, otherwise 2 when one could not be scanned. See [scanning for malware](docs/architecture.md#scanning-for-malware).

## Taking a session offline

While an interactive session handles something untrusted, take it offline. `safeclaw net off` saves the session's networks and disconnects it from them, and `safeclaw net on` reconnects it to exactly those networks. Its web terminal is unreachable while it is offline, and it stays offline across restarts.

```bash
safeclaw net off work --owner triage --reason "opening an emailed pdf"
safeclaw ls                      # NETWORK shows: offline (triage)
safeclaw net on work --owner triage
```

Each `net off` records a hold for its `--owner` (or one shared unnamed hold without it), and the session is reconnected only once every hold is released, so one job can't bring a session back online while another still relies on it being offline. `--force` releases every hold. A held session can't be removed either: `safeclaw rm` and the dashboard's delete refuse it, naming its holders, until they release their holds, and `safeclaw rm --release-holds` removes it anyway. The saved state is tied to the container, so a session recreated under the same name starts online. See [architecture](docs/architecture.md#offline-sessions) for details.

## Starting and scripting sessions

Start sessions with `safeclaw run`, `safeclaw new`, or the dashboard, never a raw `docker start`. They refresh the session's `.env`, git config, and ttyd; `docker start` only starts the container, so its web terminal never comes up.

`safeclaw run -q "QUERY"` sends a query to Claude Code once its prompt is ready. To type into a running session from a script, send keys to its tmux session, `main`. The first Enter sometimes doesn't submit the prompt, so check the pane and send another Enter if the text is still there:

```bash
docker exec safeclaw-work tmux send-keys -t main 'your command' Enter
docker exec safeclaw-work tmux capture-pane -t main -p   # still unsubmitted? send Enter again
docker exec safeclaw-work tmux send-keys -t main Enter
```

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
- In the `sandbox` variant: poppler-utils, tesseract-ocr with English, 7zip, file, clamav and clamav-freshclam, `safeclaw-unpack`, `safeclaw-totext`, `safeclaw-mail`, and `safeclaw-expand`

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

Claude Code loads `MEMORY.md` into every later conversation, including after the container is recreated, so a single prompt-injected turn can leave instructions that persist across rebuilds. Auto memory stays on by default. To turn it off for a session, pass `--no-memory` to `run` or `new`:

```bash
safeclaw run -s triage --no-memory          # auto memory off
safeclaw run -s triage --no-memory=false    # back on
```

The choice is remembered for the session like its secrets, including after `safeclaw rm` or `safeclaw build --recreate`, and changing it recreates the container. It is set in a root-owned managed settings file, so the agent can't turn it back on. Memory already in the history directory is kept but not loaded while auto memory is off. See [architecture](docs/architecture.md#auto-memory) for details.

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

The choice is remembered for the session, so rerunning `safeclaw run -s chat` or starting it from the dashboard keeps it. It is kept on the host outside the history directory, so it still applies after `safeclaw rm` or `safeclaw build --recreate`; give a different choice, such as `--all-secrets`, to change it. Sessions removed before choices were kept get every secret again, with a warning. Giving a different set recreates the container, keeping its port, mounts, and variant. Listed secrets must exist. A session that does not receive `CLAUDE_CODE_OAUTH_TOKEN` starts Claude Code logged out, and one that does not receive `GH_TOKEN` gets no git configuration. Sandboxes never receive secrets.

### Sharing the host's IPC namespace

Sessions get a private IPC namespace and `/dev/shm`, so they can't reach the docker host's shared memory. If something in a session needs the host's, opt in with `--host-ipc`:

```bash
safeclaw run -s work --host-ipc          # share the host's IPC namespace
safeclaw run -s work --host-ipc=false    # back to a private one
```

The choice is remembered with the container, and changing it recreates the container. Unlike secrets and auto memory, it is not kept after `safeclaw rm` or `safeclaw build --recreate`, so the session goes back to a private namespace. See [architecture](docs/architecture.md#ipc-namespace) for details.

## Commands

| Command | Description |
|---------|-------------|
| `safeclaw build` | Build the image from the build context embedded in the binary (`--context .` for a checkout), then each `--variant` and every variant already built. Warns about sessions on an older image; `--recreate` removes them, skipping offline sessions. |
| `safeclaw pull` | Pull `ghcr.io/josegonzalez/safeclaw` for this version and tag it `safeclaw`, then fetch each `--variant` and every variant already present. `--verify` checks each published image's build provenance attestation with `gh attestation verify` and pulls it by the verified digest |
| `safeclaw run` | Start/reuse a container, inject auth, start ttyd. `-s name` for named sessions, `-v` for volumes, `--variant` for an image variant, `--secrets`, `--no-secrets`, or `--all-secrets` to choose the secrets it receives, `--host-ipc` to share the host's IPC namespace, `--no-memory` to turn Claude Code's auto memory off, `--fresh-history` to move its history aside and start with an empty one, `-n` to skip opening the browser, `-q "question"` to start with a query. |
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
| `safeclaw url NAME` | Print a running session's terminal URL with its credential. `--open` also opens it, through the dashboard when one is running and otherwise without the credential, which the browser asks for |
| `safeclaw stop NAME` | Stop a session |
| `safeclaw rm NAME` | Delete a session container (history and its secrets and auto memory choices are kept). `-f` removes a running one, and `--release-holds` one held offline. |
| `safeclaw attach NAME` | Attach to a session's tmux session in this terminal. Clipboard writes, passthrough, hyperlinks to anything but http and https sites off localhost, and other sequences that act on the host terminal are filtered out, and the titles and modes the session leaves set are reset after it detaches ([details](docs/architecture.md#attaching-from-the-host)) |
| `safeclaw net off NAME` | Save a session's networks and disconnect it from them. `--owner` names the hold and `--reason` says why. |
| `safeclaw net on NAME` | Release the hold for `--owner` (or the unnamed hold) and reconnect the session once none remain. `--force` releases every hold. |
| `safeclaw sandbox run -s NAME` | Create or start a headless sandbox for untrusted files. `-v` mounts a host directory recursively read-only and can be repeated, `--variant` picks the image variant, `--memory`, `--pids-limit`, `--cpus`, and `--disk` (the size of `/sandbox`) set limits. `--verify` runs the `sandbox verify` checks once it has started, exiting non-zero and removing it if this run created it and a check fails. |
| `safeclaw sandbox run --rm [-s NAME]` | Create a one-off sandbox that is removed when it stops, and print its name |
| `safeclaw sandbox exec NAME -- CMD` | Run a command in a sandbox as the sandbox user (`-i` for stdin, `-t` for a TTY, `--escape-controls` to escape control characters in its output, `--timeout DUR` to stop it after DUR and exit 124, `-e NAME=VALUE` or `-e NAME` to set an environment variable for the command without putting the value in docker's arguments) |
| `safeclaw sandbox exec --ephemeral [-s NAME] -- CMD` | Run a command in a new one-off sandbox that is removed when it exits, returning its exit code. Takes the same `-v`, `--variant`, and limit flags as `sandbox run`, and the same `--timeout` and `-e` as `sandbox exec`. With `--verify`, the command only starts once the sandbox has passed the `sandbox verify` checks, and a sandbox that fails one is removed without running it. |
| `safeclaw sandbox cp-in NAME FILE...` | Copy regular host files into a running sandbox as `N-name`, owned by the sandbox user, refusing links and other file types. `--to` picks a directory under `/sandbox` (default `/sandbox/in`). |
| `safeclaw sandbox cp-out NAME DIR HOST_DIR --only GLOB` | Copy the regular files directly in a sandbox directory that match an `--only` glob into an existing host directory, dropping links, directories, sparse files, and nested files. Names that are not printable UTF-8 or start with `-` refuse the copy, and hidden files only match a glob starting with `.`. Existing files are refused unless `--force` is given. `--replace` implies `--force` and also removes the regular files in the host directory that match an `--only` glob but were not copied, keeping symlinks, directories, and other files, and only once every file has arrived and passed every check. `--max-size` (default `1g`) caps the total, and `--max-files` (default `1000`) caps the number of files. Every file is scanned for malware first, outside the sandbox, and a flagged or unscannable file refuses the copy unless `--allow-flagged` is given; `--no-scan` skips the scan. |
| `safeclaw sandbox scan NAME PATH...` | Scan files in a running sandbox with ClamAV, printing clean, infected with the signature name, or error for each. Advisory, since it runs inside the sandbox. `--json` prints the signatures and results as JSON. Exits 1 when a file is infected, otherwise 2 when one could not be scanned. |
| `safeclaw sandbox update-signatures` | Download the latest ClamAV signatures with freshclam in a short-lived networked container into `~/.cache/safeclaw/clamav`, keeping the old ones if it fails, and print their date and version. |
| `safeclaw sandbox ls` | List sandboxes |
| `safeclaw sandbox status NAME` | Print `running`, `stopped`, or `missing`, exiting 0, 3, or 4. A name that is an interactive session exits 5 with an error, and any other error exits 1. |
| `safeclaw sandbox inspect NAME` | Print a sandbox's status, variant, network, user, capabilities, read-only root, limits including `--disk`, mounts, and safeclaw labels as JSON with a versioned schema. `--field NAME` prints one top-level field, a string as plain text and anything else as JSON. |
| `safeclaw sandbox verify NAME` | Check a sandbox's configuration and, when it is running, what the sandbox user sees inside it against the sandbox's isolation guarantees, exiting non-zero and naming the failed checks. The configuration checks are authoritative, and the live checks advisory, since the sandbox can lie to them. `--json` prints the report as JSON. |
| `safeclaw sandbox stop NAME` | Stop a sandbox, emptying its `/sandbox` |
| `safeclaw sandbox rm NAME` | Delete a sandbox |
| `safeclaw variant ls` | List image variants, whether their images exist, and which session types default to them |
| `safeclaw variant dockerfile NAME` | Print the Dockerfile that builds a variant |
| `safeclaw completion SHELL` | Shell completions |
| `safeclaw version` | Version information. `--json` prints the version, commit, and build time as JSON with a versioned schema, and `--require VERSION` exits non-zero, naming both versions, when this build is older than `VERSION` or is a development build ([details](docs/development.md#version-checks)) |

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
