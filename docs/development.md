# Development

## Layout

One binary, `safeclaw`, is built from `cmd/safeclaw`.

- `internal/session` - the session and sandbox lifecycle shared by the CLI and dashboard (`Ensure` is upstream's `run.sh`)
- `internal/secrets` - secret storage: the system keychain, or files when there is none
- `internal/variant` - image variants: built-ins, the `config.yaml` loader, and generated Dockerfiles
- `internal/docker` - docker CLI wrapper; `dockertest` is the fake used in tests
- `internal/dashboard` - HTTP server, templates, and vendored front-end files
- `internal/wrapper` - in-container tmux bootstrap (`safeclaw ttyd-wrapper`)
- `internal/unpack` - the archive checks behind `safeclaw unpack` and `safeclaw-unpack`
- `internal/totext` - the document-to-text conversion behind `safeclaw totext` and `safeclaw-totext`, including `--recursive` (`ConvertTree`), which reads `internal/expand`'s manifest with `ReadManifest`; `totexttest` generates the PDFs its tests use
- `internal/mail` - the email reader behind `safeclaw mail` and `safeclaw-mail`
- `internal/expand` - the tree walker behind `safeclaw expand` and `safeclaw-expand`, built on `internal/unpack` and `internal/mail`, and its versioned manifest (`ReadManifest` reads and checks one)
- `internal/scan` - ClamAV signature files and clamscan results, behind `sandbox update-signatures`, `sandbox scan`, and cp-out's scan; the containers that run them are in `internal/session`
- `internal/version` - build information, `version --json`, and `--require`
- `internal/cli` - cobra commands
- `Dockerfile`, `setup/` - the image, embedded into the binary by `embed.go`

## Building

```bash
make build      # ./safeclaw with version info
make install    # go install
make image      # build the image from this checkout (safeclaw build --context .)
./safeclaw build --context . --variant sandbox   # also build the sandbox variant
```

### Version checks

`safeclaw version --json` prints `{"schema": 1, "version", "commit", "built"}`, where `version` is the version the binary was built with (`dev` for a plain `go build`, `git describe` output for `make build`), `commit` the short commit, and `built` the build time. `schema` is the version of the output: fields may be added within a version, but are never renamed, removed, or given a new meaning without a new one.

Scripts that need a given release can run `safeclaw version --require 0.3.0`, which prints the version as usual and then exits non-zero with an error naming the installed and required versions when the installed one is older. Versions are `MAJOR.MINOR.PATCH`, with or without a leading `v`, and a malformed required version is refused before anything is printed. Only a release version counts as installed: a development build, including `dev`, `make build` output between tags or with local changes (such as `v0.3.0-5-g8d41adf` or `v0.3.0-dirty`), and goreleaser snapshots, has no release version and fails any `--require`, since its version is unknown.

```bash
safeclaw version --require 0.3.0 >/dev/null || exit 1
safeclaw version --json | jq -r .version
```

## Testing

```bash
make test               # unit tests (docker is faked)
make lint               # golangci-lint
make test-integration   # real docker; needs the safeclaw image, safeclaw:sandbox for the variant, unpack, totext, mail, expand, and scan tests, and 7z on the host
SAFECLAW_TEST_SIGNATURES=1 make test-integration   # also downloads the real ClamAV signatures and scans with them, which needs the network
```

CI also runs [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) on every pull request, every push to `main`, and weekly, since new advisories appear without code changes. It fails when a known vulnerability in a dependency or the Go standard library is reachable from the code. To run it locally, `go install golang.org/x/vuln/cmd/govulncheck@v1.10.0` and then `govulncheck ./...`.

Unit tests use `internal/docker/dockertest`, a fake docker runner that records every command. Exec's stdin is unit tested against a stand-in docker script, checking that a command waiting for EOF gets it, that input given as `Input` ends even when docker never passes the close of its stdin on, and that the runner returns once its context is done even while its stdin blocks. The `--escape-controls` runner is unit tested against local commands: escaping on both streams, stdin, exit codes, death by signal, and signal forwarding. The integration tests (`-tags integration`) create, restart, and delete a real session container, checking that its processes have no capabilities and can't gain privileges and that its 0700 history directory is writable from inside. Another checks that a session gets only its chosen secrets, and that its env file and git config are root-owned and sclaw can't change or replace them, and that git gets `GH_TOKEN` for github.com through the system credential helper. Another turns a session's auto memory off and back on with `--no-memory`, checking that the managed settings file holding the choice is root-owned and sclaw can't change, replace, or add to it. They also check a real sandbox's isolation: its user, network, read-only mounts and root fs, and that `/sandbox` is a tmpfs owned by the sandbox user where writes past `--disk` fail, which is emptied but keeps its size when the sandbox is stopped and started. The same sandbox must pass every `sandbox verify` check, and `sandbox inspect` must report its `--disk`. Another checks `sandbox cp-in` and `cp-out`: that copied files are owned by the sandbox user and numbered across calls, that the directories cp-in creates are mode 755 and its files 644 whatever umask docker exec gives, that links are refused on the way in and links, directories, and nested files are dropped on the way out, that existing host files need `--force`, that `--replace` removes a stale match but keeps non-matching files, directories, and symlinks, and leaves everything in place when the copy fails, and that `--max-size` and stopped sandboxes are refused. They also check that a one-off sandbox from `sandbox run --rm` is removed when stopped, and that `sandbox exec --ephemeral` passes stdin, stdout, and the exit code through, mounts several `-v` directories read-only, reads the command's environment from an env file on an inherited fd, exits 124 when `--timeout` ends the command, and leaves no container behind. Another checks that a one-off sandbox made with `--verify` passes every check, that a verified `--ephemeral` command reads the stdin given before it was let through and finds no gate file in `/tmp`, and that one interrupted before its checks end is removed without running. These run on the base image. With the `sandbox` variant built, another test checks that sandboxes use it by default, that its poppler, tesseract (with English), 7zip, and file tools run, and that it keeps the sandbox's label, user, and network isolation. Another runs `safeclaw-totext` in it on generated PDFs, images, and text, described below. Another runs `safeclaw-unpack` in it on generated archives, checking that a tar with a `..` path and a symlink is listed with the right flags, rejected with exit 2 leaving its destination empty, and extracted with `--drop-bad` with only the safe file, and that a tar.gz inside a zip is unpacked into nested `.unpacked` directories. Another runs `safeclaw-mail` in it on a generated message, checking that the plain-text alternative is used over the HTML one and its script, that an attachment named `../../evil\x1b.pdf` is listed escaped and flagged `UNSAFE-NAME` and written inside the destination under a safe, numbered name, that a forwarded message's headers and text are in `body.txt`, and that a file that isn't a message exits 5 and leaves its destination empty. Another runs `safeclaw-expand` in it on an email carrying a zip that holds a forwarded `.eml` carrying another zip, beside a zip with a symlink, checking that every level is opened into its `.unpacked` directory, that the symlink zip is left packed and flagged `REJECTED` with its entry listed and nothing it extracted left behind, that `body.txt` is never opened, that a non-empty destination exits 1, and that `--no-mail` leaves the email as a plain file. Another runs `safeclaw-expand` on an email carrying a zip of a text PDF, an encrypted PDF, and a text file, beside a zip with a symlink, then `safeclaw-totext --recursive` on what it opened, checking that the expand manifest is folded in (the opened email and zip skipped, `body.txt` converted and flagged `EXPAND-OUTPUT`, the rejected zip listed with its outcome), that the run exits 6 for the encrypted PDF and the packed zip, that every output in the JSON report is a flat, safe `.txt` name in OUTDIR, that escape sequences are gone, and that an OUTDIR inside SRC exits 1 without being created. Another generates the EICAR test string inside a sandbox, never in a file in the repository, and checks that cp-out without signatures is refused before anything is copied and copies with `--no-scan`, and that the sandbox's signature mount can't be written. With `SAFECLAW_TEST_SIGNATURES=1`, another runs `update-signatures` into the real cache directory (later runs only fetch what changed) and checks that cp-out refuses the EICAR file, leaving the host directory as it was even with `--replace`, copies it with `--allow-flagged` and with `--no-scan`, and that `sandbox scan` flags it inside the sandbox. It is skipped by default since freshclam needs the network; without it, the session tests point `XDG_CACHE_HOME` at a temporary directory so creating sandboxes never touches the real signatures.

`internal/scan` is unit tested on clamscan output and signature files the tests write: clean, infected, and error lines, the size-limit and encryption heuristics as errors, names that contain `: ` or look like another file's result, files in a directory, paths with no result, CVD and CLD headers with and without a build timestamp and malformed ones, `.cvd` and `.cld` copies of one database, and an install that is incomplete (leaving the old signatures and creating nothing) or drops a database. cp-out's scan, `sandbox scan`, and `update-signatures` are unit tested with the dockertest fake, whose clamscan reads the files the scan container mounts: the scan container's flags and mounts, the sandbox's limits with the memory floor, refusals with `--force` and `--replace` leaving the host directory unchanged, `--allow-flagged`, a failed scan, a relative HOST_DIR, missing signatures or scan image refused before the sandbox is read, the update container's flags and staging, and a failed update keeping the old signatures.

`internal/unpack` is unit tested without 7z: its `7z l -slt` parser against listings recorded from 7-Zip 26 (tar, zip, 7z, encrypted 7z, and gzip) and p7zip 17, and against malformed ones, its path checks, and extract against a fake 7z that writes links, fifos, hard links, setuid files, and files past the size limit, covering rejection, `--drop-bad`, the size checks before, during, and after extracting, passwords, nested archives and the depth limit, `--nested keep-going` leaving each kind of failing nested archive packed and flagged, removing what it extracted without following links, sharing the size budget across the tree and giving back what a failed one took, and still failing on the outer archive's own problems, name collisions with `.unpacked`, the destination checks, and emptying the destination without following links, and its format detection against each signature, short and empty files, links, fifos, and directories, with a top-level file the fake 7z can't open being not an archive unless it starts like one, which makes it corrupt. Its `TestIntegration` tests run the real 7z on archives generated with Go's `archive/tar` and `archive/zip` (hostile ones included, each extracted two directories down so anything that got out would land in the test's own directory): listing, rejection, `--drop-bad` with literal wildcard names, nested archives, a zip holding a good PDF beside a nested zip with a symlink, a nested encrypted 7z, and nested gzip and tar.gz bombs, unpacked with `--nested keep-going` and failing as a whole without it, gzip bombs, encrypted 7z and zip archives with no, wrong, and right passwords, files that aren't archives (text, empty, and PDF files, which are not an archive, and a truncated zip and tar and a bad gzip, which are corrupt), and that `detect` names generated zip, tar, and gzip files as 7z's listing does. They run in `make test` when 7z is on PATH and are skipped otherwise, and `make test-integration` runs them with `SAFECLAW_REQUIRE_7Z=1`, which fails them instead when 7z is missing. Test hostile archives only this way, or inside a sandbox, never by extracting them on the host by hand.

`internal/totext` is unit tested with a fake tool runner: type detection from magic bytes, the control character filter (including UTF-8 split across writes and invalid bytes), the pdfinfo parser against metadata that fakes its lines, the page limit and page file names, OCR fallback and when the text layer is kept, render resolution for oversized pages, encrypted PDFs, per-tool timeouts on pdfinfo, a page, a page's OCR, and an image, interrupts, tool failures, unsupported files, and the OUTDIR rules and cleanup. `--recursive` is tested with the same fake on generated trees: links to a file and a directory outside the tree and a FIFO skipped, paths that make the same safe name, dots, tabs, and accents in names, the walk order, mixed outcomes and the run's status, a hanging tool timing out on one file while the rest convert, `--max-files`, `--max-output` cutting a PDF between pages, skipping a text file that doesn't fit and everything after it, and stopping a tool that keeps writing, the OUTDIR rules (inside SRC, SRC itself, not empty, a link, SRC not a directory), and an interrupt emptying OUTDIR. An expand manifest is folded in with opened containers skipped, `body.txt` and `parts.txt` converted, a packed container, an unknown outcome, and a missing container; one that is tampered with (a path outside SRC, an absolute output, a duplicate, another schema, or a link to a manifest elsewhere) is refused and the tree converted as a plain folder, and a valid one can't hide a file by calling it an opened container whose directory isn't there. The real runner is tested against `sh`, checking that a timeout kills a child the tool started. Its `TestIntegration` tests run the real poppler and tesseract on documents generated by `internal/totext/totexttest`, which writes text PDFs, image-only PDFs, and RC4-encrypted PDFs in Go, with scans made by rendering a text PDF with pdftoppm. They run in `make test` when the tools are on PATH and are skipped otherwise. With the `sandbox` variant built, `TestIntegrationSandboxTotext` runs `safeclaw-totext` in it on the same kinds of generated documents (the scan rendered by the sandbox's own pdftoppm), checking each exit code, the JSON reports, the OCR text, that control characters are gone, and that OUTDIR is emptied on failure. Test hostile documents only on generated fixtures like these, or inside a sandbox.

`internal/mail` is unit tested on messages the tests generate, each extracted two directories down so anything that got out would land in the test's own directory: header decoding and stripping, `multipart/alternative` choices, HTML with scripts, styles, and hidden elements, hostile attachment names (`..`, slashes and backslashes, leading dots and dashes, control characters, bidi overrides, encoded words, RFC 2231, overlong names, and duplicates), forwarded messages and the depth limit, every header, part, and nesting limit, with the part and nesting limits also just under them, bad base64, quoted-printable, transfer encodings, charsets, and Content-Types, multiparts cut short or without a boundary, part headers that `net/mail` can't parse or that `mime/multipart` would refuse, `--max-size` with held alternatives, files that aren't messages, the destination rules, and cancelling. The boundary splitter, decoders, text filter, and HTML converter have their own table tests, and `FuzzList` runs `List` and `Extract` on arbitrary input, checking that they fail only with an `*Error`, write nothing outside the destination, and empty it on failure. `make test` runs its seed corpus; run `go test ./internal/mail -run XXX -fuzz FuzzList -fuzztime 1m` to fuzz it. Test hostile messages only this way, or inside a sandbox. `Detect` is table tested on messages, mbox lines, `body.txt`'s own layout, part listings, plain text, binary data, and headers over each limit, and `WriteParts` on escaped names.

`internal/expand` is unit tested with a fake 7z, keyed by archive name, on trees the tests generate, each opened two directories down: an email carrying a zip that holds a forwarded `.eml` carrying another zip, at each depth limit, forwarded messages counting as a level, `body.txt` and `parts.txt` never opened while a `body.txt` from an archive is, inputs and nested containers left packed for each outcome with what they extracted removed, a nested file that only starts like an archive left as it is while an input like that fails, the password reaching every encrypted archive, one size budget across archives and emails with the space of a failed one given back, `--no-mail`, no 7z, an email's part problems and a rejected email, name collisions with `.unpacked`, safe numbered input names, the input and destination rules, and an interrupt emptying the destination. The manifest is checked to match `manifest.json`, and `Check` and `ReadManifest` to refuse a path outside the destination, a duplicate container, another schema, and a manifest that is a link. Its `TestIntegration` test runs the real 7z on several generated inputs: that email tree with a nested password zip, a zip with a symlink, a zip bomb, and a gzip bomb, with and without a password and a large enough `--max-size`. It runs in `make test` when 7z is on PATH and is skipped otherwise, and `make test-integration` runs it with `SAFECLAW_REQUIRE_7Z=1`.

## End to end

After making changes, rebuild and test:

```bash
make image
safeclaw run -s test -n
```

Open the printed URL and verify:

1. Claude Code launches automatically with bypass permissions
2. It shows the correct model (Opus 5.5) and doesn't ask for login
3. Send a message and confirm it gets a response

For auto memory, run `/memory` in the session's terminal:

```bash
safeclaw run -s memcheck -n --no-secrets --no-memory   # Auto-memory off
safeclaw run -s memcheck -n --no-memory=false          # recreated, Auto-memory on
safeclaw rm -f memcheck
```

For sandboxes:

```bash
safeclaw sandbox run -s t -v ./docs:/in
safeclaw sandbox exec t -- id                # uid=2000(sandbox)
safeclaw sandbox exec t -- ls /home/sclaw    # permission denied
safeclaw sandbox exec t -- touch /in/x       # read-only file system
safeclaw sandbox cp-in t README.md docs/README.md   # /sandbox/in/1-README.md, /sandbox/in/2-README.md
safeclaw sandbox exec t -- ls -ln /sandbox/in       # owned by 2000
safeclaw sandbox exec t -- sh -c 'mkdir -p out/sub && echo hi > out/a.txt && echo no > out/sub/b.txt && ln -s /etc/passwd out/p.txt'
mkdir -p tmp/out
safeclaw sandbox cp-out t /sandbox/out tmp/out --only '*.txt'   # only a.txt
safeclaw sandbox cp-out t /sandbox/out tmp/out --only '*.txt'   # refused: a.txt exists
touch tmp/out/old.txt tmp/out/keep.log
safeclaw sandbox cp-out t /sandbox/out tmp/out --only '*.txt' --replace   # a.txt, keep.log; old.txt removed
safeclaw sandbox inspect t                  # JSON with "network_mode": "none" and "disk_bytes": 1073741824
safeclaw sandbox inspect t --field limits   # {"memory_bytes":...,"disk_bytes":1073741824}
safeclaw sandbox status t; echo $?          # running, 0
safeclaw sandbox verify t                   # every check ok, exit 0
safeclaw sandbox stop t
safeclaw sandbox verify t; echo $?          # running fails, live checks skipped, 1
safeclaw sandbox status t; echo $?          # stopped, 3
safeclaw sandbox rm -f t
safeclaw sandbox status t; echo $?          # missing, 4
safeclaw sandbox exec --ephemeral --disk 8m -- dd if=/dev/zero of=/sandbox/f bs=1M count=16   # No space left on device
```

For the sandbox variant:

```bash
./safeclaw build --context . --variant sandbox
safeclaw variant ls                                          # safeclaw:sandbox (present)
safeclaw sandbox exec --ephemeral -v ./docs:/in -- file /in/README.md
safeclaw sandbox exec --ephemeral -- tesseract --list-langs   # includes eng
safeclaw sandbox update-signatures                            # Signatures: daily N from DATE, then each database
safeclaw sandbox run -s s
safeclaw sandbox exec s -- sh -c 'mkdir out && printf "%s" "$1" > out/eicar.txt && echo hi > out/a.txt' sh "$EICAR"   # the EICAR test string
mkdir -p tmp/out
safeclaw sandbox cp-out s /sandbox/out tmp/out --only '*.txt'                   # refused: eicar.txt infected (Eicar-Test-Signature), tmp/out empty
safeclaw sandbox cp-out s /sandbox/out tmp/out --only '*.txt' --allow-flagged   # both copied, results on stderr
safeclaw sandbox scan s out out/missing; echo $?                                # error, clean, infected; 1
safeclaw sandbox rm -f s
safeclaw sandbox exec --ephemeral -v ./docs:/in -- safeclaw-totext /in/README.md /sandbox/out   # type text 1 -, then a page line for text.txt
safeclaw sandbox exec --ephemeral --variant base -- sh -c 'command -v pdftotext'   # not found
```

For one-off sandboxes:

```bash
safeclaw sandbox exec --ephemeral -i -- cat < README.md   # prints the file
safeclaw sandbox exec --ephemeral -- false; echo $?       # 1
safeclaw sandbox exec --ephemeral --escape-controls -- sh -c 'printf "\033[31mred\n"; exit 3'; echo $?   # \x1b[31mred, then 3
safeclaw sandbox exec --ephemeral --escape-controls -t -- true   # refused
safeclaw sandbox exec --ephemeral --timeout 2s -- sleep 30; echo $?   # Error: the command timed out after 2s, then 124
safeclaw sandbox exec --ephemeral -e 'PASSWORD=p w' -- sh -c 'echo "$PASSWORD"'   # p w
safeclaw sandbox exec --ephemeral -e GH_TOKEN=x -- true   # refused
safeclaw sandbox exec --ephemeral -v ./docs:/in -v ./internal:/opt/src -- ls /in /opt/src
safeclaw sandbox exec --ephemeral -v ./docs:/in -v ./README.md:/in -- true   # refused: /in is already used
name=$(safeclaw sandbox run --rm -v ./docs:/in)
safeclaw sandbox ls                                       # yes under ONE-OFF
safeclaw sandbox stop "$name"                             # and it is gone
name=$(safeclaw sandbox run --rm --verify)                # Verified sandbox: all 20 checks passed, only the name on stdout
safeclaw sandbox stop "$name"
safeclaw sandbox exec --ephemeral --verify -i -- sh -c 'cat; ls -A /tmp' < README.md   # prints the file, nothing in /tmp
safeclaw sandbox exec --ephemeral --verify -- sleep 30    # Ctrl-C before the checks end: removed, safeclaw sandbox ls shows nothing
safeclaw sandbox exec t --verify -- true                  # refused: only with --ephemeral
```

## Dashboard hot reload

```bash
make dev
```

This runs [air](https://github.com/air-verse/air) through `go tool air`, at the version pinned in `go.mod`, so there's nothing to install. Air rebuilds on Go changes and runs `safeclaw dashboard --dev`. In dev mode, templates and static files are read from `internal/dashboard` on every request, so HTML, CSS, and JS edits only need a browser refresh. Go changes restart the dashboard with a new token, so open the newly printed URL after each rebuild.

Dev mode trusts the working directory: `internal/dashboard` is read relative to wherever `safeclaw dashboard --dev` runs, and its templates and scripts are served with the dashboard's token. It prints the absolute directory it reads from at startup. It refuses to start when `internal/dashboard`, `internal/dashboard/templates`, or `internal/dashboard/static` is not owned by you or is group- or world-writable (fix the latter with `chmod go-w`), and files are read through an `os.Root`, so a symlink that leads out of `internal/dashboard` is refused. Only run it from a checkout you control, never from a directory a session container can write to, such as a project mounted into a session with `-v`.

## Releasing

Run the Release workflow from the Actions tab (or `gh workflow run release.yml -f bump_type=patch`) on `main` and pick `patch`, `minor`, or `major`. A run dispatched from any other branch skips every job, so nothing is tagged or published. It:

- runs `go vet`, the tests, and `govulncheck` against the commit the workflow was started on
- bumps the latest `v*` tag and pushes the new tag on that commit, only once the tests pass, so a failed run leaves no tag behind. Runs are queued, so concurrent dispatches don't pick the same version
- runs goreleaser to publish darwin/linux amd64/arm64 archives with completions, with a build provenance attestation covering every archive in `checksums.txt`. The `safeclaw` formula in `josegonzalez/homebrew-repo` is bumped by that repo's daily `update-formulas.yml` workflow, which opens a PR when a new release appears
- builds the image natively on amd64 and arm64 runners and pushes a multi-arch manifest to `ghcr.io/josegonzalez/safeclaw` tagged with the version and `latest`, then attests the manifest's digest and pushes the attestation to ghcr
- builds each built-in variant on top of that image, by the manifest's digest rather than its tag, from `safeclaw variant dockerfile NAME`, with an empty config directory so only the built-in definition applies, and pushes it tagged `<version>-NAME` and `NAME`, with an attestation for its manifest's digest

Each job gets only the token permissions it needs: the tag and release jobs can write repository contents, and the image, manifest, and variant jobs can write packages. The release, manifest, and variant manifest jobs can also request an OIDC token and write attestations: attestations are signed keylessly with a short-lived Sigstore certificate issued for the workflow run, so no signing key is stored as a secret. Storage records are not created, since they need an organization-owned repository. goreleaser fails with `go mod tidy -diff` if `go.mod` or `go.sum` are not tidy, instead of rewriting them during the release.

`make release-snapshot` runs goreleaser locally without publishing.

### Verifying release artifacts

Releases from before attestations were added have none, so verifying them, including `safeclaw pull --verify` with their `--tag`, fails. For later ones, `safeclaw pull --verify` checks the base image and each published variant before pulling it by the verified digest (it needs the GitHub CLI, logged in with `gh auth login`, and docker buildx). To check an archive or image by hand:

```bash
gh release download v1.2.3 -R josegonzalez/safeclaw -p 'safeclaw_1.2.3_linux_amd64.tar.gz'
gh attestation verify safeclaw_1.2.3_linux_amd64.tar.gz -R josegonzalez/safeclaw --signer-workflow josegonzalez/safeclaw/.github/workflows/release.yml
gh attestation verify oci://ghcr.io/josegonzalez/safeclaw:1.2.3 -R josegonzalez/safeclaw --signer-workflow josegonzalez/safeclaw/.github/workflows/release.yml
gh attestation verify oci://ghcr.io/josegonzalez/safeclaw:1.2.3-sandbox -R josegonzalez/safeclaw --signer-workflow josegonzalez/safeclaw/.github/workflows/release.yml
```

The attestation's subject is the image's multi-arch manifest digest, so verifying a tag by hand checks the manifest the tag points to when you run the command. Without `--verify`, `safeclaw pull` pulls by tag and checks nothing.

## Updating pinned versions

Built-in variants and their packages are defined in `internal/variant/variant.go` (`Builtins`). Image versions are `ARG`s at the top of the `Dockerfile`'s runtime stage (`CLAUDE_CODE_VERSION`, `NODE_VERSION`, `YT_DLP_VERSION`), plus `CLAUDE_CODE_TIPS_COMMIT` and `CONTEXT_BAR_SHA256` for claude-code-tips. When bumping `CLAUDE_CODE_VERSION`, set `CLAUDE_CODE_SHA256_LINUX_X64` and `CLAUDE_CODE_SHA256_LINUX_ARM64` to the `linux-x64` and `linux-arm64` checksums in `https://downloads.claude.ai/claude-code-releases/<version>/manifest.json`, after checking its signature (`manifest.json.sig` next to it) with `gpg --verify` against the release signing key from `https://downloads.claude.ai/keys/claude-code.asc`, whose fingerprint is `31DDDE24DDFAB679F42D7BD2BAA929FF1A7ECACE`. Playwright MCP, node-lief, and yarn are pinned to exact versions in `setup/npm/package.json`. Dependabot watches `setup/npm` and opens a grouped pull request that bumps the exact versions in `package.json` and updates `package-lock.json` together, which the embed tests check stay in agreement. To bump one by hand, change its version there and run `npm install --package-lock-only --ignore-scripts` in `setup/npm` (in a session, not on the host) to update `package-lock.json`. A new Playwright MCP may bring new browser builds: the build then fails naming each archive URL with no line in `setup/playwright/archives.sha256`, so download each one, for both `linux64` and `linux-arm64` (`PLAYWRIGHT_HOST_PLATFORM_OVERRIDE=ubuntu24.04-x64 playwright install --dry-run chromium` lists the amd64 URLs on an arm64 host), and replace the file's lines with each `sha256sum` and URL. The nodesource and GitHub CLI apt keyrings are committed in `setup/apt`, with their primary key fingerprints in `NODESOURCE_APT_FINGERPRINTS` and `GH_CLI_APT_FINGERPRINTS`; when a vendor rotates its key, the apt update fails, so fetch the new keyring (`https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key` or `https://cli.github.com/packages/githubcli-archive-keyring.gpg`), check its fingerprints from `gpg --show-keys` against the vendor's published ones, and update the file and the `ARG`. When bumping `YT_DLP_VERSION`, set `YT_DLP_SHA256` to the `yt-dlp` line of that release's `SHA2-256SUMS`. When bumping claude-code-tips, set `CLAUDE_CODE_TIPS_COMMIT` to the commit the new tag points to (`git ls-remote https://github.com/ykdojo/claude-code-tips.git 'refs/tags/<tag>*'`, taking the `^{}` line if the tag is annotated), update the tag in the comment above it, and set `CONTEXT_BAR_SHA256` to the `sha256sum` of `scripts/context-bar.sh` at that commit. The `golang` and `ubuntu` base images are pinned by digest, which dependabot updates; to bump one by hand, take the index digest from `docker buildx imagetools inspect <image>:<tag>`. Update the README's "What's included" section to match. Go dependencies are updated with `go get -u ./... && go mod tidy`. GitHub Actions in `.github/workflows` are pinned by commit SHA with the version in a trailing comment, and dependabot updates both. The goreleaser version (`version:` on the goreleaser step in `release.yml`), the golangci-lint version in `ci.yml`, and the govulncheck version in both `ci.yml` and `release.yml` are pinned exactly and are not updated by dependabot, so bump them by hand.

### Updating vendored front-end files

htmx, its SSE extension, xterm.js, and xterm.js's fit addon are vendored in `internal/dashboard/static` and embedded in the binary. `internal/dashboard/VENDOR.md` records each file's npm package, version, source URL, and SHA-256, and `TestVendoredFiles` fails when an embedded file doesn't match its row or a file in `static/` other than `app.js` and `style.css` has none. Dependabot can't see vendored files, so check the packages' releases by hand ([htmx](https://github.com/bigskysoftware/htmx/releases), [xterm.js](https://github.com/xtermjs/xterm.js/releases)). To update one, download each of its files from the source URL with the new version, save it under the same name in `static/`, and set the version, URL, and `sha256sum` of the downloaded file in its row. htmx and `hx-sse.min.js` come from the same `htmx.org` release, and `@xterm/addon-fit` has its own version numbers, so pick the one released for the new xterm.js. Then run `make dev` and check the dashboard in a browser with its console open: the sessions table loads, a session change updates it, a terminal frame connects, and the console shows no `Content-Security-Policy` violations, since the page policy refuses inline script, inline styles, and eval.
