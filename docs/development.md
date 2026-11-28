# Development

## Building

```bash
make build      # ./safeclaw with version info
make install    # go install
make image      # build the image from this checkout (safeclaw build --context .)
./safeclaw build --context . --variant sandbox   # also build the sandbox variant
```

## Testing

```bash
make test               # unit tests (docker is faked)
make lint               # golangci-lint
make test-integration   # real docker; needs the safeclaw image, and safeclaw:sandbox for the variant test
```

CI also runs [govulncheck](https://pkg.go.dev/golang.org/x/vuln/cmd/govulncheck) on every pull request, every push to `main`, and weekly, since new advisories appear without code changes. It fails when a known vulnerability in a dependency or the Go standard library is reachable from the code. To run it locally, `go install golang.org/x/vuln/cmd/govulncheck@v1.10.0` and then `govulncheck ./...`.

Unit tests use `internal/docker/dockertest`, a fake docker runner that records every command. The `--escape-controls` runner is unit tested against local commands: escaping on both streams, stdin, exit codes, death by signal, and signal forwarding. The integration tests (`-tags integration`) create, restart, and delete a real session container, checking that its processes have no capabilities and can't gain privileges and that its 0700 history directory is writable from inside. Another checks that a session gets only its chosen secrets, and that its env file and git config are root-owned and sclaw can't change or replace them, and that git gets `GH_TOKEN` for github.com through the system credential helper. Another turns a session's auto memory off and back on with `--no-memory`, checking that the managed settings file holding the choice is root-owned and sclaw can't change, replace, or add to it. They also check a real sandbox's isolation: its user, network, read-only mounts and root fs, and that `/sandbox` is a tmpfs owned by the sandbox user where writes past `--disk` fail, which is emptied but keeps its size when the sandbox is stopped and started. The same sandbox must pass every `sandbox verify` check, and `sandbox inspect` must report its `--disk`. Another checks `sandbox cp-in` and `cp-out`: that copied files are owned by the sandbox user and numbered across calls, that the directories cp-in creates are mode 755 and its files 644 whatever umask docker exec gives, that links are refused on the way in and links, directories, and nested files are dropped on the way out, that existing host files need `--force`, and that `--max-size` and stopped sandboxes are refused. They also check that a one-off sandbox from `sandbox run --rm` is removed when stopped, and that `sandbox exec --ephemeral` passes stdin, stdout, and the exit code through, mounts several `-v` directories read-only, reads the command's environment from an env file on an inherited fd, exits 124 when `--timeout` ends the command, and leaves no container behind. These run on the base image. With the `sandbox` variant built, another test checks that sandboxes use it by default, that its poppler, tesseract (with English), 7zip, and file tools run, and that it keeps the sandbox's label, user, and network isolation.

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
safeclaw sandbox inspect t                  # JSON with "network_mode": "none" and "disk_bytes": 1073741824
safeclaw sandbox verify t                   # every check ok, exit 0
safeclaw sandbox stop t
safeclaw sandbox verify t; echo $?          # running fails, live checks skipped, 1
safeclaw sandbox rm -f t
safeclaw sandbox exec --ephemeral --disk 8m -- dd if=/dev/zero of=/sandbox/f bs=1M count=16   # No space left on device
```

For the sandbox variant:

```bash
./safeclaw build --context . --variant sandbox
safeclaw variant ls                                          # safeclaw:sandbox (present)
safeclaw sandbox exec --ephemeral -v ./docs:/in -- file /in/README.md
safeclaw sandbox exec --ephemeral -- tesseract --list-langs   # includes eng
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
```

## Dashboard hot reload

```bash
make dev
```

This runs [air](https://github.com/air-verse/air), which rebuilds on Go changes and runs `safeclaw dashboard --dev`. In dev mode, templates and static files are read from `internal/dashboard` on every request, so HTML, CSS, and JS edits only need a browser refresh. Go changes restart the dashboard with a new token, so open the newly printed URL after each rebuild.

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

Built-in variants and their packages are defined in `internal/variant/variant.go` (`Builtins`). Image versions are `ARG`s at the top of the `Dockerfile`'s runtime stage (`CLAUDE_CODE_VERSION`, `PLAYWRIGHT_MCP_VERSION`, `NODE_VERSION`, `NODE_LIEF_VERSION`, `YT_DLP_VERSION`), plus `CLAUDE_CODE_TIPS_COMMIT` and `CONTEXT_BAR_SHA256` for claude-code-tips. When bumping `YT_DLP_VERSION`, set `YT_DLP_SHA256` to the `yt-dlp` line of that release's `SHA2-256SUMS`. When bumping claude-code-tips, set `CLAUDE_CODE_TIPS_COMMIT` to the commit the new tag points to (`git ls-remote https://github.com/ykdojo/claude-code-tips.git 'refs/tags/<tag>*'`, taking the `^{}` line if the tag is annotated), update the tag in the comment above it, and set `CONTEXT_BAR_SHA256` to the `sha256sum` of `scripts/context-bar.sh` at that commit. The `golang` and `ubuntu` base images are pinned by digest, which dependabot updates; to bump one by hand, take the index digest from `docker buildx imagetools inspect <image>:<tag>`. Update the README's "What's included" section to match. Go dependencies are updated with `go get -u ./... && go mod tidy`. GitHub Actions in `.github/workflows` are pinned by commit SHA with the version in a trailing comment, and dependabot updates both. The goreleaser version (`version:` on the goreleaser step in `release.yml`), the golangci-lint version in `ci.yml`, and the govulncheck version in both `ci.yml` and `release.yml` are pinned exactly and are not updated by dependabot, so bump them by hand.

### Updating vendored front-end files

htmx, its SSE extension, xterm.js, and xterm.js's fit addon are vendored in `internal/dashboard/static` and embedded in the binary. `internal/dashboard/VENDOR.md` records each file's npm package, version, source URL, and SHA-256, and `TestVendoredFiles` fails when an embedded file doesn't match its row or a file in `static/` other than `app.js` and `style.css` has none. Dependabot can't see vendored files, so check the packages' releases by hand ([htmx](https://github.com/bigskysoftware/htmx/releases), [xterm.js](https://github.com/xtermjs/xterm.js/releases)). To update one, download each of its files from the source URL with the new version, save it under the same name in `static/`, and set the version, URL, and `sha256sum` of the downloaded file in its row. htmx and `hx-sse.min.js` come from the same `htmx.org` release, and `@xterm/addon-fit` has its own version numbers, so pick the one released for the new xterm.js. Then run `make dev` and check the dashboard in a browser with its console open: the sessions table loads, a session change updates it, a terminal frame connects, and the console shows no `Content-Security-Policy` violations, since the page policy refuses inline script, inline styles, and eval.
