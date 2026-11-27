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

Unit tests use `internal/docker/dockertest`, a fake docker runner that records every command. The `--escape-controls` runner is unit tested against local commands: escaping on both streams, stdin, exit codes, death by signal, and signal forwarding. The integration tests (`-tags integration`) create, restart, and delete a real session container, and check a real sandbox's isolation: its user, network, read-only mounts and root fs, and that `/sandbox` is a tmpfs owned by the sandbox user where writes past `--disk` fail, which is emptied but keeps its size when the sandbox is stopped and started. Another checks `sandbox cp-in` and `cp-out`: that copied files are owned by the sandbox user and numbered across calls, that links are refused on the way in and links, directories, and nested files are dropped on the way out, that existing host files need `--force`, and that `--max-size` and stopped sandboxes are refused. They also check that a one-off sandbox from `sandbox run --rm` is removed when stopped, and that `sandbox exec --ephemeral` passes stdin, stdout, and the exit code through and leaves no container behind. These run on the base image. With the `sandbox` variant built, another test checks that sandboxes use it by default, that its poppler, tesseract (with English), 7zip, and file tools run, and that it keeps the sandbox's label, user, and network isolation.

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
name=$(safeclaw sandbox run --rm -v ./docs:/in)
safeclaw sandbox ls                                       # yes under ONE-OFF
safeclaw sandbox stop "$name"                             # and it is gone
```

## Dashboard hot reload

```bash
make dev
```

This runs [air](https://github.com/air-verse/air), which rebuilds on Go changes and runs `safeclaw dashboard --dev`. In dev mode, templates and static files are read from `internal/dashboard` on every request, so HTML, CSS, and JS edits only need a browser refresh. Go changes restart the dashboard with a new token, so open the newly printed URL after each rebuild.

Dev mode trusts the working directory: `internal/dashboard` is read relative to wherever `safeclaw dashboard --dev` runs, and its templates and scripts are served with the dashboard's token. Only run it from a checkout you control, never from a directory a session container can write to, such as a project mounted into a session with `-v`.

## Releasing

Run the Release workflow from the Actions tab (or `gh workflow run release.yml -f bump_type=patch`) and pick `patch`, `minor`, or `major`. It:

- runs `go vet` and the tests against the commit the workflow was started on
- bumps the latest `v*` tag and pushes the new tag on that commit, only once the tests pass, so a failed run leaves no tag behind. Runs are queued, so concurrent dispatches don't pick the same version
- runs goreleaser to publish darwin/linux amd64/arm64 archives with completions. The `safeclaw` formula in `josegonzalez/homebrew-repo` is bumped by that repo's daily `update-formulas.yml` workflow, which opens a PR when a new release appears
- builds the image natively on amd64 and arm64 runners and pushes a multi-arch manifest to `ghcr.io/josegonzalez/safeclaw` tagged with the version and `latest`
- builds each built-in variant on top of that image, by the manifest's digest rather than its tag, from `safeclaw variant dockerfile NAME`, with an empty config directory so only the built-in definition applies, and pushes it tagged `<version>-NAME` and `NAME`

Each job gets only the token permissions it needs: the tag and release jobs can write repository contents, and the image, manifest, and variant jobs can write packages. goreleaser fails with `go mod tidy -diff` if `go.mod` or `go.sum` are not tidy, instead of rewriting them during the release.

`make release-snapshot` runs goreleaser locally without publishing.

## Updating pinned versions

Built-in variants and their packages are defined in `internal/variant/variant.go` (`Builtins`). Image versions are `ARG`s at the top of the `Dockerfile`'s runtime stage (`CLAUDE_CODE_VERSION`, `PLAYWRIGHT_MCP_VERSION`, `CLAUDE_CODE_TIPS_VERSION`, `NODE_VERSION`, `NODE_LIEF_VERSION`, `YT_DLP_VERSION`). When bumping `YT_DLP_VERSION`, set `YT_DLP_SHA256` to the `yt-dlp` line of that release's `SHA2-256SUMS`. The `golang` and `ubuntu` base images are pinned by digest, which dependabot updates; to bump one by hand, take the index digest from `docker buildx imagetools inspect <image>:<tag>`. Update the README's "What's included" section to match. Go dependencies are updated with `go get -u ./... && go mod tidy`. GitHub Actions in `.github/workflows` are pinned by commit SHA with the version in a trailing comment, and dependabot updates both. The goreleaser version (`version:` on the goreleaser step in `release.yml`) and the golangci-lint version in `ci.yml` are pinned exactly and are not updated by dependabot, so bump them by hand. htmx is vendored from the `htmx.org` npm package's `dist/` directory.
