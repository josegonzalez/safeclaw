# Development

## Building

```bash
make build      # ./safeclaw with version info
make install    # go install
make image      # build the image from this checkout (safeclaw build --context .)
```

## Testing

```bash
make test               # unit tests (docker is faked)
make lint               # golangci-lint
make test-integration   # real docker; needs the safeclaw image
```

Unit tests use `internal/docker/dockertest`, a fake docker runner that records every command. The integration tests (`-tags integration`) create, restart, and delete a real session container, and check a real sandbox's isolation: its user, network, read-only mounts and root fs, `docker cp` into `/sandbox`, and that removing it removes its volume. They also check that a one-off sandbox from `sandbox run --rm` is removed with its volume when stopped, and that `sandbox exec --ephemeral` passes stdin, stdout, and the exit code through and leaves no container behind.

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
safeclaw sandbox rm -f t
```

For one-off sandboxes:

```bash
safeclaw sandbox exec --ephemeral -i -- cat < README.md   # prints the file
safeclaw sandbox exec --ephemeral -- false; echo $?       # 1
name=$(safeclaw sandbox run --rm -v ./docs:/in)
safeclaw sandbox ls                                       # yes under ONE-OFF
safeclaw sandbox stop "$name"                             # and it is gone
```

## Dashboard hot reload

```bash
make dev
```

This runs [air](https://github.com/air-verse/air), which rebuilds on Go changes and runs `safeclaw dashboard --dev`. In dev mode, templates and static files are read from `internal/dashboard` on every request, so HTML, CSS, and JS edits only need a browser refresh.

## Releasing

Run the Release workflow from the Actions tab (or `gh workflow run release.yml -f bump_type=patch`) and pick `patch`, `minor`, or `major`. It:

- bumps the latest `v*` tag, then creates and pushes the new tag
- runs the tests against the tagged commit
- runs goreleaser to publish darwin/linux amd64/arm64 archives with completions. The `safeclaw` formula in `josegonzalez/homebrew-repo` is bumped by that repo's daily `update-formulas.yml` workflow, which opens a PR when a new release appears
- builds the image natively on amd64 and arm64 runners and pushes a multi-arch manifest to `ghcr.io/josegonzalez/safeclaw` tagged with the version and `latest`

`make release-snapshot` runs goreleaser locally without publishing.

## Updating pinned versions

Image versions are `ARG`s at the top of the `Dockerfile`'s runtime stage (`CLAUDE_CODE_VERSION`, `PLAYWRIGHT_MCP_VERSION`, `CLAUDE_CODE_TIPS_VERSION`, `NODE_VERSION`, `NODE_LIEF_VERSION`). Update the README's "What's included" section to match. Go dependencies are updated with `go get -u ./... && go mod tidy`. htmx is vendored from the `htmx.org` npm package's `dist/` directory.
