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

Unit tests use `internal/docker/dockertest`, a fake docker runner that records every command. The integration test (`-tags integration`) creates, restarts, and deletes a real session container.

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

## Dashboard hot reload

```bash
make dev
```

This runs [air](https://github.com/air-verse/air), which rebuilds on Go changes and runs `safeclaw dashboard --dev`. In dev mode, templates and static files are read from `internal/dashboard` on every request, so HTML, CSS, and JS edits only need a browser refresh.

## Releasing

Push a `v*` tag. The release workflow:

- runs goreleaser to publish darwin/linux amd64/arm64 archives with completions. The `safeclaw` formula in `josegonzalez/homebrew-repo` is bumped by that repo's daily `update-formulas.yml` workflow, which opens a PR when a new release appears
- builds the image natively on amd64 and arm64 runners and pushes a multi-arch manifest to `ghcr.io/josegonzalez/safeclaw` tagged with the version and `latest`

`make release-snapshot` runs goreleaser locally without publishing.

## Updating pinned versions

Image versions are `ARG`s at the top of the `Dockerfile`'s runtime stage (`CLAUDE_CODE_VERSION`, `PLAYWRIGHT_MCP_VERSION`, `CLAUDE_CODE_TIPS_VERSION`, `NODE_VERSION`, `NODE_LIEF_VERSION`). Update the README's "What's included" section to match. Go dependencies are updated with `go get -u ./... && go mod tidy`. htmx is vendored from the `htmx.org` npm package's `dist/` directory.
