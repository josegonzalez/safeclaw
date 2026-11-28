PKG      := github.com/josegonzalez/safeclaw/internal/version
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS  := -s -w -X $(PKG).Version=$(VERSION) -X $(PKG).Commit=$(COMMIT) -X $(PKG).Date=$(DATE)

.PHONY: build install test test-integration lint dev image release-snapshot clean

build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o safeclaw ./cmd/safeclaw

install:
	go install -trimpath -ldflags "$(LDFLAGS)" ./cmd/safeclaw

test:
	go test ./...

test-integration:
	go test -tags integration -run Integration -v ./internal/session/

lint:
	golangci-lint run ./...

dev:
	go tool air

image: build
	./safeclaw build --context .

release-snapshot:
	goreleaser release --snapshot --clean

clean:
	rm -rf safeclaw dist tmp/air
