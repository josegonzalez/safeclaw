// Package safeclaw embeds the image build context so `safeclaw build` works
// from any directory.
package safeclaw

import "embed"

// BuildContext is the docker build context: the Dockerfile, the files copied
// into the image, and the Go source for the in-container binary.
//
//go:embed Dockerfile .dockerignore go.mod go.sum all:setup cmd internal embed.go
var BuildContext embed.FS
