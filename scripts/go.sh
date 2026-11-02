#!/bin/sh
# Run the Go toolchain in Docker (the project needs Go 1.25; no local install required).
# Usage: scripts/go.sh test ./...
set -eu
cd "$(dirname "$0")/.."
exec docker run --rm -v "$PWD:/src" -w /src \
  -v wpsbom-gomod:/go/pkg/mod -v wpsbom-gocache:/root/.cache/go-build \
  -e CGO_ENABLED=0 -e GOOS -e GOARCH \
  golang:1.25-bookworm go "$@"
