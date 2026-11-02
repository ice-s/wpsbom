#!/bin/sh
# Checks wpsbom against real distributions: inside each image, its package list must equal
# the package manager's own. Usage: scripts/verify-distros.sh [IMAGE...]
set -eu
cd "$(dirname "$0")/.."
arch=${GOARCH:-$(docker version -f '{{.Server.Arch}}')}
mkdir -p dist
GOOS=linux GOARCH=$arch scripts/go.sh build -o dist/wpsbom-linux-$arch ./cmd/wpsbom

images=${*:-debian:11 debian:12 ubuntu:20.04 ubuntu:22.04 ubuntu:24.04 alpine:3.18 alpine:3.19 alpine:3.20}
failed=""
for img in $images; do
  printf '%-16s ' "$img"
  if ! docker run --rm --platform "linux/$arch" \
      -v "$PWD/dist/wpsbom-linux-$arch:/usr/local/bin/wpsbom:ro" \
      -v "$PWD/scripts/compare-in-image.sh:/compare.sh:ro" \
      "$img" sh /compare.sh; then
    failed="$failed $img"
  fi
done
[ -z "$failed" ] || { echo "FAILED:$failed" >&2; exit 1; }
