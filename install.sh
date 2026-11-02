#!/bin/sh
# Install wpsbom from GitHub Releases.
#
#   curl -fsSL https://raw.githubusercontent.com/ice-s/wpsbom/main/install.sh | sh
#   curl -fsSL https://raw.githubusercontent.com/ice-s/wpsbom/main/install.sh | sh -s -- v1.0.0
#
# Installs to /usr/local/bin (with sudo when needed), or ~/.local/bin without root.
# WPSBOM_INSTALL_DIR overrides the directory. The archive is checked against the release's
# SHA-256 checksums before anything is installed.
#
# Everything runs inside main(), so a download cut short never executes half a script.

set -eu

REPO=ice-s/wpsbom

main() {
	version=${1:-latest}
	case $version in
	latest) base="https://github.com/$REPO/releases/latest/download" ;;
	v*) base="https://github.com/$REPO/releases/download/$version" ;;
	*) base="https://github.com/$REPO/releases/download/v$version" ;;
	esac

	os=$(uname -s)
	case $os in
	Linux) os=linux ;;
	Darwin) os=darwin ;;
	*) fail "unsupported OS: $os (Linux and macOS only)" ;;
	esac
	arch=$(uname -m)
	case $arch in
	x86_64 | amd64) arch=amd64 ;;
	aarch64 | arm64) arch=arm64 ;;
	*) fail "unsupported architecture: $arch (amd64 and arm64 only)" ;;
	esac

	tmp=$(mktemp -d)
	trap 'rm -rf "$tmp"' EXIT INT TERM

	# The checksum list names the archives, so "latest" needs no GitHub API call (rate limited).
	fetch "$base/checksums.txt" "$tmp/checksums.txt" || fail "no release found at $base"
	archive=$(awk -v s="_${os}_${arch}.tar.gz" 'substr($2, length($2) - length(s) + 1) == s { print $2; exit }' "$tmp/checksums.txt")
	[ -n "$archive" ] || fail "no build for $os/$arch in this release"
	expected=$(awk -v a="$archive" '$2 == a { print $1 }' "$tmp/checksums.txt")

	log "downloading $archive"
	fetch "$base/$archive" "$tmp/$archive" || fail "download failed: $base/$archive"
	actual=$(sha256 "$tmp/$archive")
	[ "$actual" = "$expected" ] || fail "checksum mismatch for $archive (expected $expected, got $actual)"

	tar -xzf "$tmp/$archive" -C "$tmp" wpsbom
	chmod 755 "$tmp/wpsbom"

	dir=${WPSBOM_INSTALL_DIR:-}
	sudo=""
	if [ -z "$dir" ]; then
		dir=/usr/local/bin
		if ! writable "$dir"; then
			if [ "$(id -u)" != 0 ] && command -v sudo >/dev/null 2>&1; then
				sudo=sudo
			else
				dir="$HOME/.local/bin"
			fi
		fi
	fi
	$sudo mkdir -p "$dir"
	# Copy next to the target, then rename: a running wpsbom is never left half-written.
	$sudo cp "$tmp/wpsbom" "$dir/.wpsbom.new"
	$sudo mv -f "$dir/.wpsbom.new" "$dir/wpsbom"

	log "installed $("$dir/wpsbom" version) to $dir/wpsbom"
	case ":$PATH:" in
	*":$dir:"*) ;;
	*) log "note: $dir is not in PATH; add it, or run $dir/wpsbom" ;;
	esac
	log "try: wpsbom scan / -o table"
}

fetch() {
	if command -v curl >/dev/null 2>&1; then
		curl -fsSL --retry 3 -o "$2" "$1"
	elif command -v wget >/dev/null 2>&1; then
		wget -q -O "$2" "$1"
	else
		fail "curl or wget is required"
	fi
}

sha256() {
	if command -v sha256sum >/dev/null 2>&1; then
		sha256sum "$1" | awk '{ print $1 }'
	elif command -v shasum >/dev/null 2>&1; then
		shasum -a 256 "$1" | awk '{ print $1 }'
	elif command -v openssl >/dev/null 2>&1; then
		openssl dgst -sha256 -r "$1" | awk '{ print $1 }'
	else
		fail "sha256sum, shasum or openssl is required to verify the download"
	fi
}

# writable DIR: DIR exists and can be written, or does not exist but its parent can.
writable() {
	if [ -d "$1" ]; then
		[ -w "$1" ]
	else
		[ -w "$(dirname "$1")" ]
	fi
}

log() { printf 'wpsbom: %s\n' "$*" >&2; }
fail() {
	log "error: $*"
	exit 1
}

main "$@"
