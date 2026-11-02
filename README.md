# wpsbom

SBOM of an operating system's installed packages, read straight from the package
manager's database. One static binary, no root, under a second.

```console
$ wpsbom scan / -o table
NAME        VERSION            ARCH   SOURCE   TYPE
libssl3     3.0.16-1~deb12u1   amd64  openssl  deb
openssl     3.0.16-1~deb12u1   amd64  openssl  deb
…
$ wpsbom scan / > sbom.cdx.json        # CycloneDX 1.6 JSON
```

## Why

General-purpose SBOM tools walk the whole file system. For keeping track of what a server or
image runs, the package database is enough, and two details decide whether vulnerability
matching works:

- **the release** (`distro=debian-12`): the same `openssl` version is patched differently on
  Debian 11 and 12;
- **the source package** (`upstream=openssl`): Debian, Ubuntu and Alpine file advisories under
  the source package, while the system has binaries such as `libssl3`.

wpsbom always writes both into the PURL:

```
pkg:deb/debian/libssl3@3.0.16-1~deb12u1?arch=amd64&distro=debian-12&upstream=openssl
pkg:apk/alpine/libcrypto3@3.3.2-r0?arch=x86_64&distro=alpine-3.20.3&upstream=openssl
```

## Supported

| Source | Distributions |
|---|---|
| `os-release` | all |
| dpkg (`/var/lib/dpkg/status`, distroless `status.d/`) | Debian, Ubuntu and derivatives |
| apk (`/lib/apk/db/installed`) | Alpine, Wolfi |

Planned: rpm (RHEL, Rocky, Alma, Fedora, SUSE, Amazon Linux), SPDX output, scanning container
images directly, and `push`/`agent` commands to send the SBOM to a server on a schedule.

## Install

Download a release from https://github.com/ice-s/wpsbom/releases (Linux and macOS, amd64 and
arm64), or with Go: `go install github.com/ice-s/wpsbom/cmd/wpsbom@latest`.

Releases are signed with Sigstore. To check one:

```sh
cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp '^https://github.com/ice-s/wpsbom/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
sha256sum --ignore-missing -c checksums.txt
```

## Usage

```
wpsbom scan [flags] [ROOT]
  -o cyclonedx-json|table   output format (default cyclonedx-json)
  -file PATH                write to a file
  -reproducible             no serial number or timestamp: same system, same bytes
  -hostname                 record the hostname as is (default: a hash of it)
```

`ROOT` defaults to `/`, the running system; the kernel release and hostname are then recorded
too. Any other directory is read as an unpacked root file system (an exported container,
a mounted disk image): symlinks resolve inside it, never on the host.

```sh
docker export "$(docker create debian:12)" | tar -x -C rootfs
wpsbom scan rootfs
```

wpsbom only reads files and makes no network requests.

## As a Go library

```go
fsys, _ := rootfs.New("/")
inv, err := wpsbom.Scan(ctx, fsys, wpsbom.Options{Live: true})
err = format.CycloneDX(os.Stdout, inv, format.Options{ToolVersion: wpsbom.Version})
```

## Development

Requires Go 1.25, or Docker: `scripts/go.sh` runs the Go toolchain in a container.

```sh
scripts/go.sh test ./...
scripts/verify-distros.sh            # compare with dpkg-query / apk info inside real images
scripts/verify-distros.sh fedora:41  # or chosen images
```

## License

Apache-2.0
