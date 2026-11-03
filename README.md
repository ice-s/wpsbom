# wpsbom

SBOM of an operating system's installed packages, read straight from the package
manager's database, plus the applications in the source directories you point it at, and of
container images layer by layer. One static binary, no root for host scans.

```console
$ wpsbom scan / -o table
NAME        VERSION            ARCH   SOURCE   TYPE
libssl3     3.0.16-1~deb12u1   amd64  openssl  deb
openssl     3.0.16-1~deb12u1   amd64  openssl  deb
…
$ wpsbom scan / > sbom.cdx.json        # CycloneDX 1.6 JSON
$ wpsbom scan / -o spdx-json=sbom.spdx.json -o csv=packages.csv
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

Planned: rpm (RHEL, Rocky, Alma, Fedora, SUSE, Amazon Linux), Maven/Gradle and NuGet lock
files, pnpm-lock.yaml.

## Output formats

| `-o` | Content | Read by |
|---|---|---|
| `cyclonedx-json` (default) | CycloneDX 1.6 JSON | Dependency-Track, Grype, Trivy, most SBOM tools |
| `cyclonedx-xml` | CycloneDX 1.6 XML | tools that only take XML |
| `spdx-json` | SPDX 2.3 JSON (ISO/IEC 5962) | compliance tooling, Trivy, GitHub |
| `csv` | one package per row, with PURL | spreadsheets |
| `table` | aligned columns | people |

Both SBOM formats pass the official validators (`cyclonedx-cli validate`, `pyspdxtools`), and
Trivy finds the same vulnerabilities from either.

## Install

```sh
curl -fsSL https://raw.githubusercontent.com/ice-s/wpsbom/main/install.sh | sh
```

The script picks the build for your OS and architecture (Linux and macOS, amd64 and arm64),
checks its SHA-256 against the release, and installs it to `/usr/local/bin` (`~/.local/bin`
without root). A specific version: `… | sh -s -- v1.0.0`. With wget: `wget -qO- … | sh`.

The binary is static: nothing else (Go included) is needed on the machine. You can also download
it from https://github.com/ice-s/wpsbom/releases, or build it with
`go install github.com/ice-s/wpsbom/cmd/wpsbom@latest`.

To upgrade later (from v1.2.0 on; older versions: run the install line again):

```sh
wpsbom upgrade            # latest release; use sudo if it lives in /usr/local/bin
wpsbom upgrade --check    # only tell whether a newer release exists
wpsbom upgrade v1.2.0     # a given version, older ones included
```

The upgrade checks the download's SHA-256 against the release and runs the new binary before
swapping it in, so a failed upgrade leaves the old one in place. wpsbom only goes online when
you run `upgrade`; it never checks for updates by itself.

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
  -o FORMAT[=FILE]          output format, repeatable; without =FILE it goes to stdout
                            (default cyclonedx-json)
  -file PATH                write the single output to a file
  -out-dir DIR              one file per SBOM (several --image, --docker)
  -path DIR                 source directory to search for applications, repeatable
  -image REF                scan a container image instead of ROOT, repeatable
  -base-image REF           the image's base image, to tell its layers apart exactly
  -image-path DIR           extra application directory inside images, repeatable
  -docker                   also scan every running container (in place, needs root)
  -split                    with --docker: one SBOM per image instead of one for everything
  -layers                   with --docker: export images to record layers (slower)
  -no-os                    application libraries only, no OS packages
  -quiet                    no progress messages
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

`scan` only reads files and makes no network requests (except `--image registry:…`).

### Applications: `--path`

wpsbom does not search the whole disk for code. Name each source directory; lock files are
looked for in it and below (dependency directories such as `node_modules/` and `vendor/` are
skipped), one application per lock file:

```sh
wpsbom scan / --path /var/www/shop --path /srv/api -o table
```

| Ecosystem | Read | Direct dependencies from |
|---|---|---|
| PHP | `composer.lock` (only what `vendor/composer/installed.json` has, when present), or `installed.json` alone | `composer.json` |
| Node.js | `package-lock.json` / `npm-shrinkwrap.json` (v1–v3), `yarn.lock` (classic and Berry) | `package.json` |
| Python | `poetry.lock`, `Pipfile.lock`, pinned `requirements*.txt`; installed packages in `site-packages` / `dist-packages` (virtualenvs, the image's Python) | `pyproject.toml`, `Pipfile` |
| Go | `go.mod`; executables with Go build info (their modules and Go version) | `// indirect` |
| Ruby | `Gemfile.lock` | its `DEPENDENCIES` |

Each package records the lock file it came from and whether it is direct or a development
dependency; in CycloneDX every application is an `application` component that depends on its
direct dependencies.

### Container images: `--image`, `--docker`

```sh
wpsbom scan --image nginx:1.27 -o table           # local daemon, else the registry
wpsbom scan --image registry:ghcr.io/acme/shop@sha256:…
wpsbom scan --image docker-archive:shop.tar       # docker save output; oci-dir:DIR for OCI layouts
wpsbom scan --image ghcr.io/acme/shop:1.4 --base-image php:8.3-fpm
wpsbom scan / --docker -o cyclonedx-json=server.cdx.json   # the host + every running container
wpsbom scan / --docker --no-os -o cyclonedx-json=server.cdx.json   # application libraries only
wpsbom scan / --docker --split --out-dir sboms/   # one file per image instead
```

Layers are replayed one by one (only package databases, lock files and executables in
application directories are extracted), so every package records the layer that added it and
whether that layer belongs to the base image: exactly with `--base-image`, otherwise inferred from
the history timestamps. Application directories in images: `WORKDIR`, `/app`, `/srv`, `/var/www`,
`/usr/src/app`, `/opt/app`, `/code`, `/workspace`, `/home/app`, `/usr/local/bin`, plus `--image-path`.

`--docker` reads every running container where it is, in seconds: its file system as Docker
mounted it on the host (overlay2), plus bind mounts and volumes over its application
directories, read at their source (so `./src:/var/www/html` is found). It needs root. In
CycloneDX each image becomes a `container` component of the host's SBOM, nesting its own OS,
applications and packages: one file, and one Watchpost project when pushed. `--split` writes
one SBOM per image instead (the flat formats, table, CSV and SPDX, always do). `--layers` exports each image instead (minutes,
temporary space in `/tmp`) to record the layer every package came from; other storage drivers
fall back to that automatically.

`--no-os` leaves out operating system packages everywhere: application libraries only.
Progress goes to stderr (`--quiet` to silence it).

`push --json` prints the upload results (projects, URLs, vulnerability counts) as JSON on
stdout; `push --out-dir DIR` also keeps the SBOMs it sent.

### Sending to Watchpost: `push`, `k8s`

```sh
export WPSBOM_TOKEN=wp_…                          # an API token from the Watchpost SBOM page
wpsbom push / --project prod-01 --path /var/www/shop --docker   # one project: host + containers
wpsbom push --image ghcr.io/acme/shop:1.4 --fail-on kev    # CI: exit status 3 on a KEV finding
wpsbom k8s --cluster k8s-prod --scan-images       # inside a cluster, see deploy/kubernetes.yaml
```

`k8s` lists running pods (RBAC: get/list pods only) and reports which image digest every
workload runs; with `--scan-images` it also pulls and scans each image (credentials from
`~/.docker/config.json`). `Dockerfile` builds the image the CronJob uses.

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
