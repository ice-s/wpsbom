// Package inventory holds what a scan finds: the operating system, its installed packages, the
// applications found in source directories and, for images, the layers they came from.
package inventory

// Distro is the operating system release, from os-release(5).
type Distro struct {
	ID              string   // "debian", "ubuntu", "alpine", "rocky"
	IDLike          []string // "rhel fedora" → ["rhel", "fedora"]
	VersionID       string   // "12", "24.04", "3.20.3"; empty on rolling releases
	VersionCodename string   // "bookworm", "noble"
	Name            string
	PrettyName      string
}

// Qualifier is the PURL "distro" qualifier: "debian-12", "alpine-3.20.3", or "debian-trixie"
// when the release has no VERSION_ID yet (testing, sid).
func (d *Distro) Qualifier() string {
	if d == nil || d.ID == "" {
		return ""
	}
	switch {
	case d.VersionID != "":
		return d.ID + "-" + d.VersionID
	case d.VersionCodename != "":
		return d.ID + "-" + d.VersionCodename
	}
	return d.ID
}

// Package types, as in PURL.
const (
	TypeDeb = "deb"
	TypeApk = "apk"
	TypeRpm = "rpm"

	TypeComposer = "composer"
	TypeNpm      = "npm"
	TypePyPI     = "pypi"
	TypeGolang   = "golang"
	TypeGem      = "gem"
)

// IsOS tells whether a package type belongs to an operating system's package manager.
func IsOS(typ string) bool { return typ == TypeDeb || typ == TypeApk || typ == TypeRpm }

// Package is one installed package.
type Package struct {
	Type    string // TypeDeb, TypeApk, TypeRpm
	Name    string // binary package: "libssl3"
	Version string // as the package manager writes it, epoch included ("1:2.3-4")
	Arch    string
	// Source package the binary was built from: Debian "Source:", Alpine origin, RPM SOURCERPM.
	// Vulnerability databases (Debian, Ubuntu, Alpine) file advisories under this name.
	Source        string
	SourceVersion string
	Licenses      []string
	PURL          string

	// Language packages only (composer, npm, …).

	// Location is the lock file or binary the package was read from, as an absolute path inside
	// the scanned root ("/var/www/shop/composer.lock").
	Location string
	// Direct is set when the application's manifest requires the package itself, not through
	// another package.
	Direct bool
	// Dev marks a development-only dependency (require-dev, devDependencies, Pipfile develop…).
	Dev bool

	// Layer is 1 + the index in Image.Layers of the layer that added this version; 0 outside images.
	Layer int
}

// App is an application found in a source directory: one lock file (or binary) and its packages.
type App struct {
	// Name from the manifest ("laravel/laravel", the go.mod module), else the directory name.
	Name    string
	Version string
	// Type is the package type of its dependencies: TypeComposer, TypeNpm, …
	Type string
	// Dir is the application's directory and Manifest the file read, both absolute inside the root.
	Dir      string
	Manifest string
}

// Layer is one file-system layer of a container image, bottom first.
type Layer struct {
	DiffID    string // "sha256:…", the uncompressed layer digest
	CreatedBy string // the Dockerfile instruction, from the image history
	// Base is set for layers inherited from the base image (FROM …) rather than added by the
	// image's own Dockerfile.
	Base bool
}

// Image describes a scanned container image.
type Image struct {
	Ref    string // as given: "nginx:1.27", "ghcr.io/acme/shop@sha256:…"
	Repo   string // "ghcr.io/acme/shop", without tag or digest
	Digest string // repository digest "sha256:…" when known, else the image (config) ID
	ID     string // config digest
	OS     string
	Arch   string
	Layers []Layer
	// BaseKnown tells whether Layer.Base comes from a given base image (exact) rather than the
	// history timestamps (inferred).
	BaseKnown bool
}

// Container is a container running on the scanned host.
type Container struct {
	ID     string // short ID
	Name   string
	Image  string // reference it was started from
	Digest string // Image.Digest of its image
}

// Inventory is the result of a scan.
type Inventory struct {
	Distro *Distro
	// Kernel is the running kernel release (uname -r); live scans only.
	Kernel string
	// Hostname is the host's name, or a hash of it unless revealed; live scans only.
	Hostname string
	Packages []Package
	Apps     []App
	// Image is set when the scan was of a container image.
	Image *Image
	// Containers running on the host (scan --docker).
	Containers []Container
}
