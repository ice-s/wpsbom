// Package inventory holds what a scan finds: the operating system and its installed packages.
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
)

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
}

// Inventory is the result of a scan.
type Inventory struct {
	Distro *Distro
	// Kernel is the running kernel release (uname -r); live scans only.
	Kernel string
	// Hostname is the host's name, or a hash of it unless revealed; live scans only.
	Hostname string
	Packages []Package
}
