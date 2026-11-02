// Package purl builds Package URLs (https://github.com/package-url/purl-spec) for OS packages.
package purl

import (
	"github.com/package-url/packageurl-go"

	"github.com/ice-s/wpsbom/pkg/inventory"
)

// Namespace when the release is unknown.
var defaultNamespace = map[string]string{
	inventory.TypeDeb: "debian",
	inventory.TypeApk: "alpine",
	inventory.TypeRpm: "redhat",
}

// For builds the PURL of an installed package, e.g.
//
//	pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl
//
// "upstream" (the source package, "name@version" when its version differs) and "distro"
// are always set when known: vulnerability data for OS packages is filed by source
// package and release.
func For(p inventory.Package, d *inventory.Distro) string {
	ns := defaultNamespace[p.Type]
	if d != nil && d.ID != "" {
		ns = d.ID
	}
	q := map[string]string{}
	if p.Arch != "" {
		q["arch"] = p.Arch
	}
	if dq := d.Qualifier(); dq != "" {
		q["distro"] = dq
	}
	if p.Source != "" {
		up := p.Source
		if p.SourceVersion != "" && p.SourceVersion != p.Version {
			up += "@" + p.SourceVersion
		}
		q["upstream"] = up
	}
	return packageurl.NewPackageURL(p.Type, ns, p.Name, p.Version, packageurl.QualifiersFromMap(q), "").ToString()
}
