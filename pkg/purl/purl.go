// Package purl builds Package URLs (https://github.com/package-url/purl-spec) for OS and language packages.
package purl

import (
	"strings"

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

// ForLang builds the PURL of a language package: name is as the ecosystem writes it
// ("laravel/framework", "@babel/core", "github.com/gin-gonic/gin", "requests").
func ForLang(typ, name, version string) string {
	ns, n := "", name
	switch typ {
	case inventory.TypeComposer, inventory.TypeGolang:
		if i := strings.LastIndex(name, "/"); i > 0 {
			ns, n = name[:i], name[i+1:]
		}
	case inventory.TypeNpm:
		if strings.HasPrefix(name, "@") {
			if i := strings.Index(name, "/"); i > 0 {
				ns, n = name[:i], name[i+1:]
			}
		}
	case inventory.TypePyPI:
		// The PURL spec lower-cases PyPI names and writes "_" as "-".
		n = strings.ReplaceAll(strings.ToLower(name), "_", "-")
	}
	return packageurl.NewPackageURL(typ, ns, n, version, nil, "").ToString()
}
