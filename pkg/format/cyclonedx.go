// Package format writes an inventory as an SBOM or a table.
package format

import (
	"crypto/rand"
	"fmt"
	"io"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/ice-s/wpsbom/pkg/inventory"
)

// Options for the SBOM encoders.
type Options struct {
	// ToolVersion is the wpsbom version recorded in metadata.tools.
	ToolVersion string
	// Reproducible leaves out the serial number and timestamp, so the same system gives
	// byte-identical output.
	Reproducible bool
}

// Property names, "wpsbom:" namespaced per the CycloneDX property taxonomy.
const (
	propPackageType   = "wpsbom:package:type"
	propSourceName    = "wpsbom:package:source-name"
	propSourceVersion = "wpsbom:package:source-version"
	propKernel        = "wpsbom:os:kernel"
	propHostname      = "wpsbom:os:hostname"
	propDistro        = "wpsbom:os:distro"
)

// CycloneDX writes a CycloneDX 1.6 JSON SBOM. metadata.component describes the operating
// system; each installed package is a library component identified by its PURL.
func CycloneDX(w io.Writer, inv *inventory.Inventory, opts Options) error {
	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{
		Tools: &cdx.ToolsChoice{Components: &[]cdx.Component{{
			Type:    cdx.ComponentTypeApplication,
			Name:    "wpsbom",
			Version: opts.ToolVersion,
		}}},
		Component: osComponent(inv),
	}
	if !opts.Reproducible {
		bom.SerialNumber = "urn:uuid:" + uuid4()
		bom.Metadata.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	comps := make([]cdx.Component, 0, len(inv.Packages))
	for _, p := range inv.Packages {
		c := cdx.Component{
			BOMRef:     p.PURL,
			Type:       cdx.ComponentTypeLibrary,
			Name:       p.Name,
			Version:    p.Version,
			PackageURL: p.PURL,
			Properties: props(
				propPackageType, p.Type,
				propSourceName, p.Source,
				propSourceVersion, p.SourceVersion,
			),
		}
		if len(p.Licenses) > 0 {
			ls := make(cdx.Licenses, 0, len(p.Licenses))
			for _, l := range p.Licenses {
				ls = append(ls, cdx.LicenseChoice{License: &cdx.License{Name: l}})
			}
			c.Licenses = &ls
		}
		comps = append(comps, c)
	}
	bom.Components = &comps

	// Unescaped HTML keeps "&" in PURLs readable.
	return cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON).SetPretty(true).SetEscapeHTML(false).EncodeVersion(bom, cdx.SpecVersion1_6)
}

func osComponent(inv *inventory.Inventory) *cdx.Component {
	c := &cdx.Component{Type: cdx.ComponentTypeOS, Name: "unknown"}
	if d := inv.Distro; d != nil {
		c.Name = d.ID
		c.Version = d.VersionID
		c.Description = d.PrettyName
		c.BOMRef = "os:" + d.Qualifier()
	}
	c.Properties = props(
		propDistro, inv.Distro.Qualifier(),
		propKernel, inv.Kernel,
		propHostname, inv.Hostname,
	)
	return c
}

// props builds a property list from name/value pairs, skipping empty values.
func props(kv ...string) *[]cdx.Property {
	var out []cdx.Property
	for i := 0; i+1 < len(kv); i += 2 {
		if kv[i+1] != "" {
			out = append(out, cdx.Property{Name: kv[i], Value: kv[i+1]})
		}
	}
	if out == nil {
		return nil
	}
	return &out
}

func uuid4() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}
