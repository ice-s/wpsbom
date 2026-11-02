// Package format writes an inventory as an SBOM or a table.
package format

import (
	"crypto/rand"
	"fmt"
	"io"
	"strconv"
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

	// Language packages and the applications they belong to.
	propLocation    = "wpsbom:package:location"
	propDev         = "wpsbom:package:dev"
	propAppDir      = "wpsbom:app:dir"
	propAppManifest = "wpsbom:app:manifest"

	// Images: per package the layer that added it; on the image component, the layer list as
	// "wpsbom:image:layer:<n>:diff-id" / ":created-by" / ":base" (n from 1, bottom first).
	propLayerDiffID = "wpsbom:image:layer:diff-id"
	propLayerIndex  = "wpsbom:image:layer:index"
	propBaseLayer   = "wpsbom:image:layer:base"
	propImageRef    = "wpsbom:image:ref"
	propImageID     = "wpsbom:image:id"
	propImageOS     = "wpsbom:image:os"
	propImageArch   = "wpsbom:image:arch"
	propBaseKnown   = "wpsbom:image:base-known"

	// Containers running on a host: "wpsbom:container:<n>:id" / ":name" / ":image" / ":digest".
	propContainer = "wpsbom:container"
)

// PackageRef is a package's bom-ref: its PURL, plus where it was found for language packages
// (the same version can be in several applications).
func PackageRef(p inventory.Package) string {
	if p.Location == "" {
		return p.PURL
	}
	return p.PURL + "#" + p.Location
}

// AppRef is an application's bom-ref.
func AppRef(a inventory.App) string { return "app:" + a.Manifest }

// CycloneDX writes a CycloneDX 1.6 JSON SBOM.
func CycloneDX(w io.Writer, inv *inventory.Inventory, opts Options) error {
	// Unescaped HTML keeps "&" in PURLs readable.
	return cdx.NewBOMEncoder(w, cdx.BOMFileFormatJSON).SetPretty(true).SetEscapeHTML(false).
		EncodeVersion(cycloneDXBOM(inv, opts), cdx.SpecVersion1_6)
}

// CycloneDXXML writes a CycloneDX 1.6 XML SBOM.
func CycloneDXXML(w io.Writer, inv *inventory.Inventory, opts Options) error {
	return cdx.NewBOMEncoder(w, cdx.BOMFileFormatXML).SetPretty(true).
		EncodeVersion(cycloneDXBOM(inv, opts), cdx.SpecVersion1_6)
}

// cycloneDXBOM builds the BOM: metadata.component describes the operating system (or the image,
// which then lists its operating system as a component); each installed package is a library
// component identified by its PURL; each application is an application component that depends
// on its direct dependencies.
func cycloneDXBOM(inv *inventory.Inventory, opts Options) *cdx.BOM {
	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{
		Tools: &cdx.ToolsChoice{Components: &[]cdx.Component{{
			Type:    cdx.ComponentTypeApplication,
			Name:    "wpsbom",
			Version: opts.ToolVersion,
		}}},
		Component: osComponent(inv),
	}
	var extra []cdx.Component
	if inv.Image != nil {
		extra = append(extra, *bom.Metadata.Component)
		bom.Metadata.Component = imageComponent(inv.Image)
	}
	if len(inv.Containers) > 0 {
		props := *orEmpty(bom.Metadata.Component.Properties)
		for i, c := range inv.Containers {
			n := fmt.Sprintf("%s:%d:", propContainer, i+1)
			props = append(props, *propsList(n+"id", c.ID, n+"name", c.Name, n+"image", c.Image, n+"digest", c.Digest)...)
		}
		bom.Metadata.Component.Properties = &props
	}
	if !opts.Reproducible {
		bom.SerialNumber = "urn:uuid:" + uuid4()
		bom.Metadata.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}

	comps := make([]cdx.Component, 0, len(extra)+len(inv.Apps)+len(inv.Packages))
	comps = append(comps, extra...)
	direct := map[string][]string{}
	for _, a := range inv.Apps {
		comps = append(comps, cdx.Component{
			BOMRef:     AppRef(a),
			Type:       cdx.ComponentTypeApplication,
			Name:       a.Name,
			Version:    a.Version,
			Properties: props(propPackageType, a.Type, propAppDir, a.Dir, propAppManifest, a.Manifest),
		})
		direct[a.Manifest] = []string{}
	}
	for _, p := range inv.Packages {
		kv := []string{
			propPackageType, p.Type,
			propSourceName, p.Source,
			propSourceVersion, p.SourceVersion,
			propLocation, p.Location,
		}
		if p.Dev {
			kv = append(kv, propDev, "true")
		}
		if l := layerOf(inv, p); l != nil {
			kv = append(kv, propLayerIndex, strconv.Itoa(p.Layer), propLayerDiffID, l.DiffID)
			if l.Base {
				kv = append(kv, propBaseLayer, "true")
			}
		}
		c := cdx.Component{
			BOMRef:     PackageRef(p),
			Type:       cdx.ComponentTypeLibrary,
			Name:       p.Name,
			Version:    p.Version,
			PackageURL: p.PURL,
			Properties: props(kv...),
		}
		if p.Direct && p.Location != "" {
			direct[p.Location] = append(direct[p.Location], c.BOMRef)
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
	if len(inv.Apps) > 0 {
		deps := make([]cdx.Dependency, 0, len(inv.Apps)+1)
		apps := make([]string, 0, len(inv.Apps))
		for _, a := range inv.Apps {
			apps = append(apps, AppRef(a))
			// Without known direct dependencies (installed Python packages, binaries) the graph says
			// nothing rather than "none of them is direct".
			if refs := direct[a.Manifest]; len(refs) > 0 {
				deps = append(deps, cdx.Dependency{Ref: AppRef(a), Dependencies: &refs})
			}
		}
		if ref := bom.Metadata.Component.BOMRef; ref != "" {
			deps = append([]cdx.Dependency{{Ref: ref, Dependencies: &apps}}, deps...)
		}
		bom.Dependencies = &deps
	}
	return bom
}

// layerOf returns the image layer a package came from, if any.
func layerOf(inv *inventory.Inventory, p inventory.Package) *inventory.Layer {
	if inv.Image == nil || p.Layer < 1 || p.Layer > len(inv.Image.Layers) {
		return nil
	}
	return &inv.Image.Layers[p.Layer-1]
}

func imageComponent(img *inventory.Image) *cdx.Component {
	c := &cdx.Component{
		Type:    cdx.ComponentTypeContainer,
		BOMRef:  "image:" + img.Digest,
		Name:    img.Repo,
		Version: img.Digest,
	}
	if c.Name == "" {
		c.Name = img.Ref
	}
	kv := []string{propImageRef, img.Ref, propImageID, img.ID, propImageOS, img.OS, propImageArch, img.Arch}
	if img.BaseKnown {
		kv = append(kv, propBaseKnown, "true")
	}
	for i, l := range img.Layers {
		n := fmt.Sprintf("wpsbom:image:layer:%d:", i+1)
		kv = append(kv, n+"diff-id", l.DiffID, n+"created-by", l.CreatedBy)
		if l.Base {
			kv = append(kv, n+"base", "true")
		}
	}
	c.Properties = props(kv...)
	return c
}

func orEmpty(p *[]cdx.Property) *[]cdx.Property {
	if p == nil {
		return &[]cdx.Property{}
	}
	return p
}

// propsList is props that never returns nil.
func propsList(kv ...string) *[]cdx.Property { return orEmpty(props(kv...)) }

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
