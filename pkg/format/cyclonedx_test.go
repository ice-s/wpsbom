package format

import (
	"bytes"
	"flag"
	"os"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"

	"github.com/ice-s/wpsbom/pkg/inventory"
	"github.com/ice-s/wpsbom/pkg/purl"
)

var update = flag.Bool("update", false, "rewrite golden files")

func sample() *inventory.Inventory {
	d := &inventory.Distro{ID: "alpine", VersionID: "3.20.3", PrettyName: "Alpine Linux v3.20"}
	inv := &inventory.Inventory{
		Distro: d,
		Kernel: "6.6.0",
		Packages: []inventory.Package{
			{Type: "apk", Name: "libcrypto3", Version: "3.3.2-r0", Arch: "x86_64", Source: "openssl", SourceVersion: "3.3.2-r0", Licenses: []string{"Apache-2.0"}},
			{Type: "apk", Name: "musl", Version: "1.2.5-r0", Arch: "x86_64", Source: "musl", SourceVersion: "1.2.5-r0"},
		},
	}
	for i := range inv.Packages {
		inv.Packages[i].PURL = purl.For(inv.Packages[i], d)
	}
	return inv
}

// Every format against its golden file; run with -update to accept a change.
func TestGolden(t *testing.T) {
	goldens := map[string]string{
		"cyclonedx-json": "alpine.cdx.json",
		"cyclonedx-xml":  "alpine.cdx.xml",
		"spdx-json":      "alpine.spdx.json",
		"csv":            "alpine.csv",
		"table":          "alpine.txt",
	}
	if len(goldens) != len(Encoders) {
		t.Fatalf("golden files for %d formats, %d formats exist", len(goldens), len(Encoders))
	}
	for name, file := range goldens {
		var buf bytes.Buffer
		if err := Encoders[name](&buf, sample(), Options{ToolVersion: "test", Reproducible: true}); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		golden := "testdata/" + file
		if *update {
			if err := os.WriteFile(golden, buf.Bytes(), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		want, err := os.ReadFile(golden)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(buf.Bytes(), want) {
			t.Errorf("%s differs from %s (run with -update to accept):\n%s", name, golden, buf.String())
		}
	}
}

func TestCycloneDXRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := CycloneDX(&buf, sample(), Options{ToolVersion: "test"}); err != nil {
		t.Fatal(err)
	}
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(&buf, cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		t.Fatal(err)
	}
	if bom.SpecVersion != cdx.SpecVersion1_6 || !strings.HasPrefix(bom.SerialNumber, "urn:uuid:") || bom.Metadata.Timestamp == "" {
		t.Errorf("header: %v %q %q", bom.SpecVersion, bom.SerialNumber, bom.Metadata.Timestamp)
	}
	if c := bom.Metadata.Component; c.Type != cdx.ComponentTypeOS || c.Name != "alpine" || c.Version != "3.20.3" {
		t.Errorf("metadata.component: %+v", c)
	}
	if n := len(*bom.Components); n != 2 {
		t.Fatalf("got %d components", n)
	}
	if p := (*bom.Components)[0].PackageURL; p != "pkg:apk/alpine/libcrypto3@3.3.2-r0?arch=x86_64&distro=alpine-3.20.3&upstream=openssl" {
		t.Errorf("purl: %s", p)
	}
}

// A host scanned with --docker carries its containers' images as nested container components,
// each with its own OS and packages under bom-refs prefixed by the image's.
func TestCycloneDXNestedImages(t *testing.T) {
	host := sample()
	img := sample()
	img.Kernel = ""
	img.Image = &inventory.Image{Ref: "acme/shop:1.4", Repo: "acme/shop", Digest: "sha256:abc"}
	img.Apps = []inventory.App{{Name: "shop", Type: "composer", Dir: "/app", Manifest: "/app/composer.lock"}}
	img.Packages = append(img.Packages, inventory.Package{Type: "composer", Name: "guzzlehttp/guzzle", Version: "7.4.0", PURL: "pkg:composer/guzzlehttp/guzzle@7.4.0", Location: "/app/composer.lock", Direct: true})
	host.Images = []*inventory.Inventory{img}

	bom := cycloneDXBOM(host, Options{Reproducible: true})
	var c *cdx.Component
	for i := range *bom.Components {
		if (*bom.Components)[i].Type == cdx.ComponentTypeContainer {
			c = &(*bom.Components)[i]
		}
	}
	if c == nil || c.BOMRef != "image:sha256:abc" || c.Components == nil {
		t.Fatalf("no nested image component: %+v", c)
	}
	refs := map[string]bool{}
	for _, n := range *c.Components {
		refs[n.BOMRef] = true
	}
	for _, want := range []string{"image:sha256:abc/os:alpine-3.20.3", "image:sha256:abc/app:/app/composer.lock", "image:sha256:abc/pkg:composer/guzzlehttp/guzzle@7.4.0#/app/composer.lock"} {
		if !refs[want] {
			t.Errorf("missing nested %s in %v", want, refs)
		}
	}
	found := false
	for _, d := range *bom.Dependencies {
		if d.Ref == "image:sha256:abc" && d.Dependencies != nil && (*d.Dependencies)[0] == "image:sha256:abc/app:/app/composer.lock" {
			found = true
		}
	}
	if !found {
		t.Error("image → application dependency missing")
	}
}
