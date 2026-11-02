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

func TestCycloneDXGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := CycloneDX(&buf, sample(), Options{ToolVersion: "test", Reproducible: true}); err != nil {
		t.Fatal(err)
	}
	const golden = "testdata/alpine.cdx.json"
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
		t.Errorf("output differs from %s (run with -update to accept):\n%s", golden, buf.String())
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
