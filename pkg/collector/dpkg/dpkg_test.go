package dpkg

import (
	"os"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/ice-s/wpsbom/pkg/inventory"
)

func TestParseDebian12(t *testing.T) {
	f, err := os.Open("testdata/debian-12.status")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	pkgs, err := Parse(f)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 88 {
		t.Errorf("got %d packages, want 88", len(pkgs))
	}
	got := index(pkgs)
	// Source with its own version (binNMU).
	if p := got["bash"]; p.Source != "bash" || p.SourceVersion != "5.2.15-2" || p.Version != "5.2.15-2+b13" {
		t.Errorf("bash: %+v", p)
	}
	// Epoch kept in the version; source version given without it.
	if p := got["bsdutils"]; p.Source != "util-linux" || p.Version != "1:2.38.1-5+deb12u3" || p.SourceVersion != "2.38.1-5+deb12u3" {
		t.Errorf("bsdutils: %+v", p)
	}
	// No Source field: the package is its own source.
	if p := got["base-files"]; p.Source != "base-files" || p.SourceVersion != p.Version {
		t.Errorf("base-files: %+v", p)
	}
}

func TestStatusFilter(t *testing.T) {
	pkgs, err := Parse(strings.NewReader(`Package: kept
Status: install ok installed
Version: 1

Package: removed
Status: deinstall ok config-files
Version: 2

Package: unpacked
Status: install ok unpacked
Version: 3
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 2 || pkgs[0].Name != "kept" || pkgs[1].Name != "unpacked" {
		t.Errorf("got %+v", pkgs)
	}
}

func TestCollectDistroless(t *testing.T) {
	fsys := fstest.MapFS{}
	entries, err := os.ReadDir("testdata/distroless-status.d")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		b, err := os.ReadFile("testdata/distroless-status.d/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		fsys[statusDir+"/"+e.Name()] = &fstest.MapFile{Data: b}
	}
	pkgs, err := Collect(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 7 {
		t.Errorf("got %d packages, want 7 (md5sums files skipped)", len(pkgs))
	}
	if p := index(pkgs)["libssl3"]; p.Source != "openssl" || p.Type != inventory.TypeDeb {
		t.Errorf("libssl3: %+v", p)
	}
}

func TestCollectNoDatabase(t *testing.T) {
	pkgs, err := Collect(fstest.MapFS{})
	if err != nil || pkgs != nil {
		t.Errorf("got %v, %v", pkgs, err)
	}
}

func index(pkgs []inventory.Package) map[string]inventory.Package {
	m := map[string]inventory.Package{}
	for _, p := range pkgs {
		m[p.Name] = p
	}
	return m
}
