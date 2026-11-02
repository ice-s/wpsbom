package wpsbom

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ice-s/wpsbom/pkg/rootfs"
)

func TestScanRootfs(t *testing.T) {
	root := t.TempDir()
	write(t, root, "usr/lib/os-release", "ID=debian\nVERSION_ID=\"12\"\n")
	must(t, os.MkdirAll(filepath.Join(root, "etc"), 0o755))
	// Debian ships etc/os-release as a symlink; an absolute one must stay inside the root.
	must(t, os.Symlink("/usr/lib/os-release", filepath.Join(root, "etc/os-release")))
	status, err := os.ReadFile("../collector/dpkg/testdata/debian-12.status")
	must(t, err)
	write(t, root, "var/lib/dpkg/status", string(status))

	fsys, err := rootfs.New(root)
	must(t, err)
	inv, err := Scan(context.Background(), fsys, Options{})
	must(t, err)
	if inv.Distro == nil || inv.Distro.Qualifier() != "debian-12" {
		t.Fatalf("distro: %+v", inv.Distro)
	}
	if len(inv.Packages) != 88 {
		t.Errorf("got %d packages, want 88", len(inv.Packages))
	}
	for i, p := range inv.Packages {
		if !strings.HasPrefix(p.PURL, "pkg:deb/debian/") || !strings.Contains(p.PURL, "distro=debian-12") {
			t.Errorf("purl: %s", p.PURL)
		}
		if i > 0 && inv.Packages[i-1].Name > p.Name {
			t.Errorf("not sorted: %s before %s", inv.Packages[i-1].Name, p.Name)
		}
	}
	if inv.Kernel != "" || inv.Hostname != "" {
		t.Errorf("non-live scan read host details: %q %q", inv.Kernel, inv.Hostname)
	}
}

func TestScanEmpty(t *testing.T) {
	fsys, err := rootfs.New(t.TempDir())
	must(t, err)
	if _, err := Scan(context.Background(), fsys, Options{}); !errors.Is(err, ErrNothingFound) {
		t.Errorf("got %v", err)
	}
}

func write(t *testing.T, root, name, data string) {
	t.Helper()
	p := filepath.Join(root, name)
	must(t, os.MkdirAll(filepath.Dir(p), 0o755))
	must(t, os.WriteFile(p, []byte(data), 0o644))
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
