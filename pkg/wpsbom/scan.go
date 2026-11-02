// Package wpsbom scans a root file system for its operating system, installed packages and the
// applications in the source directories it is given.
package wpsbom

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"sort"
	"strings"

	"github.com/ice-s/wpsbom/pkg/collector/apk"
	"github.com/ice-s/wpsbom/pkg/collector/dpkg"
	"github.com/ice-s/wpsbom/pkg/collector/lang"
	"github.com/ice-s/wpsbom/pkg/collector/osrelease"
	"github.com/ice-s/wpsbom/pkg/inventory"
	"github.com/ice-s/wpsbom/pkg/purl"
)

// Version of wpsbom, set at build time (-ldflags "-X …/pkg/wpsbom.Version=v1.2.3").
var Version = "dev"

// Options control a scan.
type Options struct {
	// Live means the root is the running system (scan of "/"): the kernel version and
	// hostname are read too.
	Live bool
	// RevealHostname reports the hostname as is instead of a hash of it.
	RevealHostname bool
	// Paths are source directories (absolute inside the root) searched for applications and
	// their lock files, or Go binaries. Nothing outside them is searched.
	Paths []string
}

// Collector lists one package manager's installed packages; nil without its database.
type Collector struct {
	Name    string
	Collect func(fs.FS) ([]inventory.Package, error)
}

// Collectors run by Scan.
var Collectors = []Collector{
	{"dpkg", dpkg.Collect},
	{"apk", apk.Collect},
}

// ErrNothingFound is returned when the root has neither an os-release file nor a package database.
var ErrNothingFound = errors.New("no operating system or package database found")

// Scan reads the operating system release and installed packages under fsys.
func Scan(ctx context.Context, fsys fs.FS, opts Options) (*inventory.Inventory, error) {
	distro, err := osrelease.Read(fsys)
	if err != nil {
		return nil, fmt.Errorf("os-release: %w", err)
	}
	inv := &inventory.Inventory{Distro: distro}
	for _, c := range Collectors {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pkgs, err := c.Collect(fsys)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.Name, err)
		}
		inv.Packages = append(inv.Packages, pkgs...)
	}
	for i := range inv.Packages {
		inv.Packages[i].PURL = purl.For(inv.Packages[i], distro)
	}
	if len(opts.Paths) > 0 {
		apps, pkgs, err := lang.Collect(fsys, opts.Paths)
		if err != nil {
			return nil, err
		}
		inv.Apps = apps
		inv.Packages = append(inv.Packages, pkgs...)
	}
	if distro == nil && len(inv.Packages) == 0 && len(inv.Apps) == 0 {
		return nil, ErrNothingFound
	}
	SortPackages(inv.Packages)

	if opts.Live {
		if b, err := fs.ReadFile(fsys, "proc/sys/kernel/osrelease"); err == nil {
			inv.Kernel = strings.TrimSpace(string(b))
		}
		if h, err := os.Hostname(); err == nil {
			inv.Hostname = h
			if !opts.RevealHostname {
				sum := sha256.Sum256([]byte(h))
				inv.Hostname = "sha256:" + hex.EncodeToString(sum[:8])
			}
		}
	}
	return inv, nil
}

// SortPackages orders packages by type, name, architecture, then location: OS packages, then
// each language's, stable from one scan to the next.
func SortPackages(ps []inventory.Package) {
	sort.SliceStable(ps, func(i, j int) bool {
		a, b := ps[i], ps[j]
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.Arch != b.Arch {
			return a.Arch < b.Arch
		}
		if a.Location != b.Location {
			return a.Location < b.Location
		}
		return a.Version < b.Version
	})
}
