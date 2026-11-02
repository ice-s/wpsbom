// Package wpsbom scans a root file system for its operating system and installed packages.
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
	if distro == nil && len(inv.Packages) == 0 {
		return nil, ErrNothingFound
	}
	for i := range inv.Packages {
		inv.Packages[i].PURL = purl.For(inv.Packages[i], distro)
	}
	sort.Slice(inv.Packages, func(i, j int) bool {
		a, b := inv.Packages[i], inv.Packages[j]
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		return a.Arch < b.Arch
	})

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
