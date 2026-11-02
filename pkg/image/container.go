package image

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/ice-s/wpsbom/pkg/collector/lang"
	"github.com/ice-s/wpsbom/pkg/docker"
	"github.com/ice-s/wpsbom/pkg/inventory"
	"github.com/ice-s/wpsbom/pkg/rootfs"
	"github.com/ice-s/wpsbom/pkg/wpsbom"
)

// ErrNoRootFS is returned when a container's file system cannot be read in place (another
// storage driver, or not root): the image has to be exported instead.
var ErrNoRootFS = errors.New("container file system not readable in place")

// ScanContainer scans a running container where it is: its root file system as the storage
// driver mounted it on the host (overlay2 MergedDir), plus the bind mounts and volumes over its
// application directories, read at their source. Without a MergedDir (the containerd image
// store, other drivers) it reads /proc/PID/root, where the mounts are already in place. Nothing is copied, so it takes seconds; the
// layer each package came from is not known this way (Scan of the exported image has it).
func ScanContainer(ctx context.Context, c *docker.Client, id string, opts Options) (*inventory.Inventory, error) {
	ct, err := c.InspectContainer(ctx, id)
	if err != nil {
		return nil, err
	}
	merged, viaProc := ct.GraphDriver.Data["MergedDir"], false
	if merged != "" {
		if _, err := os.Stat(merged); err != nil {
			merged = ""
		}
	}
	if merged == "" && ct.State.Pid > 0 {
		merged, viaProc = fmt.Sprintf("/proc/%d/root", ct.State.Pid), true
		if _, err := os.Stat(merged); err != nil {
			return nil, fmt.Errorf("%w: %v", ErrNoRootFS, err)
		}
	}
	if merged == "" {
		return nil, fmt.Errorf("%w (storage driver %q)", ErrNoRootFS, ct.GraphDriver.Name)
	}
	fsys, err := rootfs.New(merged)
	if err != nil {
		return nil, err
	}

	dirs := AppDirs(ct.Config.WorkingDir, opts.Paths)
	// Mounts hide what the image has at their destination; their content is on the host.
	// Through /proc/PID/root the container's own view already has them.
	var mounts []docker.Mount
	for _, m := range ct.Mounts {
		if viaProc {
			break
		}
		if m.Source != "" && m.Destination != "" && (m.Type == "bind" || m.Type == "volume") && relevant(m.Destination, dirs) {
			mounts = append(mounts, m)
		}
	}
	var paths []string
	for _, d := range dirs {
		if fi, err := os.Stat(filepath.Join(merged, filepath.FromSlash(d))); err == nil && fi.IsDir() {
			paths = append(paths, d)
		}
	}
	inv, err := wpsbom.Scan(ctx, fsys, wpsbom.Options{Paths: paths, NoOS: opts.NoOS})
	if errors.Is(err, wpsbom.ErrNothingFound) {
		inv, err = &inventory.Inventory{}, nil
	}
	if err != nil {
		return nil, err
	}
	inv.Apps, inv.Packages = dropUnder(inv.Apps, inv.Packages, mounts)

	if len(mounts) > 0 {
		host, err := rootfs.New("/")
		if err != nil {
			return nil, err
		}
		for _, m := range mounts {
			src := m.Source
			// A mount above an application directory: search only the application directories under it.
			var sub []string
			for _, d := range dirs {
				if within(d, m.Destination) {
					sub = append(sub, path.Join(src, strings.TrimPrefix(d, m.Destination)))
				}
			}
			// A mount at or below an application directory: all of it.
			if len(sub) == 0 {
				sub = []string{src}
			}
			for _, s := range sub {
				if fi, err := os.Stat(s); err != nil || !fi.IsDir() {
					continue
				}
				apps, pkgs, err := lang.Collect(host, []string{s})
				if err != nil {
					return nil, fmt.Errorf("mount %s: %w", m.Destination, err)
				}
				// Paths as the container sees them.
				move := func(p string) string { return m.Destination + strings.TrimPrefix(p, src) }
				for i := range apps {
					apps[i].Dir, apps[i].Manifest = move(apps[i].Dir), move(apps[i].Manifest)
				}
				for i := range pkgs {
					pkgs[i].Location = move(pkgs[i].Location)
				}
				inv.Apps, inv.Packages = append(inv.Apps, apps...), append(inv.Packages, pkgs...)
			}
		}
		wpsbom.SortPackages(inv.Packages)
	}

	meta := inventory.Image{Ref: ct.Config.Image, ID: ct.Image, Digest: ct.Image}
	if info, err := c.Inspect(ctx, ct.Image); err == nil {
		meta.OS, meta.Arch = info.Os, info.Arch
		if len(info.RepoDigests) > 0 {
			repo, digest, _ := strings.Cut(info.RepoDigests[0], "@")
			meta.Repo, meta.Digest = repo, digest
		}
	}
	if meta.Repo == "" {
		meta.Repo = repoOf(ct.Config.Image)
	}
	inv.Image = &meta
	return inv, nil
}

// relevant: a mount at, under or above one of the application directories.
func relevant(dest string, dirs []string) bool {
	for _, d := range dirs {
		if within(dest, d) || within(d, dest) {
			return true
		}
	}
	return false
}

// within: p is dir or below it.
func within(p, dir string) bool {
	return dir != "" && (p == dir || strings.HasPrefix(p, strings.TrimSuffix(dir, "/")+"/"))
}

// dropUnder removes what the image has below the mounts: the container does not see it.
func dropUnder(apps []inventory.App, pkgs []inventory.Package, mounts []docker.Mount) ([]inventory.App, []inventory.Package) {
	if len(mounts) == 0 {
		return apps, pkgs
	}
	hidden := func(p string) bool {
		for _, m := range mounts {
			if within(p, m.Destination) {
				return true
			}
		}
		return false
	}
	var a []inventory.App
	for _, x := range apps {
		if !hidden(x.Manifest) {
			a = append(a, x)
		}
	}
	var p []inventory.Package
	for _, x := range pkgs {
		if x.Location == "" || !hidden(x.Location) {
			p = append(p, x)
		}
	}
	return a, p
}
