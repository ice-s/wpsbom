package image

import (
	"archive/tar"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/ice-s/wpsbom/pkg/inventory"
	"github.com/ice-s/wpsbom/pkg/rootfs"
	"github.com/ice-s/wpsbom/pkg/wpsbom"
)

// DefaultAppDirs are where images usually keep their application, searched for lock files and
// Go binaries in addition to the image's WORKDIR and any Options.Paths.
var DefaultAppDirs = []string{"/app", "/srv", "/var/www", "/usr/src/app", "/opt/app", "/code", "/workspace", "/home/app", "/usr/local/bin", "/usr/local/lib", "/opt/venv"}

// libDirs hold shared libraries (executable bits set) and Python installs: no binaries are
// extracted from them, only Python package metadata.
var libDirs = map[string]bool{"/usr/local/lib": true}

// Options control an image scan.
type Options struct {
	// Paths are extra application directories inside the image.
	Paths []string
	// NoOS leaves out the image's OS packages.
	NoOS bool
	// BaseDiffIDs are the layers of the image's base image (FROM …): layers of this image that
	// start with the same list are marked Base. Without them the history timestamps decide.
	BaseDiffIDs []v1.Hash
}

// Files a scan reads; everything else in a layer is skipped.
var osFiles = map[string]bool{
	"etc/os-release": true, "usr/lib/os-release": true,
	"var/lib/dpkg/status": true, "lib/apk/db/installed": true, "usr/lib/apk/db/installed": true,
}

var langFiles = map[string]bool{
	"composer.lock": true, "composer.json": true, "package-lock.json": true, "npm-shrinkwrap.json": true,
	"yarn.lock": true, "package.json": true, "poetry.lock": true, "pyproject.toml": true, "Pipfile": true,
	"Pipfile.lock": true, "go.mod": true, "Gemfile.lock": true,
}

// maxExtract bounds a single extracted executable (Go binaries are read for their build info).
const maxExtract = 512 << 20

// Scan replays the image's layers and scans after every layer that changed a file the scan
// reads, so each package is attributed to the layer that added that version.
func Scan(ctx context.Context, src *Source, opts Options) (*inventory.Inventory, error) {
	img := src.Image
	cfg, err := img.ConfigFile()
	if err != nil {
		return nil, err
	}
	layers, err := img.Layers()
	if err != nil {
		return nil, err
	}
	meta := src.Meta
	if meta.OS == "" {
		meta.OS, meta.Arch = cfg.OS, cfg.Architecture
	}
	meta.Layers, meta.BaseKnown = describeLayers(cfg, layers, opts.BaseDiffIDs)

	dirs := appDirs(cfg, opts.Paths)
	tmp, err := os.MkdirTemp("", "wpsbom-rootfs-*")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(tmp)

	firstSeen := map[string]int{}
	var last *inventory.Inventory
	for i, l := range layers {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		touched, err := apply(tmp, l, dirs)
		if err != nil {
			return nil, fmt.Errorf("layer %d: %w", i+1, err)
		}
		if !touched {
			continue
		}
		inv, err := scanDir(ctx, tmp, dirs, opts.NoOS)
		if err != nil {
			return nil, fmt.Errorf("layer %d: %w", i+1, err)
		}
		for _, p := range inv.Packages {
			if _, ok := firstSeen[key(p)]; !ok {
				firstSeen[key(p)] = i + 1
			}
		}
		last = inv
	}
	if last == nil {
		return nil, wpsbom.ErrNothingFound
	}
	for i := range last.Packages {
		last.Packages[i].Layer = firstSeen[key(last.Packages[i])]
	}
	last.Image = &meta
	return last, nil
}

func key(p inventory.Package) string {
	return p.Type + "\x00" + p.Name + "\x00" + p.Version + "\x00" + p.Arch + "\x00" + p.Location
}

// scanDir scans the replayed root; application directories that do not exist (yet) are left out.
func scanDir(ctx context.Context, dir string, appDirs []string, noOS bool) (*inventory.Inventory, error) {
	fsys, err := rootfs.New(dir)
	if err != nil {
		return nil, err
	}
	var paths []string
	for _, d := range appDirs {
		if fi, err := os.Stat(filepath.Join(dir, filepath.FromSlash(d))); err == nil && fi.IsDir() {
			paths = append(paths, d)
		}
	}
	inv, err := wpsbom.Scan(ctx, fsys, wpsbom.Options{Paths: paths, NoOS: noOS})
	if errors.Is(err, wpsbom.ErrNothingFound) {
		return &inventory.Inventory{}, nil
	}
	return inv, err
}

// appDirs: the defaults, WORKDIR and the extra paths, cleaned and without duplicates.
func appDirs(cfg *v1.ConfigFile, extra []string) []string {
	return AppDirs(cfg.Config.WorkingDir, extra)
}

// AppDirs are the application directories searched in an image or container: the defaults,
// its working directory and the extra paths, cleaned and without duplicates.
func AppDirs(workingDir string, extra []string) []string {
	all := append([]string{}, DefaultAppDirs...)
	if wd := workingDir; wd != "" && path.Clean(wd) != "/" {
		all = append(all, wd)
	}
	all = append(all, extra...)
	seen := map[string]bool{}
	var out []string
	for _, d := range all {
		d = path.Clean("/" + d)
		if d != "/" && !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out
}

// wanted tells whether a file (slash path, no leading slash) must be extracted.
func wanted(name string, mode int64, size int64, dirs []string) bool {
	if osFiles[name] || strings.HasPrefix(name, "var/lib/dpkg/status.d/") {
		return true
	}
	abs := "/" + name
	for _, d := range dirs {
		if !strings.HasPrefix(abs, d+"/") {
			continue
		}
		rel := abs[len(d)+1:]
		if strings.Contains("/"+rel, "/node_modules/") || strings.Contains("/"+rel, "/.git/") {
			return false
		}
		base := path.Base(name)
		if strings.HasSuffix(rel, "vendor/composer/installed.json") {
			return true
		}
		if strings.Contains("/"+rel, "/vendor/") {
			return false
		}
		if langFiles[base] || strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt") {
			return true
		}
		// Installed Python distributions: their metadata file is enough.
		if parent := path.Base(path.Dir(name)); (base == "METADATA" && strings.HasSuffix(parent, ".dist-info")) || (base == "PKG-INFO" && strings.HasSuffix(parent, ".egg-info")) {
			return true
		}
		return !libDirs[d] && mode&0o111 != 0 && size <= maxExtract
	}
	return false
}

// apply replays one layer onto dir: whiteouts delete, wanted files and all directories and
// symlinks under them are written. It reports whether a wanted file changed.
//
// The layer is hostile input: every path is resolved inside dir the way the container sees it
// (symlinks included) and every write, removal and link goes through dir's os.Root, so nothing
// can land outside it (a symlink "app" → "/" followed by "app/etc/cron.d/x", a whiteout through
// such a link, a hard link to "../../etc/shadow"). Entries that would are skipped.
func apply(dir string, l v1.Layer, dirs []string) (bool, error) {
	fsys, err := rootfs.New(dir)
	if err != nil {
		return false, err
	}
	root := fsys.OSRoot()
	rc, err := l.Uncompressed()
	if err != nil {
		return false, err
	}
	defer rc.Close()
	tr := tar.NewReader(rc)
	touched := false
	// at: where name (a slash path inside the image) is, relative to dir, its parent resolved.
	at := func(name string) (string, bool) {
		parent, err := fsys.Rel(path.Dir(name))
		if err != nil {
			return "", false
		}
		return filepath.Join(parent, path.Base(name)), true
	}
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return touched, nil
		}
		if err != nil {
			return touched, err
		}
		name := strings.TrimPrefix(path.Clean("/"+h.Name), "/")
		if name == "" || name == "." {
			continue
		}
		base := path.Base(name)
		// Whiteouts: ".wh.X" deletes X from lower layers, ".wh..wh..opq" empties the directory.
		if strings.HasPrefix(base, ".wh.") {
			parent, err := fsys.Rel(path.Dir(name))
			if err != nil {
				continue
			}
			if base == ".wh..wh..opq" {
				if d, err := root.Open(parent); err == nil {
					entries, _ := d.ReadDir(-1)
					d.Close()
					for _, e := range entries {
						root.RemoveAll(filepath.Join(parent, e.Name()))
					}
				}
			} else {
				root.RemoveAll(filepath.Join(parent, strings.TrimPrefix(base, ".wh.")))
			}
			touched = true
			continue
		}
		switch h.Typeflag {
		case tar.TypeSymlink:
			// Links are cheap and needed to resolve paths (etc/os-release → ../usr/lib/os-release).
			if !osFiles[name] && !underDirs(name, dirs) && !isAncestor(name, dirs) {
				continue
			}
			target, ok := at(name)
			if !ok || root.MkdirAll(filepath.Dir(target), 0o755) != nil {
				continue
			}
			root.RemoveAll(target)
			// The link's own text is never followed here: rootfs resolves it inside dir when read.
			if root.Symlink(h.Linkname, target) == nil {
				touched = true
			}
		case tar.TypeReg, tar.TypeLink:
			if !wanted(name, h.Mode, h.Size, dirs) || h.Size > maxExtract {
				continue
			}
			target, ok := at(name)
			if !ok || root.MkdirAll(filepath.Dir(target), 0o755) != nil {
				continue
			}
			root.RemoveAll(target)
			var src io.Reader = tr
			var linked *os.File
			if h.Typeflag == tar.TypeLink {
				from, err := fsys.Rel(strings.TrimPrefix(path.Clean("/"+h.Linkname), "/"))
				if err != nil {
					continue
				}
				in, err := root.Open(from)
				if err != nil {
					continue
				}
				fi, err := in.Stat()
				if err != nil || !fi.Mode().IsRegular() {
					in.Close()
					continue
				}
				linked, src = in, in
			}
			f, err := root.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(h.Mode).Perm()|0o600)
			if err != nil {
				if linked != nil {
					linked.Close()
				}
				continue
			}
			_, err = io.Copy(f, io.LimitReader(src, maxExtract))
			if cerr := f.Close(); err == nil {
				err = cerr
			}
			if linked != nil {
				linked.Close()
			}
			if err != nil {
				return touched, err
			}
			touched = true
		}
	}
}

// underDirs: inside one of the application directories.
func underDirs(name string, dirs []string) bool {
	for _, d := range dirs {
		if strings.HasPrefix("/"+name, d+"/") {
			return true
		}
	}
	return false
}

// isAncestor: a directory on the way to an application directory (a symlinked /app, /var/www).
func isAncestor(name string, dirs []string) bool {
	for _, d := range dirs {
		if d == "/"+name || strings.HasPrefix(d, "/"+name+"/") {
			return true
		}
	}
	return false
}

// describeLayers pairs each layer with the history entry that created it and marks the base
// image's layers: exactly when the base image's layers are given, else by time. An image's own
// build steps are written within minutes of each other, while the base image's are older; images
// built with a fixed SOURCE_DATE_EPOCH carry no usable times and get no base marks.
func describeLayers(cfg *v1.ConfigFile, layers []v1.Layer, base []v1.Hash) ([]inventory.Layer, bool) {
	out := make([]inventory.Layer, len(layers))
	var created []time.Time
	h := 0
	for _, e := range cfg.History {
		if e.EmptyLayer {
			continue
		}
		if h < len(out) {
			out[h].CreatedBy = cleanCreatedBy(e.CreatedBy)
			created = append(created, e.Created.Time)
		}
		h++
	}
	for i, l := range layers {
		if d, err := l.DiffID(); err == nil {
			out[i].DiffID = d.String()
		}
	}

	if len(base) > 0 {
		known := len(base) <= len(out)
		for i := 0; i < len(base) && i < len(out); i++ {
			if out[i].DiffID != base[i].String() {
				known = false
				break
			}
		}
		if known {
			for i := range base {
				out[i].Base = true
			}
			return out, true
		}
	}

	if len(created) != len(out) || len(out) < 2 {
		return out, false
	}
	newest := created[len(created)-1]
	if created[0].Equal(newest) {
		return out, false
	}
	for i := range out {
		out[i].Base = created[i].Before(newest.Add(-30 * time.Minute))
	}
	return out, false
}

// cleanCreatedBy shortens the history's "/bin/sh -c #(nop) COPY …" to the instruction.
// buildArgs is BuildKit's "|2 NPM_TOKEN=… FOO=… " prefix: the build arguments of a RUN step.
var buildArgs = regexp.MustCompile(`^\|\d+(\s+\S+=\S*)*\s+`)

// secretArg is an assignment whose name says it holds a secret (TOKEN=, API_KEY=, PASSWORD=…).
var secretArg = regexp.MustCompile(`(?i)\b([A-Z0-9_]*(?:TOKEN|SECRET|PASSW(?:OR)?D|PASS|PWD|KEY|CREDENTIALS?|AUTH)[A-Z0-9_]*)=("[^"]*"|'[^']*'|\S+)`)

// cleanCreatedBy shortens a history entry to the Dockerfile step. Build arguments (often a
// registry or npm token) are dropped and values of secret-looking assignments masked: this text
// goes into the SBOM and off the machine.
func cleanCreatedBy(s string) string {
	s = strings.TrimSpace(s)
	s = buildArgs.ReplaceAllString(s, "")
	s = secretArg.ReplaceAllString(s, "$1=***")
	s = strings.TrimSpace(strings.TrimPrefix(s, "/bin/sh -c #(nop) "))
	if strings.HasPrefix(s, "/bin/sh -c ") {
		s = "RUN " + strings.TrimPrefix(s, "/bin/sh -c ")
	}
	s = strings.TrimSuffix(s, " # buildkit")
	if len(s) > 300 {
		s = s[:300] + "…"
	}
	return s
}
