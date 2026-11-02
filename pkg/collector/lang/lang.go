// Package lang finds applications in source directories and lists their dependencies from the
// lock files the language package managers write (composer.lock, package-lock.json, …) and from
// the module information Go embeds in its binaries.
//
// Only the directories given are searched: walking a whole server to guess where the code lives
// is slow and finds every tool's bundled lock files too.
package lang

import (
	"errors"
	"io/fs"
	"path"
	"sort"
	"strings"

	"github.com/ice-s/wpsbom/pkg/inventory"
	"github.com/ice-s/wpsbom/pkg/purl"
)

// MaxDepth bounds how deep below each given directory lock files are looked for.
const MaxDepth = 6

// Directories never descended into: installed dependencies (their own lock files are not the
// application's), VCS data, caches.
var skipDirs = map[string]bool{
	"node_modules": true, "vendor": true, "bower_components": true, "site-packages": true,
	"__pycache__": true, "venv": true, "env": true, "storage": true, "cache": true, "tmp": true,
}

// parser reads one kind of lock file in dir (slash path inside the root, no leading slash).
// It returns nil when that file is not there.
type parser struct {
	typ   string
	files []string // tried in order; the first present wins
	parse func(fsys fs.FS, dir, file string) (*result, error)
}

// result of one lock file: the application and its packages (Name, Version, Direct, Dev set).
type result struct {
	name, version string
	// manifest is the file actually read when it differs from the one looked for.
	manifest string
	pkgs     []inventory.Package
}

// One parser per ecosystem and directory: a directory with both package-lock.json and yarn.lock
// is one npm application, read from the better source.
var parsers = []parser{
	{inventory.TypeComposer, []string{"composer.lock", "vendor/composer/installed.json"}, parseComposer},
	{inventory.TypeNpm, []string{"package-lock.json", "npm-shrinkwrap.json", "yarn.lock"}, parseNpm},
	{inventory.TypePyPI, []string{"poetry.lock", "Pipfile.lock", "requirements.txt"}, parsePython},
	{inventory.TypeGolang, []string{"go.mod"}, parseGoMod},
	{inventory.TypeGem, []string{"Gemfile.lock"}, parseGemfile},
}

// Collect searches each directory (absolute paths inside the root, e.g. "/var/www/shop") for
// applications. A directory that does not exist is an error: it was asked for explicitly.
func Collect(fsys fs.FS, dirs []string) ([]inventory.App, []inventory.Package, error) {
	var apps []inventory.App
	var pkgs []inventory.Package
	seen := map[string]bool{}
	for _, d := range dirs {
		root := strings.Trim(path.Clean("/"+d), "/")
		if root == "" {
			root = "."
		}
		fi, err := fs.Stat(fsys, root)
		if err != nil {
			return nil, nil, &fs.PathError{Op: "scan", Path: d, Err: errors.Unwrap(err)}
		}
		if !fi.IsDir() {
			// A single file: a Go binary given directly.
			if a, ps := goBinary(fsys, root); a != nil && !seen[a.Manifest] {
				seen[a.Manifest] = true
				apps, pkgs = append(apps, *a), append(pkgs, ps...)
			}
			continue
		}
		err = walk(fsys, root, 0, func(dir string) error {
			for _, p := range parsers {
				for _, file := range p.files {
					rel := path.Join(dir, file)
					if seen[rel] {
						break
					}
					r, err := p.parse(fsys, dir, file)
					if err != nil {
						return &fs.PathError{Op: "parse", Path: "/" + rel, Err: err}
					}
					if r == nil {
						continue
					}
					seen[rel] = true
					if r.manifest != "" {
						rel = path.Join(dir, r.manifest)
					}
					app, ps := finish(p.typ, dir, rel, r)
					apps, pkgs = append(apps, app), append(pkgs, ps...)
					break
				}
			}
			return nil
		}, func(file string) {
			if a, ps := goBinary(fsys, file); a != nil && !seen[a.Manifest] {
				seen[a.Manifest] = true
				apps, pkgs = append(apps, *a), append(pkgs, ps...)
			}
		})
		if err != nil {
			return nil, nil, err
		}
	}
	return apps, pkgs, nil
}

// walk calls onDir for dir and every directory below it (to MaxDepth), and onExec for every
// executable regular file, skipping dependency, VCS and hidden directories.
func walk(fsys fs.FS, dir string, depth int, onDir func(string) error, onExec func(string)) error {
	if err := onDir(dir); err != nil {
		return err
	}
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		// Unreadable subdirectories (permissions) are skipped, not fatal.
		if depth > 0 {
			return nil
		}
		return err
	}
	for _, e := range entries {
		name := e.Name()
		child := path.Join(dir, name)
		switch {
		case e.IsDir():
			if depth < MaxDepth && !skipDirs[name] && !strings.HasPrefix(name, ".") {
				if err := walk(fsys, child, depth+1, onDir, onExec); err != nil {
					return err
				}
			}
		case e.Type().IsRegular():
			if info, err := e.Info(); err == nil && info.Mode()&0o111 != 0 {
				onExec(child)
			}
		}
	}
	return nil
}

// finish fills in what every package of an application shares: type, PURL and location.
func finish(typ, dir, manifest string, r *result) (inventory.App, []inventory.Package) {
	app := inventory.App{Name: r.name, Version: r.version, Type: typ, Dir: "/" + dir, Manifest: "/" + manifest}
	if app.Name == "" {
		app.Name = path.Base("/" + dir)
	}
	seen := map[string]bool{}
	out := make([]inventory.Package, 0, len(r.pkgs))
	for _, p := range r.pkgs {
		if p.Name == "" || p.Version == "" {
			continue
		}
		p.Type = typ
		p.PURL = purl.ForLang(typ, p.Name, p.Version)
		p.Location = app.Manifest
		if seen[p.PURL] {
			continue
		}
		seen[p.PURL] = true
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name || out[i].Name == out[j].Name && out[i].Version < out[j].Version })
	return app, out
}

// readFile reads dir/file, or returns nil without error when it does not exist.
func readFile(fsys fs.FS, dir, file string) ([]byte, error) {
	b, err := fs.ReadFile(fsys, path.Join(dir, file))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	return b, err
}

// trimV drops the "v" some ecosystems prefix versions with ("v10.48.4" → "10.48.4").
func trimV(v string) string {
	if len(v) > 1 && (v[0] == 'v' || v[0] == 'V') && v[1] >= '0' && v[1] <= '9' {
		return v[1:]
	}
	return v
}
