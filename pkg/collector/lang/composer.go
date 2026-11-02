package lang

import (
	"encoding/json"
	"io/fs"

	"github.com/ice-s/wpsbom/pkg/inventory"
)

type composerPackage struct {
	Name    string   `json:"name"`
	Version string   `json:"version"`
	License []string `json:"license"`
}

type composerLock struct {
	Packages    []composerPackage `json:"packages"`
	PackagesDev []composerPackage `json:"packages-dev"`
}

// installed.json: Composer 2 writes {"packages": [...], "dev-package-names": [...]},
// Composer 1 a bare array.
type composerInstalled struct {
	Packages        []composerPackage `json:"packages"`
	DevPackageNames []string          `json:"dev-package-names"`
}

type composerManifest struct {
	Name       string            `json:"name"`
	Version    string            `json:"version"`
	Require    map[string]string `json:"require"`
	RequireDev map[string]string `json:"require-dev"`
}

// parseComposer reads composer.lock, keeping only what vendor/ actually has when it exists
// (a production deploy runs "composer install --no-dev": the lock still lists dev packages),
// or vendor/composer/installed.json alone when the lock file was not deployed.
func parseComposer(fsys fs.FS, dir, file string) (*result, error) {
	b, err := readFile(fsys, dir, file)
	if b == nil || err != nil {
		return nil, err
	}
	var all []composerPackage
	dev := map[string]bool{}
	installed, err := readInstalled(fsys, dir)
	if err != nil {
		return nil, err
	}
	if file == "composer.lock" {
		var lock composerLock
		if err := json.Unmarshal(b, &lock); err != nil {
			return nil, err
		}
		all = append(lock.Packages, lock.PackagesDev...)
		for _, p := range lock.PackagesDev {
			dev[p.Name] = true
		}
	} else {
		all = installed.Packages
		installed = nil
		var inst composerInstalled
		if err := json.Unmarshal(b, &inst); err == nil {
			for _, n := range inst.DevPackageNames {
				dev[n] = true
			}
		}
	}

	var m composerManifest
	if mb, _ := readFile(fsys, dir, "composer.json"); mb != nil {
		_ = json.Unmarshal(mb, &m)
	}
	r := &result{name: m.Name, version: m.Version}
	for _, p := range all {
		if installed != nil && !installed.has(p.Name) {
			continue
		}
		_, req := m.Require[p.Name]
		_, reqDev := m.RequireDev[p.Name]
		r.pkgs = append(r.pkgs, inventory.Package{
			Name:     p.Name,
			Version:  trimV(p.Version),
			Licenses: p.License,
			Direct:   req || reqDev,
			Dev:      dev[p.Name],
		})
	}
	return r, nil
}

type installedSet struct {
	Packages []composerPackage
	names    map[string]bool
}

func (s *installedSet) has(name string) bool { return s.names[name] }

// readInstalled reads vendor/composer/installed.json; nil when there is none.
func readInstalled(fsys fs.FS, dir string) (*installedSet, error) {
	b, err := readFile(fsys, dir, "vendor/composer/installed.json")
	if b == nil || err != nil {
		return nil, err
	}
	var inst composerInstalled
	if err := json.Unmarshal(b, &inst); err != nil {
		var list []composerPackage
		if json.Unmarshal(b, &list) != nil {
			return nil, err
		}
		inst.Packages = list
	}
	s := &installedSet{Packages: inst.Packages, names: map[string]bool{}}
	for _, p := range inst.Packages {
		s.names[p.Name] = true
	}
	return s, nil
}
