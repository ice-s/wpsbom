package lang

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io/fs"
	"strings"

	"github.com/ice-s/wpsbom/pkg/inventory"
)

type npmManifest struct {
	Name                 string            `json:"name"`
	Version              string            `json:"version"`
	Dependencies         map[string]string `json:"dependencies"`
	DevDependencies      map[string]string `json:"devDependencies"`
	OptionalDependencies map[string]string `json:"optionalDependencies"`
}

func (m *npmManifest) requires(name string) bool {
	_, a := m.Dependencies[name]
	_, b := m.DevDependencies[name]
	_, c := m.OptionalDependencies[name]
	return a || b || c
}

// package-lock.json / npm-shrinkwrap.json: lockfileVersion 2 and 3 list every installed path in
// "packages"; version 1 nests "dependencies".
type npmLock struct {
	Name         string                `json:"name"`
	Version      string                `json:"version"`
	Packages     map[string]npmLockPkg `json:"packages"`
	Dependencies map[string]npmLockDep `json:"dependencies"`
}

type npmLockPkg struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Dev     bool   `json:"dev"`
	Link    bool   `json:"link"`
	License any    `json:"license"`
}

type npmLockDep struct {
	Version      string                `json:"version"`
	Dev          bool                  `json:"dev"`
	Dependencies map[string]npmLockDep `json:"dependencies"`
}

func parseNpm(fsys fs.FS, dir, file string) (*result, error) {
	b, err := readFile(fsys, dir, file)
	if b == nil || err != nil {
		return nil, err
	}
	var m npmManifest
	if mb, _ := readFile(fsys, dir, "package.json"); mb != nil {
		_ = json.Unmarshal(mb, &m)
	}
	r := &result{name: m.Name, version: m.Version}
	if file == "yarn.lock" {
		r.pkgs = parseYarnLock(b, &m)
		return r, nil
	}

	var lock npmLock
	if err := json.Unmarshal(b, &lock); err != nil {
		return nil, err
	}
	if r.name == "" {
		r.name, r.version = lock.Name, lock.Version
	}
	if len(lock.Packages) > 0 {
		for key, p := range lock.Packages {
			// "" is the project itself; links point at workspace packages.
			if key == "" || p.Link {
				continue
			}
			i := strings.LastIndex(key, "node_modules/")
			if i < 0 {
				continue // a workspace directory, not an installed package
			}
			name := key[i+len("node_modules/"):]
			if p.Name != "" {
				name = p.Name
			}
			// Only top-level node_modules entries can be what package.json asks for.
			top := i == 0
			r.pkgs = append(r.pkgs, inventory.Package{
				Name:     name,
				Version:  p.Version,
				Licenses: npmLicense(p.License),
				Direct:   top && m.requires(name),
				Dev:      p.Dev,
			})
		}
		return r, nil
	}
	var walkDeps func(deps map[string]npmLockDep, top bool)
	walkDeps = func(deps map[string]npmLockDep, top bool) {
		for name, d := range deps {
			r.pkgs = append(r.pkgs, inventory.Package{Name: name, Version: d.Version, Direct: top && m.requires(name), Dev: d.Dev})
			walkDeps(d.Dependencies, false)
		}
	}
	walkDeps(lock.Dependencies, true)
	return r, nil
}

func npmLicense(v any) []string {
	switch l := v.(type) {
	case string:
		if l != "" {
			return []string{l}
		}
	case map[string]any:
		if t, ok := l["type"].(string); ok && t != "" {
			return []string{t}
		}
	}
	return nil
}

// parseYarnLock reads yarn.lock, classic (v1) and Berry (v2+):
//
//	"@babel/core@^7.0.0", "@babel/core@^7.1.0":   |  "lodash@npm:^4.17.21":
//	  version "7.22.5"                             |    version: 4.17.21
func parseYarnLock(b []byte, m *npmManifest) []inventory.Package {
	var out []inventory.Package
	var name string
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line[0] != ' ' {
			name = ""
			if strings.HasSuffix(line, ":") && !strings.HasPrefix(line, "__metadata") {
				spec := strings.Trim(strings.SplitN(strings.TrimSuffix(line, ":"), ",", 2)[0], `" `)
				// The name ends at the "@" that starts the range (not the one of a scope).
				if i := strings.LastIndex(spec, "@"); i > 0 {
					rng := spec[i+1:]
					if !strings.HasPrefix(rng, "workspace:") && !strings.HasPrefix(rng, "link:") && !strings.HasPrefix(rng, "portal:") {
						name = spec[:i]
					}
				}
			}
			continue
		}
		t := strings.TrimSpace(line)
		if name == "" || !strings.HasPrefix(t, "version") {
			continue
		}
		v := strings.Trim(strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(t, "version"), ":")), `"`)
		out = append(out, inventory.Package{Name: name, Version: v, Direct: m.requires(name)})
		name = ""
	}
	return out
}
