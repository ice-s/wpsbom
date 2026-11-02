package lang

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io/fs"
	"path"
	"regexp"
	"strings"

	"github.com/ice-s/wpsbom/pkg/inventory"
)

// parsePython reads poetry.lock, Pipfile.lock or the pinned lines of requirements*.txt.
func parsePython(fsys fs.FS, dir, file string) (*result, error) {
	switch file {
	case "poetry.lock":
		return parsePoetry(fsys, dir)
	case "Pipfile.lock":
		return parsePipfileLock(fsys, dir)
	}
	return parseRequirements(fsys, dir)
}

var pySeparators = regexp.MustCompile(`[-_.]+`)

// normalizePy compares names the PEP 503 way.
func normalizePy(n string) string { return strings.ToLower(pySeparators.ReplaceAllString(n, "-")) }

// Only exact pins give a version to match: "name==1.2.3", "name[extra]===1.2.3; markers".
var reqPin = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*===?\s*([^\s;#,]+)`)

// parseRequirements reads every requirements*.txt in dir as one application (requirements.txt
// need not exist); files named for development or tests (requirements-dev.txt) mark their packages dev.
func parseRequirements(fsys fs.FS, dir string) (*result, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, nil
	}
	var r *result
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasPrefix(n, "requirements") || !strings.HasSuffix(n, ".txt") {
			continue
		}
		b, err := fs.ReadFile(fsys, path.Join(dir, n))
		if err != nil {
			return nil, err
		}
		if r == nil {
			r = &result{manifest: n}
		}
		if n == "requirements.txt" {
			r.manifest = n
		}
		dev := strings.Contains(n, "dev") || strings.Contains(n, "test")
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			if m := reqPin.FindStringSubmatch(strings.TrimSpace(sc.Text())); m != nil {
				r.pkgs = append(r.pkgs, inventory.Package{Name: m[1], Version: m[3], Direct: true, Dev: dev})
			}
		}
	}
	return r, nil
}

type pipfileLock struct {
	Default map[string]struct {
		Version string `json:"version"`
	} `json:"default"`
	Develop map[string]struct {
		Version string `json:"version"`
	} `json:"develop"`
}

func parsePipfileLock(fsys fs.FS, dir string) (*result, error) {
	b, err := readFile(fsys, dir, "Pipfile.lock")
	if b == nil || err != nil {
		return nil, err
	}
	var lock pipfileLock
	if err := json.Unmarshal(b, &lock); err != nil {
		return nil, err
	}
	direct := tomlKeys(fsys, dir, "Pipfile", "packages", "dev-packages")
	r := &result{}
	for name, p := range lock.Default {
		r.pkgs = append(r.pkgs, inventory.Package{Name: name, Version: strings.TrimLeft(p.Version, "="), Direct: direct[normalizePy(name)]})
	}
	for name, p := range lock.Develop {
		r.pkgs = append(r.pkgs, inventory.Package{Name: name, Version: strings.TrimLeft(p.Version, "="), Direct: direct[normalizePy(name)], Dev: true})
	}
	return r, nil
}

// parsePoetry reads the [[package]] tables of poetry.lock; direct dependencies come from
// pyproject.toml ([tool.poetry.dependencies] and friends, or PEP 621 [project] dependencies).
func parsePoetry(fsys fs.FS, dir string) (*result, error) {
	b, err := readFile(fsys, dir, "poetry.lock")
	if b == nil || err != nil {
		return nil, err
	}
	direct := tomlKeys(fsys, dir, "pyproject.toml", "tool.poetry.dependencies", "tool.poetry.dev-dependencies", "tool.poetry.group.dev.dependencies")
	for n := range pep621Deps(fsys, dir) {
		direct[n] = true
	}
	r := &result{}
	if name := tomlValue(fsys, dir, "pyproject.toml", "tool.poetry", "name"); name != "" {
		r.name = name
	} else {
		r.name = tomlValue(fsys, dir, "pyproject.toml", "project", "name")
	}
	var p *inventory.Package
	flush := func() {
		if p != nil {
			p.Direct = direct[normalizePy(p.Name)]
			r.pkgs = append(r.pkgs, *p)
		}
		p = nil
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			flush()
			if line == "[[package]]" {
				p = &inventory.Package{}
			}
			continue
		}
		if p == nil {
			continue
		}
		k, v, ok := tomlPair(line)
		switch {
		case !ok:
		case k == "name":
			p.Name = v
		case k == "version":
			p.Version = v
		case k == "category":
			p.Dev = v == "dev"
		}
	}
	flush()
	return r, nil
}

// tomlPair splits a `key = "value"` line of a flat TOML table.
func tomlPair(line string) (key, value string, ok bool) {
	k, v, ok := strings.Cut(line, "=")
	if !ok {
		return "", "", false
	}
	return strings.Trim(strings.TrimSpace(k), `"'`), strings.Trim(strings.TrimSpace(v), `"'`), true
}

// tomlKeys returns the keys (PEP 503 names) of the given tables in a TOML file: just enough of
// TOML for Pipfile and pyproject.toml dependency tables.
func tomlKeys(fsys fs.FS, dir, file string, tables ...string) map[string]bool {
	out := map[string]bool{}
	b, _ := readFile(fsys, dir, file)
	want := map[string]bool{}
	for _, t := range tables {
		want[t] = true
	}
	in := false
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			in = want[strings.Trim(line, "[] ")]
			continue
		}
		if k, _, ok := tomlPair(line); in && ok && k != "" && k != "python" && !strings.HasPrefix(k, "#") {
			out[normalizePy(k)] = true
		}
	}
	return out
}

// tomlValue returns key's string value in table.
func tomlValue(fsys fs.FS, dir, file, table, key string) string {
	b, _ := readFile(fsys, dir, file)
	in := false
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			in = strings.Trim(line, "[] ") == table
			continue
		}
		if k, v, ok := tomlPair(line); in && ok && k == key {
			return v
		}
	}
	return ""
}

var pep508Name = regexp.MustCompile(`^\s*["']([A-Za-z0-9][A-Za-z0-9._-]*)`)

// pep621Deps reads the names in `dependencies = [ "requests>=2", … ]` of [project].
func pep621Deps(fsys fs.FS, dir string) map[string]bool {
	out := map[string]bool{}
	b, _ := readFile(fsys, dir, "pyproject.toml")
	inProject, inList := false, false
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "[") && !inList:
			inProject = strings.Trim(line, "[] ") == "project"
		case inProject && strings.HasPrefix(line, "dependencies") && strings.Contains(line, "["):
			inList = !strings.Contains(line, "]")
			for _, item := range strings.Split(line[strings.Index(line, "[")+1:], ",") {
				if m := pep508Name.FindStringSubmatch(item); m != nil {
					out[normalizePy(m[1])] = true
				}
			}
		case inList:
			if strings.HasPrefix(line, "]") {
				inList = false
			} else if m := pep508Name.FindStringSubmatch(line); m != nil {
				out[normalizePy(m[1])] = true
			}
		}
	}
	return out
}
