// Package dpkg lists packages installed by dpkg (Debian, Ubuntu and derivatives).
package dpkg

import (
	"bufio"
	"errors"
	"io"
	"io/fs"
	"path"
	"strings"

	"github.com/ice-s/wpsbom/pkg/inventory"
)

const (
	statusFile = "var/lib/dpkg/status"
	// Distroless images have no status file: one file per package here instead.
	statusDir = "var/lib/dpkg/status.d"
)

// Package states whose files are on disk (dpkg-query(1) "db:Status-Status").
var present = map[string]bool{
	"installed":        true,
	"unpacked":         true,
	"half-configured":  true,
	"triggers-awaited": true,
	"triggers-pending": true,
}

// Collect returns the installed packages, or nil when the root has no dpkg database.
func Collect(fsys fs.FS) ([]inventory.Package, error) {
	seen := map[string]bool{}
	var out []inventory.Package
	add := func(pkgs []inventory.Package) {
		for _, p := range pkgs {
			if k := p.Name + ":" + p.Arch; !seen[k] {
				seen[k] = true
				out = append(out, p)
			}
		}
	}

	f, err := fsys.Open(statusFile)
	switch {
	case err == nil:
		pkgs, err := Parse(f)
		f.Close()
		if err != nil {
			return nil, err
		}
		add(pkgs)
	case !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}

	entries, err := fs.ReadDir(fsys, statusDir)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || strings.Contains(e.Name(), ".") { // skip "<pkg>.md5sums"
			continue
		}
		f, err := fsys.Open(path.Join(statusDir, e.Name()))
		if err != nil {
			return nil, err
		}
		pkgs, err := Parse(f)
		f.Close()
		if err != nil {
			return nil, err
		}
		add(pkgs)
	}
	return out, nil
}

// Parse reads dpkg status paragraphs. A paragraph without a Status field (distroless
// status.d) counts as installed.
func Parse(r io.Reader) ([]inventory.Package, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var out []inventory.Package
	fields := map[string]string{}
	flush := func() {
		defer clear(fields)
		name := fields["Package"]
		if name == "" {
			return
		}
		if st := strings.Fields(fields["Status"]); len(st) == 3 && !present[st[2]] {
			return
		}
		p := inventory.Package{
			Type:          inventory.TypeDeb,
			Name:          name,
			Version:       fields["Version"],
			Arch:          fields["Architecture"],
			Source:        name,
			SourceVersion: fields["Version"],
		}
		// "Source: openssl" or "Source: openssl (3.0.11-1)" when the versions differ.
		if src := fields["Source"]; src != "" {
			n, v, ok := strings.Cut(src, " (")
			p.Source = strings.TrimSpace(n)
			if ok {
				p.SourceVersion = strings.TrimSuffix(strings.TrimSpace(v), ")")
			}
		}
		out = append(out, p)
	}
	for sc.Scan() {
		line := sc.Text()
		switch {
		case strings.TrimSpace(line) == "":
			flush()
		case line[0] == ' ' || line[0] == '\t':
			// Continuation of a multi-line field (Description, Conffiles): not needed.
		default:
			if k, v, ok := strings.Cut(line, ":"); ok {
				fields[k] = strings.TrimSpace(v)
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	flush()
	return out, nil
}
