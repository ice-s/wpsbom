// Package apk lists packages installed by apk-tools (Alpine, Wolfi, postmarketOS).
package apk

import (
	"bufio"
	"errors"
	"io"
	"io/fs"

	"github.com/ice-s/wpsbom/pkg/inventory"
)

// Database locations; usr/lib is used by distributions with a merged /usr.
var paths = []string{"lib/apk/db/installed", "usr/lib/apk/db/installed"}

// Collect returns the installed packages, or nil when the root has no apk database.
func Collect(fsys fs.FS) ([]inventory.Package, error) {
	for _, p := range paths {
		f, err := fsys.Open(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		defer f.Close()
		return Parse(f)
	}
	return nil, nil
}

// Parse reads the installed database: blank-line separated records of "X:value" lines
// (apk-tools doc/apk-package.5: P name, V version, A arch, o origin, L license).
func Parse(r io.Reader) ([]inventory.Package, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4*1024*1024)
	var out []inventory.Package
	var p inventory.Package
	flush := func() {
		if p.Name != "" {
			if p.Source == "" {
				p.Source = p.Name
			}
			p.Type = inventory.TypeApk
			p.SourceVersion = p.Version
			out = append(out, p)
		}
		p = inventory.Package{}
	}
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		if len(line) < 2 || line[1] != ':' {
			continue
		}
		v := line[2:]
		switch line[0] {
		case 'P':
			p.Name = v
		case 'V':
			p.Version = v
		case 'A':
			p.Arch = v
		case 'o':
			p.Source = v
		case 'L':
			if v != "" {
				p.Licenses = []string{v}
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	flush()
	return out, nil
}
