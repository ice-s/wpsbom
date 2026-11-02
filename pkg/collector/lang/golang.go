package lang

import (
	"bufio"
	"bytes"
	"debug/buildinfo"
	"io"
	"io/fs"
	"path"
	"strings"

	"github.com/ice-s/wpsbom/pkg/inventory"
	"github.com/ice-s/wpsbom/pkg/purl"
)

// maxBinary bounds the executables inspected for Go build information.
const maxBinary = 512 << 20

// parseGoMod reads the require directives of go.mod; "// indirect" marks the transitive ones.
func parseGoMod(fsys fs.FS, dir, file string) (*result, error) {
	b, err := readFile(fsys, dir, file)
	if b == nil || err != nil {
		return nil, err
	}
	r := &result{}
	block := false
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		indirect := strings.Contains(line, "// indirect")
		if i := strings.Index(line, "//"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		f := strings.Fields(line)
		switch {
		case len(f) == 0:
		case f[0] == "module" && len(f) > 1:
			r.name = strings.Trim(f[1], `"`)
		case f[0] == "require" && len(f) == 2 && f[1] == "(":
			block = true
		case block && f[0] == ")":
			block = false
		case f[0] == "require" && len(f) >= 3:
			r.pkgs = append(r.pkgs, inventory.Package{Name: f[1], Version: f[2], Direct: !indirect})
		case block && len(f) >= 2:
			r.pkgs = append(r.pkgs, inventory.Package{Name: f[0], Version: f[1], Direct: !indirect})
		}
	}
	return r, nil
}

// goBinary reads the module information a Go toolchain embeds in an executable: one application
// (the main module) whose packages are the modules linked in, plus the standard library.
func goBinary(fsys fs.FS, file string) (*inventory.App, []inventory.Package) {
	f, err := fsys.Open(file)
	if err != nil {
		return nil, nil
	}
	defer f.Close()
	ra, ok := f.(io.ReaderAt)
	if !ok {
		return nil, nil
	}
	if fi, err := f.Stat(); err != nil || !fi.Mode().IsRegular() || fi.Size() > maxBinary {
		return nil, nil
	}
	bi, err := buildinfo.Read(ra)
	if err != nil {
		return nil, nil
	}
	loc := "/" + file
	app := &inventory.App{Name: bi.Main.Path, Version: bi.Main.Version, Type: inventory.TypeGolang, Dir: "/" + path.Dir(file), Manifest: loc}
	if app.Name == "" {
		app.Name = path.Base(file)
	}
	var pkgs []inventory.Package
	add := func(name, version string, direct bool) {
		if version == "" || version == "(devel)" {
			return
		}
		pkgs = append(pkgs, inventory.Package{
			Type: inventory.TypeGolang, Name: name, Version: version,
			PURL: purl.ForLang(inventory.TypeGolang, name, version), Location: loc, Direct: direct,
		})
	}
	// Go's own vulnerabilities are filed under the "stdlib" module, versions without "go".
	add("stdlib", strings.TrimPrefix(bi.GoVersion, "go"), true)
	for _, d := range bi.Deps {
		m := d
		if d.Replace != nil {
			m = d.Replace
		}
		// The binary does not say which modules go.mod required directly.
		add(m.Path, m.Version, false)
	}
	return app, pkgs
}
