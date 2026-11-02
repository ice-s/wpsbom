package lang

import (
	"bufio"
	"bytes"
	"io/fs"
	"strings"

	"github.com/ice-s/wpsbom/pkg/inventory"
)

// parseGemfile reads Gemfile.lock: gems are the 4-space indented "name (version)" lines under
// "specs:", and the DEPENDENCIES section lists what the Gemfile asks for directly.
func parseGemfile(fsys fs.FS, dir, file string) (*result, error) {
	b, err := readFile(fsys, dir, file)
	if b == nil || err != nil {
		return nil, err
	}
	r := &result{}
	direct := map[string]bool{}
	section := ""
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			continue
		}
		if line[0] != ' ' {
			section = strings.TrimSpace(line)
			continue
		}
		switch {
		case section == "DEPENDENCIES" && strings.HasPrefix(line, "  ") && !strings.HasPrefix(line, "   "):
			name := strings.Fields(line)[0]
			direct[strings.TrimSuffix(name, "!")] = true
		case (section == "GEM" || section == "GIT" || section == "PATH") && strings.HasPrefix(line, "    ") && !strings.HasPrefix(line, "     "):
			name, ver, ok := strings.Cut(strings.TrimSpace(line), " (")
			if !ok {
				continue
			}
			ver = strings.TrimSuffix(ver, ")")
			// A platform suffix ("1.15.4-x86_64-linux") is not part of the gem version.
			if i := strings.Index(ver, "-"); i > 0 {
				ver = ver[:i]
			}
			r.pkgs = append(r.pkgs, inventory.Package{Name: name, Version: ver})
		}
	}
	for i := range r.pkgs {
		r.pkgs[i].Direct = direct[r.pkgs[i].Name]
	}
	return r, nil
}
