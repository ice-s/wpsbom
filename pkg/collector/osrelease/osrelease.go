// Package osrelease reads the operating system release from os-release(5).
package osrelease

import (
	"bufio"
	"bytes"
	"errors"
	"io/fs"
	"strings"

	"github.com/ice-s/wpsbom/pkg/inventory"
)

// Paths in lookup order, as systemd does.
var paths = []string{"etc/os-release", "usr/lib/os-release"}

// Read returns the release, or nil when the root has no os-release file.
func Read(fsys fs.FS) (*inventory.Distro, error) {
	for _, p := range paths {
		b, err := fs.ReadFile(fsys, p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		return Parse(b), nil
	}
	return nil, nil
}

// Parse parses os-release content.
func Parse(b []byte) *inventory.Distro {
	v := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v[key] = unquote(val)
	}
	return &inventory.Distro{
		ID:              strings.ToLower(v["ID"]),
		IDLike:          strings.Fields(strings.ToLower(v["ID_LIKE"])),
		VersionID:       v["VERSION_ID"],
		VersionCodename: v["VERSION_CODENAME"],
		Name:            v["NAME"],
		PrettyName:      v["PRETTY_NAME"],
	}
}

// unquote handles the shell-like quoting os-release allows: "…" with \-escapes, or '…'.
func unquote(s string) string {
	if len(s) >= 2 && s[0] == '\'' && s[len(s)-1] == '\'' {
		return s[1 : len(s)-1]
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
		var b strings.Builder
		for i := 0; i < len(s); i++ {
			if s[i] == '\\' && i+1 < len(s) && strings.IndexByte("\"\\$`", s[i+1]) >= 0 {
				i++
			}
			b.WriteByte(s[i])
		}
		return b.String()
	}
	return s
}
