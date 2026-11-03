package image

import (
	"archive/tar"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/tarball"
)

type entry struct {
	name, link string
	typ        byte
	mode       int64
	body       string
}

func layer(t *testing.T, entries ...entry) v1.Layer {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Linkname: e.link, Typeflag: e.typ, Mode: e.mode, Size: int64(len(e.body))}
		if e.typ != tar.TypeReg {
			h.Size = 0
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.typ == tar.TypeReg {
			tw.Write([]byte(e.body))
		}
	}
	tw.Close()
	b := buf.Bytes()
	l, err := tarball.LayerFromOpener(func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(b)), nil })
	if err != nil {
		t.Fatal(err)
	}
	return l
}

// A hostile layer must not write, delete or read anything outside the directory it is replayed
// into, whatever its symlinks, whiteouts and hard links say.
func TestApplyStaysInside(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("host secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Mkdir(filepath.Join(outside, "keep"), 0o755)
	dir := t.TempDir()
	dirs := []string{"/app", "/srv"}

	l := layer(t,
		// /app → the outside directory, absolute and relative.
		entry{name: "app", link: outside, typ: tar.TypeSymlink},
		entry{name: "srv", link: "../../../../../../../../" + outside, typ: tar.TypeSymlink},
		// Executables under app dirs are extracted: through the links, onto the "host".
		entry{name: "app/pwned", typ: tar.TypeReg, mode: 0o755, body: "x"},
		entry{name: "srv/pwned2", typ: tar.TypeReg, mode: 0o755, body: "x"},
		// A hard link reading a host file into the scan.
		entry{name: "app/composer.lock", link: "../../../../../../../.." + filepath.Join(outside, "secret"), typ: tar.TypeLink},
		// Whiteouts through the links.
		entry{name: "app/.wh.keep", typ: tar.TypeReg},
		entry{name: "srv/.wh..wh..opq", typ: tar.TypeReg},
	)
	if _, err := apply(dir, l, dirs); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"pwned", "pwned2"} {
		if _, err := os.Lstat(filepath.Join(outside, f)); err == nil {
			t.Errorf("%s written outside the root", f)
		}
	}
	if _, err := os.Stat(filepath.Join(outside, "keep")); err != nil {
		t.Error("whiteout deleted a directory outside the root")
	}
	if b, err := os.ReadFile(filepath.Join(outside, "secret")); err != nil || string(b) != "host secret" {
		t.Error("file outside the root changed or removed")
	}
	// Inside the root the absolute link resolves to <dir><outside>, as in the container (emptied
	// again by the opaque whiteout through srv, which points at the same place).
	if fi, err := os.Stat(filepath.Join(dir, outside)); err != nil || !fi.IsDir() {
		t.Errorf("link target not created inside the root: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, outside, "composer.lock")); bytes.Contains(b, []byte("host secret")) {
		t.Error("hard link copied a host file into the scan")
	}
}
