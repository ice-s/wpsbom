package rootfs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

func TestSymlinksStayInsideRoot(t *testing.T) {
	root := t.TempDir()
	must(t, os.MkdirAll(filepath.Join(root, "usr/lib"), 0o755))
	must(t, os.MkdirAll(filepath.Join(root, "etc"), 0o755))
	must(t, os.WriteFile(filepath.Join(root, "usr/lib/os-release"), []byte("ID=inside\n"), 0o644))
	// Absolute and climbing links must resolve against the root, not the host.
	must(t, os.Symlink("/usr/lib/os-release", filepath.Join(root, "etc/abs")))
	must(t, os.Symlink("../../../../../../usr/lib/os-release", filepath.Join(root, "etc/climb")))
	must(t, os.Symlink("../usr/lib/os-release", filepath.Join(root, "etc/rel")))
	must(t, os.Symlink("/etc", filepath.Join(root, "etc2")))
	must(t, os.Symlink("loop", filepath.Join(root, "loop")))

	fsys, err := New(root)
	must(t, err)
	for _, name := range []string{"etc/abs", "etc/climb", "etc/rel", "etc2/abs"} {
		b, err := fs.ReadFile(fsys, name)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if string(b) != "ID=inside\n" {
			t.Errorf("%s: read %q", name, b)
		}
	}
	if _, err := fs.ReadFile(fsys, "loop"); !errors.Is(err, errLoop) {
		t.Errorf("loop: got %v", err)
	}
	if _, err := fs.ReadFile(fsys, "missing"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing: got %v", err)
	}
	if _, err := fsys.Open("/etc/abs"); err == nil {
		t.Error("rooted path accepted")
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
