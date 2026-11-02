// Package rootfs reads a directory as if it were "/": symlinks, absolute ones included,
// resolve inside the directory, never on the host running the scan.
package rootfs

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// maxLinks bounds symlink resolution, as the kernel does (ELOOP).
const maxLinks = 40

var errLoop = errors.New("too many levels of symbolic links")

// FS is an fs.FS rooted at a directory, with chroot-like symlink resolution.
type FS struct {
	root string
}

// New returns the file system rooted at dir.
func New(dir string) (*FS, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	fi, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, &fs.PathError{Op: "open", Path: dir, Err: errors.New("not a directory")}
	}
	return &FS{root: abs}, nil
}

// Root is the host directory this file system is rooted at.
func (f *FS) Root() string { return f.root }

// Open implements fs.FS. The returned *os.File also implements fs.ReadDirFile.
func (f *FS) Open(name string) (fs.File, error) {
	p, err := f.resolve(name)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	return os.Open(p)
}

// resolve maps a slash-separated path inside the root to a host path, following every
// symlink on the way. ".." never climbs above the root.
func (f *FS) resolve(name string) (string, error) {
	if !fs.ValidPath(name) {
		return "", fs.ErrInvalid
	}
	var pending []string
	if name != "." {
		pending = strings.Split(name, "/")
	}
	var done []string
	links := 0
	for len(pending) > 0 {
		c := pending[0]
		pending = pending[1:]
		switch c {
		case "", ".":
			continue
		case "..":
			if len(done) > 0 {
				done = done[:len(done)-1]
			}
			continue
		}
		p := filepath.Join(f.root, filepath.Join(append(done, c)...))
		fi, err := os.Lstat(p)
		if err != nil {
			return "", unwrap(err)
		}
		if fi.Mode()&fs.ModeSymlink == 0 {
			done = append(done, c)
			continue
		}
		if links++; links > maxLinks {
			return "", errLoop
		}
		target, err := os.Readlink(p)
		if err != nil {
			return "", unwrap(err)
		}
		target = filepath.ToSlash(target)
		if strings.HasPrefix(target, "/") {
			done = done[:0]
		}
		pending = append(strings.Split(target, "/"), pending...)
	}
	return filepath.Join(f.root, filepath.Join(done...)), nil
}

// unwrap drops the host path from an os error, so messages show paths inside the root.
func unwrap(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}
