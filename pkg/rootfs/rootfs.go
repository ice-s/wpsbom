// Package rootfs reads a directory as if it were "/": symlinks, absolute ones included,
// resolve inside the directory, never on the host running the scan.
//
// The directory may belong to someone hostile (a container's file system, an image): files are
// opened through an os.Root, so a symlink swapped in after resolution still cannot lead out of
// it; only regular files and directories are opened (never a FIFO or a device, which would hang
// or never end), and ReadFile stops at MaxFile bytes.
package rootfs

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// MaxFile is the most ReadFile reads; package databases and lock files are far smaller.
const MaxFile = 64 << 20

// ErrNotRegular is returned for anything that is neither a regular file nor a directory.
var ErrNotRegular = errors.New("not a regular file")

// ErrTooLarge is returned by ReadFile for a file over MaxFile bytes.
var ErrTooLarge = fmt.Errorf("file larger than %d bytes", MaxFile)

// maxLinks bounds symlink resolution, as the kernel does (ELOOP).
const maxLinks = 40

var errLoop = errors.New("too many levels of symbolic links")

// FS is an fs.FS rooted at a directory, with chroot-like symlink resolution.
type FS struct {
	root string
	r    *os.Root
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
	r, err := os.OpenRoot(abs)
	if err != nil {
		return nil, err
	}
	return &FS{root: abs, r: r}, nil
}

// Root is the host directory this file system is rooted at.
func (f *FS) Root() string { return f.root }

// Open implements fs.FS. The returned *os.File also implements fs.ReadDirFile.
func (f *FS) Open(name string) (fs.File, error) {
	file, err := f.open(name)
	if err != nil {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	return file, nil
}

func (f *FS) open(name string) (*os.File, error) {
	rel, err := f.rel(name)
	if err != nil {
		return nil, err
	}
	// O_NONBLOCK: opening a FIFO must not wait for a writer; it is refused just below.
	file, err := f.r.OpenFile(rel, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, unwrap(err)
	}
	fi, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() && !fi.IsDir() {
		file.Close()
		return nil, ErrNotRegular
	}
	return file, nil
}

// ReadFile implements fs.ReadFileFS (fs.ReadFile uses it): at most MaxFile bytes.
func (f *FS) ReadFile(name string) ([]byte, error) {
	file, err := f.open(name)
	if err != nil {
		return nil, &fs.PathError{Op: "read", Path: name, Err: err}
	}
	defer file.Close()
	b, err := io.ReadAll(io.LimitReader(file, MaxFile+1))
	if err != nil {
		return nil, &fs.PathError{Op: "read", Path: name, Err: err}
	}
	if len(b) > MaxFile {
		return nil, &fs.PathError{Op: "read", Path: name, Err: ErrTooLarge}
	}
	return b, nil
}

// resolve maps a slash-separated path inside the root to a host path, following every
// symlink on the way. ".." never climbs above the root.
func (f *FS) resolve(name string) (string, error) {
	rel, err := f.rel(name)
	if err != nil {
		return "", err
	}
	return filepath.Join(f.root, rel), nil
}

// rel is resolve's result relative to the root ("." for the root itself).
func (f *FS) rel(name string) (string, error) { return f.walk(name, false) }

// Rel resolves name like Open does, except that missing components are kept as they are: the
// path, relative to the root, where name would be created. For writing into the root through
// Root(), which refuses anything that would lead out of it.
func (f *FS) Rel(name string) (string, error) { return f.walk(name, true) }

// Root is the os.Root of the directory.
func (f *FS) OSRoot() *os.Root { return f.r }

func (f *FS) walk(name string, missingOK bool) (string, error) {
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
			if missingOK && errors.Is(err, fs.ErrNotExist) {
				done = append(done, c)
				continue
			}
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
	if len(done) == 0 {
		return ".", nil
	}
	return filepath.Join(done...), nil
}

// unwrap drops the host path from an os error, so messages show paths inside the root.
func unwrap(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}
