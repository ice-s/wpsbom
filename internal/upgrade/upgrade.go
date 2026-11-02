// Package upgrade replaces the running wpsbom binary with a release from GitHub.
package upgrade

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// ReleasesURL is where releases are downloaded from.
const ReleasesURL = "https://github.com/ice-s/wpsbom/releases"

// maxArchive bounds downloads; a release archive is a few MB.
const maxArchive = 64 << 20

// Options for Run.
type Options struct {
	// Current is the running version ("1.0.0"); "dev" for a local build.
	Current string
	// Target is the version to install ("v1.1.0", "1.1.0"); empty for the latest.
	Target string
	// CheckOnly reports whether an upgrade exists without installing it.
	CheckOnly bool
	// Force installs even over a development build or the same version.
	Force bool

	// For tests: release base URL, binary to replace, platform, HTTP client.
	BaseURL    string
	Executable string
	OS, Arch   string
	Client     *http.Client
	Log        io.Writer
}

// Run checks the release and, unless CheckOnly, installs it over the running binary.
func Run(ctx context.Context, o Options) error {
	o.defaults()

	base := o.BaseURL + "/latest/download"
	if o.Target != "" {
		base = o.BaseURL + "/download/v" + strings.TrimPrefix(o.Target, "v")
	}
	sums, err := o.get(ctx, base+"/checksums.txt", 1<<20)
	if err != nil {
		return fmt.Errorf("release not found: %w", err)
	}
	archive, sum, version, err := pick(sums, o.OS, o.Arch)
	if err != nil {
		return err
	}

	switch {
	case o.Current == "dev" && !o.Force:
		return fmt.Errorf("this is a development build; release %s is available, use --force to install it", version)
	case o.Target == "" && !o.Force && compare(version, o.Current) <= 0:
		fmt.Fprintf(o.Log, "wpsbom %s is up to date (latest release: %s)\n", o.Current, version)
		return nil
	case o.Target != "" && !o.Force && version == o.Current:
		fmt.Fprintf(o.Log, "wpsbom %s is already installed\n", o.Current)
		return nil
	}
	if o.CheckOnly {
		fmt.Fprintf(o.Log, "wpsbom %s is available (installed: %s); run \"wpsbom upgrade\"\n", version, o.Current)
		return nil
	}

	exe := o.Executable
	if exe == "" {
		if exe, err = os.Executable(); err != nil {
			return err
		}
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return err
	}
	if err := writable(filepath.Dir(exe)); err != nil {
		return fmt.Errorf("%w; run: sudo %s upgrade", err, exe)
	}

	fmt.Fprintf(o.Log, "downloading %s\n", archive)
	data, err := o.get(ctx, base+"/"+archive, maxArchive)
	if err != nil {
		return err
	}
	if got := sha256.Sum256(data); hex.EncodeToString(got[:]) != sum {
		return fmt.Errorf("checksum mismatch for %s: release checksums say %s, download is %x", archive, sum, got)
	}
	bin, err := extract(data, "wpsbom")
	if err != nil {
		return fmt.Errorf("%s: %w", archive, err)
	}
	if err := replace(exe, bin, version); err != nil {
		return err
	}
	fmt.Fprintf(o.Log, "upgraded wpsbom %s → %s (%s)\n", o.Current, version, exe)
	return nil
}

func (o *Options) defaults() {
	if o.BaseURL == "" {
		o.BaseURL = ReleasesURL
	}
	if o.OS == "" {
		o.OS = runtime.GOOS
	}
	if o.Arch == "" {
		o.Arch = runtime.GOARCH
	}
	if o.Client == nil {
		o.Client = &http.Client{Timeout: 2 * time.Minute}
	}
	if o.Log == nil {
		o.Log = io.Discard
	}
	o.Current = strings.TrimPrefix(o.Current, "v")
}

func (o *Options) get(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "wpsbom/"+o.Current)
	resp, err := o.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("GET %s: response larger than %d bytes", url, limit)
	}
	return b, nil
}

// pick finds this platform's archive in checksums.txt ("<sha256>  wpsbom_1.1.0_linux_amd64.tar.gz")
// and returns its name, checksum and version.
func pick(sums []byte, goos, goarch string) (archive, sum, version string, err error) {
	suffix := "_" + goos + "_" + goarch + ".tar.gz"
	sc := bufio.NewScanner(bytes.NewReader(sums))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 2 || !strings.HasPrefix(f[1], "wpsbom_") || !strings.HasSuffix(f[1], suffix) {
			continue
		}
		return f[1], f[0], strings.TrimSuffix(strings.TrimPrefix(f[1], "wpsbom_"), suffix), nil
	}
	return "", "", "", fmt.Errorf("the release has no build for %s/%s", goos, goarch)
}

// extract returns the named file from a .tar.gz.
func extract(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("no %s in the archive", name)
		}
		if err != nil {
			return nil, err
		}
		if h.Typeflag == tar.TypeReg && filepath.Base(h.Name) == name {
			return io.ReadAll(io.LimitReader(tr, maxArchive))
		}
	}
}

// writable checks, before anything is downloaded, that a file can be created in dir.
func writable(dir string) error {
	f, err := os.CreateTemp(dir, ".wpsbom-upgrade-*")
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("no permission to write %s", dir)
	}
	if err != nil {
		return err
	}
	f.Close()
	return os.Remove(f.Name())
}

// replace swaps exe for bin: the new binary is written next to exe, checked to run and
// report the expected version, then renamed over exe, so exe is never left half-written.
func replace(exe string, bin []byte, version string) error {
	dir := filepath.Dir(exe)
	tmp, err := os.CreateTemp(dir, ".wpsbom-upgrade-*")
	if errors.Is(err, fs.ErrPermission) {
		return fmt.Errorf("no permission to write %s; run: sudo %s upgrade", dir, exe)
	}
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op once renamed
	if _, err := tmp.Write(bin); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	mode := fs.FileMode(0o755)
	if fi, err := os.Stat(exe); err == nil {
		mode = fi.Mode().Perm()
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		return err
	}

	out, err := exec.Command(tmp.Name(), "version").Output()
	if err != nil {
		return fmt.Errorf("the downloaded binary does not run: %w", err)
	}
	if got := strings.TrimSpace(string(out)); got != version {
		return fmt.Errorf("the downloaded binary reports version %q, expected %q", got, version)
	}
	if err := os.Rename(tmp.Name(), exe); err != nil {
		if errors.Is(err, fs.ErrPermission) {
			return fmt.Errorf("no permission to replace %s; run: sudo %s upgrade", exe, exe)
		}
		return err
	}
	return nil
}

// compare orders "1.10.0" after "1.9.2"; a pre-release ("1.2.0-rc.1") sorts before its release.
func compare(a, b string) int {
	a, preA, _ := strings.Cut(strings.TrimPrefix(a, "v"), "-")
	b, preB, _ := strings.Cut(strings.TrimPrefix(b, "v"), "-")
	pa, pb := strings.Split(a, "."), strings.Split(b, ".")
	for i := 0; i < max(len(pa), len(pb)); i++ {
		var x, y int
		if i < len(pa) {
			x, _ = strconv.Atoi(pa[i])
		}
		if i < len(pb) {
			y, _ = strconv.Atoi(pb[i])
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	switch {
	case preA == preB:
		return 0
	case preA == "":
		return 1
	case preB == "":
		return -1
	}
	return strings.Compare(preA, preB)
}
