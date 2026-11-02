package upgrade

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// release serves a fake GitHub release whose "binary" is a script printing its version.
func release(t *testing.T, version string, corrupt bool) *httptest.Server {
	t.Helper()
	script := []byte("#!/bin/sh\necho " + version + "\n")
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, f := range []struct {
		name string
		data []byte
	}{{"LICENSE", []byte("license")}, {"wpsbom", script}} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o755, Size: int64(len(f.data)), Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
		tw.Write(f.data)
	}
	tw.Close()
	gz.Close()
	archive := fmt.Sprintf("wpsbom_%s_linux_amd64.tar.gz", version)
	sum := sha256.Sum256(buf.Bytes())
	if corrupt {
		sum[0] ^= 1
	}
	sums := fmt.Sprintf("%x  wpsbom_%s_darwin_arm64.tar.gz\n%x  %s\n", sum, version, sum, archive)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/checksums.txt") &&
			(strings.Contains(r.URL.Path, "/latest/download/") || strings.Contains(r.URL.Path, "/download/v"+version+"/")):
			w.Write([]byte(sums))
		case strings.HasSuffix(r.URL.Path, "/"+archive):
			w.Write(buf.Bytes())
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func installed(t *testing.T, version string) string {
	t.Helper()
	exe := filepath.Join(t.TempDir(), "wpsbom")
	if err := os.WriteFile(exe, []byte("#!/bin/sh\necho "+version+"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return exe
}

func opts(srv *httptest.Server, exe, current string) Options {
	return Options{Current: current, BaseURL: srv.URL, Executable: exe, OS: "linux", Arch: "amd64", Log: &bytes.Buffer{}}
}

func TestUpgrade(t *testing.T) {
	srv, exe := release(t, "1.2.0", false), installed(t, "1.1.0")
	if err := Run(context.Background(), opts(srv, exe, "1.1.0")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(exe); !strings.Contains(string(b), "1.2.0") {
		t.Errorf("binary not replaced: %q", b)
	}
	if left, _ := filepath.Glob(filepath.Join(filepath.Dir(exe), ".wpsbom-upgrade-*")); len(left) > 0 {
		t.Errorf("temp files left: %v", left)
	}
}

func TestUpToDateAndCheck(t *testing.T) {
	srv := release(t, "1.2.0", false)
	for _, c := range []struct {
		current string
		check   bool
		log     string
	}{
		{"1.2.0", false, "up to date"},
		{"1.10.0", false, "up to date"}, // numeric, not string, order
		{"1.1.0", true, "1.2.0 is available"},
	} {
		exe := installed(t, c.current)
		o := opts(srv, exe, c.current)
		o.CheckOnly = c.check
		if err := Run(context.Background(), o); err != nil {
			t.Fatal(err)
		}
		if log := o.Log.(*bytes.Buffer).String(); !strings.Contains(log, c.log) {
			t.Errorf("%s: log %q", c.current, log)
		}
		if b, _ := os.ReadFile(exe); !strings.Contains(string(b), c.current) {
			t.Errorf("%s: binary changed", c.current)
		}
	}
}

func TestRefusals(t *testing.T) {
	exe := installed(t, "1.1.0")
	if err := Run(context.Background(), opts(release(t, "1.2.0", true), exe, "1.1.0")); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Errorf("corrupt download: %v", err)
	}
	if err := Run(context.Background(), opts(release(t, "1.2.0", false), exe, "dev")); err == nil || !strings.Contains(err.Error(), "development build") {
		t.Errorf("dev build: %v", err)
	}
	o := opts(release(t, "1.2.0", false), exe, "1.1.0")
	o.Target = "v9.9.9"
	if err := Run(context.Background(), o); err == nil {
		t.Error("missing version: no error")
	}
	o = opts(release(t, "1.2.0", false), exe, "1.1.0")
	o.Arch = "riscv64"
	if err := Run(context.Background(), o); err == nil || !strings.Contains(err.Error(), "no build for linux/riscv64") {
		t.Errorf("platform: %v", err)
	}
	if b, _ := os.ReadFile(exe); !strings.Contains(string(b), "1.1.0") {
		t.Error("binary changed by a refused upgrade")
	}
}

func TestDowngradeToTarget(t *testing.T) {
	srv, exe := release(t, "1.0.0", false), installed(t, "1.1.0")
	o := opts(srv, exe, "1.1.0")
	o.Target = "v1.0.0"
	if err := Run(context.Background(), o); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(exe); !strings.Contains(string(b), "1.0.0") {
		t.Errorf("not downgraded: %q", b)
	}
}

func TestCompare(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1.2.0", "1.10.0", -1}, {"1.10.0", "1.9.9", 1}, {"v1.1.0", "1.1.0", 0},
		{"1.2.0-rc.1", "1.2.0", -1}, {"2.0", "1.99.99", 1},
	} {
		if got := compare(c.a, c.b); got != c.want {
			t.Errorf("compare(%s, %s) = %d", c.a, c.b, got)
		}
	}
}

func TestNoPermissionBeforeDownload(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere")
	}
	srv, exe := release(t, "1.2.0", false), installed(t, "1.1.0")
	dir := filepath.Dir(exe)
	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o755)
	o := opts(srv, exe, "1.1.0")
	if err := Run(context.Background(), o); err == nil || !strings.Contains(err.Error(), "sudo") {
		t.Errorf("got %v", err)
	}
	if log := o.Log.(*bytes.Buffer).String(); strings.Contains(log, "downloading") {
		t.Errorf("downloaded before checking permissions: %q", log)
	}
}
