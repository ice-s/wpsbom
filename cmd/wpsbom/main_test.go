package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fakeRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for name, data := range map[string]string{
		"etc/os-release":       "ID=alpine\nVERSION_ID=3.20.3\n",
		"lib/apk/db/installed": "P:musl\nV:1.2.5-r0\nA:x86_64\nL:MIT\n\nP:libcrypto3\nV:3.3.2-r0\nA:x86_64\no:openssl\n",
	} {
		p := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(data), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestScanSeveralOutputs(t *testing.T) {
	root, dir := fakeRoot(t), t.TempDir()
	var stdout bytes.Buffer
	err := run(context.Background(), []string{"scan", root,
		"-o", "spdx-json=" + filepath.Join(dir, "sbom.spdx.json"),
		"-o", "cyclonedx-xml=" + filepath.Join(dir, "sbom.cdx.xml"),
		"-o", "csv=" + filepath.Join(dir, "pkgs.csv"),
		"-o", "table",
	}, &stdout)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), "libcrypto3") {
		t.Errorf("table on stdout: %q", stdout.String())
	}
	for file, want := range map[string]string{
		"sbom.spdx.json": `"spdxVersion": "SPDX-2.3"`,
		"sbom.cdx.xml":   `<bom xmlns="http://cyclonedx.org/schema/bom/1.6"`,
		"pkgs.csv":       "musl,1.2.5-r0,x86_64,musl,1.2.5-r0,apk,alpine-3.20.3,MIT,",
	} {
		b, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), want) {
			t.Errorf("%s lacks %q:\n%s", file, want, b)
		}
	}
}

func TestScanDefaultAndFileFlag(t *testing.T) {
	root := fakeRoot(t)
	var stdout bytes.Buffer
	if err := run(context.Background(), []string{"scan", root}, &stdout); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout.String(), `"bomFormat": "CycloneDX"`) {
		t.Errorf("default output is not CycloneDX JSON")
	}
	out := filepath.Join(t.TempDir(), "x.csv")
	if err := run(context.Background(), []string{"scan", root, "-o", "csv", "-file", out}, &stdout); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(out); !strings.HasPrefix(string(b), "name,version,") {
		t.Errorf("-file: %q", b)
	}
}

func TestScanBadOutputs(t *testing.T) {
	root := fakeRoot(t)
	for _, args := range [][]string{
		{"scan", root, "-o", "pdf"},
		{"scan", root, "-o", "table", "-o", "csv"}, // two outputs on stdout
	} {
		if err := run(context.Background(), args, &bytes.Buffer{}); err == nil {
			t.Errorf("%v: no error", args)
		}
	}
}
