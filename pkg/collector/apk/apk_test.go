package apk

import (
	"os"
	"testing"
	"testing/fstest"
)

func TestCollectAlpine(t *testing.T) {
	b, err := os.ReadFile("testdata/alpine-3.20.installed")
	if err != nil {
		t.Fatal(err)
	}
	pkgs, err := Collect(fstest.MapFS{"lib/apk/db/installed": {Data: b}})
	if err != nil {
		t.Fatal(err)
	}
	if len(pkgs) != 14 {
		t.Errorf("got %d packages, want 14", len(pkgs))
	}
	for _, p := range pkgs {
		if p.Name == "libcrypto3" {
			if p.Source != "openssl" || p.Version != "3.3.7-r0" || p.Arch != "aarch64" || len(p.Licenses) != 1 {
				t.Errorf("libcrypto3: %+v", p)
			}
			return
		}
	}
	t.Error("libcrypto3 not found")
}

func TestCollectMergedUsr(t *testing.T) {
	pkgs, err := Collect(fstest.MapFS{"usr/lib/apk/db/installed": {Data: []byte("P:musl\nV:1.2.5-r0\nA:x86_64\n")}})
	if err != nil || len(pkgs) != 1 || pkgs[0].Source != "musl" {
		t.Errorf("got %+v, %v", pkgs, err)
	}
}
