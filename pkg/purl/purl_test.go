package purl

import (
	"testing"

	"github.com/ice-s/wpsbom/pkg/inventory"
)

func TestFor(t *testing.T) {
	debian := &inventory.Distro{ID: "debian", VersionID: "12"}
	alpine := &inventory.Distro{ID: "alpine", VersionID: "3.20.3"}
	cases := []struct {
		p    inventory.Package
		d    *inventory.Distro
		want string
	}{
		{
			inventory.Package{Type: "deb", Name: "libssl3", Version: "3.0.11-1~deb12u2", Arch: "amd64", Source: "openssl", SourceVersion: "3.0.11-1~deb12u2"},
			debian,
			"pkg:deb/debian/libssl3@3.0.11-1~deb12u2?arch=amd64&distro=debian-12&upstream=openssl",
		},
		{
			inventory.Package{Type: "deb", Name: "bash", Version: "5.2.15-2+b13", Arch: "amd64", Source: "bash", SourceVersion: "5.2.15-2"},
			debian,
			"pkg:deb/debian/bash@5.2.15-2%2Bb13?arch=amd64&distro=debian-12&upstream=bash%405.2.15-2",
		},
		{
			inventory.Package{Type: "deb", Name: "mount", Version: "1:2.38.1-5", Arch: "amd64", Source: "util-linux", SourceVersion: "2.38.1-5"},
			debian,
			"pkg:deb/debian/mount@1:2.38.1-5?arch=amd64&distro=debian-12&upstream=util-linux%402.38.1-5",
		},
		{
			inventory.Package{Type: "apk", Name: "libcrypto3", Version: "3.3.7-r0", Arch: "x86_64", Source: "openssl", SourceVersion: "3.3.7-r0"},
			alpine,
			"pkg:apk/alpine/libcrypto3@3.3.7-r0?arch=x86_64&distro=alpine-3.20.3&upstream=openssl",
		},
		{
			inventory.Package{Type: "apk", Name: "musl", Version: "1.2.5-r0"},
			nil,
			"pkg:apk/alpine/musl@1.2.5-r0",
		},
	}
	for _, c := range cases {
		if got := For(c.p, c.d); got != c.want {
			t.Errorf("%s:\n got  %s\n want %s", c.p.Name, got, c.want)
		}
	}
}
