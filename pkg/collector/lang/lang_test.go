package lang

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/ice-s/wpsbom/pkg/inventory"
	"github.com/ice-s/wpsbom/pkg/rootfs"
)

// pkgLine is a compact, comparable form of a package: "purl location [direct] [dev]".
func pkgLine(p inventory.Package) string {
	s := p.PURL + " " + p.Location
	if p.Direct {
		s += " direct"
	}
	if p.Dev {
		s += " dev"
	}
	return s
}

func TestCollect(t *testing.T) {
	fsys, err := rootfs.New("testdata")
	if err != nil {
		t.Fatal(err)
	}
	apps, pkgs, err := Collect(fsys, []string{"/srv"})
	if err != nil {
		t.Fatal(err)
	}

	var gotApps []string
	for _, a := range apps {
		gotApps = append(gotApps, a.Type+" "+a.Name+" "+a.Dir+" "+a.Manifest)
	}
	sort.Strings(gotApps)
	wantApps := []string{
		"composer acme/shop /srv/shop /srv/shop/composer.lock",
		"gem rb /srv/rb /srv/rb/Gemfile.lock",
		"golang github.com/acme/svc /srv/svc /srv/svc/go.mod",
		"npm b /srv/berry /srv/berry/yarn.lock",
		"npm shop-assets /srv/shop /srv/shop/package-lock.json",
		"npm y1 /srv/yarn1 /srv/yarn1/yarn.lock",
		"pypi acme-api /srv/api /srv/api/poetry.lock",
		"pypi legacy /srv/legacy /srv/legacy/requirements.txt",
	}
	if strings.Join(gotApps, "\n") != strings.Join(wantApps, "\n") {
		t.Errorf("apps:\n%s\nwant:\n%s", strings.Join(gotApps, "\n"), strings.Join(wantApps, "\n"))
	}

	var got []string
	for _, p := range pkgs {
		got = append(got, pkgLine(p))
	}
	sort.Strings(got)
	want := []string{
		"pkg:composer/laravel/framework@10.48.4 /srv/shop/composer.lock direct",
		// phpunit is in the lock (require-dev) but not installed in vendor/: a --no-dev deploy.
		"pkg:composer/symfony/console@6.4.1 /srv/shop/composer.lock",
		"pkg:gem/actionpack@7.0.4 /srv/rb/Gemfile.lock direct",
		"pkg:gem/nokogiri@1.15.4 /srv/rb/Gemfile.lock direct",
		"pkg:gem/rack@2.2.6 /srv/rb/Gemfile.lock",
		"pkg:golang/github.com/gin-gonic/gin@v1.9.0 /srv/svc/go.mod direct",
		"pkg:golang/github.com/go-playground/validator/v10@v10.14.0 /srv/svc/go.mod",
		"pkg:golang/golang.org/x/net@v0.17.0 /srv/svc/go.mod",
		"pkg:npm/%40babel/core@7.22.5 /srv/yarn1/yarn.lock direct",
		"pkg:npm/%40vitejs/plugin-vue@5.0.2 /srv/shop/package-lock.json direct dev",
		"pkg:npm/axios@1.6.0 /srv/shop/package-lock.json direct",
		"pkg:npm/esbuild@0.19.11 /srv/shop/package-lock.json dev",
		"pkg:npm/follow-redirects@1.15.3 /srv/shop/package-lock.json",
		"pkg:npm/lodash@4.17.20 /srv/yarn1/yarn.lock direct",
		"pkg:npm/lodash@4.17.21 /srv/berry/yarn.lock direct",
		"pkg:npm/vite@5.0.10 /srv/shop/package-lock.json direct dev",
		"pkg:pypi/django@4.2.7 /srv/api/poetry.lock direct",
		"pkg:pypi/flask@2.0.1 /srv/legacy/requirements.txt direct",
		"pkg:pypi/pytest@6.2.0 /srv/legacy/requirements.txt direct dev",
		"pkg:pypi/pytest@7.4.3 /srv/api/poetry.lock direct dev",
		"pkg:pypi/requests@2.25.0 /srv/legacy/requirements.txt direct",
		"pkg:pypi/sqlparse@0.4.4 /srv/api/poetry.lock",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("packages:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestCollectMissingDir(t *testing.T) {
	fsys, _ := rootfs.New("testdata")
	if _, _, err := Collect(fsys, []string{"/nope"}); err == nil {
		t.Fatal("want an error for a directory that does not exist")
	}
}

func TestGoBinary(t *testing.T) {
	// The test binary itself carries Go build information.
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	b, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "server"), b, 0o755); err != nil {
		t.Fatal(err)
	}
	fsys, _ := rootfs.New(dir)
	apps, pkgs, err := Collect(fsys, []string{"/"})
	if err != nil {
		t.Fatal(err)
	}
	if len(apps) != 1 || apps[0].Type != inventory.TypeGolang || apps[0].Manifest != "/server" {
		t.Fatalf("apps: %+v", apps)
	}
	if len(pkgs) == 0 || pkgs[0].Name != "stdlib" || strings.HasPrefix(pkgs[0].Version, "go") {
		t.Errorf("want stdlib first, version without \"go\": %+v", pkgs)
	}
}
