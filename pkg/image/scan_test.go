package image

import (
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/random"
)

func TestDescribeLayers(t *testing.T) {
	img, err := random.Image(64, 4)
	if err != nil {
		t.Fatal(err)
	}
	layers, _ := img.Layers()
	old := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 11, 2, 9, 0, 0, 0, time.UTC)
	cfg := &v1.ConfigFile{History: []v1.History{
		{Created: v1.Time{Time: old}, CreatedBy: "/bin/sh -c #(nop) ADD file:abc in / "},
		{Created: v1.Time{Time: old}, CreatedBy: "/bin/sh -c #(nop)  CMD [\"bash\"]", EmptyLayer: true},
		{Created: v1.Time{Time: old.Add(time.Hour)}, CreatedBy: "/bin/sh -c apt-get install -y php"},
		{Created: v1.Time{Time: now.Add(-2 * time.Minute)}, CreatedBy: "RUN apk add curl # buildkit"},
		{Created: v1.Time{Time: now}, CreatedBy: "COPY . /app # buildkit"},
	}}

	got, known := describeLayers(cfg, layers, nil)
	if known {
		t.Error("base inferred from times, not known")
	}
	wantBase := []bool{true, true, false, false}
	for i, l := range got {
		if l.Base != wantBase[i] {
			t.Errorf("layer %d base=%v", i+1, l.Base)
		}
	}
	if got[0].CreatedBy != "ADD file:abc in /" || got[1].CreatedBy != "RUN apt-get install -y php" || got[3].CreatedBy != "COPY . /app" {
		t.Errorf("created-by: %q %q %q", got[0].CreatedBy, got[1].CreatedBy, got[3].CreatedBy)
	}

	// The given base image wins over the times.
	d0, _ := layers[0].DiffID()
	got, known = describeLayers(cfg, layers, []v1.Hash{d0})
	if !known || !got[0].Base || got[1].Base {
		t.Errorf("exact base: known=%v %+v", known, got)
	}

	// A base list that does not match leaves the inference.
	if _, known = describeLayers(cfg, layers, []v1.Hash{{Algorithm: "sha256", Hex: "00"}}); known {
		t.Error("mismatching base must not count as known")
	}

	// Reproducible builds carry one time for everything: no base marks.
	for i := range cfg.History {
		cfg.History[i].Created = v1.Time{Time: old}
	}
	got, _ = describeLayers(cfg, layers, nil)
	for _, l := range got {
		if l.Base {
			t.Error("equal times must give no base marks")
		}
	}
}

func TestWanted(t *testing.T) {
	dirs := []string{"/var/www", "/usr/local/bin", "/usr/local/lib"}
	cases := map[string]bool{
		"var/lib/dpkg/status":                           true,
		"var/lib/dpkg/status.d/base":                    true,
		"usr/lib/os-release":                            true,
		"var/www/shop/composer.lock":                    true,
		"var/www/shop/vendor/composer/installed.json":   true,
		"var/www/shop/vendor/laravel/x/composer.json":   false,
		"var/www/shop/node_modules/a/package-lock.json": false,
		"var/www/api/requirements-dev.txt":              true,
		"var/www/shop/README.md":                        false,
		"etc/passwd":                                    false,
		"usr/local/lib/python3.12/site-packages/requests-2.31.0.dist-info/METADATA": true,
		"usr/local/lib/python3.12/site-packages/requests/api.py":                    false,
	}
	for name, want := range cases {
		if got := wanted(name, 0o644, 100, dirs); got != want {
			t.Errorf("%s: got %v", name, got)
		}
	}
	if !wanted("usr/local/bin/server", 0o755, 1<<20, dirs) || wanted("usr/local/bin/huge", 0o755, maxExtract+1, dirs) || wanted("usr/bin/ls", 0o755, 100, dirs) || wanted("usr/local/lib/libssl.so.3", 0o755, 100, dirs) {
		t.Error("executables: only in application directories and below the size limit")
	}
}

func TestCleanCreatedByHidesSecrets(t *testing.T) {
	for in, want := range map[string]string{
		`|2 NPM_TOKEN=npm_abc123 VERSION=1.4 /bin/sh -c npm ci`:                         "RUN npm ci",
		`/bin/sh -c curl -H "x" https://x/?a=1 && GITHUB_TOKEN=ghp_secret make install`: `RUN curl -H "x" https://x/?a=1 && GITHUB_TOKEN=*** make install`,
		`/bin/sh -c #(nop)  ENV DB_PASSWORD=hunter2`:                                    "ENV DB_PASSWORD=***",
		`/bin/sh -c #(nop)  ENV PATH=/usr/local/bin:/usr/bin`:                           "ENV PATH=/usr/local/bin:/usr/bin",
	} {
		if got := cleanCreatedBy(in); got != want {
			t.Errorf("cleanCreatedBy(%q) = %q, want %q", in, got, want)
		}
	}
}
