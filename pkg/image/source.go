// Package image scans container images: it replays the layers into a scratch directory (only
// the files a scan reads: package databases, lock files, executables in application
// directories), scans after each layer, and so knows which layer added every package.
package image

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/layout"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	"github.com/google/go-containerregistry/pkg/v1/tarball"

	"github.com/ice-s/wpsbom/pkg/docker"
	"github.com/ice-s/wpsbom/pkg/inventory"
)

// Source is an opened image and what is known about it before reading its layers.
type Source struct {
	Image v1.Image
	Meta  inventory.Image
	close func()
}

// Close removes temporary files (an exported image).
func (s *Source) Close() {
	if s.close != nil {
		s.close()
	}
}

// Open resolves a reference:
//
//	docker:REF            the local Docker daemon (exported like "docker save")
//	registry:REF          pulled from its registry (credentials from ~/.docker/config.json)
//	docker-archive:FILE   a "docker save" tar file (FILE ending in .tar works too)
//	oci-dir:DIR           an OCI image layout directory
//	REF                   the daemon when it has the image, else the registry
func Open(ctx context.Context, ref string) (*Source, error) {
	switch scheme, rest, _ := strings.Cut(ref, ":"); scheme {
	case "docker":
		return fromDaemon(ctx, rest)
	case "registry":
		return fromRegistry(ctx, rest)
	case "docker-archive":
		return fromArchive(rest)
	case "oci-dir":
		return fromLayout(rest)
	}
	if strings.HasSuffix(ref, ".tar") {
		if _, err := os.Stat(ref); err == nil {
			return fromArchive(ref)
		}
	}
	src, err := fromDaemon(ctx, ref)
	if err == nil {
		return src, nil
	}
	if !errors.Is(err, docker.ErrNotFound) && !isNoDaemon(err) {
		return nil, err
	}
	return fromRegistry(ctx, ref)
}

func isNoDaemon(err error) bool {
	return errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "docker socket") || strings.Contains(err.Error(), "connect")
}

// FromDaemon opens an image (reference or ID) held by the local Docker daemon.
func FromDaemon(ctx context.Context, c *docker.Client, ref string) (*Source, error) {
	info, err := c.Inspect(ctx, ref)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ref, err)
	}
	f, err := os.CreateTemp("", "wpsbom-image-*.tar")
	if err != nil {
		return nil, err
	}
	cleanup := func() { f.Close(); os.Remove(f.Name()) }
	// Export by ID: a tag can move while the export runs.
	if err := c.Save(ctx, info.ID, f); err != nil {
		cleanup()
		return nil, fmt.Errorf("%s: export: %w", ref, err)
	}
	img, err := tarball.ImageFromPath(f.Name(), nil)
	if err != nil {
		cleanup()
		return nil, fmt.Errorf("%s: %w", ref, err)
	}
	meta := inventory.Image{Ref: ref, ID: info.ID, OS: info.Os, Arch: info.Arch, Digest: info.ID}
	// A repository digest identifies the image the same way the registry and Kubernetes do.
	if len(info.RepoDigests) > 0 {
		repo, digest, _ := strings.Cut(info.RepoDigests[0], "@")
		meta.Repo, meta.Digest = repo, digest
	}
	if meta.Repo == "" {
		meta.Repo = repoOf(ref)
		if meta.Repo == "" && len(info.RepoTags) > 0 {
			meta.Repo = repoOf(info.RepoTags[0])
		}
	}
	return &Source{Image: img, Meta: meta, close: cleanup}, nil
}

func fromDaemon(ctx context.Context, ref string) (*Source, error) {
	c, err := docker.New()
	if err != nil {
		return nil, err
	}
	return FromDaemon(ctx, c, ref)
}

func fromRegistry(ctx context.Context, ref string) (*Source, error) {
	r, err := name.ParseReference(ref)
	if err != nil {
		return nil, err
	}
	desc, err := remote.Get(r, remote.WithContext(ctx), remote.WithAuthFromKeychain(authn.DefaultKeychain))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ref, err)
	}
	img, err := desc.Image()
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ref, err)
	}
	meta := inventory.Image{Ref: ref, Repo: r.Context().Name(), Digest: desc.Digest.String()}
	if cfg, err := img.ConfigName(); err == nil {
		meta.ID = cfg.String()
	}
	return &Source{Image: img, Meta: meta}, nil
}

func fromArchive(file string) (*Source, error) {
	img, err := tarball.ImageFromPath(file, nil)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", file, err)
	}
	src := fromLocal(file, img)
	// "docker save" records the tags it exported: they name the repository.
	if m, err := tarball.LoadManifest(func() (io.ReadCloser, error) { return os.Open(file) }); err == nil && len(m) > 0 && len(m[0].RepoTags) > 0 {
		src.Meta.Repo = repoOf(m[0].RepoTags[0])
	}
	if src.Meta.Repo == "" {
		src.Meta.Repo = strings.TrimSuffix(filepath.Base(file), ".tar")
	}
	return src, nil
}

func fromLayout(dir string) (*Source, error) {
	p, err := layout.FromPath(dir)
	if err != nil {
		return nil, err
	}
	idx, err := p.ImageIndex()
	if err != nil {
		return nil, err
	}
	m, err := idx.IndexManifest()
	if err != nil {
		return nil, err
	}
	if len(m.Manifests) == 0 {
		return nil, fmt.Errorf("%s: empty image layout", dir)
	}
	img, err := p.Image(m.Manifests[0].Digest)
	if err != nil {
		return nil, err
	}
	src := fromLocal(dir, img)
	src.Meta.Digest = m.Manifests[0].Digest.String()
	if n := m.Manifests[0].Annotations["org.opencontainers.image.ref.name"]; n != "" {
		src.Meta.Repo = repoOf(n)
	}
	return src, nil
}

// fromLocal describes an image read from a file: no registry digest, so the config ID stands in.
func fromLocal(ref string, img v1.Image) *Source {
	meta := inventory.Image{Ref: ref}
	if cfg, err := img.ConfigName(); err == nil {
		meta.ID, meta.Digest = cfg.String(), cfg.String()
	}
	return &Source{Image: img, Meta: meta}
}

// repoOf is the repository of a reference, "" for an ID: "nginx:1.27" → "index.docker.io/library/nginx".
func repoOf(ref string) string {
	if strings.HasPrefix(ref, "sha256:") {
		return ""
	}
	r, err := name.ParseReference(ref)
	if err != nil {
		return ""
	}
	return r.Context().Name()
}
