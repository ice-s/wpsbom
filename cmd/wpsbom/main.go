// Command wpsbom generates SBOMs of servers, container images and the applications on them,
// and can send them to Watchpost.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"

	"github.com/ice-s/wpsbom/internal/upgrade"
	"github.com/ice-s/wpsbom/pkg/docker"
	"github.com/ice-s/wpsbom/pkg/format"
	"github.com/ice-s/wpsbom/pkg/image"
	"github.com/ice-s/wpsbom/pkg/inventory"
	"github.com/ice-s/wpsbom/pkg/k8s"
	"github.com/ice-s/wpsbom/pkg/push"
	"github.com/ice-s/wpsbom/pkg/rootfs"
	"github.com/ice-s/wpsbom/pkg/wpsbom"
)

const usage = `wpsbom: SBOM of a server's OS packages, of container images, and of the applications
in the source directories you point it at.

Usage:
  wpsbom scan [flags] [ROOT]   scan ROOT (default "/": the running system)
  wpsbom push [flags] [ROOT]   scan, then upload to Watchpost (--project, --token)
  wpsbom k8s [flags]           upload what a Kubernetes cluster runs (--cluster, --token)
  wpsbom upgrade [--check] [--force] [VERSION]
                               replace this binary with the latest (or given) release
  wpsbom version

Examples:
  wpsbom scan / -o table
  wpsbom scan / --path /var/www/shop --path /srv/api > sbom.cdx.json
  wpsbom scan --image ghcr.io/acme/shop:1.4 -o table
  wpsbom scan --docker --out-dir sboms/
  wpsbom push / --project prod-01 --path /var/www/shop --docker
  wpsbom k8s --cluster k8s-prod --scan-images

Environment: WPSBOM_TOKEN (API token), WPSBOM_URL (API base, default ` + push.DefaultURL + `).

Flags:
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "wpsbom:", err)
		if errors.Is(err, push.ErrPolicy) {
			os.Exit(3)
		}
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		newFlags("scan", new(opts)).PrintDefaults()
		return errors.New("missing command")
	}
	switch args[0] {
	case "scan":
		return scanCmd(ctx, args[1:], stdout)
	case "push":
		return pushCmd(ctx, args[1:])
	case "k8s":
		return k8sCmd(ctx, args[1:])
	case "upgrade":
		return upgradeCmd(ctx, args[1:])
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, wpsbom.Version)
		return nil
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		f := newFlags("scan", new(opts))
		f.SetOutput(stdout)
		f.PrintDefaults()
		return nil
	}
	return fmt.Errorf("unknown command %q (try \"wpsbom help\")", args[0])
}

// output is one "-o FORMAT[=FILE]"; an empty file means stdout.
type output struct {
	format string
	file   string
}

type outputs []output

func (o *outputs) String() string { return "" }

func (o *outputs) Set(v string) error {
	name, file, _ := strings.Cut(v, "=")
	if format.Encoders[name] == nil {
		return fmt.Errorf("unknown format %q (one of %s)", name, strings.Join(format.Names(), ", "))
	}
	*o = append(*o, output{name, file})
	return nil
}

// list is a repeatable string flag.
type list []string

func (l *list) String() string     { return strings.Join(*l, ",") }
func (l *list) Set(v string) error { *l = append(*l, v); return nil }

type opts struct {
	// what to scan
	paths      list
	images     list
	baseImage  string
	imagePaths list
	docker     bool
	// scan output
	outputs      outputs
	file         string
	outDir       string
	reproducible bool
	hostname     bool
	// push
	project string
	token   string
	url     string
	failOn  string
	// k8s
	cluster    string
	namespace  string
	scanImages bool
	server     string
	tokenFile  string
	caFile     string
}

func newFlags(cmd string, o *opts) *flag.FlagSet {
	f := flag.NewFlagSet(cmd, flag.ContinueOnError)
	if cmd == "scan" || cmd == "push" {
		f.Var(&o.paths, "path", "source `DIR` to search for applications (composer.lock, package-lock.json, yarn.lock,\n"+
			"poetry.lock, Pipfile.lock, requirements*.txt, go.mod, Gemfile.lock, Go binaries); repeatable")
		f.Var(&o.images, "image", "scan a container image `REF` instead of ROOT (docker:REF, registry:REF,\n"+
			"docker-archive:FILE, oci-dir:DIR, or REF: the local daemon, else the registry); repeatable")
		f.StringVar(&o.baseImage, "base-image", "", "the image's base image `REF` (FROM …), to tell its layers apart exactly")
		f.Var(&o.imagePaths, "image-path", "extra application `DIR` inside images (besides WORKDIR, /app, /var/www, /srv, …); repeatable")
		f.BoolVar(&o.docker, "docker", false, "also scan the image of every running Docker container (needs the docker socket)")
		f.BoolVar(&o.hostname, "hostname", false, "record the hostname as is (default: a hash of it)")
	}
	if cmd == "scan" {
		f.Var(&o.outputs, "o", "output `FORMAT[=FILE]`, repeatable; formats: "+strings.Join(format.Names(), ", ")+" (default cyclonedx-json)")
		f.StringVar(&o.file, "file", "", "write the output to this file instead of stdout (single -o without =FILE)")
		f.StringVar(&o.outDir, "out-dir", "", "write one file per SBOM into `DIR` (needed when a scan gives several: --docker, several --image)")
		f.BoolVar(&o.reproducible, "reproducible", false, "no serial number or timestamp: same system, same bytes")
	}
	if cmd == "push" || cmd == "k8s" {
		f.StringVar(&o.token, "token", os.Getenv("WPSBOM_TOKEN"), "Watchpost API `TOKEN` (default $WPSBOM_TOKEN)")
		f.StringVar(&o.url, "url", envOr("WPSBOM_URL", push.DefaultURL), "Watchpost API base `URL` (default $WPSBOM_URL)")
		f.StringVar(&o.failOn, "fail-on", "", "exit with status 3 when an upload has `kev` or `critical` vulnerabilities (for CI)")
	}
	if cmd == "push" {
		f.StringVar(&o.project, "project", "", "project `NAME` for this host (or for the single --image; default: the image repository)")
	}
	if cmd == "k8s" {
		f.StringVar(&o.cluster, "cluster", "", "project `NAME` for the cluster")
		f.StringVar(&o.namespace, "namespace", "", "only this `NAMESPACE` (default: all)")
		f.BoolVar(&o.scanImages, "scan-images", false, "also pull and scan every running image (registry credentials from ~/.docker/config.json)")
		f.StringVar(&o.server, "server", "", "API server `URL` when not running in the cluster")
		f.StringVar(&o.tokenFile, "token-file", "", "service account token `FILE` when not running in the cluster")
		f.StringVar(&o.caFile, "ca-file", "", "cluster CA `FILE` when not running in the cluster")
	}
	return f
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

// parse reads flags, which may come before and after the single optional ROOT argument.
func parse(f *flag.FlagSet, args []string) (root string, err error) {
	if err := f.Parse(args); err != nil {
		return "", err
	}
	root = "/"
	if f.NArg() > 0 {
		root = f.Arg(0)
		if err := f.Parse(f.Args()[1:]); err != nil {
			return "", err
		}
		if f.NArg() > 0 {
			return "", fmt.Errorf("unexpected argument %q", f.Arg(0))
		}
	}
	return root, nil
}

// sbom is one scan result and where it goes.
type sbom struct {
	inv  *inventory.Inventory
	kind string // "host" or "image"
	name string // file / project name
}

// collect runs the scans the flags ask for: the host (ROOT and its --path directories) unless
// only images were given, each --image, and with --docker every running container's image.
func collect(ctx context.Context, root string, o *opts) ([]sbom, error) {
	var base []v1.Hash
	if o.baseImage != "" {
		src, err := image.Open(ctx, o.baseImage)
		if err != nil {
			return nil, fmt.Errorf("--base-image: %w", err)
		}
		cfg, err := src.Image.ConfigFile()
		src.Close()
		if err != nil {
			return nil, fmt.Errorf("--base-image: %w", err)
		}
		base = cfg.RootFS.DiffIDs
	}
	imgOpts := image.Options{Paths: o.imagePaths, BaseDiffIDs: base}

	var out []sbom
	seen := map[string]bool{}
	addImage := func(src *image.Source) (*inventory.Inventory, error) {
		defer src.Close()
		inv, err := image.Scan(ctx, src, imgOpts)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", src.Meta.Ref, err)
		}
		if !seen[inv.Image.Digest] {
			seen[inv.Image.Digest] = true
			out = append(out, sbom{inv: inv, kind: "image", name: push.ProjectName(firstNonEmpty(inv.Image.Repo, inv.Image.Ref))})
		}
		return inv, nil
	}
	for _, ref := range o.images {
		src, err := image.Open(ctx, ref)
		if err != nil {
			return nil, err
		}
		if _, err := addImage(src); err != nil {
			return nil, err
		}
	}
	if len(o.images) > 0 && !o.docker && len(o.paths) == 0 {
		return out, nil
	}

	fsys, err := rootfs.New(root)
	if err != nil {
		return nil, err
	}
	live := fsys.Root() == filepath.Clean("/")
	host, err := wpsbom.Scan(ctx, fsys, wpsbom.Options{Live: live, RevealHostname: o.hostname, Paths: o.paths})
	if err != nil {
		return nil, err
	}
	if o.docker {
		c, err := docker.New()
		if err != nil {
			return nil, err
		}
		containers, err := c.Containers(ctx)
		if err != nil {
			return nil, err
		}
		digests := map[string]string{} // image ID → digest
		for _, ct := range containers {
			if _, ok := digests[ct.ImageID]; !ok {
				src, err := image.FromDaemon(ctx, c, ct.ImageID)
				if err != nil {
					return nil, err
				}
				// The reference the container was started from names the image better than its ID.
				src.Meta.Ref = ct.Image
				if src.Meta.Repo == "" {
					src.Meta.Repo = repoOfRef(ct.Image)
				}
				inv, err := addImage(src)
				if err != nil {
					return nil, err
				}
				digests[ct.ImageID] = inv.Image.Digest
			}
			host.Containers = append(host.Containers, inventory.Container{ID: shortID(ct.ID), Name: ct.Name(), Image: ct.Image, Digest: digests[ct.ImageID]})
		}
	}
	name := "host"
	if host.Hostname != "" && o.hostname {
		name = host.Hostname
	}
	return append([]sbom{{inv: host, kind: "host", name: name}}, out...), nil
}

func firstNonEmpty(s ...string) string {
	for _, v := range s {
		if v != "" {
			return v
		}
	}
	return ""
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

var tagSuffix = regexp.MustCompile(`:[\w][\w.-]*$`)

// repoOfRef drops the tag or digest of a reference ("nginx:1.27" → "nginx").
func repoOfRef(ref string) string {
	if i := strings.Index(ref, "@"); i >= 0 {
		ref = ref[:i]
	}
	if i := strings.LastIndex(ref, "/"); tagSuffix.MatchString(ref[i+1:]) {
		ref = ref[:i+1] + tagSuffix.ReplaceAllString(ref[i+1:], "")
	}
	return ref
}

var fileExt = map[string]string{
	"cyclonedx-json": ".cdx.json", "cyclonedx-xml": ".cdx.xml", "spdx-json": ".spdx.json", "csv": ".csv", "table": ".txt",
}

var unsafeFile = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func scanCmd(ctx context.Context, args []string, stdout io.Writer) error {
	var o opts
	f := newFlags("scan", &o)
	root, err := parse(f, args)
	if err != nil {
		return err
	}
	outs := o.outputs
	if len(outs) == 0 {
		outs = outputs{{format: "cyclonedx-json"}}
	}
	sboms, err := collect(ctx, root, &o)
	if err != nil {
		return err
	}
	opts := format.Options{ToolVersion: wpsbom.Version, Reproducible: o.reproducible}

	if o.outDir != "" {
		if err := os.MkdirAll(o.outDir, 0o755); err != nil {
			return err
		}
		for _, s := range sboms {
			base := s.kind + "-" + unsafeFile.ReplaceAllString(s.name, "_")
			if s.inv.Image != nil {
				base += "-" + shortID(strings.TrimPrefix(s.inv.Image.Digest, "sha256:"))
			}
			for _, out := range outs {
				file := filepath.Join(o.outDir, base+fileExt[out.format])
				if err := write(output{out.format, file}, stdout, encoder(out.format, s.inv, opts)); err != nil {
					return err
				}
				fmt.Fprintln(os.Stderr, "wrote", file)
			}
		}
		return nil
	}
	if len(sboms) > 1 {
		return fmt.Errorf("this scan gives %d SBOMs (host and images): write them with --out-dir DIR", len(sboms))
	}

	toStdout := 0
	for i := range outs {
		if outs[i].file == "" && o.file != "" && len(outs) == 1 {
			outs[i].file = o.file
		}
		if outs[i].file == "" {
			toStdout++
		}
	}
	if toStdout > 1 {
		return errors.New("several outputs to stdout: give each -o a file (-o FORMAT=FILE)")
	}
	for _, out := range outs {
		if err := write(out, stdout, encoder(out.format, sboms[0].inv, opts)); err != nil {
			return err
		}
	}
	return nil
}

func encoder(name string, inv *inventory.Inventory, opts format.Options) func(io.Writer) error {
	return func(w io.Writer) error { return format.Encoders[name](w, inv, opts) }
}

// write runs encode on stdout or on out.file.
func write(out output, stdout io.Writer, encode func(io.Writer) error) error {
	if out.file == "" {
		return encode(stdout)
	}
	f, err := os.Create(out.file)
	if err != nil {
		return err
	}
	if err := encode(f); err != nil {
		f.Close()
		return fmt.Errorf("%s: %w", out.file, err)
	}
	return f.Close()
}

func newClient(o *opts) *push.Client {
	return &push.Client{URL: o.url, Token: o.token, UserAgent: "wpsbom/" + wpsbom.Version}
}

func checkFailOn(v string) error {
	if v != "" && v != "kev" && v != "critical" {
		return fmt.Errorf("--fail-on %q: use kev or critical", v)
	}
	return nil
}

func pushCmd(ctx context.Context, args []string) error {
	var o opts
	f := newFlags("push", &o)
	root, err := parse(f, args)
	if err != nil {
		return err
	}
	if err := checkFailOn(o.failOn); err != nil {
		return err
	}
	sboms, err := collect(ctx, root, &o)
	if err != nil {
		return err
	}
	hasHost := sboms[0].kind == "host"
	if hasHost && o.project == "" {
		return errors.New("--project NAME is required for a host scan")
	}
	c := newClient(&o)
	var policy error
	// Images first, so the host's containers point at SBOMs that exist.
	for i := len(sboms) - 1; i >= 0; i-- {
		s := sboms[i]
		name := s.name
		if s.kind == "host" || (o.project != "" && len(sboms) == 1) {
			name = o.project
		}
		if err := upload(ctx, c, name, s, o.failOn); err != nil {
			if !errors.Is(err, push.ErrPolicy) {
				return err
			}
			policy = err
		}
	}
	return policy
}

func upload(ctx context.Context, c *push.Client, project string, s sbom, failOn string) error {
	var buf bytes.Buffer
	if err := format.CycloneDX(&buf, s.inv, format.Options{ToolVersion: wpsbom.Version}); err != nil {
		return err
	}
	res, err := c.Upload(ctx, project, s.kind, failOn, buf.Bytes())
	if res != nil {
		n := res.Counts
		fmt.Fprintf(os.Stderr, "%s (%s): %d components, %d vulnerabilities (KEV %d, critical %d, high %d)",
			res.Project.Name, s.kind, res.Components, n.Total, n.KEV, n.Critical, n.High)
		if res.Project.URL != "" {
			fmt.Fprintf(os.Stderr, " %s", res.Project.URL)
		}
		fmt.Fprintln(os.Stderr)
	}
	if err != nil && !errors.Is(err, push.ErrPolicy) {
		return fmt.Errorf("%s: %w", project, err)
	}
	return err
}

func k8sCmd(ctx context.Context, args []string) error {
	var o opts
	f := newFlags("k8s", &o)
	if err := f.Parse(args); err != nil {
		return err
	}
	if f.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q", f.Arg(0))
	}
	if o.cluster == "" {
		return errors.New("--cluster NAME is required")
	}
	if err := checkFailOn(o.failOn); err != nil {
		return err
	}
	kc, err := k8s.New(k8s.Config{Server: o.server, TokenFile: o.tokenFile, CAFile: o.caFile})
	if err != nil {
		return err
	}
	ws, err := kc.Workloads(ctx, o.namespace)
	if err != nil {
		return err
	}
	c := newClient(&o)
	var policy error
	if o.scanImages {
		done := map[string]bool{}
		for _, w := range ws {
			ref := w.Repo + "@" + w.Digest
			if w.Repo == "" || done[ref] {
				continue
			}
			done[ref] = true
			src, err := image.Open(ctx, "registry:"+ref)
			if err != nil {
				// One unreachable registry should not stop the others.
				fmt.Fprintln(os.Stderr, "wpsbom: skip", ref+":", err)
				continue
			}
			inv, err := image.Scan(ctx, src, image.Options{})
			src.Close()
			if err != nil {
				fmt.Fprintln(os.Stderr, "wpsbom: skip", ref+":", err)
				continue
			}
			if err := upload(ctx, c, push.ProjectName(w.Repo), sbom{inv: inv, kind: "image"}, o.failOn); err != nil {
				if !errors.Is(err, push.ErrPolicy) {
					return err
				}
				policy = err
			}
		}
	}
	n, err := c.Workloads(ctx, o.cluster, ws)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%s: %d workload containers\n", o.cluster, n)
	return policy
}

func upgradeCmd(ctx context.Context, args []string) error {
	f := flag.NewFlagSet("upgrade", flag.ContinueOnError)
	check := f.Bool("check", false, "only report whether a newer release exists")
	force := f.Bool("force", false, "install even over a development build or the same version")
	if err := f.Parse(args); err != nil {
		return err
	}
	o := upgrade.Options{Current: wpsbom.Version, CheckOnly: *check, Force: *force, Log: os.Stderr}
	if f.NArg() > 0 {
		o.Target = f.Arg(0)
	}
	return upgrade.Run(ctx, o)
}
