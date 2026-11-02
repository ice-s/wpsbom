// Command wpsbom generates an SBOM of an operating system's installed packages.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"

	"github.com/ice-s/wpsbom/pkg/format"
	"github.com/ice-s/wpsbom/pkg/rootfs"
	"github.com/ice-s/wpsbom/pkg/wpsbom"
)

const usage = `wpsbom: SBOM of an operating system's installed packages (dpkg, apk).

Usage:
  wpsbom scan [flags] [ROOT]   scan ROOT (default "/": the running system)
  wpsbom version

Scan flags:
`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "wpsbom:", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stdout io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		scanFlags(new(scanOpts)).PrintDefaults()
		return errors.New("missing command")
	}
	switch args[0] {
	case "scan":
		return scan(ctx, args[1:], stdout)
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, wpsbom.Version)
		return nil
	case "help", "-h", "--help":
		fmt.Fprint(stdout, usage)
		f := scanFlags(new(scanOpts))
		f.SetOutput(stdout)
		f.PrintDefaults()
		return nil
	}
	return fmt.Errorf("unknown command %q (try \"wpsbom help\")", args[0])
}

type scanOpts struct {
	output       string
	file         string
	reproducible bool
	hostname     bool
}

func scanFlags(o *scanOpts) *flag.FlagSet {
	f := flag.NewFlagSet("scan", flag.ContinueOnError)
	f.StringVar(&o.output, "o", "cyclonedx-json", "output format: cyclonedx-json, table")
	f.StringVar(&o.file, "file", "", "write to this file instead of stdout")
	f.BoolVar(&o.reproducible, "reproducible", false, "no serial number or timestamp: same system, same bytes")
	f.BoolVar(&o.hostname, "hostname", false, "record the hostname as is (default: a hash of it)")
	return f
}

func scan(ctx context.Context, args []string, stdout io.Writer) error {
	var o scanOpts
	f := scanFlags(&o)
	if err := f.Parse(args); err != nil {
		return err
	}
	// Flags may also follow ROOT: "wpsbom scan / -o table".
	root := "/"
	if f.NArg() > 0 {
		root = f.Arg(0)
		if err := f.Parse(f.Args()[1:]); err != nil {
			return err
		}
		if f.NArg() > 0 {
			return fmt.Errorf("unexpected argument %q", f.Arg(0))
		}
	}
	if o.output != "cyclonedx-json" && o.output != "table" {
		return fmt.Errorf("unknown output format %q", o.output)
	}

	fsys, err := rootfs.New(root)
	if err != nil {
		return err
	}
	live := fsys.Root() == filepath.Clean("/")
	inv, err := wpsbom.Scan(ctx, fsys, wpsbom.Options{Live: live, RevealHostname: o.hostname})
	if err != nil {
		return err
	}

	w := stdout
	if o.file != "" {
		out, err := os.Create(o.file)
		if err != nil {
			return err
		}
		defer out.Close()
		w = out
	}
	if o.output == "table" {
		err = format.Table(w, inv)
	} else {
		err = format.CycloneDX(w, inv, format.Options{ToolVersion: wpsbom.Version, Reproducible: o.reproducible})
	}
	if err != nil {
		return err
	}
	if c, ok := w.(io.Closer); ok && w != stdout {
		return c.Close()
	}
	return nil
}
