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
	"strings"

	"github.com/ice-s/wpsbom/pkg/format"
	"github.com/ice-s/wpsbom/pkg/rootfs"
	"github.com/ice-s/wpsbom/pkg/wpsbom"
)

const usage = `wpsbom: SBOM of an operating system's installed packages (dpkg, apk).

Usage:
  wpsbom scan [flags] [ROOT]   scan ROOT (default "/": the running system)
  wpsbom version

Examples:
  wpsbom scan / -o table
  wpsbom scan / > sbom.cdx.json
  wpsbom scan / -o spdx-json=sbom.spdx.json -o csv=packages.csv -o table

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

type scanOpts struct {
	outputs      outputs
	file         string
	reproducible bool
	hostname     bool
}

func scanFlags(o *scanOpts) *flag.FlagSet {
	f := flag.NewFlagSet("scan", flag.ContinueOnError)
	f.Var(&o.outputs, "o", "output `FORMAT[=FILE]`, repeatable; formats: "+strings.Join(format.Names(), ", ")+" (default cyclonedx-json)")
	f.StringVar(&o.file, "file", "", "write the output to this file instead of stdout (single -o without =FILE)")
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
	outs := o.outputs
	if len(outs) == 0 {
		outs = outputs{{format: "cyclonedx-json"}}
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

	fsys, err := rootfs.New(root)
	if err != nil {
		return err
	}
	live := fsys.Root() == filepath.Clean("/")
	inv, err := wpsbom.Scan(ctx, fsys, wpsbom.Options{Live: live, RevealHostname: o.hostname})
	if err != nil {
		return err
	}

	opts := format.Options{ToolVersion: wpsbom.Version, Reproducible: o.reproducible}
	for _, out := range outs {
		if err := write(out, stdout, func(w io.Writer) error { return format.Encoders[out.format](w, inv, opts) }); err != nil {
			return err
		}
	}
	return nil
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
