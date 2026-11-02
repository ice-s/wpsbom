package format

import (
	"encoding/csv"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/ice-s/wpsbom/pkg/inventory"
)

// Table writes one package per line: NAME VERSION ARCH SOURCE TYPE, plus LOCATION when the
// scan found applications.
func Table(w io.Writer, inv *inventory.Inventory, _ Options) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	if len(inv.Apps) == 0 {
		fmt.Fprintln(tw, "NAME\tVERSION\tARCH\tSOURCE\tTYPE")
		for _, p := range inv.Packages {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", p.Name, p.Version, p.Arch, p.Source, p.Type)
		}
		return tw.Flush()
	}
	fmt.Fprintln(tw, "NAME\tVERSION\tARCH\tSOURCE\tTYPE\tLOCATION")
	for _, p := range inv.Packages {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", p.Name, p.Version, p.Arch, p.Source, p.Type, p.Location)
	}
	return tw.Flush()
}

// CSV writes one package per row with a header, for spreadsheets.
func CSV(w io.Writer, inv *inventory.Inventory, _ Options) error {
	cw := csv.NewWriter(w)
	cw.Write([]string{"name", "version", "arch", "source", "source_version", "type", "distro", "licenses", "purl", "location", "direct", "dev", "layer"})
	distro := inv.Distro.Qualifier()
	for _, p := range inv.Packages {
		d := distro
		if !inventory.IsOS(p.Type) {
			d = ""
		}
		layer := ""
		if l := layerOf(inv, p); l != nil {
			layer = l.DiffID
		}
		cw.Write([]string{p.Name, p.Version, p.Arch, p.Source, p.SourceVersion, p.Type, d, strings.Join(p.Licenses, "; "), p.PURL,
			p.Location, boolStr(p.Location != "" && p.Direct), boolStr(p.Dev), layer})
	}
	cw.Flush()
	return cw.Error()
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return ""
}
