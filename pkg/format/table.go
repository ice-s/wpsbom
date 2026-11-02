package format

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/ice-s/wpsbom/pkg/inventory"
)

// Table writes one package per line: NAME VERSION ARCH SOURCE TYPE.
func Table(w io.Writer, inv *inventory.Inventory) error {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tVERSION\tARCH\tSOURCE\tTYPE")
	for _, p := range inv.Packages {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", p.Name, p.Version, p.Arch, p.Source, p.Type)
	}
	return tw.Flush()
}
