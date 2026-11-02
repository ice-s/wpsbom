package format

import (
	"io"
	"sort"

	"github.com/ice-s/wpsbom/pkg/inventory"
)

// Encoder writes an inventory in one format.
type Encoder func(w io.Writer, inv *inventory.Inventory, opts Options) error

// Encoders by the name given to "wpsbom scan -o".
var Encoders = map[string]Encoder{
	"cyclonedx-json": CycloneDX,
	"cyclonedx-xml":  CycloneDXXML,
	"spdx-json":      SPDX,
	"csv":            CSV,
	"table":          Table,
}

// Names lists the format names, sorted.
func Names() []string {
	names := make([]string, 0, len(Encoders))
	for n := range Encoders {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
