package format

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestSPDX(t *testing.T) {
	var buf bytes.Buffer
	if err := SPDX(&buf, sample(), Options{ToolVersion: "test"}); err != nil {
		t.Fatal(err)
	}
	var doc spdxDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SPDXVersion != "SPDX-2.3" || !strings.HasPrefix(doc.DocumentNamespace, "https://github.com/ice-s/wpsbom/spdx/alpine-3.20.3-") {
		t.Errorf("header: %+v", doc)
	}
	// OS package + 2 installed; DESCRIBES + 2 CONTAINS.
	if len(doc.Packages) != 3 || len(doc.Relationships) != 3 {
		t.Fatalf("got %d packages, %d relationships", len(doc.Packages), len(doc.Relationships))
	}
	p := doc.Packages[1]
	if p.Name != "libcrypto3" || p.LicenseDeclared != "Apache-2.0" || p.ExternalRefs[0].ReferenceLocator != sample().Packages[0].PURL {
		t.Errorf("package: %+v", p)
	}
	ids := map[string]bool{}
	for _, p := range doc.Packages {
		if ids[p.SPDXID] || spdxIDChars.MatchString(strings.TrimPrefix(p.SPDXID, "SPDXRef-")) {
			t.Errorf("bad or duplicate SPDXID %q", p.SPDXID)
		}
		ids[p.SPDXID] = true
	}
}

func TestLicenseExpression(t *testing.T) {
	cases := map[string]string{
		"MIT":                                "MIT",
		"GPL-2.0-only AND LGPL-2.1-or-later": "GPL-2.0-only AND LGPL-2.1-or-later",
		"(MIT OR Apache-2.0)":                "(MIT OR Apache-2.0)",
		"GPL-2.0-or-later WITH Classpath-exception-2.0": "GPL-2.0-or-later WITH Classpath-exception-2.0",
		"MIT BSD":                     noAssertion,
		"custom license, see COPYING": noAssertion,
		"":                            noAssertion,
	}
	for in, want := range cases {
		var ls []string
		if in != "" {
			ls = []string{in}
		}
		if got := licenseExpression(ls); got != want {
			t.Errorf("%q: got %q, want %q", in, got, want)
		}
	}
}
