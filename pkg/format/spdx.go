package format

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/ice-s/wpsbom/pkg/inventory"
)

// SPDX 2.3 JSON document (https://spdx.github.io/spdx-spec/v2.3/), the subset wpsbom fills.
type spdxDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      spdxCreationInfo   `json:"creationInfo"`
	Packages          []spdxPackage      `json:"packages"`
	Relationships     []spdxRelationship `json:"relationships"`
}

type spdxCreationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
	Comment  string   `json:"comment,omitempty"`
}

type spdxPackage struct {
	Name                  string            `json:"name"`
	SPDXID                string            `json:"SPDXID"`
	VersionInfo           string            `json:"versionInfo,omitempty"`
	DownloadLocation      string            `json:"downloadLocation"`
	FilesAnalyzed         bool              `json:"filesAnalyzed"`
	LicenseConcluded      string            `json:"licenseConcluded"`
	LicenseDeclared       string            `json:"licenseDeclared"`
	CopyrightText         string            `json:"copyrightText"`
	SourceInfo            string            `json:"sourceInfo,omitempty"`
	Description           string            `json:"description,omitempty"`
	PrimaryPackagePurpose string            `json:"primaryPackagePurpose,omitempty"`
	ExternalRefs          []spdxExternalRef `json:"externalRefs,omitempty"`
}

type spdxExternalRef struct {
	ReferenceCategory string `json:"referenceCategory"`
	ReferenceType     string `json:"referenceType"`
	ReferenceLocator  string `json:"referenceLocator"`
}

type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

const (
	noAssertion = "NOASSERTION"
	spdxOSID    = "SPDXRef-OperatingSystem"
)

// SPDX writes an SPDX 2.3 JSON SBOM: the document describes the operating system package,
// which CONTAINS every installed package. Each package carries its PURL as an external ref.
func SPDX(w io.Writer, inv *inventory.Inventory, opts Options) error {
	name := "unknown-os"
	if q := inv.Distro.Qualifier(); q != "" {
		name = q
	}
	doc := spdxDocument{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              name,
		DocumentNamespace: "https://github.com/ice-s/wpsbom/spdx/" + name + "-" + documentID(inv, opts),
		CreationInfo: spdxCreationInfo{
			Created:  created(opts).Format(time.RFC3339),
			Creators: []string{"Tool: wpsbom-" + opts.ToolVersion},
		},
	}

	osPkg := spdxPackage{
		Name:                  name,
		SPDXID:                spdxOSID,
		DownloadLocation:      noAssertion,
		LicenseConcluded:      noAssertion,
		LicenseDeclared:       noAssertion,
		CopyrightText:         noAssertion,
		PrimaryPackagePurpose: "OPERATING-SYSTEM",
	}
	if d := inv.Distro; d != nil {
		osPkg.Name = d.ID
		osPkg.VersionInfo = d.VersionID
		osPkg.Description = d.PrettyName
	}
	var details []string
	if inv.Kernel != "" {
		details = append(details, "kernel "+inv.Kernel)
	}
	if inv.Hostname != "" {
		details = append(details, "hostname "+inv.Hostname)
	}
	doc.CreationInfo.Comment = strings.Join(details, "; ")
	doc.Packages = append(doc.Packages, osPkg)
	doc.Relationships = append(doc.Relationships, spdxRelationship{"SPDXRef-DOCUMENT", "DESCRIBES", spdxOSID})

	// Each application is described by the document too, and contains its dependencies.
	appIDs := map[string]string{}
	for i, a := range inv.Apps {
		id := fmt.Sprintf("SPDXRef-Application-%s-%d", spdxIDChars.ReplaceAllString(a.Name, "-"), i)
		appIDs[a.Manifest] = id
		doc.Packages = append(doc.Packages, spdxPackage{
			Name:                  a.Name,
			SPDXID:                id,
			VersionInfo:           a.Version,
			DownloadLocation:      noAssertion,
			LicenseConcluded:      noAssertion,
			LicenseDeclared:       noAssertion,
			CopyrightText:         noAssertion,
			Description:           a.Type + " application in " + a.Dir + " (" + a.Manifest + ")",
			PrimaryPackagePurpose: "APPLICATION",
		})
		doc.Relationships = append(doc.Relationships, spdxRelationship{"SPDXRef-DOCUMENT", "DESCRIBES", id})
	}

	for i, p := range inv.Packages {
		id := fmt.Sprintf("SPDXRef-Package-%s-%s-%d", p.Type, spdxIDChars.ReplaceAllString(p.Name, "-"), i)
		sp := spdxPackage{
			Name:             p.Name,
			SPDXID:           id,
			VersionInfo:      p.Version,
			DownloadLocation: noAssertion,
			LicenseConcluded: noAssertion,
			LicenseDeclared:  licenseExpression(p.Licenses),
			CopyrightText:    noAssertion,
		}
		if p.Source != "" {
			sp.SourceInfo = "built from source package " + strings.TrimSpace(p.Source+" "+p.SourceVersion)
		}
		if p.PURL != "" {
			sp.ExternalRefs = []spdxExternalRef{{"PACKAGE-MANAGER", "purl", p.PURL}}
		}
		if p.Location != "" {
			sp.PrimaryPackagePurpose = "LIBRARY"
		}
		doc.Packages = append(doc.Packages, sp)
		switch app, ok := appIDs[p.Location]; {
		case !ok:
			doc.Relationships = append(doc.Relationships, spdxRelationship{spdxOSID, "CONTAINS", id})
		case p.Direct && p.Dev:
			doc.Relationships = append(doc.Relationships, spdxRelationship{id, "DEV_DEPENDENCY_OF", app})
		case p.Direct:
			doc.Relationships = append(doc.Relationships, spdxRelationship{app, "DEPENDS_ON", id})
		default:
			doc.Relationships = append(doc.Relationships, spdxRelationship{app, "CONTAINS", id})
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(doc)
}

// SPDX identifiers allow letters, digits, "." and "-" only.
var spdxIDChars = regexp.MustCompile(`[^A-Za-z0-9.-]+`)

// A license expression made of SPDX-style identifiers and operators. Anything else (free text
// some packages carry) is reported as NOASSERTION rather than an invalid expression.
var licenseExpr = regexp.MustCompile(`^[()]*[A-Za-z0-9.+-]+[()]*( +(AND|OR|WITH) +[()]*[A-Za-z0-9.+-]+[()]*)*$`)

func licenseExpression(ls []string) string {
	if len(ls) != 1 || !licenseExpr.MatchString(ls[0]) {
		return noAssertion
	}
	return ls[0]
}

// created is the document time: now, or for reproducible output SOURCE_DATE_EPOCH (else the
// Unix epoch), since SPDX requires a creation time.
func created(opts Options) time.Time {
	if !opts.Reproducible {
		return time.Now().UTC().Truncate(time.Second)
	}
	if s, err := strconv.ParseInt(os.Getenv("SOURCE_DATE_EPOCH"), 10, 64); err == nil {
		return time.Unix(s, 0).UTC()
	}
	return time.Unix(0, 0).UTC()
}

// documentID makes the namespace unique: random, or derived from the content when reproducible.
func documentID(inv *inventory.Inventory, opts Options) string {
	if !opts.Reproducible {
		return uuid4()
	}
	h := sha256.New()
	io.WriteString(h, inv.Distro.Qualifier())
	for _, p := range inv.Packages {
		io.WriteString(h, "\n"+p.PURL)
	}
	return fmt.Sprintf("%x", h.Sum(nil)[:16])
}
