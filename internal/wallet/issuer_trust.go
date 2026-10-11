// Copyright 2026 Dominik Schlosser
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package wallet

import (
	"crypto/x509"
	"fmt"
	"log"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/credtype"
	"github.com/dominikschlosser/eudi-dev/v3/internal/dcql"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jsonutil"
	"github.com/dominikschlosser/eudi-dev/v3/internal/lote"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mdoc"
	"github.com/dominikschlosser/eudi-dev/v3/internal/regcert"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
	"github.com/dominikschlosser/eudi-dev/v3/internal/sdjwt"
	"github.com/dominikschlosser/eudi-dev/v3/internal/trustedlists"
	"github.com/dominikschlosser/eudi-dev/v3/internal/validate"
)

// catalogueEntryFor returns the catalogue entry that lists format with one of
// the types.
func (w *Wallet) catalogueEntryFor(format string, types []string) (registrar.CatalogAttestation, bool) {
	return catalogueEntryIn(w.Registrar().CatalogAttestations(), format, types)
}

func catalogueEntryIn(entries []registrar.CatalogAttestation, format string, types []string) (registrar.CatalogAttestation, bool) {
	matches := catalogueEntriesIn(entries, format, types)
	if len(matches) == 0 {
		return registrar.CatalogAttestation{}, false
	}
	return matches[0], true
}

// catalogueEntriesIn returns every catalogue entry that lists format with one
// of the types.
func catalogueEntriesIn(entries []registrar.CatalogAttestation, format string, types []string) []registrar.CatalogAttestation {
	var matches []registrar.CatalogAttestation
	for _, entry := range entries {
		if slices.ContainsFunc(entry.Credentials, func(c registrar.CatalogCredential) bool {
			return c.Format == format && slices.Contains(types, c.Type)
		}) {
			matches = append(matches, entry)
		}
	}
	return matches
}

// catalogueFindings reports offered attestations that are missing from the
// catalogue.
// No specification has the wallet check this, so these findings only warn.
func (w *Wallet) catalogueFindings(metadata map[string]any, configurations []string) []string {
	if !w.ARFChecks() {
		return nil
	}
	entries := w.Registrar().CatalogAttestations()
	var findings []string
	for _, o := range offeredAttestations(metadata, configurations, nil) {
		if !o.known || len(o.types) == 0 {
			continue
		}
		if _, ok := catalogueEntryIn(entries, o.format, o.types); !ok {
			findings = append(findings, fmt.Sprintf("Attestation catalogue: the issuer offers %s (%s), and the catalogue has no entry for it. Add an entry to describe its schema and trusted list.", regcert.TypeName(o.format, o.types), o.format))
		}
	}
	return findings
}

// reportCatalogueFindings warns in both modes.
func (w *Wallet) reportCatalogueFindings(issuer string, findings []string) {
	for _, f := range findings {
		log.Printf("[VCI] WARNING: %s", f)
		w.addProtocolWarning("issuance", "catalogue_finding", f, map[string]any{"issuer": issuer})
	}
}

// trustAnchorFindings validates the signature of a received credential with
// the trusted lists of its catalogue entry when --arf is on. The lists of an
// EAA entry that give no anchors go to the activity log.
func (w *Wallet) trustAnchorFindings(cred StoredCredential) []string {
	if !w.ARFChecks() {
		return nil
	}
	anchoring, _ := w.catalogueAnchoring(cred)
	for _, warning := range anchoring.Warnings {
		w.addProtocolWarning("issuance", "trusted_list", warning, nil)
	}
	return anchoring.Findings
}

// CatalogueAnchoring is the result of validating a credential with the
// trusted lists of its catalogue entry.
type CatalogueAnchoring = validate.CatalogueAnchoring

// StatusListAnchors returns the anchors of a credential's status list: the
// revocation service of the trusted list that anchors the credential. It is
// empty when no list of the credential's catalogue entry anchors it.
func (w *Wallet) StatusListAnchors(raw string) []*x509.Certificate {
	anchoring, _ := w.CheckCatalogueAnchoring(raw)
	return anchoring.StatusAnchors
}

// CheckCatalogueAnchoring validates a raw SD-JWT VC or mdoc with the trusted
// lists of its catalogue entry. found is false when the catalogue has no entry
// for its type.
func (w *Wallet) CheckCatalogueAnchoring(raw string) (anchoring CatalogueAnchoring, found bool) {
	return w.catalogueAnchoring(receivedCredential(raw))
}

// catalogueAnchoring validates the signature of a credential with the trusted
// lists of its catalogue entry. The entry's category decides which rule
// applies. ARF ISSU_07, ISSU_08 and ISSU_09 have the wallet validate a PID,
// QEAA or PuB-EAA with the list of its providers, so an entry without a
// readable list is a finding. ISSU_10 asks for the check of an EAA only when
// the wallet has the anchors. PID and PuB-EAA lists on the list of trusted
// lists count too, because ETSI TS 119 602 V1.1.1 gives them a type (Annexes D
// and H).
//
// Several entries can list one type. Every national PID lists the mdoc doctype
// eu.europa.ec.eudi.pid.1. Their lists together anchor the credential, and
// the one entry that links the anchoring list names it. When several entries
// match and no single one links that list, the result names none.
func (w *Wallet) catalogueAnchoring(cred StoredCredential) (CatalogueAnchoring, bool) {
	entries := catalogueEntriesIn(w.Registrar().CatalogAttestations(), cred.Format, []string{cred.VCT, cred.DocType})
	if len(entries) == 0 {
		return CatalogueAnchoring{}, false
	}
	category := registrar.CategoryOf(entries[0].Category)
	result := CatalogueAnchoring{Category: category.ID}
	if len(entries) == 1 {
		result.Entry = entries[0].Name
	}
	described := "its catalogue entries"
	if result.Entry != "" {
		described = fmt.Sprintf("its catalogue entry %q", result.Entry)
	}
	rule := category.TrustRule
	eaa := rule == registrar.CategoryOf(credtemplate.CategoryEAA).TrustRule
	var candidates []trustedlists.List
	for _, entry := range entries {
		for _, authority := range entry.Schema.TrustedAuthorities {
			// The wallet reads lists of trusted entities (ETSI TS 119 602) only.
			if authority.FrameworkType == "etsi_tl" && authority.IsLOTE != nil && *authority.IsLOTE && authority.Value != "" && !listedIn(candidates, authority.Value) {
				list, err := w.TrustedLists().ReadList(authority.Value)
				candidates = append(candidates, trustedlists.List{URL: authority.Value, List: list, Err: err})
			}
		}
	}
	if listType := categoryListType(entries[0].Category); listType != "" {
		for _, tl := range w.TrustedLists().Lists() {
			if tl.Err == nil && tl.List.SchemeInfo.LoTEType == listType && !listedIn(candidates, tl.URL) {
				candidates = append(candidates, tl)
			}
		}
	}
	var problems []string
	read := false
	now := time.Now()
	for _, c := range candidates {
		switch {
		case c.Err != nil && eaa:
			// ISSU_10 needs anchors, so the list is only a warning.
			result.Warnings = append(result.Warnings, fmt.Sprintf("The trusted list %s of %s gives no anchors: %v", c.URL, described, c.Err))
			continue
		case c.Err != nil:
			problems = append(problems, fmt.Sprintf("%s (%v)", c.URL, c.Err))
			continue
		}
		read = true
		issuance, err := lote.Anchors(c.List, lote.IssuanceServices, now)
		if err == nil {
			err = validateWithAnchors(cred, issuance)
		}
		var revocation []*x509.Certificate
		if err == nil {
			revocation, err = lote.Anchors(c.List, lote.RevocationServices, now)
		}
		if err == nil {
			result.AnchoredBy = c.URL
			result.IssuanceAnchors = issuance
			result.StatusAnchors = revocation
			if linking := entriesLinking(entries, c.URL); len(linking) == 1 {
				result.Entry = linking[0].Name
			}
			return result, true
		}
		problems = append(problems, fmt.Sprintf("%s (%v)", c.URL, err))
	}
	switch {
	case !read && eaa:
	case !read && len(problems) == 0:
		result.Findings = []string{fmt.Sprintf("%s: no trusted list of %s is readable, so the wallet cannot validate the received %s", rule, described, credentialLabel(cred))}
	default:
		result.Findings = []string{fmt.Sprintf("%s: the signature of the received %s does not validate with the trusted lists of %s: %s", rule, credentialLabel(cred), described, strings.Join(problems, ", "))}
	}
	return result, true
}

func listedIn(lists []trustedlists.List, url string) bool {
	return slices.ContainsFunc(lists, func(l trustedlists.List) bool { return l.URL == url })
}

// entriesLinking returns the catalogue entries that name the trusted list.
func entriesLinking(entries []registrar.CatalogAttestation, listURL string) []registrar.CatalogAttestation {
	var out []registrar.CatalogAttestation
	for _, entry := range entries {
		if slices.ContainsFunc(entry.Schema.TrustedAuthorities, func(a registrar.TrustAuthority) bool { return a.Value == listURL }) {
			out = append(out, entry)
		}
	}
	return out
}

// categoryListType is the ETSI TS 119 602 list type of a category, if the
// standard defines one.
func categoryListType(category string) string {
	if c := registrar.CategoryOf(category); c.ETSIAnnex != "" {
		return c.LoTEType
	}
	return ""
}

func validateWithAnchors(cred StoredCredential, anchors []*x509.Certificate) error {
	if len(anchors) == 0 {
		return fmt.Errorf("the trusted list names no issuance service")
	}
	key, err := dcql.ChainKey(dcqlCredential(cred), anchors)
	if err != nil {
		return err
	}
	var valid bool
	switch cred.Format {
	case credtype.FormatSDJWT:
		token, err := sdjwt.ParseLenient(cred.Raw)
		if err != nil {
			return err
		}
		valid = sdjwt.Verify(token, key).SignatureValid
	case credtype.FormatMDOC:
		doc, err := mdoc.Parse(cred.Raw)
		if err != nil {
			return err
		}
		valid = mdoc.Verify(doc, key).SignatureValid
	}
	if !valid {
		return fmt.Errorf("the signature does not verify with the key of its certificate")
	}
	return nil
}

// checkReceivedCredentials checks every credential of a credential response
// before the wallet stores one, on every issuance path. Each copy of a batch
// is signed on its own. With --haip it applies HAIP 1.0 §6.1.1, and with
// --arf the trust anchor check. In strict mode a failed check refuses the
// response (ARF ISSU_11b). In debug mode it returns the findings.
func (w *Wallet) checkReceivedCredentials(credResp map[string]any, issuer string) ([]string, error) {
	credentials := credentialStringsFromResponse(credResp)
	var debugFindings []string
	if w.HAIPChecks() {
		var violations []string
		for _, raw := range credentials {
			violations = append(violations, w.haipCredentialViolations(raw)...)
		}
		if len(violations) > 0 {
			violations = dedupeStrings(violations)
			if err := w.reportHAIPViolations("Credential", issuer, violations); err != nil {
				return nil, err
			}
			debugFindings = append(debugFindings, violations...)
		}
	}
	var findings []string
	for _, raw := range credentials {
		findings = append(findings, w.trustAnchorFindings(receivedCredential(raw))...)
	}
	if len(findings) == 0 {
		return debugFindings, nil
	}
	findings = dedupeStrings(findings)
	if err := w.reportARFFindings(issuer, findings, "the received credential fails the ARF checks"); err != nil {
		return nil, err
	}
	return append(debugFindings, findings...), nil
}

// receivedCredential reads the format and type of a raw SD-JWT VC or mdoc.
func receivedCredential(raw string) StoredCredential {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "~") {
		token, err := sdjwt.ParseLenient(raw)
		if err != nil {
			return StoredCredential{}
		}
		return StoredCredential{Format: credtype.FormatSDJWT, VCT: jsonutil.Text(token.Payload["vct"]), Raw: raw}
	}
	doc, err := mdoc.Parse(raw)
	if err != nil {
		return StoredCredential{}
	}
	return StoredCredential{Format: credtype.FormatMDOC, DocType: doc.DocType, Raw: raw}
}

// dedupeStrings trims the values and returns each non-empty one once, sorted.
func dedupeStrings(values []string) []string {
	seen := make(map[string]bool)
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
