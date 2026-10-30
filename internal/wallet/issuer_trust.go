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
	"slices"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/dcql"
	"github.com/eudi-dev/eudi-dev/v3/internal/findings"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
	"github.com/eudi-dev/eudi-dev/v3/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v3/internal/regcert"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
	"github.com/eudi-dev/eudi-dev/v3/internal/trustedlists"
	"github.com/eudi-dev/eudi-dev/v3/internal/validate"
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
func (w *Wallet) catalogueFindings(metadata map[string]any, configurations []string) findings.List {
	if !w.ARFChecks() {
		return nil
	}
	entries := w.Registrar().CatalogAttestations()
	var list findings.List
	for _, o := range offeredAttestations(metadata, configurations, nil) {
		if !o.known || len(o.types) == 0 {
			continue
		}
		if _, ok := catalogueEntryIn(entries, o.format, o.types); !ok {
			list = append(list, findings.UncitedRegistration(fmt.Sprintf("the attestation catalogue has no entry for %s (%s), which the issuer offers. Add an entry to describe its schema and trusted list", regcert.TypeName(o.format, o.types), o.format)))
		}
	}
	return list
}

// trustAnchorFindings validates the signature of a received credential with
// the trusted lists of its catalogue entry when --arf is on. The lists of an
// EAA entry that give no anchors go to the activity log.
func (w *Wallet) trustAnchorFindings(cred StoredCredential) findings.List {
	if !w.ARFChecks() {
		return nil
	}
	anchoring, _ := w.catalogueAnchoring(cred)
	w.warnFindings("issuance", "trusted_list", subjectCredential, "Some trusted lists of the catalogue entry have no trust anchors", uncitedRegistrations(anchoring.Warnings), nil)
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

// RefusesTrustFindings reports whether a received credential with anchoring
// findings is refused, as in checkReceivedCredentials.
func (w *Wallet) RefusesTrustFindings() bool {
	return w.Mode() == ValidationModeStrict && w.ARFChecks()
}

// RefusesHAIPFindings reports whether a status list with HAIP 1.0 findings is
// refused. Strict mode refuses them only with --haip.
func (w *Wallet) RefusesHAIPFindings() bool {
	return w.Mode() == ValidationModeStrict && w.HAIPChecks()
}

// CheckCatalogueAnchoring validates a raw SD-JWT VC or mdoc with the trusted
// lists of its catalogue entry. found is false when the catalogue has no entry
// for its type.
func (w *Wallet) CheckCatalogueAnchoring(raw string) (anchoring CatalogueAnchoring, found bool) {
	if anchoring, found := w.registrationCertificateAnchoring(raw); found {
		return anchoring, true
	}
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
// eu.europa.ec.eudi.pid.1. Their lists together anchor the credential. The
// result holds the one entry linking the anchoring list. When several entries
// match and none of them alone links that list, the result holds no entry.
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
	rule := findings.ARF.Registration(category.TrustRequirement)
	eaa := category.TrustRule == registrar.CategoryOf(credtemplate.CategoryEAA).TrustRule
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
			result.Warnings = append(result.Warnings, fmt.Sprintf("The trusted list %s of %s has no trust anchors: %v", c.URL, described, c.Err))
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
		result.Findings = findings.List{rule.Newf("no trusted list of %s is readable, so the wallet cannot validate the received %s", described, credentialLabel(cred))}
	default:
		result.Findings = findings.List{rule.Newf("the signature of the received %s does not validate with the trusted lists of %s: %s", credentialLabel(cred), described, strings.Join(problems, ", "))}
	}
	return result, true
}

func listedIn(lists []trustedlists.List, url string) bool {
	return slices.ContainsFunc(lists, func(l trustedlists.List) bool { return l.URL == url })
}

// entriesLinking returns the catalogue entries that link the trusted list.
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
		return fmt.Errorf("the trusted list has no issuance service")
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
// is signed on its own. Copies of a batch must share their attribute values
// (OpenID4VCI 1.0 §3.3.2). With --haip it applies HAIP 1.0 §6.1.1. With
// --arf it checks the trust anchor, the requested type (ISSU_06), the
// validity period of the batch (ISSU_11a) and the validity and status of
// every copy (CIR (EU) 2024/2982 Article 4(3)(d)). In strict mode a failed
// check refuses the response (ARF ISSU_11b). In debug mode it returns the
// findings. configID is the requested credential configuration.
func (w *Wallet) checkReceivedCredentials(credResp, metadata map[string]any, configID, issuer string) (findings.List, error) {
	credentials := credentialStringsFromResponse(credResp)
	received := make([]StoredCredential, 0, len(credentials))
	for _, raw := range credentials {
		received = append(received, receivedCredential(raw))
	}
	var debugFindings findings.List
	if w.HAIPChecks() {
		var violations findings.List
		for _, raw := range credentials {
			violations = append(violations, w.haipCredentialViolations(raw)...)
		}
		if len(violations) > 0 {
			violations = dedupeFindings(violations)
			if err := w.reportHAIPViolations(subjectCredential, issuer, violations); err != nil {
				return nil, err
			}
			debugFindings = append(debugFindings, violations...)
		}
	}
	for _, deviation := range batchDatasetFindings(received) {
		if err := w.reportServerDeviation(deviation); err != nil {
			return nil, err
		}
		debugFindings = append(debugFindings, deviation)
	}
	if !w.ARFChecks() {
		return debugFindings, nil
	}
	var list findings.List
	for _, cred := range received {
		list = append(list, w.trustAnchorFindings(cred)...)
	}
	list = append(list, requestedTypeFindings(received, metadata, configID)...)
	list = append(list, batchValidityFindings(received)...)
	list = append(list, w.receivedValidityFindings(received, time.Now())...)
	if len(list) == 0 {
		return debugFindings, nil
	}
	list = dedupeFindings(list)
	if err := w.reportARFFindings(issuer, subjectCredential, "The received credential does not meet the ARF rules", list); err != nil {
		return nil, err
	}
	return append(debugFindings, list...), nil
}

// receivedCredential reads the format, type and claims of a raw SD-JWT VC or
// mdoc.
func receivedCredential(raw string) StoredCredential {
	raw = strings.TrimSpace(raw)
	if strings.Contains(raw, "~") {
		token, err := sdjwt.ParseLenient(raw)
		if err != nil {
			return StoredCredential{}
		}
		return StoredCredential{Format: credtype.FormatSDJWT, VCT: jsonutil.Text(token.Payload["vct"]), Claims: token.ResolvedClaims, Raw: raw}
	}
	doc, err := mdoc.Parse(raw)
	if err != nil {
		return StoredCredential{}
	}
	claims := make(map[string]any)
	for ns, items := range doc.NameSpaces {
		for _, item := range items {
			claims[ns+":"+item.ElementIdentifier] = item.ElementValue
		}
	}
	return StoredCredential{Format: credtype.FormatMDOC, DocType: doc.DocType, Claims: claims, Raw: raw}
}

// dedupeStrings trims the values and returns each non-empty one once, sorted.
func dedupeFindings(list findings.List) findings.List {
	seen := make(map[string]bool)
	out := make(findings.List, 0, len(list))
	for _, finding := range list {
		text := finding.String()
		if seen[text] {
			continue
		}
		seen[text] = true
		out = append(out, finding)
	}
	slices.SortFunc(out, func(a, b findings.Finding) int { return strings.Compare(a.String(), b.String()) })
	return out
}

// uncitedRegistrations makes an uncited registration finding of each text.
func uncitedRegistrations(texts []string) findings.List {
	list := make(findings.List, 0, len(texts))
	for _, text := range texts {
		list = append(list, findings.UncitedRegistration(text))
	}
	return list
}
