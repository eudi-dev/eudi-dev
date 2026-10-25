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

// Package regcert checks the registration certificates (ETSI TS 119 475) of
// verifiers and issuers and their binding to access certificates (ARF Topic
// 44).
package regcert

import (
	"crypto/x509"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/certchain"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
	"github.com/eudi-dev/eudi-dev/v3/internal/statuslist"
	"github.com/eudi-dev/eudi-dev/v3/internal/validate"
)

// Registration is a registration certificate whose signature verifies with
// its x5c leaf.
type Registration struct {
	Claims map[string]any
	Chain  []*x509.Certificate
}

// Verify verifies the registration certificates of a verifier_info or
// issuer_info array against their own x5c leaf. ETSI TS 119 475 V1.2.1 types
// them rc-wrp+jwt, whatever the entry's format. This does not establish trust
// in the signer. Each problem completes the sentence "the registration
// certificate ...".
func Verify(entries []map[string]any) (registrations []Registration, problems []string) {
	for _, entry := range entries {
		data := certificateJWT(entry["data"])
		if data == "" {
			continue
		}
		header, claims, _, err := format.ParseJWTParts(data)
		if err != nil {
			continue
		}
		if typ, _ := header["typ"].(string); !format.JOSETypeIs(typ, registrar.RegistrationCertificateTyp) {
			continue
		}
		chain, err := validate.X5CCertificates(header)
		if err != nil || len(chain) == 0 {
			problems = append(problems, "has no readable x5c certificate")
			continue
		}
		if _, err := jws.Verify(data, chain[0].PublicKey); err != nil {
			problems = append(problems, "has a signature that does not verify with its x5c leaf")
			continue
		}
		registrations = append(registrations, Registration{Claims: claims, Chain: chain})
	}
	return registrations, problems
}

// certificateJWT returns the compact JWT of a registration_cert entry. In
// verifier_info the data is "the base64url encoding of the serialized RP
// registration certificate" (ETSI TS 119 472-2 V1.3.1
// OIDFVP-HAIP-COMMON-REQ-RO-16). In issuer_info it "shall be the registration
// certificate" (ETSI TS 119 472-3 V1.1.1 ISS-MDATA-REG_CERT-4.2.3-06), the
// compact JWT itself. Both arrays share this reader.
func certificateJWT(value any) string {
	data, _ := value.(string)
	if format.IsJWT(data) {
		return data
	}
	decoded, err := format.DecodeBase64URL(data)
	if err != nil || !format.IsJWT(string(decoded)) {
		return ""
	}
	return string(decoded)
}

// StatusFindings checks a registration certificate against its registrar's
// status list (ARF §6.6.3.3 step 4). The list must chain to the
// revocation service of a trusted registrar (ARF RPACANot_03b). An untrusted
// chain is a finding. The wallet then reads the status with the token's own
// certificate and still reports a revocation. An unreadable
// status is a finding too, because then the wallet can't tell whether the
// certificate is revoked.
func StatusFindings(cert map[string]any, client *http.Client, statusCAs []*x509.Certificate, rule string) []string {
	ref := statuslist.ExtractStatusRef(cert)
	if ref == nil {
		return nil
	}
	name := jsonutil.FirstNonEmpty(jsonutil.Text(cert["name"]), jsonutil.Text(cert["sub"]), "the relying party")
	anchors := make([]statuslist.TrustCert, 0, len(statusCAs))
	for _, ca := range statusCAs {
		anchors = append(anchors, statuslist.TrustCert{Raw: ca.Raw})
	}
	var findings []string
	result, err := statuslist.CheckWithOptions(ref, statuslist.CheckOptions{HTTPClient: client, CandidateAnchors: anchors, Prefer: statuslist.FormatJWT})
	switch {
	case err != nil:
		findings = append(findings, fmt.Sprintf("%s: the status of the registration certificate of %s cannot be checked: %v", rule, name, err))
	case !result.IsValid:
		findings = append(findings, fmt.Sprintf("%s: the registrar revoked the registration certificate of %s (status %s at index %d of %s)", rule, name, result.StatusName, ref.Idx, ref.URI))
	}
	if err == nil && len(anchors) > 0 && !result.TrustAnchored {
		findings = append(findings, fmt.Sprintf("%s: the status list of the registration certificate of %s is %s. Its certificate chain doesn't lead to a trusted registrar", rule, name, result.SignatureInfo))
	}
	if len(statusCAs) == 0 {
		findings = append(findings, fmt.Sprintf("ARF RPACANot_03b: the status list of the registration certificate of %s is not anchored, because no trusted list has a revocation service of a registration certificate provider", name))
	}
	return findings
}

// Purposes collects the purposes and the privacy policy links of
// registration certificates, each once.
func Purposes(certs []map[string]any) (purposes, privacyPolicies []string) {
	for _, cert := range certs {
		for _, purpose := range purposeStrings(cert["purpose"]) {
			if !containsPurpose(purposes, purpose) {
				purposes = append(purposes, purpose)
			}
		}
		if policy := jsonutil.Text(cert["privacy_policy"]); format.IsWebURL(policy) && !containsPurpose(privacyPolicies, policy) {
			privacyPolicies = append(privacyPolicies, policy)
		}
	}
	return purposes, privacyPolicies
}

// Bound reports whether a registration certificate identifies the relying party of
// the access certificate. ETSI TS 119 475 V1.2.1 GEN-5.1.1-03 links the two
// "solely on the matching identifier" when other attributes, such as
// organizational units, differ.
func Bound(cert map[string]any, access *x509.Certificate) bool {
	identifier, _ := accessIdentifier(cert)
	return identifier != "" && identifier == certchain.OrganizationIdentifier(access)
}

// accessIdentifier returns the identifier required in the access certificate.
// An intermediary's access certificate identifies the intermediary. The
// registration certificate carries it in act.sub (ETSI TS 119 475 V1.2.1
// GEN-5.2.4-09).
func accessIdentifier(cert map[string]any) (identifier string, intermediated bool) {
	if act, ok := cert["act"].(map[string]any); ok && jsonutil.Text(act["sub"]) != "" {
		return jsonutil.Text(act["sub"]), true
	}
	return jsonutil.Text(cert["sub"]), false
}

// BindingFindings links a registration certificate to the access certificate
// of the request through the relying party identifier and the service
// identifier (ARF RPRC_17a). The access certificate carries the service in
// organizationalUnit (ETSI TS 119 411-8 V1.1.1 GEN-6.6.1-08). For an
// intermediary the service in the registration certificate is the
// intermediated relying party's, so only the identifiers are compared.
func BindingFindings(cert map[string]any, access *x509.Certificate, rule string) []string {
	identifier, intermediated := accessIdentifier(cert)
	var findings []string
	if !Bound(cert, access) {
		findings = append(findings, fmt.Sprintf("%s: the registration certificate identifies %q, but the access certificate's organizationIdentifier is %q", rule, identifier, certchain.OrganizationIdentifier(access)))
	}
	if intermediated {
		return findings
	}
	var accessService string
	if len(access.Subject.OrganizationalUnit) > 0 {
		accessService = access.Subject.OrganizationalUnit[0]
	}
	if service := jsonutil.Text(cert[registrar.ServiceIdentifierClaim]); service != accessService {
		findings = append(findings, fmt.Sprintf("%s: the registration certificate is for the service %q, but the access certificate's organizationalUnit is %q", rule, service, accessService))
	}
	return findings
}

// ContentFindings checks the required content of a relying party's
// registration certificate (ETSI TS 119 475 V1.2.1 §5.2.4 and ARF Topic 44).
// Missing fields are ARF findings.
func ContentFindings(cert map[string]any) []string {
	var findings []string
	miss := func(field, rule string) {
		findings = append(findings, fmt.Sprintf("%s: the registration certificate has no %s", rule, field))
	}
	if jsonutil.Text(cert["name"]) == "" {
		miss("name (trade name)", "ARF RPRC_06")
	}
	if jsonutil.Text(cert["sub"]) == "" {
		miss("sub (relying party identifier)", "ARF RPRC_07")
	}
	if jsonutil.Text(cert["privacy_policy"]) == "" {
		miss("privacy_policy", "ETSI TS 119 475 V1.2.1 GEN-5.2.4-01")
	}
	if len(purposeStrings(cert["srv_description"])) == 0 {
		miss("srv_description", "ETSI TS 119 475 V1.2.1 GEN-5.2.4-01")
	}
	if !nonEmptyList(cert["entitlements"]) {
		miss("entitlements (at least one)", "ETSI TS 119 475 V1.2.1 GEN-5.2.4-03")
	}
	// ARF RPRC_12 also asks for the authority's name and country. ETSI TS 119
	// 475 V1.2.1 maps supervisory_authority only to email, phone and uri, so
	// a registration certificate has no claim for them to check.
	partyFindings(cert, miss, "ARF RPRC_11", "ARF RPRC_12")
	if !nonEmptyList(cert["credentials"]) {
		miss("credentials (the registered attestations and attributes)", "ETSI TS 119 475 V1.2.1 GEN-5.2.4-06")
	}
	if statuslist.ExtractStatusRef(cert) == nil {
		miss("status (its entry in the registrar's status list), so the wallet cannot check revocation", "ETSI TS 119 475 V1.2.1 Table 7")
	}
	return append(findings, validityFindings(cert, "ARF RPRC_17")...)
}

// partyFindings checks the fields of ETSI TS 119 475 V1.2.1 Table 7
// (GEN-5.2.4-01). Every registered relying party has them, verifier or
// provider. Not every registry entry has an infoURI, so info_uri is optional.
// The ARF asks a relying party for the contacts (RPRC_11, RPRC_12). For a
// provider they are Table 7 fields. The caller passes the rules to cite.
func partyFindings(cert map[string]any, miss func(field, rule string), supportRule, supervisoryRule string) {
	const table7 = "ETSI TS 119 475 V1.2.1 GEN-5.2.4-01"
	if jsonutil.Text(cert["country"]) == "" {
		miss("country", table7)
	}
	if jsonutil.Text(cert["registry_uri"]) == "" {
		miss("registry_uri", table7)
	}
	if !nonEmptyList(cert["policy_id"]) {
		miss("policy_id", table7)
	}
	if jsonutil.Text(cert["certificate_policy"]) == "" {
		miss("certificate_policy", table7)
	}
	if !hasContact(cert["support_uri"]) {
		miss("support_uri (data deletion contact)", supportRule)
	}
	if !hasSupervisoryAuthority(cert["supervisory_authority"]) {
		miss("supervisory_authority contact", supervisoryRule)
	}
}

// ETSI TS 119 475 V1.2.1 GEN-5.2.4-01 (Table 7) requires iat, and GEN-5.2.4-08
// limits exp to 12 months after it. An expired certificate is invalid (ARF
// RPRC_17).
func validityFindings(cert map[string]any, rule string) []string {
	var findings []string
	iat, hasIat := numberClaim(cert["iat"])
	if !hasIat {
		findings = append(findings, "ETSI TS 119 475 V1.2.1 GEN-5.2.4-01: the registration certificate has no iat")
	}
	exp, hasExp := numberClaim(cert["exp"])
	if !hasExp {
		return findings
	}
	expTime := time.Unix(int64(exp), 0)
	if expTime.Before(time.Now()) {
		findings = append(findings, rule+": the registration certificate has expired")
	}
	if hasIat && expTime.After(time.Unix(int64(iat), 0).AddDate(1, 0, 0)) {
		findings = append(findings, "ETSI TS 119 475 V1.2.1 GEN-5.2.4-08: the registration certificate is valid for more than 12 months")
	}
	return findings
}

// Provides reports whether a listed attestation has the format and one of
// the types. A listed entry without a type matches nothing, because
// provides_attestations lists the types a provider is allowed to issue (ARF
// RPRC_15).
func Provides(provided []Credential, format string, types []string) bool {
	return slices.ContainsFunc(provided, func(p Credential) bool {
		return p.format == format && len(p.types) > 0 && slices.ContainsFunc(types, func(t string) bool { return slices.Contains(p.types, t) })
	})
}

// ProvidedAttestations reads provides_attestations (ETSI TS 119 475 V1.2.1
// Table 8). A type matches when format and type are the same.
func ProvidedAttestations(cert map[string]any) []Credential {
	var out []Credential
	for _, entry := range jsonutil.Maps(cert["provides_attestations"]) {
		format, _ := entry["format"].(string)
		out = append(out, Credential{format: format, types: registrar.CredentialTypes(entry["meta"])})
	}
	return out
}

// ProviderContentFindings checks a provider's registration certificate
// against ETSI TS 119 475 V1.2.1 §5.2.4 and ARF Topic 44. A
// provider certificate has no intended use (RPRC_05), so it has no privacy
// policy either.
func ProviderContentFindings(cert map[string]any) []string {
	var findings []string
	miss := func(field, rule string) {
		findings = append(findings, fmt.Sprintf("%s: the issuer's registration certificate has no %s", rule, field))
	}
	if jsonutil.Text(cert["name"]) == "" {
		miss("name (trade name)", "ARF RPRC_06")
	}
	if jsonutil.Text(cert["sub"]) == "" {
		miss("sub (provider identifier)", "ARF RPRC_07")
	}
	if len(purposeStrings(cert["srv_description"])) == 0 {
		miss("srv_description", "ETSI TS 119 475 V1.2.1 GEN-5.2.4-01")
	}
	if !nonEmptyList(cert["entitlements"]) {
		miss("entitlements (at least one)", "ETSI TS 119 475 V1.2.1 GEN-5.2.4-03")
	}
	partyFindings(cert, miss, "ETSI TS 119 475 V1.2.1 GEN-5.2.4-01", "ETSI TS 119 475 V1.2.1 GEN-5.2.4-01")
	if !nonEmptyList(cert["provides_attestations"]) {
		miss("provides_attestations (its attestation types)", "ARF RPRC_15")
	}
	if statuslist.ExtractStatusRef(cert) == nil {
		miss("status (its entry in the registrar's status list), so the wallet cannot check revocation", "ETSI TS 119 475 V1.2.1 Table 7")
	}
	return append(findings, validityFindings(cert, "ARF RPRC_22a")...)
}
