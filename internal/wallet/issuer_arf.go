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
	"net/http"
	"slices"
	"strings"

	"github.com/dominikschlosser/eudi-dev/v3/internal/certchain"
	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/credtype"
	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
	"github.com/dominikschlosser/eudi-dev/v3/internal/statuslist"
)

// issuerAuthentication is what the wallet knows about an issuer before it
// requests a credential: its metadata, the certificate chain of the metadata
// signature (nil for unsigned metadata) and the offered configurations.
type issuerAuthentication struct {
	metadata       map[string]any
	signerChain    []*x509.Certificate
	configurations []string
	accessCAs      []*x509.Certificate
	registrarCAs   []*x509.Certificate
	statusCAs      []*x509.Certificate
	statusClient   *http.Client
	// category returns the category of an offered type. The pid category
	// gets the rules of a PID Provider.
	category func(format string, types []string) string
}

// issuerRules are the ARF requirements for one kind of provider. A PID
// Provider has its own numbers for the same checks.
type issuerRules struct {
	signing, access, registrar, entitlement, attestationType string
	entitled                                                 func([]string) bool
	kind                                                     string
}

var (
	pidProviderRules = issuerRules{
		signing: "ARF ISSU_22", access: "ARF ISSU_24", registrar: "ARF ISSU_23c", entitlement: "ARF ISSU_24a", attestationType: "ARF RPRC_23 and ISSU_24b",
		entitled: func(e []string) bool { return slices.Contains(e, registrar.PIDProviderEntitlement) },
		kind:     "PID Provider",
	}
	attestationProviderRules = issuerRules{
		signing: "ARF ISSU_32", access: "ARF ISSU_34", registrar: "ARF ISSU_33a", entitlement: "ARF ISSU_34a", attestationType: "ARF RPRC_23 and ISSU_34b",
		entitled: func(e []string) bool {
			return slices.ContainsFunc(e, func(v string) bool {
				return v == registrar.QEAAProviderEntitlement || v == registrar.PubEAAProviderEntitlement || v == registrar.NonQEAAProviderEntitlement
			})
		},
		kind: "QEAA Provider, PuB-EAA Provider or EAA Provider",
	}
)

// offeredAttestation is the type of one offered credential configuration.
// known is false when the metadata doesn't list the configuration.
type offeredAttestation struct {
	id, format, category string
	types                []string
	known                bool
}

func (o offeredAttestation) rules() issuerRules {
	if o.category == credtemplate.CategoryPID {
		return pidProviderRules
	}
	return attestationProviderRules
}

func offeredAttestations(metadata map[string]any, configurations []string, category func(string, []string) string) []offeredAttestation {
	supported, _ := metadata["credential_configurations_supported"].(map[string]any)
	offered := make([]offeredAttestation, 0, len(configurations))
	for _, id := range configurations {
		config, ok := supported[id].(map[string]any)
		o := offeredAttestation{id: id, known: ok}
		if ok {
			o.format = stringClaim(config["format"])
			for _, key := range []string{"vct", "doctype"} {
				if t := stringClaim(config[key]); t != "" {
					o.types = append(o.types, t)
				}
			}
			if category == nil {
				category = typeCategory
			}
			o.category = category(o.format, o.types)
		}
		offered = append(offered, o)
	}
	return offered
}

// ruleNames joins the requirement of each kind of provider in the offer, so a
// finding about a PID and another attestation cites both.
func ruleNames(offered []offeredAttestation, pick func(issuerRules) string) string {
	var names []string
	for _, o := range offered {
		if name := pick(o.rules()); !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return pick(attestationProviderRules)
	}
	return strings.Join(names, " and ")
}

// issuerARFFindings checks how an issuer authenticates before the wallet
// requests a credential (ARF v3.0.0 §6.6.2.2 and §6.6.2.3).
//
// The access certificate signs the Credential Issuer Metadata (ISSU_22,
// ISSU_32, ETSI TS 119 472-3 V1.1.1 §4.2.2). The registration certificate is
// in its issuer_info (RPRC_22, §4.2.3).
func issuerARFFindings(a issuerAuthentication) []string {
	offered := offeredAttestations(a.metadata, a.configurations, a.category)
	accessRule := ruleNames(offered, func(r issuerRules) string { return r.access })
	registrarRule := ruleNames(offered, func(r issuerRules) string { return r.registrar })
	signingRule := ruleNames(offered, func(r issuerRules) string { return r.signing })

	var findings []string
	if len(a.signerChain) == 0 {
		findings = append(findings, accessRule+": the Credential Issuer Metadata is not signed, so the wallet cannot check the issuer's access certificate. The issuer must sign it as OpenID4VCI 1.0 §12.2.3 describes ("+signingRule+")")
	} else if _, err := certchain.Verify(a.signerChain, a.accessCAs); err != nil {
		findings = append(findings, fmt.Sprintf("%s: the access certificate %q of the signed issuer metadata does not chain to a trusted access certificate authority: %v", accessRule, a.signerChain[0].Subject.String(), err))
	}

	entries := infoEntries(a.metadata, "issuer_info")
	findings = append(findings, issuerInfoShapeFindings(entries)...)
	registrations, problems := verifyRegistrationEntries(entries)
	for _, problem := range problems {
		findings = append(findings, "ARF RPRC_22a: the issuer's registration certificate "+problem)
	}
	if len(registrations) == 0 {
		if len(problems) == 0 {
			findings = append(findings, "ARF RPRC_22a: the issuer metadata carries no registration certificate (an issuer_info entry with typ rc-wrp+jwt, ETSI TS 119 472-3 V1.1.1 §4.2.3)")
		}
		return findings
	}

	var entitlements []string
	var provided []registeredCredential
	for _, r := range registrations {
		cert := r.claims
		name := firstNonEmpty(stringClaim(cert["name"]), stringClaim(cert["sub"]), "the issuer")
		findings = append(findings, providerCertificateContentFindings(cert)...)
		if len(a.signerChain) > 0 {
			findings = append(findings, registrationBindingFindings(cert, a.signerChain[0], "ARF RPRC_22b")...)
		}
		if _, err := certchain.Verify(r.chain, a.registrarCAs); err != nil {
			findings = append(findings, fmt.Sprintf("%s: the registration certificate of %s does not chain to a trusted registrar: %v", registrarRule, name, err))
		}
		findings = append(findings, registrationStatusFindings(cert, a.statusClient, a.statusCAs, "ARF RPRC_22a")...)
		for _, e := range toAnyList(cert["entitlements"]) {
			if s, ok := e.(string); ok {
				entitlements = append(entitlements, s)
			}
		}
		provided = append(provided, providedAttestationsOf(cert)...)
	}
	var reported []string
	for _, o := range offered {
		rules := o.rules()
		if !rules.entitled(entitlements) && !slices.Contains(reported, rules.entitlement) {
			reported = append(reported, rules.entitlement)
			findings = append(findings, fmt.Sprintf("%s: the issuer's registration certificate does not register it as a %s", rules.entitlement, rules.kind))
		}
		switch {
		case !o.known:
			findings = append(findings, fmt.Sprintf("%s: the issuer metadata has no configuration %s, so the wallet can't tell the offered type", rules.attestationType, o.id))
		case len(o.types) == 0:
			findings = append(findings, fmt.Sprintf("%s: the offered configuration %s names no vct or doctype, so the wallet can't check it against provides_attestations", rules.attestationType, o.id))
		case !providesType(provided, o.format, o.types):
			findings = append(findings, fmt.Sprintf("%s: the issuer's registration certificate does not list %s in provides_attestations", rules.attestationType, credentialTypeName(o.format, o.types)))
		}
	}
	return findings
}

// providesType reports whether a listed attestation has the format and one of
// the types. A listed entry without a type matches nothing, because
// provides_attestations lists the types that a provider may issue (ARF
// RPRC_15).
func providesType(provided []registeredCredential, format string, types []string) bool {
	return slices.ContainsFunc(provided, func(p registeredCredential) bool {
		return p.format == format && len(p.types) > 0 && slices.ContainsFunc(types, func(t string) bool { return slices.Contains(p.types, t) })
	})
}

// providedAttestationsOf reads provides_attestations (ETSI TS 119 475 V1.2.1
// Table 8). A type matches when format and type are the same.
func providedAttestationsOf(cert map[string]any) []registeredCredential {
	var out []registeredCredential
	for _, entry := range listOfMaps(cert["provides_attestations"]) {
		format, _ := entry["format"].(string)
		out = append(out, registeredCredential{format: format, types: registrar.CredentialTypes(entry["meta"])})
	}
	return out
}

// providerCertificateContentFindings checks a provider's registration
// certificate against ETSI TS 119 475 V1.2.1 §5.2.4 and ARF Topic 44. A
// provider certificate has no intended use (RPRC_05), so it has no privacy
// policy either.
func providerCertificateContentFindings(cert map[string]any) []string {
	var findings []string
	miss := func(field, rule string) {
		findings = append(findings, fmt.Sprintf("%s: the issuer's registration certificate has no %s", rule, field))
	}
	if stringClaim(cert["name"]) == "" {
		miss("name (trade name)", "ARF RPRC_06")
	}
	if stringClaim(cert["sub"]) == "" {
		miss("sub (provider identifier)", "ARF RPRC_07")
	}
	if len(purposeStrings(cert["srv_description"])) == 0 {
		miss("srv_description", "ETSI TS 119 475 V1.2.1 GEN-5.2.4-01")
	}
	if !nonEmptyList(cert["entitlements"]) {
		miss("entitlements (at least one)", "ETSI TS 119 475 V1.2.1 GEN-5.2.4-03")
	}
	registeredPartyFindings(cert, miss, "ETSI TS 119 475 V1.2.1 GEN-5.2.4-01", "ETSI TS 119 475 V1.2.1 GEN-5.2.4-01")
	if !nonEmptyList(cert["provides_attestations"]) {
		miss("provides_attestations (its attestation types)", "ARF RPRC_15")
	}
	if statuslist.ExtractStatusRef(cert) == nil {
		miss("status (its entry in the registrar's status list), so the wallet cannot check revocation", "ETSI TS 119 475 V1.2.1 Table 7")
	}
	return append(findings, registrationValidityFindings(cert, "ARF RPRC_22a")...)
}

// issuerARFCheck runs the issuer checks when --arf is on.
func (w *Wallet) issuerARFCheck(metadata map[string]any, signerChain []*x509.Certificate, configurations []string) []string {
	if !w.ARFChecks() {
		return nil
	}
	return issuerARFFindings(issuerAuthentication{
		metadata:       metadata,
		signerChain:    signerChain,
		configurations: configurations,
		accessCAs:      w.RelyingPartyCAs(),
		registrarCAs:   w.RegistrarCAs(),
		statusCAs:      w.RegistrationStatusCAs(),
		statusClient:   w.RegistrationStatusClient(),
		category:       w.offeredCategory,
	})
}

// offeredCategory is the category of the catalogue entry for an offered type.
// A type without an entry is a PID when its name says so (ARF PID_04 and
// PID_14, see typeCategory).
func (w *Wallet) offeredCategory(format string, types []string) string {
	if entry, ok := w.catalogueEntryFor(format, types); ok {
		return entry.Category
	}
	return typeCategory(format, types)
}

func typeCategory(_ string, types []string) string {
	if slices.ContainsFunc(types, credtype.IsPIDType) {
		return credtemplate.CategoryPID
	}
	return ""
}

// reportARFIssuanceFindings warns in debug mode and refuses in strict mode
// (ADR 0021). The ARF has the wallet warn the user and not request the
// credential (RPRC_22a, RPRC_22b, RPRC_23, ISSU_24a, ISSU_24b, ISSU_34a,
// ISSU_34b).
func (w *Wallet) reportARFIssuanceFindings(issuer string, findings []string) error {
	return w.reportARFFindings(issuer, findings, "the issuer does not authenticate as the ARF requires")
}

// reportARFFindings warns in debug mode. In strict mode it returns refusal
// with the findings.
func (w *Wallet) reportARFFindings(issuer string, findings []string, refusal string) error {
	return w.reportDeviation(deviation{
		action: "issuance", event: "arf_finding",
		detail:  findingsSummary("The issuer does not meet the ARF rules", findings),
		details: map[string]any{"issuer": issuer, "findings": findings},
		refusal: fmt.Errorf("%s: %s", refusal, strings.Join(findings, ", ")),
	})
}

// issuerInfoShapeFindings checks the elements of issuer_info (ETSI TS 119
// 472-3 V1.1.1 §4.2.3): the registration certificate has the format
// registration_cert, and a registrar_dataset element holds the identifier,
// srvDescription, registryURI and providesAttestations of the provider.
func issuerInfoShapeFindings(entries []map[string]any) []string {
	const rule = "ETSI TS 119 472-3 V1.1.1 ISS-MDATA-REG_CERT-4.2.3-"
	var findings []string
	var dataset map[string]any
	for _, entry := range entries {
		entryFormat, _ := entry["format"].(string)
		if entryFormat == "registrar_dataset" {
			dataset, _ = entry["data"].(map[string]any)
			continue
		}
		data, _ := entry["data"].(string)
		if header, _, err := decodeCompactJWT(data); err == nil && entryFormat != "registration_cert" {
			if typ, _ := header["typ"].(string); format.JOSETypeIs(typ, registrar.RegistrationCertificateTyp) {
				findings = append(findings, fmt.Sprintf("%s05: the issuer_info element with the registration certificate has the format %q, not registration_cert", rule, entryFormat))
			}
		}
	}
	if len(entries) == 0 {
		return findings
	}
	if len(dataset) == 0 {
		return append(findings, rule+"07: issuer_info has no registrar_dataset element with the provider's registration information")
	}
	for i, member := range []string{"identifier", "srvDescription", "registryURI", "providesAttestations"} {
		if value, ok := dataset[member]; !ok || value == nil || value == "" || isEmptyList(value) {
			findings = append(findings, fmt.Sprintf("%s%d: the registrar_dataset has no %s", rule, 10+i, member))
		}
	}
	return findings
}

func isEmptyList(value any) bool {
	list, ok := value.([]any)
	return ok && len(list) == 0
}
