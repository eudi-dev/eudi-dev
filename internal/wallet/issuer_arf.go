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
	"net/http"
	"slices"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/certchain"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/findings"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
	"github.com/eudi-dev/eudi-dev/v3/internal/regcert"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
	"github.com/eudi-dev/eudi-dev/v3/internal/trustedlists"
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

// issuerRules are the ARF requirements for one kind of provider, such as
// ISSU_22. A PID Provider has its own numbers for the same checks.
type issuerRules struct {
	signing, access, registrar, entitlement string
	attestationType                         findings.Rule
	entitled                                func([]string) bool
	kind                                    string
}

var (
	pidProviderRules = issuerRules{
		signing: "ISSU_22", access: "ISSU_24", registrar: "ISSU_23c", entitlement: "ISSU_24a",
		attestationType: findings.ARF.Registration("RPRC_23").Cited("ARF RPRC_23 and ISSU_24b"),
		entitled:        func(e []string) bool { return slices.Contains(e, registrar.PIDProviderEntitlement) },
		kind:            "PID Provider",
	}
	attestationProviderRules = issuerRules{
		signing: "ISSU_32", access: "ISSU_34", registrar: "ISSU_33a", entitlement: "ISSU_34a",
		attestationType: findings.ARF.Registration("RPRC_23").Cited("ARF RPRC_23 and ISSU_34b"),
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
			o.format = jsonutil.Text(config["format"])
			for _, key := range []string{"vct", "doctype"} {
				if t := jsonutil.Text(config[key]); t != "" {
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

// offerRule cites the requirement of each kind of provider in the offer. A
// finding about a PID and another attestation cites both, with the first as
// its identifier.
func offerRule(offered []offeredAttestation, pick func(issuerRules) string) findings.Rule {
	var names []string
	for _, o := range offered {
		if name := pick(o.rules()); !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return findings.ARF.Registration(pick(attestationProviderRules))
	}
	rule := findings.ARF.Registration(names[0])
	if len(names) > 1 {
		rule = rule.Cited("ARF " + strings.Join(names, " and ARF "))
	}
	return rule
}

// issuerARFFindings checks how an issuer authenticates before the wallet
// requests a credential (ARF §6.6.2.2 and §6.6.2.3).
//
// The access certificate signs the Credential Issuer Metadata (ISSU_22,
// ISSU_32, ETSI TS 119 472-3 V1.1.1 §4.2.2). The registration certificate is
// in its issuer_info (RPRC_22, §4.2.3).
func issuerARFFindings(a issuerAuthentication) findings.List {
	offered := offeredAttestations(a.metadata, a.configurations, a.category)
	accessRule := offerRule(offered, func(r issuerRules) string { return r.access })
	registrarRule := offerRule(offered, func(r issuerRules) string { return r.registrar })
	signingRule := offerRule(offered, func(r issuerRules) string { return r.signing })

	var list findings.List
	if len(a.signerChain) == 0 {
		rule := accessRule.Cited(accessRule.Citation() + ", " + signingRule.Citation() + ", OID4VCI 1.0 §12.2.3")
		list = append(list, rule.New("the Credential Issuer Metadata is not signed, so the wallet cannot check the issuer's access certificate"))
	} else if path, err := certchain.VerifiedPath(a.signerChain, a.accessCAs); err != nil {
		list = append(list, accessRule.Newf("the access certificate %q of the signed issuer metadata does not chain to a trusted access certificate authority: %v", a.signerChain[0].Subject.String(), err))
	} else {
		// ISSU_24 and ISSU_34: the access certificate "is valid at the time of
		// validation". CIR (EU) 2024/2982 Article 3(1) and 4(2) require the wallet
		// to authenticate the issuer before it requests a credential.
		list = append(list, certchain.RevocationFindings(path, a.statusClient, accessRule.Cited(accessRule.Citation()+" and CIR (EU) 2024/2982 Article 3(1) and 4(2)"))...)
	}

	entries := regcert.InfoEntries(a.metadata, "issuer_info")
	list = append(list, issuerInfoShapeFindings(entries)...)
	registrations, problems := regcert.Verify(entries)
	for _, problem := range problems {
		list = append(list, findings.ARF.Registration("RPRC_22a").New("the issuer's registration certificate "+problem))
	}
	if len(registrations) == 0 {
		return list
	}

	var entitlements []string
	var provided []regcert.Credential
	for _, r := range registrations {
		cert := r.Claims
		name := jsonutil.FirstNonEmpty(jsonutil.Text(cert["name"]), jsonutil.Text(cert["sub"]), "the issuer")
		list = append(list, regcert.ProviderContentFindings(cert)...)
		if len(a.signerChain) > 0 {
			list = append(list, regcert.IdentifierFindings(cert, a.signerChain[0], findings.ARF.Registration("RPRC_22b"))...)
		}
		if _, err := certchain.Verify(r.Chain, a.registrarCAs); err != nil {
			list = append(list, registrarRule.Newf("the registration certificate of %s does not chain to a trusted registrar: %v", name, err))
		}
		list = append(list, regcert.StatusFindings(cert, a.statusClient, a.statusCAs, findings.ARF.Registration("RPRC_22a"))...)
		for _, e := range jsonutil.List(cert["entitlements"]) {
			if s, ok := e.(string); ok {
				entitlements = append(entitlements, s)
			}
		}
		provided = append(provided, regcert.ProvidedAttestations(cert)...)
	}
	var reported []string
	for _, o := range offered {
		rules := o.rules()
		if !rules.entitled(entitlements) && !slices.Contains(reported, rules.entitlement) {
			reported = append(reported, rules.entitlement)
			list = append(list, findings.ARF.Registration(rules.entitlement).Newf("the issuer's registration certificate does not register it as a %s", rules.kind))
		}
		switch {
		case !o.known:
			list = append(list, rules.attestationType.Newf("the issuer metadata has no configuration %s, so the wallet can't tell the offered type", o.id))
		case len(o.types) == 0:
			list = append(list, rules.attestationType.Newf("the offered configuration %s names no vct or doctype, so the wallet can't check it against provides_attestations", o.id))
		case !regcert.Provides(provided, o.format, o.types):
			list = append(list, rules.attestationType.Newf("the issuer's registration certificate does not list %s in provides_attestations", regcert.TypeName(o.format, o.types)))
		}
	}
	return list
}

// issuerARFCheck runs the issuer checks when --arf is on.
func (w *Wallet) issuerARFCheck(metadata map[string]any, signerChain []*x509.Certificate, configurations []string) findings.List {
	if !w.ARFChecks() {
		return nil
	}
	// One read of the trusted lists gives every anchor set, so the checks
	// see one state of the lists.
	lists := w.TrustedLists().Lists()
	return issuerARFFindings(issuerAuthentication{
		metadata:       metadata,
		signerChain:    signerChain,
		configurations: configurations,
		accessCAs:      trustedlists.AnchorsOf(lists, lote.AccessCertProvidersListType, lote.IssuanceServices),
		registrarCAs:   trustedlists.AnchorsOf(lists, lote.RegistrationCertProvidersListType, lote.IssuanceServices),
		statusCAs:      trustedlists.AnchorsOf(lists, lote.RegistrationCertProvidersListType, lote.RevocationServices),
		statusClient:   w.RegistrationStatusClient(),
		category:       w.CatalogueCategory,
	})
}

// issuerARFAdvisories warns about issuer metadata without a registration
// certificate, and about a revoked registrar certificate, when --arf is on.
// Wallets must check registration certificates only from
// oid4vp.RegistrationDeadline, so these are warnings in every mode.
func (w *Wallet) issuerARFAdvisories(metadata map[string]any) findings.List {
	if !w.ARFChecks() {
		return nil
	}
	registrations, problems := regcert.Verify(regcert.InfoEntries(metadata, "issuer_info"))
	if len(registrations)+len(problems) == 0 {
		rule := findings.ARF.Registration("RPRC_22a").Cited("ARF RPRC_22a and ETSI TS 119 472-3 V1.1.1 ISS-MDATA-REG_CERT-4.2.3-04 as adapted by CIR (EU) 2026/1731 Annex XI, CIR (EU) 2024/2982 Article 3(4)")
		return findings.List{rule.New("the issuer metadata carries no registration certificate (an issuer_info entry with typ rc-wrp+jwt). Wallets must check registration certificates from " + oid4vp.RegistrationDeadline)}
	}
	registrarCAs := trustedlists.AnchorsOf(w.TrustedLists().Lists(), lote.RegistrationCertProvidersListType, lote.IssuanceServices)
	return oid4vp.RegistrarRevocationAdvisories(registrations, registrarCAs, w.RegistrationStatusClient(), findings.ARF.Registration("RPRC_22a").Cited("ARF RPRC_22a and CIR (EU) 2024/2982 Article 3(4)"))
}

// CatalogueCategory is the category of the catalogue entry for a type. A type
// without an entry is a PID when its name says so (ARF PID_04 and PID_14, see
// typeCategory). Otherwise its category is unknown and empty.
func (w *Wallet) CatalogueCategory(format string, types []string) string {
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
func (w *Wallet) reportARFIssuanceFindings(issuer string, list findings.List) error {
	return w.reportARFFindings(issuer, subjectIssuer, "The issuer does not meet the ARF rules", list)
}

// reportARFFindings warns in debug mode. In strict mode it refuses with the
// findings.
func (w *Wallet) reportARFFindings(issuer string, subject findingSubject, summary string, list findings.List) error {
	return w.reportDeviation(deviation{
		action: "issuance", event: "arf_finding", subject: subject,
		summary: summary, findings: list,
		details: map[string]any{"issuer": issuer},
	})
}

// issuerInfoShapeFindings checks that the registration certificate in
// issuer_info has the format registration_cert (ETSI TS 119 472-3 V1.1.1
// ISS-MDATA-REG_CERT-4.2.3-05). CIR (EU) 2026/1731 Annex XI voids -07 to -13,
// so other elements carry no requirements.
func issuerInfoShapeFindings(entries []map[string]any) findings.List {
	var list findings.List
	for _, entry := range entries {
		entryFormat, _ := entry["format"].(string)
		data, _ := entry["data"].(string)
		if header, _, _, err := format.ParseJWTParts(data); err == nil && entryFormat != "registration_cert" {
			if typ, _ := header["typ"].(string); format.JOSETypeIs(typ, registrar.RegistrationCertificateTyp) {
				list = append(list, findings.ETSI1194723.Registration("ISS-MDATA-REG_CERT-4.2.3-05").Newf("the issuer_info element with the registration certificate has the format %q, not registration_cert", entryFormat))
			}
		}
	}
	return list
}
