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
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
)

const testDiplomaVCT = "urn:example:diploma:1"

// registerTestIssuer registers an attestation provider that issues the
// diploma as SD-JWT VC.
func registerTestIssuer(t *testing.T, w *Wallet, entitlement string, provides ...registrar.ProvidedAttestation) registrar.WalletRelyingParty {
	t.Helper()
	if len(provides) == 0 {
		provides = []registrar.ProvidedAttestation{{Format: "dc+sd-jwt", Type: testDiplomaVCT}}
	}
	rp, err := w.Registrar().RegisterRelyingParty(registrar.WalletRelyingParty{
		TradeName: "Example University",
		Services: []registrar.WalletRelyingPartyService{{
			ServiceIdentifier:    "diplomas",
			Entitlements:         []string{entitlement},
			ProvidesAttestations: provides,
		}},
	})
	if err != nil {
		t.Fatalf("RegisterRelyingParty: %v", err)
	}
	return rp
}

func issueTestIssuerInfo(t *testing.T, w *Wallet, rp registrar.WalletRelyingParty) *registrar.RegistrationCertificateResult {
	t.Helper()
	result, err := w.Registrar().IssueRegistrationCertificate(registrar.RegistrationCertificateRequest{Identifier: rp.Identifier[0].Identifier})
	if err != nil {
		t.Fatalf("IssueRegistrationCertificate: %v", err)
	}
	return result
}

func TestAnIssuerGetsOneCertificateForItsService(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestIssuer(t, w, registrar.NonQEAAProviderEntitlement)
	result := issueTestIssuerInfo(t, w, rp)
	if result.VerifierInfo != "" || result.IssuerInfo == "" {
		t.Fatalf("result %+v, want issuer_info and no verifier_info", result)
	}

	var info []registrar.IssuerInfoEntry
	if err := json.Unmarshal([]byte(result.IssuerInfo), &info); err != nil {
		t.Fatal(err)
	}
	// ETSI TS 119 472-3 V1.1.1 §4.2.3: a registrar_dataset with identifier,
	// srvDescription, registryURI and providesAttestations, and the registration
	// certificate in a registration_cert entry.
	if len(info) != 2 || info[0].Format != "registrar_dataset" || info[1].Format != "registration_cert" || info[1].Data != result.RegistrationCertificate {
		t.Fatalf("issuer_info %+v", info)
	}
	dataset, _ := info[0].Data.(map[string]any)
	for _, field := range []string{"identifier", "srvDescription", "registryURI", "providesAttestations"} {
		if dataset[field] == nil {
			t.Errorf("registrar_dataset has no %s: %v", field, dataset)
		}
	}

	registrations, problems := verifyRegistrationEntries(infoEntries(map[string]any{"issuer_info": result.IssuerInfo}, "issuer_info"))
	if len(registrations) != 1 || len(problems) != 0 {
		t.Fatalf("registrations %d, problems %v", len(registrations), problems)
	}
	cert := registrations[0].claims
	if got := providerCertificateContentFindings(cert); len(got) != 0 {
		t.Errorf("content findings %v", got)
	}
	// A provider certificate has no intended use (ARF RPRC_05), so it has no
	// purpose, privacy policy or credentials. It carries the policy of ETSI TS
	// 119 475 V1.2.1 OVR-6.1.3-01.
	for _, absent := range []string{"credentials", "purpose", "privacy_policy"} {
		if _, ok := cert[absent]; ok {
			t.Errorf("provider certificate has %s", absent)
		}
	}
	if policies, _ := cert["policy_id"].([]any); len(policies) != 1 || policies[0] != "0.4.0.19475.3.1" {
		t.Errorf("policy_id %v", cert["policy_id"])
	}
	if provided := providedAttestationsOf(cert); len(provided) != 1 || !providesType(provided, "dc+sd-jwt", []string{testDiplomaVCT}) {
		t.Errorf("provides_attestations %v", cert["provides_attestations"])
	}
}

func TestIssuerRegistrationsAreChecked(t *testing.T) {
	w := generateTestWallet(t)
	for _, tc := range []struct {
		name    string
		service registrar.WalletRelyingPartyService
		want    string
	}{
		{"a provider without attestations", registrar.WalletRelyingPartyService{Entitlements: []string{registrar.PIDProviderEntitlement}}, "RPRC_15"},
		{"an unknown entitlement only", registrar.WalletRelyingPartyService{Entitlements: []string{"https://example.com/entitled"}}, "Annex A.2"},
		{"an attestation in another format", registrar.WalletRelyingPartyService{Entitlements: []string{registrar.NonQEAAProviderEntitlement}, ProvidesAttestations: []registrar.ProvidedAttestation{{Format: "jwt_vc_json", Type: "x"}}}, "not dc+sd-jwt or mso_mdoc"},
		{"an attestation without a type", registrar.WalletRelyingPartyService{Entitlements: []string{registrar.NonQEAAProviderEntitlement}, ProvidesAttestations: []registrar.ProvidedAttestation{{Format: "mso_mdoc"}}}, "needs its type"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := w.Registrar().RegisterRelyingParty(registrar.WalletRelyingParty{TradeName: "Example", Services: []registrar.WalletRelyingPartyService{tc.service}})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

// A provider without an entitlement gets the entitlement of each attestation
// type's category: from the catalogue, else PID for a PID type and EAA for
// another type.
func TestAnIssuerGetsTheEntitlementsOfItsCategories(t *testing.T) {
	w := generateTestWallet(t)
	entry := diplomaCatalogEntry()
	entry.Category = "qeaa"
	if _, err := w.Registrar().AddCatalogAttestation(entry); err != nil {
		t.Fatal(err)
	}
	rp, err := w.Registrar().RegisterRelyingParty(registrar.WalletRelyingParty{
		TradeName: "Example Provider",
		Services: []registrar.WalletRelyingPartyService{{ProvidesAttestations: []registrar.ProvidedAttestation{
			{Format: "dc+sd-jwt", Type: testDiplomaVCT},
			{Format: "dc+sd-jwt", Type: "urn:eudi:pid:fr:1"},
			{Format: "dc+sd-jwt", Type: "urn:example:badge:1"},
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{registrar.NonQEAAProviderEntitlement, registrar.PIDProviderEntitlement, registrar.QEAAProviderEntitlement}
	if got := rp.Services[0].Entitlements; !slices.Equal(got, want) {
		t.Errorf("entitlements %v, want %v", got, want)
	}
}

// A provider that also requests attributes registers as a service provider
// too (ARF RPRC_05 note).
func TestAProviderWithAnIntendedUseIsAServiceProviderToo(t *testing.T) {
	w := generateTestWallet(t)
	rp, err := w.Registrar().RegisterRelyingParty(registrar.WalletRelyingParty{
		TradeName: "Example University",
		Services: []registrar.WalletRelyingPartyService{{
			Entitlements:         []string{registrar.NonQEAAProviderEntitlement},
			ProvidesAttestations: []registrar.ProvidedAttestation{{Format: "dc+sd-jwt", Type: testDiplomaVCT}},
			IntendedUses: []registrar.IntendedUse{{Purpose: []registrar.MultiLangString{{Lang: "en", Content: "Identity check"}}, Credentials: []registrar.RegisteredCredential{{
				Format: "dc+sd-jwt", Meta: map[string]any{"vct_values": []string{mock.DefaultPIDVCT}}, Claims: []registrar.RegisteredClaim{{Path: []any{"family_name"}}},
			}}}},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := rp.Services[0].Entitlements; len(got) != 2 || got[1] != registrar.ServiceProviderEntitlement {
		t.Fatalf("entitlements %v, want the provider entitlement and the service provider entitlement", got)
	}
	// With an intended use and a provider service the request has to say which.
	use := rp.Services[0].IntendedUses[0].IntendedUseIdentifier
	if result, err := w.Registrar().IssueRegistrationCertificate(registrar.RegistrationCertificateRequest{Identifier: rp.Identifier[0].Identifier, IntendedUseIdentifier: use}); err != nil || result.VerifierInfo == "" {
		t.Fatalf("intended use certificate: %v %+v", err, result)
	}
	if result, err := w.Registrar().IssueRegistrationCertificate(registrar.RegistrationCertificateRequest{Identifier: rp.Identifier[0].Identifier}); err != nil || result.IssuerInfo == "" {
		t.Fatalf("provider certificate: %v %+v", err, result)
	}
}

func TestAVerifierHasNoProviderCertificate(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	_, err := w.Registrar().IssueRegistrationCertificate(registrar.RegistrationCertificateRequest{Identifier: rp.Identifier[0].Identifier})
	if !registrar.IsNotRegistered(err) || !strings.Contains(err.Error(), "as an attestation provider") {
		t.Fatalf("got %v", err)
	}
}

func TestProviderCertificatesFollowTheRegistration(t *testing.T) {
	srv, ts := registrarServer(t)
	w := srv.wallet
	rp := registerTestIssuer(t, w, registrar.NonQEAAProviderEntitlement)
	certOf := func(result *registrar.RegistrationCertificateResult) map[string]any {
		registrations, _ := verifyRegistrationEntries(infoEntries(map[string]any{"issuer_info": result.IssuerInfo}, "issuer_info"))
		return registrations[0].claims
	}
	first := certOf(issueTestIssuerInfo(t, w, rp))
	second := certOf(issueTestIssuerInfo(t, w, rp))
	if got := registrationStatusFindings(first, ts.Client(), nil, "ARF RPRC_17"); len(got) != 1 || !strings.Contains(got[0], "revoked") {
		t.Fatalf("the replaced certificate: %v, want revoked", got)
	}
	if got := registrationStatusFindings(second, ts.Client(), nil, "ARF RPRC_17"); len(got) != 0 {
		t.Fatalf("the new certificate: %v", got)
	}

	// Revoking the service revokes its certificate, and activating restores it.
	scope := registrar.RegistrationScope{ServiceIdentifier: "diplomas"}
	if n, err := w.Registrar().SetRegistrationCertificatesRevoked(rp.Identifier[0].Identifier, scope, true); err != nil || n != 1 {
		t.Fatalf("revoke: %d %v", n, err)
	}
	if n, err := w.Registrar().SetRegistrationCertificatesRevoked(rp.Identifier[0].Identifier, scope, false); err != nil || n != 1 {
		t.Fatalf("activate: %d %v", n, err)
	}
	if _, err := w.Registrar().SetRegistrationCertificatesRevoked(rp.Identifier[0].Identifier, registrar.RegistrationScope{ServiceIdentifier: "unknown"}, true); err == nil {
		t.Fatal("an unknown service was accepted")
	}
	if _, err := w.Registrar().SetRegistrationCertificatesRevoked(rp.Identifier[0].Identifier, registrar.RegistrationScope{ServiceIdentifier: "diplomas", IntendedUseIdentifier: "elsewhere"}, true); err == nil {
		t.Fatal("an intended use outside the service was accepted")
	}

	// An update that adds an attestation type changes the certificate content,
	// so the certificate is revoked for good.
	rp.Services[0].ProvidesAttestations = append(rp.Services[0].ProvidesAttestations, registrar.ProvidedAttestation{Format: "mso_mdoc", Type: "org.example.diploma.1"})
	if _, err := w.Registrar().UpdateRelyingParty(rp); err != nil {
		t.Fatal(err)
	}
	if got := registrationStatusFindings(second, ts.Client(), nil, "ARF RPRC_17"); len(got) != 1 {
		t.Fatalf("after the update: %v, want revoked", got)
	}
	if n, err := w.Registrar().SetRegistrationCertificatesRevoked(rp.Identifier[0].Identifier, scope, false); err != nil || n != 0 {
		t.Fatalf("activating a superseded certificate: %d %v", n, err)
	}
}

// The demo issuer registers a template without a category as an EAA before
// it issued one, so its first offer passes the RPRC_23 check.
func TestTheDemoIssuerRegistersAnUncategorizedTemplateAsAnEAA(t *testing.T) {
	w := generateTestWallet(t)
	if _, err := credtemplate.Save(w.Templates, credtemplate.Template{Name: "badge", Format: "sdjwt", VCT: "urn:example:badge:1", Claims: map[string]any{"level": 1}}); err != nil {
		t.Fatal(err)
	}
	rp, err := w.demoIssuerRegistration()
	if err != nil {
		t.Fatal(err)
	}
	service := rp.Services[0]
	if !slices.ContainsFunc(service.ProvidesAttestations, func(p registrar.ProvidedAttestation) bool { return p.Type == "urn:example:badge:1" }) || !slices.Contains(service.Entitlements, registrar.NonQEAAProviderEntitlement) {
		t.Errorf("provides %v with entitlements %v, want the badge as an EAA", service.ProvidesAttestations, service.Entitlements)
	}
}
