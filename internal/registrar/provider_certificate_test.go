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

package registrar

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

// A relying party gets one certificate per provider service (ARF RPRC_13)
// and one per intended use (ARF RPRC_09).
func TestCertificateRequestsNameEveryCertificate(t *testing.T) {
	w := generateTestWallet(t)
	rp, err := w.RegisterRelyingParty(WalletRelyingParty{TradeName: "Example University", Services: []WalletRelyingPartyService{
		{ServiceIdentifier: "diplomas", ProvidesAttestations: []ProvidedAttestation{{Format: "dc+sd-jwt", Type: testDiplomaVCT}}, IntendedUses: []IntendedUse{ageCheckUse("Identity check")}},
		{ServiceIdentifier: "checkout", IntendedUses: []IntendedUse{ageCheckUse("Age check")}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	id := rp.Identifier[0].Identifier
	want := []RegistrationCertificateRequest{
		{Identifier: id, ServiceIdentifier: "diplomas"},
		{Identifier: id, IntendedUseIdentifier: rp.Services[0].IntendedUses[0].IntendedUseIdentifier},
		{Identifier: id, IntendedUseIdentifier: rp.Services[1].IntendedUses[0].IntendedUseIdentifier},
	}
	reqs := CertificateRequests(rp)
	if !reflect.DeepEqual(reqs, want) {
		t.Fatalf("requests %+v, want %+v", reqs, want)
	}
	for _, req := range reqs {
		result, err := w.IssueRegistrationCertificate(req)
		if err != nil {
			t.Fatalf("%+v: %v", req, err)
		}
		// ARF RPRC_22: a provider shows its certificate in issuer_info, a
		// verifier in verifier_info.
		if provider := req.IntendedUseIdentifier == ""; (result.IssuerInfo != "") != provider || (result.VerifierInfo != "") == provider {
			t.Errorf("%+v: issuer_info %q, verifier_info %q", req, result.IssuerInfo, result.VerifierInfo)
		}
	}
}

func TestProviderCertificateRequestsAreChecked(t *testing.T) {
	w := generateTestWallet(t)
	provider := func(id string) WalletRelyingPartyService {
		return WalletRelyingPartyService{ServiceIdentifier: id, ProvidesAttestations: []ProvidedAttestation{{Format: "dc+sd-jwt", Type: "urn:example:" + id}}}
	}
	twoProviders, err := w.RegisterRelyingParty(WalletRelyingParty{TradeName: "Example University", Services: []WalletRelyingPartyService{
		provider("diplomas"), provider("transcripts"), {ServiceIdentifier: "checkout", IntendedUses: []IntendedUse{ageCheckUse("Age check")}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	verifier := registerTestRelyingParty(t, w)
	university := twoProviders.Identifier[0].Identifier
	for _, tc := range []struct {
		name string
		req  RegistrationCertificateRequest
		want string
	}{
		{"several providers", RegistrationCertificateRequest{Identifier: university}, "has 2 attestation provider services"},
		{"unknown service", RegistrationCertificateRequest{Identifier: university, ServiceIdentifier: "newsletter"}, `no service "newsletter"`},
		{"verifier service", RegistrationCertificateRequest{Identifier: university, ServiceIdentifier: "checkout"}, "Issue its certificates per intended use"},
		{"no provider", RegistrationCertificateRequest{Identifier: verifier.Identifier[0].Identifier}, "as an attestation provider"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := w.IssueRegistrationCertificate(tc.req); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %v, want %q", err, tc.want)
			}
		})
	}
	if _, err := w.IssueRegistrationCertificate(RegistrationCertificateRequest{Identifier: university, ServiceIdentifier: "transcripts"}); err != nil {
		t.Errorf("a named provider service: %v", err)
	}
}

// ETSI TS 119 475 V1.2.1 Table 8 shapes provides_attestations like a DCQL
// credential query.
func TestProvidedAttestationsTakeTheDCQLShape(t *testing.T) {
	content := RegistrationCertificateContent{Name: "University", Subject: "NTRNL-NLTEST.1", ProvidesAttestations: []ProvidedAttestation{
		{Format: "dc+sd-jwt", Type: testDiplomaVCT},
		{Format: "mso_mdoc", Type: "org.example.diploma.1"},
	}}
	claims, err := RegistrationCertificateClaimsFor("https://wallet.example", content, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(claims["provides_attestations"])
	if err != nil {
		t.Fatal(err)
	}
	want := `[{"format":"dc+sd-jwt","meta":{"vct_values":["` + testDiplomaVCT + `"]}},{"format":"mso_mdoc","meta":{"doctype_value":"org.example.diploma.1"}}]`
	if string(encoded) != want {
		t.Errorf("provides_attestations %s, want %s", encoded, want)
	}
}

// Deleting a relying party revokes its certificates for good.
func TestDeletingARelyingPartyRevokesItsCertificates(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	other, err := w.RegisterRelyingParty(WalletRelyingParty{TradeName: "Other Shop", Services: []WalletRelyingPartyService{{IntendedUses: []IntendedUse{ageCheckUse("Age check")}}}})
	if err != nil {
		t.Fatal(err)
	}
	issueTestRegistrationCertificate(t, w, rp)
	issueTestRegistrationCertificate(t, w, other)
	if err := w.DeleteRelyingParty("NTRNL-" + rp.Identifier[0].Identifier); err != nil {
		t.Fatal(err)
	}
	statuses := w.RegistrationCertificateStatuses("")
	if len(statuses) != 2 {
		t.Fatalf("statuses %+v, want both entries kept", statuses)
	}
	if deleted := statuses[0]; !deleted.Revoked || !deleted.Superseded || deleted.Reason != supersededDeleted || deleted.Certificate != "" {
		t.Errorf("entry of the deleted party %+v", deleted)
	}
	if kept := statuses[1]; kept.Revoked || kept.Superseded {
		t.Errorf("entry of the other party %+v, want it valid", kept)
	}
	err = w.DeleteRelyingParty(rp.Identifier[0].Identifier)
	if !IsNotRegistered(err) {
		t.Errorf("deleting again: %v, want not registered", err)
	}
	if _, err := w.IssueRegistrationCertificate(RegistrationCertificateRequest{Identifier: rp.Identifier[0].Identifier}); !IsNotRegistered(err) {
		t.Errorf("issuing for a deleted party: %v, want not registered", err)
	}
}

func TestEnsureRelyingPartyNeedsAnIdentifier(t *testing.T) {
	w := generateTestWallet(t)
	if _, changed, err := w.EnsureRelyingParty(shopRegistration()); err == nil || changed {
		t.Errorf("changed %v, %v, want an error", changed, err)
	}
	rp := shopRegistration()
	rp.Identifier = []Identifier{{Identifier: "NLTEST.SHOP", Type: EUIDIdentifierType}}
	if stored, changed, err := w.EnsureRelyingParty(rp); err != nil || !changed || stored.Identifier[0].Identifier != "NLTEST.SHOP" {
		t.Errorf("first call: %+v, changed %v, %v", stored.Identifier, changed, err)
	}
	rp.Country = "Netherlands"
	if _, changed, err := w.EnsureRelyingParty(rp); err == nil || changed {
		t.Errorf("an invalid update: changed %v, %v", changed, err)
	}
}

// TS05 v1.5 §2.4.1 makes srvDescription an array of arrays. A flat array
// reads as one description.
func TestServiceDescriptionReadsBothShapes(t *testing.T) {
	for _, tc := range []struct {
		json string
		want ServiceDescription
		fail bool
	}{
		{`[[{"lang":"en","content":"Shop"},{"lang":"de","content":"Laden"}],[{"lang":"en","content":"Tickets"}]]`, ServiceDescription{{{"en", "Shop"}, {"de", "Laden"}}, {{"en", "Tickets"}}}, false},
		{`[{"lang":"en","content":"Shop"}]`, ServiceDescription{{{"en", "Shop"}}}, false},
		{`[]`, ServiceDescription{}, false},
		{`"Shop"`, nil, true},
	} {
		var got ServiceDescription
		err := json.Unmarshal([]byte(tc.json), &got)
		if (err != nil) != tc.fail || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s: %+v, %v, want %+v", tc.json, got, err, tc.want)
		}
	}
}

// OpenID4VP 1.0 §B.1.1: a W3C credential lists alternative type sets in
// type_values.
func TestCredentialTypesReadEveryMetaShape(t *testing.T) {
	for _, tc := range []struct {
		name string
		meta any
		want []string
	}{
		{"SD-JWT VC", map[string]any{"vct_values": []any{mock.DefaultPIDVCT, 7}}, []string{mock.DefaultPIDVCT}},
		{"typed vct list", map[string]any{"vct_values": []string{"urn:a", "urn:b"}}, []string{"urn:a", "urn:b"}},
		{"mdoc", map[string]any{"doctype_value": mock.PIDNamespace}, []string{mock.PIDNamespace}},
		{"W3C", map[string]any{"type_values": []any{[]any{"VerifiableCredential", "Diploma"}, []any{}, "Badge"}}, []string{"Diploma VerifiableCredential"}},
		{"not an object", []any{"urn:a"}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := CredentialTypes(tc.meta); !slices.Equal(got, tc.want) {
				t.Errorf("types %q, want %q", got, tc.want)
			}
		})
	}
}

// A clone of the state changes independently of the state.
func TestAStateCloneIsIndependent(t *testing.T) {
	w := generateTestWallet(t)
	registerTestRelyingParty(t, w)
	clone := w.State.Clone()
	clone.RelyingParties[0].TradeName = "Changed"
	clone.Catalog = append(clone.Catalog, CatalogAttestation{Name: "Added"})
	if w.RelyingParties[0].TradeName != "Example Shop" || len(w.Catalog) != 0 {
		t.Errorf("the clone changed the state: %q, %d catalogue entries", w.RelyingParties[0].TradeName, len(w.Catalog))
	}
}

func TestHoursWritesWholeHours(t *testing.T) {
	if got := Hours(180 * 24 * time.Hour); got != "4320h" {
		t.Errorf("Hours = %s, want 4320h", got)
	}
	if got := Hours(90 * time.Minute); got != "1h" {
		t.Errorf("Hours = %s, want 1h", got)
	}
}
