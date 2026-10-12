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
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/regcert"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
)

func diplomaCatalogEntry() registrar.CatalogAttestation {
	isLOTE := true
	return registrar.CatalogAttestation{
		Name: "University diploma",
		Credentials: []registrar.CatalogCredential{
			{Format: "dc+sd-jwt", Type: testDiplomaVCT, Claims: [][]any{{"degree"}, {"graduation_date"}}},
			{Format: "mso_mdoc", Type: "org.example.diploma.1", Claims: [][]any{{"org.example.diploma.1", "degree"}}},
		},
		Schema: registrar.AttestationSchema{
			RulebookURI:        "https://example.com/diploma-rulebook",
			AttestationLoS:     "iso_18045_moderate",
			TrustedAuthorities: []registrar.TrustAuthority{{FrameworkType: "etsi_tl", Value: "https://example.com/lote", IsLOTE: &isLOTE}},
		},
	}
}
func issueTestRegistrationCertificate(t *testing.T, w *Wallet, rp registrar.WalletRelyingParty) *registrar.RegistrationCertificateResult {
	t.Helper()
	result, err := w.Registrar().IssueRegistrationCertificate(registrar.RegistrationCertificateRequest{
		Identifier:            rp.Identifier[0].Identifier,
		IntendedUseIdentifier: rp.Services[0].IntendedUses[0].IntendedUseIdentifier,
	})
	if err != nil {
		t.Fatalf("IssueRegistrationCertificate: %v", err)
	}
	return result
}
func mustJSON(t *testing.T, v any) string {
	t.Helper()
	encoded, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}

// ownProviderIdentifier is the registered identifier of the wallet's own
// provider, found through the organizationIdentifier of its access certificate.
func ownProviderIdentifier(t *testing.T, w *Wallet) string {
	t.Helper()
	_, access, err := w.AccessSigningMaterial()
	if err != nil {
		t.Fatal(err)
	}
	identifier, _, _ := registrar.AccessCertificateSubject(access[0])
	if rp, ok := w.Registrar().RelyingParty(identifier); ok {
		return rp.Identifier[0].Identifier
	}
	return identifier
}

// semanticIdentifier is the identifier in a registration's certificates (ETSI
// TS 119 475 V1.2.1 GEN-5.1.3).
func semanticIdentifier(t *testing.T, rp registrar.WalletRelyingParty) string {
	t.Helper()
	semantic, err := registrar.SemanticIdentifier(rp.Identifier[0], rp.Country)
	if err != nil {
		t.Fatal(err)
	}
	return semantic
}
func pidQueryForRegistration() map[string]any {
	return map[string]any{"credentials": []any{map[string]any{
		"id":     "pid",
		"format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
		"claims": []any{map[string]any{"path": []any{"given_name"}}},
	}}}
}

// registerTestRelyingParty registers a relying party whose intended use asks
// for the PID's given_name.
func registerTestRelyingParty(t *testing.T, w *Wallet) registrar.WalletRelyingParty {
	t.Helper()
	rp, err := w.Registrar().RegisterRelyingParty(registrar.WalletRelyingParty{
		TradeName: "Example Shop",
		Services: []registrar.WalletRelyingPartyService{{IntendedUses: []registrar.IntendedUse{{
			Purpose: []registrar.MultiLangString{{Lang: "en", Content: "Age check"}},
			Credentials: []registrar.RegisteredCredential{{
				Format: "dc+sd-jwt",
				Meta:   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
				Claims: []registrar.RegisteredClaim{{Path: []any{"given_name"}}},
			}},
		}}}},
	})
	if err != nil {
		t.Fatalf("RegisterRelyingParty: %v", err)
	}
	return rp
}
func testAccessCSR(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

// verifiedRegistrationCertificates returns the claims of the verified
// registration certificates in verifier_info, and the problems of the others.
func verifiedRegistrationCertificates(payload map[string]any) ([]map[string]any, []string) {
	registrations, problems := regcert.Verify(regcert.InfoEntries(payload, "verifier_info"))
	certs := make([]map[string]any, 0, len(registrations))
	for _, r := range registrations {
		certs = append(certs, r.Claims)
	}
	return certs, problems
}
