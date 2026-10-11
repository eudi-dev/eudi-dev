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
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vp"
	"github.com/dominikschlosser/eudi-dev/v3/internal/regcert"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
)

// A registration certificate created by the wallet passes the wallet's own
// ETSI TS 119 475 content checks and the ARF RPRC_21 over-asking check for the
// registered query.
func TestACreatedRegistrationCertificatePassesTheWalletsChecks(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://wallet.example"
	rp := registerTestRelyingParty(t, w)
	result := issueTestRegistrationCertificate(t, w, rp)

	var verifierInfo []map[string]any
	if err := json.Unmarshal([]byte(result.VerifierInfo), &verifierInfo); err != nil {
		t.Fatalf("verifier_info %q is not a JSON array: %v", result.VerifierInfo, err)
	}
	if verifierInfo[0]["format"] != "registration_cert" || verifierInfo[0]["data"] != base64.RawURLEncoding.EncodeToString([]byte(result.RegistrationCertificate)) {
		t.Fatalf("verifier_info %v, want the certificate as registration_cert", verifierInfo)
	}
	certs, findings := verifiedRegistrationCertificates(map[string]any{"verifier_info": result.VerifierInfo})
	if len(certs) != 1 || len(findings) != 0 {
		t.Fatalf("certificates %d, findings %v, want one verified certificate", len(certs), findings)
	}
	if got := regcert.ContentFindings(certs[0]); len(got) != 0 {
		t.Errorf("content findings %v, want none", got)
	}
	if got := regcert.OverAskingFindings(certs[0], pidQueryForRegistration()); len(got) != 0 {
		t.Errorf("over-asking findings %v, want none", got)
	}
	if got, _ := regcert.Purposes([]map[string]any{certs[0]}); len(got) != 1 || got[0] != "Age check" {
		t.Errorf("purpose %v, want Age check", got)
	}
	if certs[0]["sub"] != semanticIdentifier(t, rp) || certs[0]["registry_uri"] != rp.RegistryURI {
		t.Errorf("sub %v, registry_uri %v, want the registration's", certs[0]["sub"], certs[0]["registry_uri"])
	}
	// ETSI TS 119 475 V1.2.1 Table 7 and OVR-6.1.3-01.
	if policies, _ := certs[0]["policy_id"].([]any); len(policies) != 1 || policies[0] != "0.4.0.19475.3.1" || certs[0]["certificate_policy"] == nil {
		t.Errorf("policy_id %v, certificate_policy %v", certs[0]["policy_id"], certs[0]["certificate_policy"])
	}
}

// ARF RPRC_17a: the registration certificate and the access certificate that
// signs the request name the same relying party.
func TestTheRegistrationCertificateMatchesTheAccessCertificate(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	access, err := w.Registrar().IssueAccessCertificate(registrar.AccessCertificateRequest{Identifier: rp.Identifier[0].Identifier, CSR: testAccessCSR(t, key)})
	if err != nil {
		t.Fatalf("IssueAccessCertificate: %v", err)
	}
	block, _ := pem.Decode([]byte(access.Certificate))
	accessCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	certs, _ := verifiedRegistrationCertificates(map[string]any{"verifier_info": issueTestRegistrationCertificate(t, w, rp).VerifierInfo})
	if got := regcert.BindingFindings(certs[0], accessCert, "ARF RPRC_17a"); len(got) != 0 {
		t.Errorf("findings %v for the relying party's own access certificate, want none", got)
	}

	_, demoChain, err := w.AccessSigningMaterial()
	if err != nil {
		t.Fatal(err)
	}
	if got := regcert.BindingFindings(certs[0], demoChain[0], "ARF RPRC_17a"); len(got) == 0 || !strings.Contains(got[0], "RPRC_17a") {
		t.Errorf("findings %v for another relying party's access certificate, want the RPRC_17a warning", got)
	}
	// An intermediary's certificate names the relying party in act.sub (ETSI
	// TS 119 475 GEN-5.2.4-09).
	intermediary := map[string]any{"sub": "LEIXG-INTERMEDIARY", "act": map[string]any{"sub": semanticIdentifier(t, rp)}}
	if got := regcert.BindingFindings(intermediary, accessCert, "ARF RPRC_17a"); len(got) != 0 {
		t.Errorf("findings %v for an intermediary acting for the relying party, want none", got)
	}
}

// ARF RPRC_07a and RPRC_17a: a registration certificate names its service,
// so it binds only to the access certificate of that service.
func TestTheRegistrationCertificateBindsToTheAccessCertificateOfItsService(t *testing.T) {
	w := generateTestWallet(t)
	use := func(purpose string) []registrar.IntendedUse {
		return []registrar.IntendedUse{{
			Purpose: []registrar.MultiLangString{{Lang: "en", Content: purpose}},
			Credentials: []registrar.RegisteredCredential{{
				Format: "dc+sd-jwt",
				Meta:   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
				Claims: []registrar.RegisteredClaim{{Path: []any{"given_name"}}},
			}},
		}}
	}
	rp, err := w.Registrar().RegisterRelyingParty(registrar.WalletRelyingParty{
		TradeName: "Example Shop",
		Services: []registrar.WalletRelyingPartyService{
			{ServiceIdentifier: "shop", ServiceTradeName: "Example Shop", IntendedUses: use("Age check")},
			{ServiceIdentifier: "loyalty", ServiceTradeName: "Example Loyalty", IntendedUses: use("Membership")},
		},
	})
	if err != nil {
		t.Fatalf("RegisterRelyingParty: %v", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	accessCert := func(service string) *x509.Certificate {
		access, err := w.Registrar().IssueAccessCertificate(registrar.AccessCertificateRequest{Identifier: rp.Identifier[0].Identifier, ServiceIdentifier: service, CSR: testAccessCSR(t, key)})
		if err != nil {
			t.Fatalf("IssueAccessCertificate: %v", err)
		}
		block, _ := pem.Decode([]byte(access.Certificate))
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	result, err := w.Registrar().IssueRegistrationCertificate(registrar.RegistrationCertificateRequest{
		Identifier:            rp.Identifier[0].Identifier,
		ServiceIdentifier:     "shop",
		IntendedUseIdentifier: rp.Services[0].IntendedUses[0].IntendedUseIdentifier,
	})
	if err != nil {
		t.Fatalf("IssueRegistrationCertificate: %v", err)
	}
	certs, _ := verifiedRegistrationCertificates(map[string]any{"verifier_info": result.VerifierInfo})
	if got := regcert.BindingFindings(certs[0], accessCert("shop"), "ARF RPRC_17a"); len(got) != 0 {
		t.Errorf("findings %v for the access certificate of the same service, want none", got)
	}
	if got := regcert.BindingFindings(certs[0], accessCert("loyalty"), "ARF RPRC_17a"); len(got) != 1 {
		t.Errorf("findings %v for the access certificate of another service, want the RPRC_17a warning", got)
	}
}

// ARF RPA_10: the consent dialog links the registered privacy policy.
func TestTheConsentDialogLinksThePrivacyPolicy(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://wallet.example"
	key, chain, verifierInfo := registeredVerifier(t, w)
	purposes, policies := oid4vp.ConsentRegistration(signedARFRequest(t, w, key, chain, verifierInfo))
	if len(purposes) != 1 || len(policies) != 1 || policies[0] != "https://wallet.example/privacy-policy" {
		t.Errorf("purposes %v, privacy policies %v, want the registered purpose and policy", purposes, policies)
	}
}

// The consent dialog names the relying party of the bound registration
// certificate instead of the client identifier.
func TestTheConsentDialogNamesTheRegisteredRelyingParty(t *testing.T) {
	w := generateTestWallet(t)
	key, chain, verifierInfo := registeredVerifier(t, w)
	if got := oid4vp.RegisteredName(signedARFRequest(t, w, key, chain, verifierInfo)); got != "Example Shop" {
		t.Errorf("registered name = %q, want Example Shop", got)
	}
}
