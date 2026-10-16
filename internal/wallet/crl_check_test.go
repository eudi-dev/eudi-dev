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
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
)

// revokedVerifier registers a relying party, issues its certificates and
// deletes it, so the relying party access CA revokes its access certificate
// (CIR (EU) 2025/848 Article 9(6)).
func revokedVerifier(t *testing.T, w *Wallet) *oid4vp.Request {
	t.Helper()
	rp := registerTestRelyingParty(t, w)
	key, chain := issueTestAccessCertificate(t, w, rp.Identifier[0].Identifier)
	verifierInfo := issueTestRegistrationCertificate(t, w, rp).VerifierInfo
	if err := w.Registrar().DeleteRelyingParty(rp.Identifier[0].Identifier); err != nil {
		t.Fatal(err)
	}
	return signedARFRequest(t, w, key, chain, verifierInfo)
}

// CIR (EU) 2024/2982 Article 3(1) and 5(2) and RFC 5280 §6.1.3 (a)(3): the
// wallet answers only a request whose access certificate is not revoked. With
// --arf, debug mode warns and strict mode refuses (ARF RPA_06a).
func TestARFRefusesARequestWithARevokedAccessCertificate(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://wallet.example"
	fresh := arfRequest(t, w, w)
	if findings := oid4vp.ARFFindings(fresh); containsSubstring(findings, "RPA_06a") {
		t.Fatalf("findings %v for a valid access certificate", findings)
	}
	params := revokedVerifier(t, w)
	findings, err := oid4vp.ValidateAuthorizationRequest(oid4vp.Checks{ARF: true}, params)
	if err != nil || !containsSubstring(findings, "RPA_06a") || !containsSubstring(findings, "is revoked") {
		t.Errorf("debug mode: findings %v (%v), want the revoked access certificate", findings, err)
	}
	_, err = oid4vp.ValidateAuthorizationRequest(oid4vp.Checks{Strict: true, ARF: true}, params)
	if err == nil || !strings.Contains(err.Error(), "RPA_06a") {
		t.Errorf("strict mode: err %v, want the RPA_06a refusal", err)
	}
	// RPA_06a: with a revoked access certificate "Relying Party authentication
	// fails", so the refusal stays in the wallet (RFC 6749 §4.1.2.1).
	var authenticated *oid4vp.AuthenticatedRefusal
	if errors.As(err, &authenticated) {
		t.Errorf("strict mode answers the relying party of a revoked access certificate with %s", authenticated.Code)
	}
}

type unreachable struct{}

func (unreachable) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("connection refused")
}

// An unreadable CRL is a finding too, because the wallet can't tell whether
// the certificate is revoked (ADR 0021 treats an unreadable status list the
// same way).
func TestARFReportsAnUnreadableCRL(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://wallet.example"
	params := arfRequest(t, w, w)
	params.StatusClient = &http.Client{Transport: unreachable{}}
	if findings := oid4vp.ARFFindings(params); !containsSubstring(findings, "cannot be checked") {
		t.Errorf("findings %v, want the unreadable CRL", findings)
	}
}

// ARF ISSU_24 and ISSU_34: the wallet verifies that the issuer's access
// certificate "is valid at the time of validation" before it requests a
// credential (CIR (EU) 2024/2982 Article 4(2)).
func TestARFRefusesAnIssuerWithARevokedAccessCertificate(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://wallet.example"
	rp := registerTestRelyingParty(t, w)
	_, chain := issueTestAccessCertificate(t, w, rp.Identifier[0].Identifier)
	_, accessCA, err := w.Signer().RelyingPartyAccessCA()
	if err != nil {
		t.Fatal(err)
	}
	check := func() []string {
		return issuerARFFindings(issuerAuthentication{
			metadata:     map[string]any{},
			signerChain:  chain,
			accessCAs:    []*x509.Certificate{accessCA},
			statusClient: w.RegistrationStatusClient(),
		})
	}
	if findings := check(); containsSubstring(findings, "is revoked") {
		t.Fatalf("findings %v before the revocation", findings)
	}
	if err := w.Registrar().DeleteRelyingParty(rp.Identifier[0].Identifier); err != nil {
		t.Fatal(err)
	}
	if findings := check(); !containsSubstring(findings, "ISSU_34 and CIR (EU) 2024/2982 Article 3(1) and 4(2): the certificate") || !containsSubstring(findings, "is revoked") {
		t.Errorf("findings %v, want the revoked access certificate", findings)
	}
}
