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
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/provider"
)

func TestCRLEndpointServesSignedEmptyList(t *testing.T) {
	srv := newTestServerWithStatusList(t)

	resp := serverRequest(t, srv, http.MethodGet, "/api/crl", "")
	if resp.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.Code)
	}
	if got := resp.Header().Get("Content-Type"); got != "application/pkix-crl" {
		t.Errorf("Content-Type = %q, want application/pkix-crl", got)
	}
	crl, err := x509.ParseRevocationList(resp.Body.Bytes())
	if err != nil {
		t.Fatalf("parsing CRL: %v", err)
	}
	caCert := srv.wallet.Signer().TrustAnchor()
	if err := crl.CheckSignatureFrom(caCert); err != nil {
		t.Errorf("CRL signature does not verify against the wallet CA: %v", err)
	}
	if len(crl.RevokedCertificateEntries) != 0 {
		t.Errorf("expected an empty CRL, got %d entries", len(crl.RevokedCertificateEntries))
	}
	if !crl.NextUpdate.After(crl.ThisUpdate) {
		t.Error("nextUpdate must be after thisUpdate")
	}
}

// ISO/IEC 18013-5 Table B.3 defines countryName in the document signer subject.
func TestSigningChainCountryFollowsIssuingCountry(t *testing.T) {
	w := generateTestWallet(t)

	spec := provider.IssuedAttestationSpec{Format: "mso_mdoc", DocType: DefaultMDOCDocType}
	_, chain, err := w.Signer().ForCredential(spec, map[string]any{"issuing_country": "DE"})
	if err != nil {
		t.Fatalf("ForCredential: %v", err)
	}
	if got := chain[0].Subject.Country; len(got) != 1 || got[0] != "DE" {
		t.Errorf("leaf subject country = %v, want [DE]", got)
	}

	_, chain, err = w.Signer().ForCredential(spec, map[string]any{})
	if err != nil {
		t.Fatalf("ForCredential: %v", err)
	}
	if got := chain[0].Subject.Country; len(got) != 1 || got[0] != "NL" {
		t.Errorf("leaf subject country without a claim = %v, want the default [NL]", got)
	}
}
