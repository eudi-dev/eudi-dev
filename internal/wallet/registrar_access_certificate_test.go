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
	"encoding/pem"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
)

// A verifier signs its request object with the key behind the CSR. The wallet
// accepts the issued certificate for the x509_hash client identifier.
func TestAnAccessCertificateFromACSRSignsARequest(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	result, err := w.Registrar().IssueAccessCertificate(registrar.AccessCertificateRequest{
		Identifier: rp.Identifier[0].Identifier, CSR: testAccessCSR(t, key), DNSNames: []string{"shop.example"},
	})
	if err != nil {
		t.Fatalf("IssueAccessCertificate: %v", err)
	}
	block, _ := pem.Decode([]byte(result.Certificate))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	identifier, legalName, country := registrar.AccessCertificateSubject(leaf)
	if identifier != semanticIdentifier(t, rp) || legalName != "Example Shop" || country != rp.Country || leaf.Subject.CommonName != "Example Shop" {
		t.Errorf("subject %v, want the registration's identifier, names and country", leaf.Subject)
	}
	if strings.Count(result.Chain, "BEGIN CERTIFICATE") != 2 {
		t.Errorf("chain holds %d certificates, want the leaf and the CA", strings.Count(result.Chain, "BEGIN CERTIFICATE"))
	}

	for _, clientID := range result.ClientIDs {
		header := map[string]any{"alg": "ES256", "typ": "oauth-authz-req+jwt", "x5c": []any{base64.StdEncoding.EncodeToString(leaf.Raw)}}
		payload := map[string]any{"client_id": clientID}
		raw, err := jws.Sign(header, payload, key)
		if err != nil {
			t.Fatal(err)
		}
		req := &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{
			ClientID: clientID, ResponseType: "vp_token", ResponseMode: "direct_post",
			ResponseURI: "https://shop.example/response", Nonce: "n",
			DCQLQuery:     map[string]any{"credentials": []any{map[string]any{"id": "pid", "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []any{"urn:eudi:pid:1"}}}}},
			RequestObject: &oid4vc.RequestObjectJWT{Raw: raw, Header: header, Payload: payload},
		}, RequestPayload: payload}
		if _, err := oid4vp.ValidateAuthorizationRequest(oid4vp.Checks{Strict: true}, req); err != nil {
			t.Errorf("%s: %v", clientID, err)
		}
	}
}

// The registrar signs anyone's CSR, so access certificates have a separate CA.
// No credential issuer chain leads to it.
func TestAccessCertificatesDoNotChainToTheWalletCA(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	result, err := w.Registrar().IssueAccessCertificate(registrar.AccessCertificateRequest{Identifier: rp.Identifier[0].Identifier, CSR: testAccessCSR(t, key)})
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode([]byte(result.Certificate))
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	walletCA := x509.NewCertPool()
	walletCA.AddCert(w.CertChain[len(w.CertChain)-1])
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: walletCA, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err == nil {
		t.Error("an access certificate chains to the wallet CA, which anchors credential issuers")
	}
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: certPool(w.TrustedLists().RelyingPartyCAs()), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		t.Errorf("an access certificate does not verify to the relying party CAs: %v", err)
	}
}

func certPool(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}
