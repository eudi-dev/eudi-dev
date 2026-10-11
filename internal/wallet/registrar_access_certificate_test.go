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

	"github.com/dominikschlosser/eudi-dev/v3/internal/jws"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vp"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
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

	clientID := result.ClientIDs[0]
	header := map[string]any{"alg": "ES256", "typ": "oauth-authz-req+jwt", "x5c": []any{base64.StdEncoding.EncodeToString(leaf.Raw)}}
	raw, err := jws.Sign(header, map[string]any{"client_id": clientID}, key)
	if err != nil {
		t.Fatal(err)
	}
	reqObj := &oid4vc.RequestObjectJWT{Raw: raw, Header: header, Payload: map[string]any{"client_id": clientID}}
	if finding := oid4vp.VerifyClientID(clientID, reqObj, "", ""); finding != "" {
		t.Errorf("x509_hash client_id: %s", finding)
	}
	if finding := oid4vp.VerifyClientID(result.ClientIDs[1], reqObj, "", ""); finding != "" {
		t.Errorf("x509_san_dns client_id: %s", finding)
	}
	if finding := oid4vp.VerifyRequestObjectSignature(clientID, reqObj); finding != "" {
		t.Errorf("request object signature: %s", finding)
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
