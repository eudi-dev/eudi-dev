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

package oid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
)

func testCA(t *testing.T, name string) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

// x5cSignedRequest returns an x509_san_dns:example.com request whose Request
// Object carries the leaf, issued by issuerCA, followed by the supplied CA.
func x5cSignedRequest(t *testing.T, issuerKey *ecdsa.PrivateKey, issuerCA, supplied *x509.Certificate) *Request {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(11),
		Subject:      pkix.Name{CommonName: "verifier"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"example.com"},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}, issuerCA, &leafKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	const clientID = "x509_san_dns:example.com"
	payload := map[string]any{
		"client_id": clientID, "response_type": "vp_token", "response_mode": "direct_post",
		"response_uri": "https://example.com/response", "nonce": "n-1",
	}
	raw, err := jws.Sign(map[string]any{
		"alg": "ES256", "typ": "oauth-authz-req+jwt",
		"x5c": []any{base64.StdEncoding.EncodeToString(leafDER), base64.StdEncoding.EncodeToString(supplied.Raw)},
	}, payload, leafKey)
	if err != nil {
		t.Fatal(err)
	}
	header, parsed, _, err := format.ParseJWTParts(raw)
	if err != nil {
		t.Fatal(err)
	}
	return &Request{AuthorizationRequest: oid4vc.AuthorizationRequest{
		ClientID: clientID, ResponseType: "vp_token", ResponseMode: "direct_post",
		ResponseURI: "https://example.com/response", Nonce: "n-1",
		RequestObject: &oid4vc.RequestObjectJWT{Raw: raw, Header: header, Payload: parsed},
	}}
}

// RFC 7515 §4.1.6 orders x5c "with each subsequent certificate being the one
// used to certify the previous one." A CA in x5c that did not issue the leaf breaks
// the chain even when the leaf's own signature is valid.
func TestX5CChainMustCertifyTheLeaf(t *testing.T) {
	issuerKey, issuerCA := testCA(t, "issuing CA")
	_, otherCA := testCA(t, "unrelated CA")

	consistent := x5cSignedRequest(t, issuerKey, issuerCA, issuerCA)
	if finding := verifyRequestObjectSignature(consistent.ClientID, consistent.RequestObject); finding.Text != "" {
		t.Fatalf("a consistent chain drew the finding %q", finding)
	}

	broken := x5cSignedRequest(t, issuerKey, issuerCA, otherCA)
	findings, err := ValidateAuthorizationRequest(Checks{}, broken)
	if err != nil {
		t.Fatalf("debug mode refused the request: %v", err)
	}
	if !containsSubstring(findings.Texts(), "x5c chain is not internally consistent") {
		t.Errorf("findings %v, want the inconsistent x5c chain", findings)
	}
	if _, err := ValidateAuthorizationRequest(Checks{Strict: true}, broken); err == nil || !strings.Contains(err.Error(), "x5c chain is not internally consistent") {
		t.Errorf("strict mode: err = %v, want a refusal for the inconsistent x5c chain", err)
	}
}

// singleCertRequest returns an x509_san_dns:example.com request signed by a
// self-signed leaf with the given validity period, alone in x5c.
func singleCertRequest(t *testing.T, notBefore, notAfter time.Time) *Request {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(12),
		Subject:      pkix.Name{CommonName: "verifier"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     []string{"example.com"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	const clientID = "x509_san_dns:example.com"
	header := map[string]any{"alg": "ES256", "typ": "oauth-authz-req+jwt", "x5c": []any{base64.StdEncoding.EncodeToString(der)}}
	reqObj := signedRequestObject(t, header, map[string]any{"client_id": clientID, "nonce": "n-1"}, key)
	return &Request{AuthorizationRequest: oid4vc.AuthorizationRequest{
		ClientID: clientID, ResponseType: "vp_token", ResponseMode: "direct_post",
		ResponseURI: "https://example.com/response", Nonce: "n-1", RequestObject: reqObj,
	}}
}

// RFC 5280 §6.1.3 (a)(2): a certificate is valid only from notBefore to notAfter.
// That holds for a signer alone in x5c as much as for a chain.
func TestX5CSignerMustBeWithinItsValidityPeriod(t *testing.T) {
	now := time.Now()
	valid := singleCertRequest(t, now.Add(-time.Hour), now.Add(time.Hour))
	if finding := verifyRequestObjectSignature(valid.ClientID, valid.RequestObject); finding.Text != "" {
		t.Fatalf("a valid signer drew the finding %q", finding)
	}

	for name, req := range map[string]*Request{
		"expired":       singleCertRequest(t, now.Add(-2*time.Hour), now.Add(-time.Hour)),
		"not yet valid": singleCertRequest(t, now.Add(time.Hour), now.Add(2*time.Hour)),
	} {
		t.Run(name, func(t *testing.T) {
			findings, err := ValidateAuthorizationRequest(Checks{}, req)
			if err != nil {
				t.Fatalf("debug mode refused the request: %v", err)
			}
			if !containsSubstring(findings.Texts(), "RFC 5280 §6.1.3 (a)(2)") {
				t.Errorf("findings %v, want the validity period", findings)
			}
			if _, err := ValidateAuthorizationRequest(Checks{Strict: true}, req); err == nil || !strings.Contains(err.Error(), "RFC 5280 §6.1.3 (a)(2)") {
				t.Errorf("strict mode: err = %v, want a refusal for the validity period", err)
			}
			if signed, _ := ClientAuthState(req); signed {
				t.Error("consent would show a verified signer")
			}
		})
	}
}

// The validity period applies to every certificate of the chain, so an
// expired CA behind a valid leaf is a finding too.
func TestX5CChainChecksTheValidityOfEveryCertificate(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(13), Subject: pkix.Name{CommonName: "expired CA"},
		NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(-time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	req := x5cSignedRequest(t, key, ca, ca)
	finding := verifyRequestObjectSignature(req.ClientID, req.RequestObject)
	if !strings.Contains(finding.String(), "position 2") || !strings.Contains(finding.String(), "expired CA") {
		t.Errorf("finding = %q, want the expired CA at position 2", finding)
	}
}
