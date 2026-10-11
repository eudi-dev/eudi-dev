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

	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jws"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
)

// Exercise ValidateAuthorizationRequest so the test includes the signature and
// certificate hash checks used with HAIP.
func TestHAIPEnforcesTheRequestSignature(t *testing.T) {
	t.Run("a signature that does not verify", func(t *testing.T) {
		params, reqObj := haipCompliantParams(t)
		// Keep the header and client_id, swap the payload for another one, so
		// the signature no longer covers what is presented.
		parts := strings.Split(reqObj.Raw, ".")
		parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"client_id":"x509_hash:tampered"}`))
		reqObj.Raw = strings.Join(parts, ".")
		params.RequestObject = reqObj

		findings, err := ValidateAuthorizationRequest(Checks{HAIP: true}, params)
		if err != nil {
			t.Fatal(err)
		}
		if !containsSubstring(findings, "signature") {
			t.Errorf("findings = %v, want the signature refused", findings)
		}
	})

	t.Run("a client_id naming another certificate", func(t *testing.T) {
		params, reqObj := haipCompliantParams(t)
		params.ClientID = "x509_hash:" + format.EncodeBase64URL([]byte("not the certificate"))
		params.RequestObject = reqObj

		findings, err := ValidateAuthorizationRequest(Checks{HAIP: true}, params)
		if err != nil {
			t.Fatal(err)
		}
		if !containsSubstring(findings, "x509_hash") {
			t.Errorf("findings = %v, want the hash mismatch refused", findings)
		}
	})

	t.Run("a signed DC API request whose expected_origins excludes the caller", func(t *testing.T) {
		params, reqObj := haipCompliantParams(t)
		params.RequestOrigin = "https://wallet.example"
		params.RequestObject = reqObj

		findings, err := ValidateAuthorizationRequest(Checks{HAIP: true}, params)
		if err != nil {
			t.Fatal(err)
		}
		if !containsSubstring(findings, "expected_origins") {
			t.Errorf("findings = %v, want the origin mismatch reported", findings)
		}
	})
}

// HAIP §5: "The X.509 certificate of the trust anchor MUST NOT be included in
// the x5c JOSE header of the signed request. The X.509 certificate signing the
// request MUST NOT be self-signed."
func TestHAIPRejectsSelfSignedAndAnchoredChains(t *testing.T) {
	t.Run("a self-signed signing certificate", func(t *testing.T) {
		caCert, caKey := selfSignedCert(t)
		claims := map[string]any{
			"client_id":     X509HashClientID(caCert),
			"response_type": "vp_token",
			"response_mode": "dc_api.jwt",
			"nonce":         "n",
		}
		raw, err := SignRequestObjectJWT(claims, caKey, []*x509.Certificate{caCert})
		if err != nil {
			t.Fatal(err)
		}
		header, payload, _, err := format.ParseJWTParts(raw)
		if err != nil {
			t.Fatal(err)
		}
		params, _ := haipCompliantParams(t)
		params.ClientID = X509HashClientID(caCert)
		params.RequestOrigin = ""
		reqObj := &oid4vc.RequestObjectJWT{Raw: raw, Header: header, Payload: payload}

		violations := ValidateHAIPCompliance(params, reqObj)
		if !containsSubstring(violations, "self-signed") {
			t.Errorf("violations = %v, want the self-signed certificate refused", violations)
		}
	})

	t.Run("the trust anchor shipped in the chain", func(t *testing.T) {
		caCert, leafCert, leafKey, _ := authorityChain(t)
		claims := map[string]any{
			"client_id":     X509HashClientID(leafCert),
			"response_type": "vp_token",
			"response_mode": "dc_api.jwt",
			"nonce":         "n",
		}
		// SignRequestObjectJWT strips a self-signed anchor from the chain, as
		// HAIP requires. The test builds the forbidden chain by hand.
		raw, err := jws.Sign(map[string]any{
			"alg": "ES256",
			"typ": "oauth-authz-req+jwt",
			"x5c": []any{
				base64.StdEncoding.EncodeToString(leafCert.Raw),
				base64.StdEncoding.EncodeToString(caCert.Raw),
			},
		}, claims, leafKey)
		if err != nil {
			t.Fatal(err)
		}
		header, payload, _, err := format.ParseJWTParts(raw)
		if err != nil {
			t.Fatal(err)
		}
		params, _ := haipCompliantParams(t)
		params.ClientID = X509HashClientID(leafCert)
		params.RequestOrigin = ""
		reqObj := &oid4vc.RequestObjectJWT{Raw: raw, Header: header, Payload: payload}

		violations := ValidateHAIPCompliance(params, reqObj)
		// Report the self-signed certificate that was observed. Without configured
		// trust anchors, the wallet cannot identify a certificate as the trusted root.
		if !containsSubstring(violations, "self-signed certificate at position 2") {
			t.Errorf("violations = %v, want the self-signed certificate named with its position", violations)
		}
		if !containsSubstring(violations, caCert.Subject.String()) {
			t.Errorf("violations = %v, want the offending certificate's subject named", violations)
		}
		if !containsSubstring(violations, "trust anchor") {
			t.Errorf("violations = %v, want the anchor refused", violations)
		}
	})
}

// HAIP §5.3.1 and §5.3.2 profile only mso_mdoc and dc+sd-jwt.
func TestHAIPRejectsCredentialFormatsOutsideTheProfile(t *testing.T) {
	params, reqObj := haipCompliantParams(t)
	params.DCQLQuery = map[string]any{"credentials": []any{
		map[string]any{"id": "vc", "format": "jwt_vc_json"},
	}}

	violations := ValidateHAIPCompliance(params, reqObj)
	if !containsSubstring(violations, "credential format") {
		t.Errorf("violations = %v, want the format refused", violations)
	}
}

// HAIP §5: "Verifiers MUST list both A128GCM and A256GCM in
// encrypted_response_enc_values_supported in their client metadata." A
// Verifier listing one of them gets a warning in every mode, and the wallet
// encrypts with that one. A Verifier listing neither is refused in strict
// mode.
func TestHAIPContentEncryptionAlgorithmsListing(t *testing.T) {
	for _, listed := range []any{[]any{"A128GCM"}, []any{"A256GCM"}} {
		params, reqObj := haipCompliantParams(t)
		params.RequestObject = reqObj
		params.ClientMetadata = map[string]any{"encrypted_response_enc_values_supported": listed}

		findings, err := ValidateAuthorizationRequest(Checks{Strict: true, HAIP: true}, params)
		if err != nil {
			t.Fatalf("listing %v: strict mode refused the request: %v", listed, err)
		}
		if !containsSubstring(findings, "encrypted_response_enc_values_supported") {
			t.Errorf("listing %v: findings = %v, want the missing algorithm reported", listed, findings)
		}
	}

	params, reqObj := haipCompliantParams(t)
	params.RequestObject = reqObj
	params.ClientMetadata = map[string]any{"encrypted_response_enc_values_supported": []any{}}
	if _, err := ValidateAuthorizationRequest(Checks{Strict: true, HAIP: true}, params); err == nil || !strings.Contains(err.Error(), "lists neither") {
		t.Errorf("listing neither algorithm: err = %v, want the request refused", err)
	}
}

// HAIP §5: "The Response type MUST be vp_token."
func TestHAIPRequiresVPTokenResponseType(t *testing.T) {
	params, reqObj := haipCompliantParams(t)
	params.ResponseType = "id_token"

	violations := ValidateHAIPCompliance(params, reqObj)
	if !containsSubstring(violations, "response_type") {
		t.Errorf("violations = %v, want the response type refused", violations)
	}
}

// HAIP checks run in every mode. The validation mode decides whether a
// finding stops the flow.
func TestHAIPChecksRunInBothModesAndTheModeDecidesSeverity(t *testing.T) {
	violating := func(t *testing.T) *Request {
		t.Helper()
		params, reqObj := haipCompliantParams(t)
		params.RequestObject = reqObj
		// A Verifier listing no content encryption algorithm violates §5.
		params.ClientMetadata = map[string]any{
			"encrypted_response_enc_values_supported": []any{},
		}
		return params
	}

	t.Run("strict refuses", func(t *testing.T) {
		findings, err := ValidateAuthorizationRequest(Checks{Strict: true, HAIP: true}, violating(t))
		if err == nil {
			t.Fatalf("strict mode accepted a profile violation, findings = %v", findings)
		}
		if !strings.Contains(err.Error(), "encrypted_response_enc_values_supported") {
			t.Errorf("error = %q, want it to name the violation", err)
		}
	})

	t.Run("debug reports and continues", func(t *testing.T) {
		findings, err := ValidateAuthorizationRequest(Checks{HAIP: true}, violating(t))
		if err != nil {
			t.Fatalf("debug mode refused the request: %v", err)
		}
		if !containsSubstring(findings, "encrypted_response_enc_values_supported") {
			t.Errorf("findings = %v, want the violation reported", findings)
		}
	})

	t.Run("without --haip the profile checks do not run at all", func(t *testing.T) {
		findings, err := ValidateAuthorizationRequest(Checks{Strict: true}, violating(t))
		if err != nil {
			t.Fatalf("a request that only breaks the profile was refused without --haip: %v", err)
		}
		if containsSubstring(findings, "HAIP") {
			t.Errorf("findings = %v, want no profile checks without --haip", findings)
		}
	})
}

func selfSignedCert(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(99),
		Subject:               pkix.Name{CommonName: "Self Signed Verifier"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

// The fixture is a real signed request with x509_hash and a CA-issued leaf, so
// the signature and certificate hash checks run against it.
func haipCompliantParams(t *testing.T) (*Request, *oid4vc.RequestObjectJWT) {
	t.Helper()

	_, leafCert, leafKey, _ := authorityChain(t)

	clientID := X509HashClientID(leafCert)
	claims := map[string]any{
		"client_id":        clientID,
		"response_type":    "vp_token",
		"response_mode":    "dc_api.jwt",
		"nonce":            "n-haip",
		"expected_origins": []any{"https://verifier.example"},
	}
	raw, err := SignRequestObjectJWT(claims, leafKey, []*x509.Certificate{leafCert})
	if err != nil {
		t.Fatal(err)
	}
	header, payload, _, err := format.ParseJWTParts(raw)
	if err != nil {
		t.Fatal(err)
	}

	params := &Request{
		ClientID:      clientID,
		ResponseType:  "vp_token",
		ResponseMode:  "dc_api.jwt",
		Nonce:         "n-haip",
		RequestOrigin: "https://verifier.example",
		DCQLQuery: map[string]any{"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta":   map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
			},
		}},
		ClientMetadata: map[string]any{
			"encrypted_response_enc_values_supported": []any{"A128GCM", "A256GCM"},
		},
		RequestPayload: payload,
	}
	reqObj := &oid4vc.RequestObjectJWT{Raw: raw, Header: header, Payload: payload}
	return params, reqObj
}

func containsSubstring(values []string, want string) bool {
	for _, value := range values {
		if strings.Contains(value, want) {
			return true
		}
	}
	return false
}

// authorityChain returns a CA and a leaf it signed. The leaf carries an
// authority key identifier. An "aki" trusted authority matches on it.
func authorityChain(t *testing.T) (ca, leaf *x509.Certificate, leafKey *ecdsa.PrivateKey, aki []byte) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	subjectKeyID := []byte{0x01, 0x02, 0x03, 0x04}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Authority CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
		SubjectKeyId:          subjectKeyID,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Document Signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err = x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return ca, leaf, leafKey, subjectKeyID
}
