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
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
)

// A Request Object that cannot be checked as a JWS (RFC 7515) is reported,
// never treated as verified.
func TestVerifyRequestObjectSignatureNamesAnUncheckableJWS(t *testing.T) {
	const clientID = "x509_san_dns:example.com"
	for _, tt := range []struct {
		name   string
		reqObj *oid4vc.RequestObjectJWT
		want   string
	}{
		{"raw JWT unavailable", &oid4vc.RequestObjectJWT{Header: map[string]any{"alg": "ES256"}}, "raw JWT is unavailable"},
		{"no header", &oid4vc.RequestObjectJWT{Raw: "a.b.c"}, "has no header"},
		{"no alg", &oid4vc.RequestObjectJWT{Raw: "a.b.c", Header: map[string]any{"typ": "oauth-authz-req+jwt"}}, "unsupported signing algorithm"},
		{"not compact", &oid4vc.RequestObjectJWT{Raw: "a.b", Header: map[string]any{"alg": "ES256"}}, "not a compact JWS"},
		{"unreadable x5c", &oid4vc.RequestObjectJWT{Raw: "a.b.c", Header: map[string]any{"alg": "ES256", "x5c": []any{"!!not base64"}}}, "x5c header is unreadable"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := verifyRequestObjectSignature(clientID, tt.reqObj); !strings.Contains(got, tt.want) {
				t.Errorf("finding = %q, want %q", got, tt.want)
			}
		})
	}
}

// OID4VP 1.0 §5.9.3: under x509_hash: the value is the hash of the leaf
// certificate in x5c. Without x5c there is nothing to compare.
func TestVerifyX509HashNeedsTheLeafCertificate(t *testing.T) {
	clientID := "x509_hash:" + format.EncodeBase64URL(make([]byte, 32))
	got := verifyClientID(clientID, &oid4vc.RequestObjectJWT{Header: map[string]any{"alg": "ES256"}}, "", "")
	if !strings.Contains(got, "x5c header is empty or missing") {
		t.Errorf("finding = %q, want the missing x5c", got)
	}
}

// RFC 9101 §4 makes the Request Object a JWT, so it has a JOSE header.
// RFC 7518 §3.1 ties an ES alg to an EC key and RS or PS to an RSA key.
func TestValidateRequestObjectHeaderFindings(t *testing.T) {
	certB64, _ := testCertDER([]string{"example.com"})
	for _, tt := range []struct {
		name   string
		reqObj *oid4vc.RequestObjectJWT
		want   string
	}{
		{"no header", &oid4vc.RequestObjectJWT{}, "has no header"},
		{"RSA alg for an EC certificate", &oid4vc.RequestObjectJWT{Header: map[string]any{
			"alg": "RS256", "typ": "oauth-authz-req+jwt", "x5c": []any{certB64},
		}}, "not compatible with EC key"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := validateRequestObject("x509_san_dns:example.com", tt.reqObj); !strings.Contains(got, tt.want) {
				t.Errorf("finding = %q, want %q", got, tt.want)
			}
		})
	}
}

// OID4VP 1.0 §12: "A Verifier Attestation JWT MUST set the typ JOSE header to
// verifier-attestation+jwt", and the JWT has to parse to be checked at all.
func TestVerifyVerifierAttestationRefusesAnUnreadableOrMistypedJWT(t *testing.T) {
	f := newAttestationFixture(t)
	const clientID = "verifier_attestation:verifier.example"

	mistyped, err := jws.Sign(map[string]any{"alg": "ES256", "typ": "JWT"}, map[string]any{
		"sub": "verifier.example", "exp": time.Now().Add(time.Hour).Unix(),
	}, f.issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name, attestation, want string
	}{
		{"payload does not parse", "e30.!!!.c2ln", "does not parse"},
		{"wrong typ", mistyped, `has typ "JWT"`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			reqObj := &oid4vc.RequestObjectJWT{Header: map[string]any{"alg": "ES256", "jwt": tt.attestation}}
			if got := verifyClientID(clientID, reqObj, "", ""); !strings.Contains(got, tt.want) {
				t.Errorf("finding = %q, want %q", got, tt.want)
			}
		})
	}
}

// OID4VP 1.0 §5.9.3: the request "MUST be signed with the private key
// corresponding to the public key in the cnf claim", and "The Wallet MUST
// validate the signature on the Verifier attestation JWT". Without a readable
// cnf key or an x5c key for the attestation, the signer stays unverified.
func TestVerifyAttestedSignatureNeedsBothKeys(t *testing.T) {
	f := newAttestationFixture(t)
	const clientID = "verifier_attestation:verifier.example"

	unreadableCNF := f.attestation(t, map[string]any{"cnf": map[string]any{"jwk": map[string]any{"kty": "EC", "crv": "P-256"}}})

	x, y, err := format.ECPublicCoords(&f.verifierKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	withoutX5C, err := jws.Sign(map[string]any{"alg": "ES256", "typ": "verifier-attestation+jwt"}, map[string]any{
		"iss": "https://attester.example", "sub": "verifier.example", "exp": time.Now().Add(time.Hour).Unix(),
		"cnf": map[string]any{"jwk": map[string]any{"kty": "EC", "crv": "P-256", "x": format.EncodeBase64URL(x), "y": format.EncodeBase64URL(y)}},
	}, f.issuerKey)
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name, attestation, want string
	}{
		{"unreadable cnf key", unreadableCNF, "cnf.jwk of the Verifier Attestation JWT is unreadable"},
		{"attestation without x5c", withoutX5C, `carries no x5c header, and this wallet has no key for its issuer "https://attester.example"`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			finding := verifyRequestObjectSignature(clientID, f.request(t, tt.attestation, f.verifierKey))
			if !strings.Contains(finding, tt.want) {
				t.Errorf("finding = %q, want %q", finding, tt.want)
			}
		})
	}
}
