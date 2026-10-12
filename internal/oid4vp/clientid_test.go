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
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
)

func testCertDER(dnsNames []string) (string, []byte) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     dnsNames,
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return base64.StdEncoding.EncodeToString(der), der
}

func testCertWithKeyDER(dnsNames []string) (*ecdsa.PrivateKey, string, []byte) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "test-signer"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     dnsNames,
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return key, base64.StdEncoding.EncodeToString(der), der
}

func testRSACertDER() (string, []byte) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-rsa"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"example.com"},
	}
	der, _ := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	return base64.StdEncoding.EncodeToString(der), der
}

func reqObjWithX5C(certs ...string) *oid4vc.RequestObjectJWT {
	x5c := make([]any, len(certs))
	for i, c := range certs {
		x5c[i] = c
	}
	return &oid4vc.RequestObjectJWT{
		Header: map[string]any{"x5c": x5c},
	}
}

func TestVerifyClientID_X509SanDNS(t *testing.T) {
	certB64, _ := testCertDER([]string{"example.com", "other.com"})

	tests := []struct {
		name      string
		clientID  string
		reqObj    *oid4vc.RequestObjectJWT
		wantEmpty bool
	}{
		{"no prefix", "https://verifier.example", reqObjWithX5C(certB64), true},
		{"dns match", "x509_san_dns:example.com", reqObjWithX5C(certB64), true},
		{"dns match in another case", "x509_san_dns:Example.COM", reqObjWithX5C(certB64), true},
		{"dns mismatch", "x509_san_dns:wrong.example", reqObjWithX5C(certB64), false},
		{"nil request object", "x509_san_dns:example.com", nil, false},
		{"no x5c header", "x509_san_dns:example.com", &oid4vc.RequestObjectJWT{Header: map[string]any{}}, false},
		{"empty x5c array", "x509_san_dns:example.com", &oid4vc.RequestObjectJWT{Header: map[string]any{"x5c": []any{}}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warning := verifyClientID(tt.clientID, tt.reqObj, "", "")
			if tt.wantEmpty && warning != "" {
				t.Errorf("expected no warning, got: %s", warning)
			}
			if !tt.wantEmpty && warning == "" {
				t.Error("expected a warning, got empty string")
			}
		})
	}
}

// x509_san_dns binds the FQDN of the response destination to the client_id
// (OID4VP 1.0 §5.9.3). A signed request with a valid certificate cannot send
// the response and its disclosed claims to another host. The DC API is
// origin-bound and exempt.
func TestVerifyClientID_X509SanDNSResponseFQDN(t *testing.T) {
	certB64, _ := testCertDER([]string{"example.com"})
	req := reqObjWithX5C(certB64)
	const clientID = "x509_san_dns:example.com"

	for _, tt := range []struct {
		name          string
		responseURI   string
		requestOrigin string
		wantEmpty     bool
	}{
		{"matching response host", "https://example.com/response", "", true},
		{"matching host with a port", "https://example.com:8443/response", "", true},
		{"mismatched response host", "https://evil.example/collect", "", false},
		{"dc api is origin-bound, not checked", "", "https://wallet.example", true},
		{"no response uri", "", "", true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			warning := verifyClientID(clientID, req, tt.responseURI, tt.requestOrigin)
			if tt.wantEmpty && warning != "" {
				t.Errorf("expected no finding, got %q", warning)
			}
			if !tt.wantEmpty && warning == "" {
				t.Error("expected a finding for a mismatched response host")
			}
		})
	}
}

func TestVerifyClientID_X509Hash(t *testing.T) {
	certB64, der := testCertDER([]string{"example.com"})
	hash := sha256.Sum256(der)
	correctHash := format.EncodeBase64URL(hash[:])
	wrongHash := format.EncodeBase64URL([]byte("wrong-hash-value-1234567890123"))

	tests := []struct {
		name      string
		clientID  string
		wantEmpty bool
	}{
		{"matching hash", "x509_hash:" + correctHash, true},
		{"mismatched hash", "x509_hash:" + wrongHash, false},
		{"invalid base64url", "x509_hash:not-valid!!", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warning := verifyClientID(tt.clientID, reqObjWithX5C(certB64), "", "")
			if tt.wantEmpty && warning != "" {
				t.Errorf("expected no warning, got: %s", warning)
			}
			if !tt.wantEmpty && warning == "" {
				t.Error("expected a warning, got empty string")
			}
		})
	}
}

func TestVerifyClientID_RedirectURI(t *testing.T) {
	tests := []struct {
		name        string
		clientID    string
		reqObj      *oid4vc.RequestObjectJWT
		responseURI string
		wantEmpty   bool
	}{
		{
			name:        "matching URI",
			clientID:    "redirect_uri:https://verifier.example/callback",
			responseURI: "https://verifier.example/callback",
			wantEmpty:   true,
		},
		{
			name:        "mismatched URI",
			clientID:    "redirect_uri:https://verifier.example/callback",
			responseURI: "https://other.example/callback",
			wantEmpty:   false,
		},
		{
			name:      "with request object (not allowed)",
			clientID:  "redirect_uri:https://verifier.example/callback",
			reqObj:    &oid4vc.RequestObjectJWT{Header: map[string]any{"typ": "oauth-authz-req+jwt"}},
			wantEmpty: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warning := verifyClientID(tt.clientID, tt.reqObj, tt.responseURI, "")
			if tt.wantEmpty && warning != "" {
				t.Errorf("expected no warning, got: %s", warning)
			}
			if !tt.wantEmpty && warning == "" {
				t.Error("expected a warning, got empty string")
			}
		})
	}
}

func TestValidateRequestObject(t *testing.T) {
	tests := []struct {
		name      string
		clientID  string
		reqObj    *oid4vc.RequestObjectJWT
		wantEmpty bool
		wantMsg   string
	}{
		{
			name:      "correct typ",
			clientID:  "x509_san_dns:example.com",
			reqObj:    &oid4vc.RequestObjectJWT{Header: map[string]any{"typ": "oauth-authz-req+jwt"}},
			wantEmpty: true,
		},
		// RFC 7515 §4.1.9: media types are case insensitive, and a typ without
		// a slash means "application/" prepended.
		{
			name:      "typ as a full media type in other case",
			clientID:  "x509_san_dns:example.com",
			reqObj:    &oid4vc.RequestObjectJWT{Header: map[string]any{"typ": "Application/OAuth-Authz-Req+JWT"}},
			wantEmpty: true,
		},
		{
			name:     "missing typ",
			clientID: "x509_san_dns:example.com",
			reqObj:   &oid4vc.RequestObjectJWT{Header: map[string]any{"alg": "ES256"}},
			wantMsg:  "missing the required typ header",
		},
		{
			name:      "unsigned without typ",
			clientID:  "redirect_uri:https://verifier.example/response",
			reqObj:    &oid4vc.RequestObjectJWT{Header: map[string]any{"alg": "none"}},
			wantEmpty: true,
		},
		{
			name:     "wrong typ",
			clientID: "x509_san_dns:example.com",
			reqObj:   &oid4vc.RequestObjectJWT{Header: map[string]any{"typ": "JWT"}},
			wantMsg:  "has typ",
		},
		{
			name:     "no request object with signing prefix",
			clientID: "x509_san_dns:example.com",
			reqObj:   nil,
			wantMsg:  "requires a signed Request Object",
		},
		{
			name:      "no request object without signing prefix",
			clientID:  "https://verifier.example",
			reqObj:    nil,
			wantEmpty: true,
		},
		{
			name:      "no request object with redirect_uri prefix",
			clientID:  "redirect_uri:https://verifier.example",
			reqObj:    nil,
			wantEmpty: true,
		},
		{
			name:     "unsigned request object with signing prefix",
			clientID: "x509_hash:abc",
			reqObj:   &oid4vc.RequestObjectJWT{Header: map[string]any{"alg": "none"}},
			wantMsg:  "requires a signed Request Object",
		},
		{
			name:      "unsigned request object with redirect_uri prefix",
			clientID:  "redirect_uri:https://verifier.example/cb",
			reqObj:    &oid4vc.RequestObjectJWT{Header: map[string]any{"alg": "none", "typ": "oauth-authz-req+jwt"}},
			wantEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warning := validateRequestObject(tt.clientID, tt.reqObj)
			if tt.wantEmpty && warning != "" {
				t.Errorf("expected no warning, got: %s", warning)
			}
			if tt.wantMsg != "" && !strings.Contains(warning, tt.wantMsg) {
				t.Errorf("expected warning containing %q, got: %s", tt.wantMsg, warning)
			}
		})
	}
}

func TestVerifyAlgMatchesCert(t *testing.T) {
	ecCertB64, _ := testCertDER([]string{"example.com"})
	rsaCertB64, _ := testRSACertDER()

	tests := []struct {
		name      string
		alg       string
		certB64   string
		wantEmpty bool
	}{
		{"ES256 with EC cert", "ES256", ecCertB64, true},
		{"ES384 with EC cert", "ES384", ecCertB64, true},
		{"RS256 with RSA cert", "RS256", rsaCertB64, true},
		{"PS256 with RSA cert", "PS256", rsaCertB64, true},
		{"RS256 with EC cert", "RS256", ecCertB64, false},
		{"PS256 with EC cert", "PS256", ecCertB64, false},
		{"ES256 with RSA cert", "ES256", rsaCertB64, false},
		{"no alg header", "", ecCertB64, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reqObj := reqObjWithX5C(tt.certB64)
			reqObj.Header["typ"] = "oauth-authz-req+jwt"
			if tt.alg != "" {
				reqObj.Header["alg"] = tt.alg
			}
			warning := verifyAlgMatchesCert(reqObj)
			if tt.wantEmpty && warning != "" {
				t.Errorf("expected no warning, got: %s", warning)
			}
			if !tt.wantEmpty && warning == "" {
				t.Error("expected a warning, got empty string")
			}
		})
	}
}

func TestVerifyClientID_VerifierAttestation(t *testing.T) {
	tests := []struct {
		name      string
		clientID  string
		reqObj    *oid4vc.RequestObjectJWT
		wantEmpty bool
		wantMsg   string
	}{
		{
			name:     "no request object",
			clientID: "verifier_attestation:my-verifier",
			reqObj:   nil,
			wantMsg:  "requires a signed Request Object",
		},
		{
			name:     "missing jwt header",
			clientID: "verifier_attestation:my-verifier",
			reqObj:   &oid4vc.RequestObjectJWT{Header: map[string]any{"alg": "ES256"}},
			wantMsg:  "must carry a 'jwt' header",
		},
		{
			name:     "invalid jwt value",
			clientID: "verifier_attestation:my-verifier",
			reqObj:   &oid4vc.RequestObjectJWT{Header: map[string]any{"jwt": "not-a-jwt"}},
			wantMsg:  "not a valid JWT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warning := verifyClientID(tt.clientID, tt.reqObj, "", "")
			if tt.wantEmpty && warning != "" {
				t.Errorf("expected no warning, got: %s", warning)
			}
			if tt.wantMsg != "" && !strings.Contains(warning, tt.wantMsg) {
				t.Errorf("expected warning containing %q, got: %q", tt.wantMsg, warning)
			}
		})
	}
}

func TestVerifyClientID_DecentralizedIdentifier(t *testing.T) {
	tests := []struct {
		name      string
		clientID  string
		reqObj    *oid4vc.RequestObjectJWT
		wantEmpty bool
		wantMsg   string
	}{
		{
			name:     "invalid DID format",
			clientID: "decentralized_identifier:not-a-did",
			reqObj:   &oid4vc.RequestObjectJWT{Header: map[string]any{"alg": "ES256"}},
			wantMsg:  "not a valid DID",
		},
		{
			name:     "DID with empty method",
			clientID: "decentralized_identifier:did::abc",
			reqObj:   &oid4vc.RequestObjectJWT{Header: map[string]any{"alg": "ES256"}},
			wantMsg:  "not a valid DID",
		},
		{
			name:     "no request object",
			clientID: "decentralized_identifier:did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			reqObj:   nil,
			wantMsg:  "requires a signed Request Object",
		},
		{
			name:      "valid DID with matching kid",
			clientID:  "decentralized_identifier:did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			reqObj:    &oid4vc.RequestObjectJWT{Header: map[string]any{"kid": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK#key-1"}},
			wantEmpty: true,
		},
		{
			name:     "kid does not reference DID",
			clientID: "decentralized_identifier:did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
			reqObj:   &oid4vc.RequestObjectJWT{Header: map[string]any{"kid": "did:web:other.example#key-1"}},
			wantMsg:  "does not reference the DID",
		},
		{
			name:      "valid DID without kid (no check)",
			clientID:  "decentralized_identifier:did:web:example.com",
			reqObj:    &oid4vc.RequestObjectJWT{Header: map[string]any{"alg": "ES256"}},
			wantEmpty: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warning := verifyClientID(tt.clientID, tt.reqObj, "", "")
			if tt.wantEmpty && warning != "" {
				t.Errorf("expected no warning, got: %s", warning)
			}
			if tt.wantMsg != "" && !strings.Contains(warning, tt.wantMsg) {
				t.Errorf("expected warning containing %q, got: %q", tt.wantMsg, warning)
			}
		})
	}
}

func TestVerifyAlgMatchesCert_NoX5C(t *testing.T) {
	reqObj := &oid4vc.RequestObjectJWT{
		Header: map[string]any{"alg": "ES256", "typ": "oauth-authz-req+jwt"},
	}
	if warning := verifyAlgMatchesCert(reqObj); warning != "" {
		t.Errorf("expected no warning without x5c, got: %s", warning)
	}
}

func TestVerifyRequestObjectSignature(t *testing.T) {
	key, certB64, _ := testCertWithKeyDER([]string{"example.com"})
	header := map[string]any{
		"alg": "ES256",
		"typ": "oauth-authz-req+jwt",
		"x5c": []any{certB64},
	}
	payload := map[string]any{
		"client_id":     "x509_san_dns:example.com",
		"response_type": "vp_token",
		"nonce":         "nonce-123",
	}

	raw, err := jws.Sign(header, payload, key)
	if err != nil {
		t.Fatalf("signJWT: %v", err)
	}
	parsedHeader, parsedPayload, _, err := format.ParseJWTParts(raw)
	if err != nil {
		t.Fatalf("ParseJWTParts: %v", err)
	}

	reqObj := &oid4vc.RequestObjectJWT{
		Raw:     raw,
		Header:  parsedHeader,
		Payload: parsedPayload,
	}
	if warning := verifyRequestObjectSignature("x509_san_dns:example.com", reqObj); warning != "" {
		t.Fatalf("expected valid signature, got %s", warning)
	}

	parts := strings.Split(raw, ".")
	reqObj.Raw = parts[0] + "." + parts[1] + ".AAAA"
	if warning := verifyRequestObjectSignature("x509_san_dns:example.com", reqObj); warning == "" {
		t.Fatal("expected signature verification failure")
	}
}

// The x5c requirement applies only to the x509 client_id prefixes. Their
// signing certificate travels in the x5c header. Under verifier_attestation:
// and decentralized_identifier: the key comes from the attestation JWT or the
// DID, so a missing x5c draws no finding there. An x509 prefix without x5c
// draws one.
func TestVerifyRequestObjectSignature_X5CScopedToX509Prefixes(t *testing.T) {
	header := map[string]any{
		"alg": "ES256",
		"typ": "oauth-authz-req+jwt",
	}
	payload := map[string]any{"response_type": "vp_token", "nonce": "n"}
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)
	raw := format.EncodeBase64URL(headerJSON) + "." + format.EncodeBase64URL(payloadJSON) + ".AAAA"
	reqObj := &oid4vc.RequestObjectJWT{Raw: raw, Header: header, Payload: payload}

	tests := []struct {
		name       string
		clientID   string
		wantx5cReq bool
	}{
		{"verifier_attestation without x5c", "verifier_attestation:https://verifier.example", false},
		{"decentralized_identifier without x5c", "decentralized_identifier:did:web:verifier.example", false},
		{"x509_san_dns without x5c", "x509_san_dns:verifier.example", true},
		{"x509_hash without x5c", "x509_hash:abc", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warning := verifyRequestObjectSignature(tt.clientID, reqObj)
			gotX5CReq := warning == "OID4VP 1.0 §5.9.3: Request Object signature verification requires an x5c header"
			if gotX5CReq != tt.wantx5cReq {
				t.Errorf("x5c-required finding = %v (warning %q), want %v", gotX5CReq, warning, tt.wantx5cReq)
			}
		})
	}
}

func TestVerifyRequestObjectSignature_AllowsAlgNone(t *testing.T) {
	header := map[string]any{
		"alg": "none",
		"typ": "oauth-authz-req+jwt",
	}
	payload := map[string]any{
		"client_id": "redirect_uri:https://verifier.example/cb",
	}

	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)
	raw := format.EncodeBase64URL(headerJSON) + "." + format.EncodeBase64URL(payloadJSON) + "."

	reqObj := &oid4vc.RequestObjectJWT{
		Raw:     raw,
		Header:  header,
		Payload: payload,
	}
	if warning := verifyRequestObjectSignature("redirect_uri:https://verifier.example/cb", reqObj); warning != "" {
		t.Fatalf("expected alg=none request object to bypass signature verification, got %s", warning)
	}
}

func TestVerifyClientID_RedirectURIAllowsUnsignedRequestObject(t *testing.T) {
	reqObj := &oid4vc.RequestObjectJWT{
		Header: map[string]any{
			"alg": "none",
			"typ": "oauth-authz-req+jwt",
		},
	}

	warning := verifyClientID(
		"redirect_uri:https://verifier.example/cb",
		reqObj,
		"https://verifier.example/cb",
		"",
	)
	if warning != "" {
		t.Fatalf("expected redirect_uri client_id to allow unsigned request objects, got %s", warning)
	}
}

// OID4VP 1.0 §5.9.3 reserves the origin prefix: "The Wallet MUST NOT accept
// this Client Identifier Prefix in requests." The wallet derives that audience
// from the platform origin, so a request cannot set it.
func TestVerifyClientIDRejectsReservedAndUnsupportedPrefixes(t *testing.T) {
	tests := []struct {
		name     string
		clientID string
		want     string
	}{
		{"reserved origin prefix", "origin:https://verifier.example", "reserved"},
		{"openid_federation is not implemented", "openid_federation:https://verifier.example", "not supported"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			warning := verifyClientID(tt.clientID, nil, "", "https://verifier.example")
			if warning == "" {
				t.Fatal("expected the prefix to be refused")
			}
			if !strings.Contains(warning, tt.want) {
				t.Errorf("warning = %q, want it to mention %q", warning, tt.want)
			}
		})
	}
}

// §5.9.2: "If a : character is not present in the Client Identifier, the
// Wallet MUST treat the Client Identifier as referencing a pre-registered
// client."
func TestBareClientIDIsPreRegisteredRatherThanUnknown(t *testing.T) {
	if !hasKnownClientIDPrefix("example-client") {
		t.Error("a bare client_id was reported as an unsupported prefix")
	}
	if hasKnownClientIDPrefix("nonsense:value") {
		t.Error("an unrecognised prefix was accepted")
	}
}

// The finding states which key resolution the wallet does not support, so an
// unverified request never looks verified (ADR-0013).
func TestVerifyRequestObjectSignature_NamesWhatItCouldNotVerify(t *testing.T) {
	header := map[string]any{"alg": "ES256", "typ": "oauth-authz-req+jwt"}
	payload := map[string]any{"response_type": "vp_token", "nonce": "n"}
	headerJSON, _ := json.Marshal(header)
	payloadJSON, _ := json.Marshal(payload)
	raw := format.EncodeBase64URL(headerJSON) + "." + format.EncodeBase64URL(payloadJSON) + ".AAAA"
	reqObj := &oid4vc.RequestObjectJWT{Raw: raw, Header: header, Payload: payload}

	for _, tt := range []struct {
		name     string
		clientID string
		want     string
	}{
		{"a DID resolves nowhere here", "decentralized_identifier:did:key:z6Mkabc", "did:key:z6Mkabc"},
		{"an attestation key is not read", "verifier_attestation:https://verifier.example", "Verifier Attestation JWT"},
		{"a federation chain is not resolved", "openid_federation:https://verifier.example", "OpenID Federation"},
		{"a bare client_id was never registered", "example-client", "pre-registered"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			finding := verifyRequestObjectSignature(tt.clientID, reqObj)
			if finding == "" {
				t.Fatal("a signature this wallet cannot verify was reported as fine")
			}
			if !strings.Contains(finding, "not verified") || !strings.Contains(finding, tt.want) {
				t.Errorf("finding = %q, want it to say the signature was not verified and to name %q", finding, tt.want)
			}
		})
	}
}

// No duplicate finding when another check already reports the unsigned or
// improperly signed request.
func TestVerifyRequestObjectSignature_QuietWhereAnotherCheckSpeaks(t *testing.T) {
	header := map[string]any{"alg": "none", "typ": "oauth-authz-req+jwt"}
	reqObj := &oid4vc.RequestObjectJWT{Raw: "e30.e30.", Header: header, Payload: map[string]any{}}
	if finding := verifyRequestObjectSignature("redirect_uri:https://verifier.example/cb", reqObj); finding != "" {
		t.Errorf("an unsigned request under redirect_uri: was reported: %s", finding)
	}

	signed := map[string]any{"alg": "ES256", "typ": "oauth-authz-req+jwt"}
	signedReq := &oid4vc.RequestObjectJWT{Raw: "e30.e30.AAAA", Header: signed, Payload: map[string]any{}}
	if finding := verifyRequestObjectSignature("redirect_uri:https://verifier.example/cb", signedReq); finding != "" {
		t.Errorf("a signed request under redirect_uri: is VerifyClientID's finding, but the signature check also reported: %s", finding)
	}
}

func signedRequestObject(t *testing.T, header, payload map[string]any, key *ecdsa.PrivateKey) *oid4vc.RequestObjectJWT {
	t.Helper()
	raw, err := jws.Sign(header, payload, key)
	if err != nil {
		t.Fatal(err)
	}
	h, p, _, err := format.ParseJWTParts(raw)
	if err != nil {
		t.Fatal(err)
	}
	return &oid4vc.RequestObjectJWT{Raw: raw, Header: h, Payload: p}
}

// OID4VP 1.0 §5.9.3 binds the request key to the Client Identifier Prefix.
// Only x509_san_dns: and x509_hash: take it from x5c. A DID takes it from the
// DID Document, verifier_attestation: from the cnf claim of the attestation,
// and a pre-registered client from its registration.
func TestVerifyRequestObjectSignature_X5CNeverVerifiesOtherPrefixes(t *testing.T) {
	key, certB64, _ := testCertWithKeyDER([]string{"verifier.example"})
	header := map[string]any{"alg": "ES256", "typ": "oauth-authz-req+jwt", "x5c": []any{certB64}}
	reqObj := signedRequestObject(t, header, map[string]any{"nonce": "n"}, key)

	for _, clientID := range []string{
		"decentralized_identifier:did:web:verifier.example",
		"verifier_attestation:verifier.example",
		"verifier.example",
	} {
		t.Run(clientID, func(t *testing.T) {
			if finding := verifyRequestObjectSignature(clientID, reqObj); finding == "" {
				t.Fatal("the request was verified against its own x5c")
			}
			if signed, _ := ClientAuthState(&Request{AuthorizationRequest: oid4vc.AuthorizationRequest{ClientID: clientID, RequestObject: reqObj}}); signed {
				t.Error("consent would show a verified signer")
			}
		})
	}
}

type attestationFixture struct {
	issuerKey, verifierKey *ecdsa.PrivateKey
	issuerCert             string
}

func newAttestationFixture(t *testing.T) attestationFixture {
	t.Helper()
	issuerKey, issuerCert, _ := testCertWithKeyDER(nil)
	verifierKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return attestationFixture{issuerKey: issuerKey, verifierKey: verifierKey, issuerCert: issuerCert}
}

// attestation signs a Verifier Attestation JWT. A nil claim value removes it.
func (f attestationFixture) attestation(t *testing.T, claims map[string]any) string {
	t.Helper()
	x, y, err := format.ECPublicCoords(&f.verifierKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{
		"iss": "https://attester.example",
		"sub": "verifier.example",
		"exp": time.Now().Add(time.Hour).Unix(),
		"cnf": map[string]any{"jwk": map[string]any{"kty": "EC", "crv": "P-256", "x": format.EncodeBase64URL(x), "y": format.EncodeBase64URL(y)}},
	}
	for k, v := range claims {
		if v == nil {
			delete(payload, k)
		} else {
			payload[k] = v
		}
	}
	header := map[string]any{"alg": "ES256", "typ": "verifier-attestation+jwt", "x5c": []any{f.issuerCert}}
	raw, err := jws.Sign(header, payload, f.issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (f attestationFixture) request(t *testing.T, attestation string, signer *ecdsa.PrivateKey) *oid4vc.RequestObjectJWT {
	t.Helper()
	header := map[string]any{"alg": "ES256", "typ": "oauth-authz-req+jwt", "jwt": attestation}
	return signedRequestObject(t, header, map[string]any{"nonce": "n"}, signer)
}

// OID4VP 1.0 §12: sub "MUST be the client_id", exp is REQUIRED and "The
// Wallet MUST reject any Verifier Attestation JWT with an expiration time that
// has passed", cnf is REQUIRED, and typ is verifier-attestation+jwt.
func TestVerifyClientID_VerifierAttestationClaims(t *testing.T) {
	f := newAttestationFixture(t)
	const clientID = "verifier_attestation:verifier.example"
	for _, tt := range []struct {
		name   string
		claims map[string]any
		want   string
	}{
		{"valid", nil, ""},
		{"missing sub", map[string]any{"sub": nil}, "sub"},
		{"other sub", map[string]any{"sub": "other.example"}, "sub"},
		{"missing exp", map[string]any{"exp": nil}, "exp"},
		{"expired", map[string]any{"exp": time.Now().Add(-time.Hour).Unix()}, "expired"},
		{"missing cnf", map[string]any{"cnf": nil}, "cnf"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			finding := verifyClientID(clientID, f.request(t, f.attestation(t, tt.claims), f.verifierKey), "", "")
			if tt.want == "" {
				if finding != "" {
					t.Fatalf("finding = %q, want none", finding)
				}
				return
			}
			if !strings.Contains(finding, tt.want) {
				t.Fatalf("finding = %q, want it to name %q", finding, tt.want)
			}
		})
	}
}

// §5.9.3: "The request MUST be signed with the private key corresponding to
// the public key in the cnf claim". "The Wallet MUST validate the signature on
// the Verifier attestation JWT" and "If the Wallet cannot establish trust, it
// MUST refuse the request." This wallet has no anchors for attestation
// issuers, so a valid attestation still leaves the signer unverified.
func TestVerifyRequestObjectSignature_VerifierAttestation(t *testing.T) {
	f := newAttestationFixture(t)
	const clientID = "verifier_attestation:verifier.example"
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	attestation := f.attestation(t, nil)
	parts := strings.Split(attestation, ".")
	forged := parts[0] + "." + parts[1] + ".AAAA"

	for _, tt := range []struct {
		name        string
		attestation string
		signer      *ecdsa.PrivateKey
		want        string
	}{
		{"request not signed by the cnf key", attestation, other, "cnf"},
		{"attestation signature invalid", forged, f.verifierKey, "Verifier Attestation JWT signature"},
		{"valid but unanchored issuer", attestation, f.verifierKey, "https://attester.example"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			reqObj := f.request(t, tt.attestation, tt.signer)
			finding := verifyRequestObjectSignature(clientID, reqObj)
			if !strings.Contains(finding, tt.want) {
				t.Fatalf("finding = %q, want it to name %q", finding, tt.want)
			}
			if signed, _ := ClientAuthState(&Request{AuthorizationRequest: oid4vc.AuthorizationRequest{ClientID: clientID, RequestObject: reqObj}}); signed {
				t.Error("consent would show a verified signer")
			}
		})
	}
}
