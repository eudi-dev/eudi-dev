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

package statuslist

import (
	"bytes"
	"compress/zlib"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"io"
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
)

func generateTestKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	return key
}

func TestGenerateStatusListJWT_ValidStructure(t *testing.T) {
	key := generateTestKey(t)
	bitstring := make([]byte, 16)

	cfg := StatusListConfig{
		URI:    "https://example.com/statuslists/1",
		Issuer: "https://example.com",
	}
	jwt, err := GenerateStatusListJWT(bitstring, key, cfg)
	if err != nil {
		t.Fatalf("GenerateStatusListJWT: %v", err)
	}

	parts := strings.SplitN(jwt, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("expected 3 JWT parts, got %d", len(parts))
	}

	headerBytes, err := format.DecodeBase64URL(parts[0])
	if err != nil {
		t.Fatalf("decoding header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		t.Fatalf("parsing header: %v", err)
	}
	if header["alg"] != "ES256" {
		t.Errorf("expected alg ES256, got %v", header["alg"])
	}
	if header["typ"] != "statuslist+jwt" {
		t.Errorf("expected typ statuslist+jwt, got %v", header["typ"])
	}

	payloadBytes, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		t.Fatalf("decoding payload: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		t.Fatalf("parsing payload: %v", err)
	}

	if payload["sub"] != "https://example.com/statuslists/1" {
		t.Errorf("expected sub=https://example.com/statuslists/1, got %v", payload["sub"])
	}
	if payload["iss"] != "https://example.com" {
		t.Errorf("expected iss=https://example.com, got %v", payload["iss"])
	}
	if payload["ttl"] != float64(43200) {
		t.Errorf("expected default ttl=43200, got %v", payload["ttl"])
	}

	sl, ok := payload["status_list"].(map[string]any)
	if !ok {
		t.Fatal("missing status_list in payload")
	}
	if sl["bits"] != float64(1) {
		t.Errorf("expected bits=1, got %v", sl["bits"])
	}
	if _, ok := sl["lst"].(string); !ok {
		t.Fatal("missing lst in status_list")
	}
}

func TestGenerateStatusListJWT_RoundTrip(t *testing.T) {
	key := generateTestKey(t)
	bitstring := make([]byte, 16)
	bitstring[0] = 1 << 3

	jwt, err := GenerateStatusListJWT(bitstring, key, StatusListConfig{URI: "https://example.com/statuslists/1"})
	if err != nil {
		t.Fatalf("GenerateStatusListJWT: %v", err)
	}

	parts := strings.SplitN(jwt, ".", 3)
	payloadBytes, _ := format.DecodeBase64URL(parts[1])
	var payload map[string]any
	json.Unmarshal(payloadBytes, &payload)

	sl := payload["status_list"].(map[string]any)
	lst := sl["lst"].(string)

	compressed, err := format.DecodeBase64URL(lst)
	if err != nil {
		t.Fatalf("decoding lst: %v", err)
	}

	r, err := zlib.NewReader(bytes.NewReader(compressed))
	if err != nil {
		t.Fatalf("zlib reader: %v", err)
	}
	decompressed, err := io.ReadAll(r)
	r.Close()
	if err != nil {
		t.Fatalf("decompressing: %v", err)
	}

	if len(decompressed) != len(bitstring) {
		t.Fatalf("decompressed length %d != original %d", len(decompressed), len(bitstring))
	}
	if !bytes.Equal(decompressed, bitstring) {
		t.Error("decompressed bitstring does not match original")
	}

	status, err := extractStatus(decompressed, 3, 1)
	if err != nil {
		t.Fatalf("extractStatus: %v", err)
	}
	if status != 1 {
		t.Errorf("expected index 3 to be revoked (1), got %d", status)
	}

	status, err = extractStatus(decompressed, 0, 1)
	if err != nil {
		t.Fatalf("extractStatus: %v", err)
	}
	if status != 0 {
		t.Errorf("expected index 0 to be valid (0), got %d", status)
	}
}

func TestGenerateStatusListJWT_AllZeros(t *testing.T) {
	key := generateTestKey(t)
	bitstring := make([]byte, 16)

	jwt, err := GenerateStatusListJWT(bitstring, key, StatusListConfig{URI: "https://example.com/statuslists/1"})
	if err != nil {
		t.Fatalf("GenerateStatusListJWT: %v", err)
	}

	if jwt == "" {
		t.Fatal("expected non-empty JWT")
	}
}

func TestGenerateStatusListJWT_WithCertChain(t *testing.T) {
	key := generateTestKey(t)

	caKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := mock.GenerateCACert(caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafCert, err := mock.GenerateLeafCertWithOptions(caKey, caCert, &key.PublicKey, mock.LeafCertOptions{})
	if err != nil {
		t.Fatal(err)
	}

	bitstring := make([]byte, 16)
	jwt, err := GenerateStatusListJWT(bitstring, key, StatusListConfig{
		URI:       "https://example.com/statuslists/1",
		CertChain: []*x509.Certificate{leafCert, caCert},
	})
	if err != nil {
		t.Fatalf("GenerateStatusListJWT with cert chain: %v", err)
	}

	parts := strings.SplitN(jwt, ".", 3)
	headerBytes, _ := format.DecodeBase64URL(parts[0])
	var header map[string]any
	json.Unmarshal(headerBytes, &header)

	x5c, ok := header["x5c"].([]any)
	if !ok {
		t.Fatal("expected x5c array in header")
	}
	// HAIP 6.1 excludes the self-signed trust anchor from x5c.
	if len(x5c) != 1 {
		t.Fatalf("expected only the leaf certificate in x5c, got %d", len(x5c))
	}
	if _, ok := x5c[0].(string); !ok {
		t.Error("expected string certificate in x5c[0]")
	}
}

func TestGenerateStatusListJWT_WithoutCertChain(t *testing.T) {
	key := generateTestKey(t)
	bitstring := make([]byte, 16)

	jwt, err := GenerateStatusListJWT(bitstring, key, StatusListConfig{URI: "https://example.com/statuslists/1"})
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.SplitN(jwt, ".", 3)
	headerBytes, _ := format.DecodeBase64URL(parts[0])
	var header map[string]any
	json.Unmarshal(headerBytes, &header)

	if header["x5c"] != nil {
		t.Error("expected no x5c when cert chain not provided")
	}
}

// HAIP 6.1 excludes the trust anchor from x5c.
func TestGenerateStatusListJWTExcludesTrustAnchorFromX5C(t *testing.T) {
	caKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	caCert, err := mock.GenerateCACert(caKey)
	if err != nil {
		t.Fatalf("generating CA cert: %v", err)
	}
	leafKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating leaf key: %v", err)
	}
	leafCert, err := mock.GenerateLeafCertWithOptions(caKey, caCert, &leafKey.PublicKey, mock.LeafCertOptions{})
	if err != nil {
		t.Fatalf("generating leaf cert: %v", err)
	}

	jwt, err := GenerateStatusListJWT([]byte{0x00}, leafKey, StatusListConfig{
		URI:       "https://issuer.example/api/statuslist",
		Issuer:    "https://issuer.example",
		CertChain: []*x509.Certificate{leafCert, caCert},
	})
	if err != nil {
		t.Fatalf("GenerateStatusListJWT: %v", err)
	}

	header := decodeJWTHeader(t, jwt)
	if typ, _ := header["typ"].(string); typ != "statuslist+jwt" {
		t.Errorf("typ = %v, want statuslist+jwt", typ)
	}
	x5c, ok := header["x5c"].([]any)
	if !ok {
		t.Fatalf("x5c missing from the header: %v", header)
	}
	if len(x5c) != 1 {
		t.Fatalf("x5c holds %d certificates, want only the leaf", len(x5c))
	}
	leafDER := base64.StdEncoding.EncodeToString(leafCert.Raw)
	if x5c[0] != leafDER {
		t.Error("the first x5c entry must be the signing certificate")
	}
	caDER := base64.StdEncoding.EncodeToString(caCert.Raw)
	for _, entry := range x5c {
		if entry == caDER {
			t.Error("the self-signed trust anchor must not be included in x5c")
		}
	}
}

func decodeJWTHeader(t *testing.T, jwt string) map[string]any {
	t.Helper()
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		t.Fatalf("expected a compact JWS, got %d segments", len(parts))
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decoding header: %v", err)
	}
	var header map[string]any
	if err := json.Unmarshal(raw, &header); err != nil {
		t.Fatalf("parsing header: %v", err)
	}
	return header
}

// The embedded jwk must match the key certified by the x5c leaf.
func TestGenerateStatusListJWTEmbedsSigningKeyMatchingX5C(t *testing.T) {
	caKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	caCert, err := mock.GenerateCACert(caKey)
	if err != nil {
		t.Fatalf("generating CA cert: %v", err)
	}
	leafKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("generating leaf key: %v", err)
	}
	leafCert, err := mock.GenerateLeafCertWithOptions(caKey, caCert, &leafKey.PublicKey, mock.LeafCertOptions{})
	if err != nil {
		t.Fatalf("generating leaf cert: %v", err)
	}

	jwt, err := GenerateStatusListJWT([]byte{0x00}, leafKey, StatusListConfig{
		URI:       "https://issuer.example/api/statuslist",
		Issuer:    "https://issuer.example",
		CertChain: []*x509.Certificate{leafCert, caCert},
	})
	if err != nil {
		t.Fatalf("GenerateStatusListJWT: %v", err)
	}

	header := decodeJWTHeader(t, jwt)
	jwk, ok := header["jwk"].(map[string]any)
	if !ok {
		t.Fatalf("no jwk in the header: %v", header)
	}
	want := mock.PublicKeyJWKMap(&leafKey.PublicKey)
	for _, field := range []string{"kty", "crv", "x", "y"} {
		if jwk[field] != want[field] {
			t.Errorf("jwk %s = %v, want %v", field, jwk[field], want[field])
		}
	}
	// A private key must never leak into the header.
	if _, present := jwk["d"]; present {
		t.Error("the embedded jwk must be a public key")
	}

	leafJWK := mock.PublicKeyJWKMap(leafCert.PublicKey.(*ecdsa.PublicKey))
	if jwk["x"] != leafJWK["x"] || jwk["y"] != leafJWK["y"] {
		t.Error("the embedded jwk does not match the public key in the x5c leaf certificate")
	}
	if _, ok := header["x5c"]; !ok {
		t.Error("x5c must still be present: it is what anchors the key in a trust anchor")
	}
}
