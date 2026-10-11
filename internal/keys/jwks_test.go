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

package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

func selfSignedCertPEM(t *testing.T, key any, pub any) ([]byte, []byte) {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "jwks-test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), der
}

func decodeJWKS(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var jwks struct {
		Keys []map[string]any `json:"keys"`
	}
	if err := json.Unmarshal(data, &jwks); err != nil {
		t.Fatalf("parsing JWKS: %v", err)
	}
	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key in JWKS, got %d", len(jwks.Keys))
	}
	return jwks.Keys[0]
}

func TestCertificatePEMToJWKS_EC(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	certPEM, der := selfSignedCertPEM(t, key, &key.PublicKey)

	out, err := CertificatePEMToJWKS(certPEM)
	if err != nil {
		t.Fatalf("CertificatePEMToJWKS: %v", err)
	}
	jwk := decodeJWKS(t, out)

	if jwk["kty"] != "EC" || jwk["crv"] != "P-256" || jwk["alg"] != "ES256" || jwk["use"] != "sig" {
		t.Fatalf("unexpected JWK params: %v", jwk)
	}
	if jwk["kid"] == "" || jwk["x"] == "" || jwk["y"] == "" {
		t.Fatalf("expected kid, x, y to be set: %v", jwk)
	}
	if _, hasD := jwk["d"]; hasD {
		t.Fatal("JWKS must not contain private key material")
	}
	x5c, ok := jwk["x5c"].([]any)
	if !ok || len(x5c) != 1 {
		t.Fatalf("expected x5c with 1 entry, got %v", jwk["x5c"])
	}
	if x5c[0] != base64.StdEncoding.EncodeToString(der) {
		t.Fatal("x5c entry does not match certificate DER")
	}
	if jwk["x5t#S256"] == "" {
		t.Fatal("expected x5t#S256 to be set")
	}

	keyJSON, _ := json.Marshal(jwk)
	pub, err := ParseJWK(keyJSON)
	if err != nil {
		t.Fatalf("re-parsing JWK: %v", err)
	}
	if !key.PublicKey.Equal(pub.(*ecdsa.PublicKey)) {
		t.Fatal("JWK public key does not match certificate public key")
	}
}

func TestCertificatePEMToJWKS_RSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	certPEM, _ := selfSignedCertPEM(t, key, &key.PublicKey)

	out, err := CertificatePEMToJWKS(certPEM)
	if err != nil {
		t.Fatalf("CertificatePEMToJWKS: %v", err)
	}
	jwk := decodeJWKS(t, out)

	if jwk["kty"] != "RSA" || jwk["alg"] != "RS256" {
		t.Fatalf("unexpected JWK params: %v", jwk)
	}
	keyJSON, _ := json.Marshal(jwk)
	pub, err := ParseJWK(keyJSON)
	if err != nil {
		t.Fatalf("re-parsing JWK: %v", err)
	}
	if !key.PublicKey.Equal(pub.(*rsa.PublicKey)) {
		t.Fatal("JWK public key does not match certificate public key")
	}
}

func TestCertificatePEMToJWKS_ChainKeepsAllCertsInX5C(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	certPEM1, der1 := selfSignedCertPEM(t, key, &key.PublicKey)
	certPEM2, der2 := selfSignedCertPEM(t, key, &key.PublicKey)

	out, err := CertificatePEMToJWKS(append(certPEM1, certPEM2...))
	if err != nil {
		t.Fatalf("CertificatePEMToJWKS: %v", err)
	}
	jwk := decodeJWKS(t, out)
	x5c, ok := jwk["x5c"].([]any)
	if !ok || len(x5c) != 2 {
		t.Fatalf("expected x5c with 2 entries, got %v", jwk["x5c"])
	}
	if x5c[0] != base64.StdEncoding.EncodeToString(der1) || x5c[1] != base64.StdEncoding.EncodeToString(der2) {
		t.Fatal("x5c entries do not match certificate DER in order")
	}
}

func TestCertificatePEMToJWKS_NoCertificate(t *testing.T) {
	if _, err := CertificatePEMToJWKS([]byte("not a cert")); err == nil {
		t.Fatal("expected error for non-certificate input")
	}
}

// RFC 7638 §3.1 example. Members outside the required ones do not count.
func TestThumbprint(t *testing.T) {
	jwk := map[string]any{
		"kty": "RSA",
		"n":   "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		"e":   "AQAB",
		"alg": "RS256",
		"kid": "2011-04-29",
	}
	sum, err := Thumbprint(jwk)
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.RawURLEncoding.EncodeToString(sum); got != "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" {
		t.Errorf("Thumbprint = %s", got)
	}

	if _, err := Thumbprint(map[string]any{"kty": "EC", "crv": "P-256", "x": "abc"}); err == nil {
		t.Error("an EC JWK without y was accepted")
	}
}

// The thumbprint follows the key's curve.
func TestPublicKeyThumbprintCoversTheCurve(t *testing.T) {
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := PublicJWK(&p384.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if jwk["crv"] != "P-384" {
		t.Fatalf("crv = %v, want P-384", jwk["crv"])
	}
	want, err := Thumbprint(jwk)
	if err != nil {
		t.Fatal(err)
	}
	got, err := PublicKeyThumbprint(&p384.PublicKey)
	if err != nil || string(got) != string(want) {
		t.Errorf("PublicKeyThumbprint = %x, %v, want %x", got, err, want)
	}
}
