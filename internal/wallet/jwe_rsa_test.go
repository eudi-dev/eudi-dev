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
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // RSA-OAEP is defined with SHA-1
	"encoding/json"
	"math/big"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jwe"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
)

func rsaEncJWK(pub *rsa.PublicKey, alg string) map[string]any {
	return map[string]any{
		"kty": "RSA", "use": "enc", "alg": alg, "kid": "verifier-enc-1",
		"n": format.EncodeBase64URL(pub.N.Bytes()),
		"e": format.EncodeBase64URL(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func ecEncJWK(t *testing.T, use string) map[string]any {
	t.Helper()
	jwk := mock.SigningJWKMap(&testKey(t).PublicKey)
	jwk["use"] = use
	jwk["alg"] = "ECDH-ES"
	jwk["kid"] = "ec"
	return jwk
}

// OID4VP 1.0 allows an RSA-OAEP encryption key and HAIP does not. The wallet
// answers such a verifier with a JWE it can decrypt with its RSA private key.
func TestEncryptJWERSARoundTrip(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	payload := []byte(`{"vp_token":"eyJ...","state":"abc"}`)

	compact, cek, err := jwe.EncryptRSAOAEP(payload, &priv.PublicKey, "verifier-enc-1", "RSA-OAEP", "A128GCM")
	if err != nil {
		t.Fatalf("EncryptJWERSA: %v", err)
	}
	parts := strings.Split(compact, ".")
	if len(parts) != 5 {
		t.Fatalf("expected 5 JWE parts, got %d", len(parts))
	}
	if parts[1] == "" {
		t.Fatal("RSA-OAEP JWE must carry an encrypted key in the second part")
	}

	dec := func(s string) []byte {
		b, decErr := format.DecodeBase64URL(s)
		if decErr != nil {
			t.Fatalf("decoding %q: %v", s, decErr)
		}
		return b
	}
	encryptedKey := dec(parts[1])
	unwrapped, err := rsa.DecryptOAEP(sha1.New(), rand.Reader, priv, encryptedKey, nil)
	if err != nil {
		t.Fatalf("unwrapping CEK: %v", err)
	}
	if string(unwrapped) != string(cek) {
		t.Fatal("unwrapped CEK does not match the one EncryptJWERSA returned")
	}

	block, err := aes.NewCipher(unwrapped)
	if err != nil {
		t.Fatalf("aes cipher: %v", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("gcm: %v", err)
	}
	ciphertext := append(dec(parts[3]), dec(parts[4])...) // ciphertext || tag
	plaintext, err := aead.Open(nil, dec(parts[2]), ciphertext, []byte(parts[0]))
	if err != nil {
		t.Fatalf("decrypting: %v", err)
	}
	if string(plaintext) != string(payload) {
		t.Fatalf("decrypted payload = %q, want %q", plaintext, payload)
	}
}

func TestExtractEncryptionKeyRSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating RSA key: %v", err)
	}
	meta := map[string]any{"jwks": map[string]any{"keys": []any{rsaEncJWK(&priv.PublicKey, "RSA-OAEP")}}}
	info, err := extractEncryptionKey(ValidationModeDebug, nil, meta)
	if err != nil {
		t.Fatalf("extractEncryptionKey: %v", err)
	}
	if info.RSAKey == nil {
		t.Fatal("expected an RSA key")
	}
	if info.Key != nil {
		t.Fatal("EC key must be nil for an RSA verifier key")
	}
	if info.RSAKey.N.Cmp(priv.PublicKey.N) != 0 || info.RSAKey.E != priv.PublicKey.E {
		t.Fatal("the parsed RSA key does not match the JWK")
	}
}

// A verifier that publishes only a key marked for signing is misconfigured.
// Debug mode encrypts to it and records a finding. Strict mode refuses.
func TestExtractEncryptionKeySigningOnlyFallback(t *testing.T) {
	meta := map[string]any{"jwks": map[string]any{"keys": []any{ecEncJWK(t, "sig")}}}

	info, err := extractEncryptionKey(ValidationModeDebug, nil, meta)
	if err != nil {
		t.Fatalf("debug should encrypt to a signing-only key: %v", err)
	}
	if info.Finding == "" {
		t.Fatal("debug must record a finding for a signing-only encryption key")
	}

	if _, err := extractEncryptionKey(ValidationModeStrict, nil, meta); err == nil {
		t.Fatal("strict must refuse a signing-only encryption key")
	}
}

// The response follows the same key rule as the extraction, so strict mode
// refuses a signing-only key with the missing-key error.
func TestAuthorizationResponseUsesTheModeForTheEncryptionKey(t *testing.T) {
	meta := map[string]any{"jwks": map[string]any{"keys": []any{ecEncJWK(t, "sig")}}}
	params := &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{ResponseMode: "direct_post.jwt", ClientMetadata: meta}}

	strict := generateTestWallet(t)
	strict.ValidationMode = ValidationModeStrict
	if _, err := strict.buildAuthorizationErrorResponse("access_denied", "", "s", params); err == nil || !strings.Contains(err.Error(), "carries no encryption key") {
		t.Errorf("strict: %v", err)
	}
	debug := generateTestWallet(t)
	debug.ValidationMode = ValidationModeDebug
	if _, err := debug.buildAuthorizationErrorResponse("access_denied", "", "s", params); err != nil {
		t.Errorf("debug: %v", err)
	}
}

func TestEncryptJWERSAUnsupportedAlg(t *testing.T) {
	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	if _, _, err := jwe.EncryptRSAOAEP([]byte("{}"), &priv.PublicKey, "k", "RSA1_5", "A128GCM"); err == nil {
		t.Fatal("expected an error for an unsupported RSA alg")
	}
	compact, _, err := jwe.EncryptRSAOAEP([]byte("{}"), &priv.PublicKey, "k", "RSA-OAEP-256", "A256GCM")
	if err != nil {
		t.Fatalf("RSA-OAEP-256 with A256GCM: %v", err)
	}
	hdr, _ := format.DecodeBase64URL(strings.Split(compact, ".")[0])
	var header map[string]any
	if err := json.Unmarshal(hdr, &header); err != nil {
		t.Fatalf("header is not valid JSON: %v", err)
	}
	if header["alg"] != "RSA-OAEP-256" || header["enc"] != "A256GCM" {
		t.Fatalf("unexpected header %v", header)
	}
}
