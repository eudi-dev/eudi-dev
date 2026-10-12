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

package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jwe"
)

func TestDecryptJWEWithCEK(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := map[string]any{"vp_token": "test-credential", "state": "abc123"}
	payloadJSON, _ := json.Marshal(payload)

	jwe, cek, err := jwe.EncryptECDHES(payloadJSON, &key.PublicKey, "test-kid", "A128GCM", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	if len(cek) == 0 {
		t.Fatal("expected non-empty CEK")
	}

	plaintext, err := DecryptJWEWithCEK(jwe, cek)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(plaintext, &result); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}

	if result["vp_token"] != "test-credential" {
		t.Errorf("expected vp_token=test-credential, got %v", result["vp_token"])
	}
	if result["state"] != "abc123" {
		t.Errorf("expected state=abc123, got %v", result["state"])
	}
}

func TestDecryptJWEWithCEK_A256GCM(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"test":"value"}`)
	jwe, cek, err := jwe.EncryptECDHES(payload, &key.PublicKey, "kid", "A256GCM", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	plaintext, err := DecryptJWEWithCEK(jwe, cek)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	if string(plaintext) != `{"test":"value"}` {
		t.Errorf("unexpected plaintext: %s", plaintext)
	}
}

func TestDecryptJWEWithCEK_InvalidParts(t *testing.T) {
	_, err := DecryptJWEWithCEK("not.a.jwe", []byte{1, 2, 3})
	if err == nil {
		t.Error("expected error for invalid JWE")
	}
}

func TestDecryptJWEWithCEK_WrongKey(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	payload := []byte(`{"test":"value"}`)
	jwe, _, err := jwe.EncryptECDHES(payload, &key.PublicKey, "kid", "A128GCM", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	wrongKey := make([]byte, 16)
	rand.Read(wrongKey)

	_, err = DecryptJWEWithCEK(jwe, wrongKey)
	if err == nil {
		t.Error("expected error with wrong key")
	}
}

func TestDecryptJWEWithJWK(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := map[string]any{"vp_token": "test-cred", "state": "s1"}
	payloadJSON, _ := json.Marshal(payload)

	jwe, _, err := jwe.EncryptECDHES(payloadJSON, &key.PublicKey, "kid", "A128GCM", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	jwkJSON := ecPrivateKeyToJWK(t, key)

	plaintext, err := DecryptJWEWithJWK(jwe, jwkJSON)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}

	var result map[string]any
	if err := json.Unmarshal(plaintext, &result); err != nil {
		t.Fatalf("unmarshal failed: %v", err)
	}
	if result["vp_token"] != "test-cred" {
		t.Errorf("expected vp_token=test-cred, got %v", result["vp_token"])
	}
}

func TestDecryptJWEWithJWK_A256GCM(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"test":"value256"}`)
	jwe, _, err := jwe.EncryptECDHES(payload, &key.PublicKey, "kid", "A256GCM", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	jwkJSON := ecPrivateKeyToJWK(t, key)
	plaintext, err := DecryptJWEWithJWK(jwe, jwkJSON)
	if err != nil {
		t.Fatalf("decryption failed: %v", err)
	}
	if string(plaintext) != `{"test":"value256"}` {
		t.Errorf("unexpected plaintext: %s", plaintext)
	}
}

func TestDecryptJWEWithJWK_WithAPU(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"test":"apu-test"}`)
	apu := []byte("mdoc-generated-nonce-123")
	jwe, _, err := jwe.EncryptECDHES(payload, &key.PublicKey, "kid", "A128GCM", "", apu, nil)
	if err != nil {
		t.Fatal(err)
	}

	jwkJSON := ecPrivateKeyToJWK(t, key)
	plaintext, err := DecryptJWEWithJWK(jwe, jwkJSON)
	if err != nil {
		t.Fatalf("decryption with APU failed: %v", err)
	}
	if string(plaintext) != `{"test":"apu-test"}` {
		t.Errorf("unexpected plaintext: %s", plaintext)
	}
}

func TestDecryptJWEWithJWK_WrongKey(t *testing.T) {
	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	payload := []byte(`{"test":"value"}`)
	jwe, _, _ := jwe.EncryptECDHES(payload, &key1.PublicKey, "kid", "A128GCM", "", nil, nil)

	jwkJSON := ecPrivateKeyToJWK(t, key2)
	_, err := DecryptJWEWithJWK(jwe, jwkJSON)
	if err == nil {
		t.Error("expected error with wrong key")
	}
}

func ecPrivateKeyToJWK(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	x, y, err := format.ECPublicCoords(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	d, err := key.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	jwk := map[string]string{
		"kty": "EC",
		"crv": "P-256",
		"x":   format.EncodeBase64URL(x),
		"y":   format.EncodeBase64URL(y),
		"d":   format.EncodeBase64URL(d),
	}
	out, err := json.Marshal(jwk)
	if err != nil {
		t.Fatal(err)
	}
	return string(out)
}
