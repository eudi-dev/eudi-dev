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

package jwe

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
)

func TestEncryptECDHES_CompactFormat(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"vp_token":"test","state":"abc123"}`)
	compact, _, err := EncryptECDHES(payload, &key.PublicKey, "test-kid", "A128GCM", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(compact, ".")
	if len(parts) != 5 {
		t.Fatalf("expected 5 parts, got %d", len(parts))
	}

	// RFC 7516 §5.1: with Direct Key Agreement the JWE Encrypted Key is empty.
	if parts[1] != "" {
		t.Errorf("expected empty encrypted key, got %q", parts[1])
	}

	headerJSON, err := format.DecodeBase64URL(parts[0])
	if err != nil {
		t.Fatal(err)
	}

	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatal(err)
	}

	if header["alg"] != "ECDH-ES" {
		t.Errorf("expected alg=ECDH-ES, got %v", header["alg"])
	}
	if header["enc"] != "A128GCM" {
		t.Errorf("expected enc=A128GCM, got %v", header["enc"])
	}
	if header["kid"] != "test-kid" {
		t.Errorf("expected kid=test-kid, got %v", header["kid"])
	}
	if _, ok := header["epk"]; !ok {
		t.Error("expected epk in header")
	}
	if _, ok := header["apu"]; ok {
		t.Error("expected no apu when nil")
	}
}

// A recipient key without a kid gives a header without one. RFC 7516 §4.1.6
// defines kid as a hint that references the key.
func TestEncryptOmitsAnEmptyKid(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	compact, _, err := EncryptECDHES([]byte("{}"), &key.PublicKey, "", "A128GCM", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	header, err := ParseHeader(compact)
	if err != nil {
		t.Fatal(err)
	}
	if _, present := header.Raw["kid"]; present {
		t.Errorf("header = %v, want no kid", header.Raw)
	}
}

func TestEncryptECDHES_WithAPU(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	apu := []byte("mdoc-nonce-value")
	compact, _, err := EncryptECDHES([]byte(`{}`), &key.PublicKey, "kid2", "A256GCM", "", apu, nil)
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(compact, ".")
	headerJSON, _ := format.DecodeBase64URL(parts[0])

	var header map[string]any
	json.Unmarshal(headerJSON, &header)

	apuVal, ok := header["apu"].(string)
	if !ok {
		t.Fatal("expected apu in header")
	}
	decoded, err := format.DecodeBase64URL(apuVal)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != "mdoc-nonce-value" {
		t.Errorf("expected apu=mdoc-nonce-value, got %s", decoded)
	}
}

func TestEncryptECDHES_WithAPV(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	apv := []byte("auth-request-nonce")
	compact, _, err := EncryptECDHES([]byte(`{}`), &key.PublicKey, "kid3", "A256GCM", "", nil, apv)
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(compact, ".")
	headerJSON, _ := format.DecodeBase64URL(parts[0])

	var header map[string]any
	json.Unmarshal(headerJSON, &header)

	apvVal, ok := header["apv"].(string)
	if !ok {
		t.Fatal("expected apv in header")
	}
	decoded, err := format.DecodeBase64URL(apvVal)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != "auth-request-nonce" {
		t.Errorf("expected apv=auth-request-nonce, got %s", decoded)
	}
}

func TestEncryptECDHES_A256GCM(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"test":"value"}`)
	compact, _, err := EncryptECDHES(payload, &key.PublicKey, "kid3", "A256GCM", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(compact, ".")
	if len(parts) != 5 {
		t.Fatalf("expected 5 parts, got %d", len(parts))
	}

	headerJSON, _ := format.DecodeBase64URL(parts[0])
	var header map[string]any
	json.Unmarshal(headerJSON, &header)

	if header["enc"] != "A256GCM" {
		t.Errorf("expected enc=A256GCM, got %v", header["enc"])
	}
}

func TestEncryptECDHES_A128CBC_HS256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"vp_token":"test","state":"abc123"}`)
	compact, cek, err := EncryptECDHES(payload, &key.PublicKey, "test-kid", "A128CBC-HS256", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(compact, ".")
	if len(parts) != 5 {
		t.Fatalf("expected 5 parts, got %d", len(parts))
	}

	// RFC 7516 §5.1: with Direct Key Agreement the JWE Encrypted Key is empty.
	if parts[1] != "" {
		t.Errorf("expected empty encrypted key, got %q", parts[1])
	}

	// RFC 7518 §5.2.3: A128CBC-HS256 takes a 256 bit key (MAC and ENC halves).
	if len(cek) != 32 {
		t.Errorf("expected 32-byte CEK for A128CBC-HS256, got %d bytes", len(cek))
	}

	headerJSON, err := format.DecodeBase64URL(parts[0])
	if err != nil {
		t.Fatal(err)
	}

	var header map[string]any
	if err := json.Unmarshal(headerJSON, &header); err != nil {
		t.Fatal(err)
	}

	if header["enc"] != "A128CBC-HS256" {
		t.Errorf("expected enc=A128CBC-HS256, got %v", header["enc"])
	}
}

func TestEncryptECDHES_UnsupportedEnc(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = EncryptECDHES([]byte(`{}`), &key.PublicKey, "kid", "A192GCM", "", nil, nil)
	if err == nil {
		t.Error("expected error for unsupported enc algorithm")
	}
}

func TestPkcs7Pad(t *testing.T) {
	data13 := make([]byte, 13)
	for i := range data13 {
		data13[i] = byte(i)
	}
	padded13 := pkcs7Pad(data13, 16)
	if len(padded13) != 16 {
		t.Errorf("expected 16 bytes, got %d", len(padded13))
	}
	for i := 13; i < 16; i++ {
		if padded13[i] != 0x03 {
			t.Errorf("expected padding byte 0x03 at index %d, got 0x%02x", i, padded13[i])
		}
	}

	// Input already a block multiple gets a whole block of padding.
	data16 := make([]byte, 16)
	padded16 := pkcs7Pad(data16, 16)
	if len(padded16) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(padded16))
	}
	for i := 16; i < 32; i++ {
		if padded16[i] != 0x10 {
			t.Errorf("expected padding byte 0x10 at index %d, got 0x%02x", i, padded16[i])
		}
	}
}

func TestEncryptECDHES_ReturnsCEK(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"test":"value"}`)

	_, cek128, err := EncryptECDHES(payload, &key.PublicKey, "kid", "A128GCM", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cek128) != 16 {
		t.Errorf("expected 16-byte CEK for A128GCM, got %d bytes", len(cek128))
	}

	_, cek256, err := EncryptECDHES(payload, &key.PublicKey, "kid", "A256GCM", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cek256) != 32 {
		t.Errorf("expected 32-byte CEK for A256GCM, got %d bytes", len(cek256))
	}
}

// RFC 7518 §6.2.1.2 requires full-width coordinates. Strict mode rejects short ones.
// Debug mode pads them and records a finding.

// The wallet answers a verifier that offers only A128CBC-HS256 with that enc,
// so the package decrypts what it encrypts.
func TestEncryptedJWEsRoundTrip(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecdhKey, err := key.ECDH()
	if err != nil {
		t.Fatal(err)
	}
	for _, enc := range []string{"A128GCM", "A256GCM", "A128CBC-HS256"} {
		for _, payload := range []string{`{}`, `{"vp_token":{"q":["abcdefghijklmnop"]}}`, strings.Repeat("x", 32)} {
			compact, _, err := EncryptECDHES([]byte(payload), &key.PublicKey, "kid", enc, "", []byte("apu"), []byte("apv"))
			if err != nil {
				t.Fatalf("%s: encrypting: %v", enc, err)
			}
			plaintext, err := Decrypt(compact, ecdhKey)
			if err != nil {
				t.Fatalf("%s: decrypting: %v", enc, err)
			}
			if string(plaintext) != payload {
				t.Errorf("%s: plaintext %q, want %q", enc, plaintext, payload)
			}
		}
	}
}

func TestA128CBCHS256RefusesATamperedTag(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	ecdhKey, _ := key.ECDH()
	compact, _, err := EncryptECDHES([]byte(`{"a":1}`), &key.PublicKey, "kid", "A128CBC-HS256", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(compact, ".")
	tag, _ := format.DecodeBase64URL(parts[4])
	tag[0] ^= 1
	parts[4] = format.EncodeBase64URL(tag)
	if _, err := Decrypt(strings.Join(parts, "."), ecdhKey); err == nil {
		t.Error("a tampered tag decrypted")
	}
}
