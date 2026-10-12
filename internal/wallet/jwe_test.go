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
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v2/internal/format"
)

func TestEncryptJWE_CompactFormat(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"vp_token":"test","state":"abc123"}`)
	jwe, _, err := EncryptJWE(payload, &key.PublicKey, "test-kid", "ECDH-ES", "A128GCM", nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(jwe, ".")
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

func TestEncryptJWE_WithAPU(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	apu := []byte("mdoc-nonce-value")
	jwe, _, err := EncryptJWE([]byte(`{}`), &key.PublicKey, "kid2", "ECDH-ES", "A256GCM", apu, nil)
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(jwe, ".")
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

func TestEncryptJWE_WithAPV(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	apv := []byte("auth-request-nonce")
	jwe, _, err := EncryptJWE([]byte(`{}`), &key.PublicKey, "kid3", "ECDH-ES", "A256GCM", nil, apv)
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(jwe, ".")
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

func TestEncryptJWE_A256GCM(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"test":"value"}`)
	jwe, _, err := EncryptJWE(payload, &key.PublicKey, "kid3", "ECDH-ES", "A256GCM", nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(jwe, ".")
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

func TestEncryptJWE_A128CBC_HS256(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"vp_token":"test","state":"abc123"}`)
	jwe, cek, err := EncryptJWE(payload, &key.PublicKey, "test-kid", "ECDH-ES", "A128CBC-HS256", nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Split(jwe, ".")
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

func TestEncryptJWE_UnsupportedEnc(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = EncryptJWE([]byte(`{}`), &key.PublicKey, "kid", "ECDH-ES", "A192GCM", nil, nil)
	if err == nil {
		t.Error("expected error for unsupported enc algorithm")
	}
}

func TestEcdsaPublicKeyFromJWK(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// RFC 7518 §6.2.1.2: "The length of this octet string MUST be the full size
	// of a coordinate for the curve". Strict mode enforces this.
	xRaw, yRaw, err := format.ECPublicCoords(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	xB64 := format.EncodeBase64URL(xRaw)
	yB64 := format.EncodeBase64URL(yRaw)

	pub, _, err := ecdsaPublicKeyFromJWK(ValidationModeStrict, xB64, yB64)
	if err != nil {
		t.Fatalf("ecdsaPublicKeyFromJWK() error: %v", err)
	}

	if !pub.Equal(&key.PublicKey) {
		t.Error("parsed key does not match original")
	}
	if pub.Curve != elliptic.P256() {
		t.Error("expected P-256 curve")
	}
}

func TestEcdsaPublicKeyFromJWK_InvalidX(t *testing.T) {
	_, _, err := ecdsaPublicKeyFromJWK(ValidationModeStrict, "not-valid-base64!!!", "dGVzdA")
	if err == nil {
		t.Error("expected error for invalid x coordinate")
	}
}

func TestEcdsaPublicKeyFromJWK_InvalidY(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	xRaw, _, coordErr := format.ECPublicCoords(&key.PublicKey)
	if coordErr != nil {
		t.Fatal(coordErr)
	}
	xB64 := format.EncodeBase64URL(xRaw)

	_, _, err := ecdsaPublicKeyFromJWK(ValidationModeStrict, xB64, "not-valid-base64!!!")
	if err == nil {
		t.Error("expected error for invalid y coordinate")
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

func TestEncryptJWE_ReturnsCEK(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte(`{"test":"value"}`)

	_, cek128, err := EncryptJWE(payload, &key.PublicKey, "kid", "ECDH-ES", "A128GCM", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cek128) != 16 {
		t.Errorf("expected 16-byte CEK for A128GCM, got %d bytes", len(cek128))
	}

	_, cek256, err := EncryptJWE(payload, &key.PublicKey, "kid", "ECDH-ES", "A256GCM", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(cek256) != 32 {
		t.Errorf("expected 32-byte CEK for A256GCM, got %d bytes", len(cek256))
	}
}

// RFC 7518 §6.2.1.2 requires full-width coordinates. Strict mode rejects short ones.
// Debug mode pads them and records a finding.
func TestEncryptionJWKShortCoordinate_StrictRefusesDebugReports(t *testing.T) {
	for attempt := 0; attempt < 20000; attempt++ {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		x, y, err := format.ECPublicCoords(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if x[0] != 0 { // no leading zero byte, keep looking
			continue
		}
		shortX := base64.RawURLEncoding.EncodeToString(bytes.TrimLeft(x, "\x00"))
		fullY := base64.RawURLEncoding.EncodeToString(y)

		if _, _, err := ecdsaPublicKeyFromJWK(ValidationModeStrict, shortX, fullY); err == nil {
			t.Error("strict mode accepted a JWK the specification does not allow")
		}

		got, finding, err := ecdsaPublicKeyFromJWK(ValidationModeDebug, shortX, fullY)
		if err != nil {
			t.Fatalf("debug mode refused to read the key: %v", err)
		}
		if !got.Equal(&key.PublicKey) {
			t.Error("debug mode read a different key than the one sent")
		}
		if finding == "" {
			t.Error("debug mode read past the violation without reporting it")
		}
		return
	}
	t.Fatal("no key with a short X coordinate generated in 20000 attempts")
}

// Debug mode accepts a short coordinate and reports the repair in the activity log.
func TestShortCoordinateIsReportedInTheActivityLog(t *testing.T) {
	var shortX, fullY string
	var holder *ecdsa.PublicKey
	for attempt := 0; attempt < 20000 && shortX == ""; attempt++ {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		x, y, err := format.ECPublicCoords(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		if x[0] != 0 {
			continue
		}
		shortX = base64.RawURLEncoding.EncodeToString(bytes.TrimLeft(x, "\x00"))
		fullY = base64.RawURLEncoding.EncodeToString(y)
		holder = &key.PublicKey
	}
	if shortX == "" {
		t.Fatal("no key with a short X coordinate generated in 20000 attempts")
	}

	w := generateTestWallet(t)
	w.ValidationMode = ValidationModeDebug

	params := PresentationParams{
		ClientMetadata: map[string]any{
			"jwks": map[string]any{
				"keys": []any{map[string]any{
					"kty": "EC", "crv": "P-256", "use": "enc", "alg": "ECDH-ES",
					"kid": "verifier-key", "x": shortX, "y": fullY,
				}},
			},
		},
	}

	if _, _, err := w.encryptDirectPostJWTPayload(map[string]any{"vp_token": "x"}, "", params); err != nil {
		t.Fatalf("debug mode refused to encrypt to a repairable key: %v", err)
	}
	_ = holder

	var reported bool
	for _, entry := range w.GetLog() {
		if strings.Contains(entry.Detail, "narrower than P-256") {
			reported = true
		}
	}
	if !reported {
		t.Error("the repair never reached the activity log, so nothing tells the user their verifier is non-conformant")
	}
}
