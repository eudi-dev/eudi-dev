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

package mdoc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/veraison/go-cose"

	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
)

func generateTestMDoc(t *testing.T, cfg mock.MDOCConfig) *Document {
	t.Helper()
	raw, err := mock.GenerateMDOC(cfg)
	if err != nil {
		t.Fatalf("GenerateMDOC: %v", err)
	}
	doc, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return doc
}

func TestVerify(t *testing.T) {
	key1, _ := mock.GenerateKey()
	key2, _ := mock.GenerateKey()

	tests := []struct {
		name         string
		cfg          mock.MDOCConfig
		verifyKey    crypto.PublicKey
		useNilDoc    bool
		wantSigValid bool
		wantExpired  bool
		wantErrors   bool
		checkFields  bool
	}{
		{
			name: "valid signature",
			cfg: mock.MDOCConfig{
				DocType: "org.iso.18013.5.1.mDL", Namespace: "org.iso.18013.5.1",
				Claims: mock.DefaultClaims, Key: key1,
			},
			verifyKey:    &key1.PublicKey,
			wantSigValid: true,
			checkFields:  true,
		},
		{
			name: "wrong key",
			cfg: mock.MDOCConfig{
				DocType: "org.iso.18013.5.1.mDL", Namespace: "org.iso.18013.5.1",
				Claims: mock.DefaultClaims, Key: key1,
			},
			verifyKey:    &key2.PublicKey,
			wantSigValid: false,
			wantErrors:   true,
		},
		{
			name: "expired document",
			cfg: mock.MDOCConfig{
				DocType: "org.iso.18013.5.1.mDL", Namespace: "org.iso.18013.5.1",
				Claims: mock.DefaultClaims, Key: key1,
				ExpiresIn: -1 * time.Hour,
			},
			verifyKey:    &key1.PublicKey,
			wantSigValid: true,
			wantExpired:  true,
		},
		{
			name: "validity dates present",
			cfg: mock.MDOCConfig{
				DocType: "org.iso.18013.5.1.mDL", Namespace: "org.iso.18013.5.1",
				Claims: mock.DefaultClaims, Key: key1,
				ExpiresIn: 30 * 24 * time.Hour,
			},
			verifyKey:    &key1.PublicKey,
			wantSigValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := generateTestMDoc(t, tt.cfg)

			result := Verify(doc, tt.verifyKey)

			if result.SignatureValid != tt.wantSigValid {
				t.Errorf("SignatureValid = %v, want %v (errors: %v)", result.SignatureValid, tt.wantSigValid, result.Errors)
			}
			if result.Expired != tt.wantExpired {
				t.Errorf("Expired = %v, want %v", result.Expired, tt.wantExpired)
			}
			if tt.wantErrors && len(result.Errors) == 0 {
				t.Error("expected errors, got none")
			}
			if tt.checkFields {
				if result.Algorithm != "ES256" {
					t.Errorf("expected algorithm ES256, got %q", result.Algorithm)
				}
				if result.DocType != "org.iso.18013.5.1.mDL" {
					t.Errorf("expected doctype org.iso.18013.5.1.mDL, got %q", result.DocType)
				}
			}
			if tt.name == "validity dates present" {
				if result.ValidFrom == nil {
					t.Error("expected ValidFrom to be set")
				}
				if result.ValidUntil == nil {
					t.Error("expected ValidUntil to be set")
				}
				if result.Signed == nil {
					t.Error("expected Signed to be set")
				}
			}
		})
	}
}

// ISO 18013-5 requires validityInfo. Without it the dates and validity flags
// stay unset, so the caller can report the missing check.
func TestVerify_NoValidityInfo(t *testing.T) {
	key, _ := mock.GenerateKey()
	doc := generateTestMDoc(t, mock.MDOCConfig{
		DocType: "org.iso.18013.5.1.mDL", Namespace: "org.iso.18013.5.1",
		Claims: mock.DefaultClaims, Key: key, OmitValidityInfo: true,
	})

	result := Verify(doc, &key.PublicKey)

	if !result.SignatureValid {
		t.Fatalf("SignatureValid = false, want true (errors: %v)", result.Errors)
	}
	if result.ValidUntil != nil || result.ValidFrom != nil || result.Signed != nil {
		t.Errorf("validity dates = (from %v, until %v, signed %v), want all nil", result.ValidFrom, result.ValidUntil, result.Signed)
	}
	if result.Expired || result.NotYetValid {
		t.Errorf("Expired = %v, NotYetValid = %v, want both false", result.Expired, result.NotYetValid)
	}
}

// ISO 18013-5 requires digestAlgorithm. An MSO without it verifies with
// SHA-256 and gets a warning.
func TestVerify_NoDigestAlgorithm(t *testing.T) {
	key, _ := mock.GenerateKey()
	doc := generateTestMDoc(t, mock.MDOCConfig{
		DocType: "org.iso.18013.5.1.mDL", Namespace: "org.iso.18013.5.1",
		Claims: mock.DefaultClaims, Key: key, OmitDigestAlgorithm: true,
	})

	result := Verify(doc, &key.PublicKey)

	if !result.SignatureValid {
		t.Fatalf("SignatureValid = false, want true (errors: %v)", result.Errors)
	}
	found := false
	for _, w := range result.Warnings {
		if strings.Contains(w, "digestAlgorithm") {
			found = true
		}
	}
	if !found {
		t.Errorf("Warnings = %v, want one naming digestAlgorithm", result.Warnings)
	}
}

func TestCOSEAlgorithmName(t *testing.T) {
	tests := []struct {
		alg  cose.Algorithm
		want string
	}{
		{-7, "ES256"},
		{-9, "ESP256"},
		{-35, "ES384"},
		{-36, "ES512"},
		{-37, "PS256"},
		{-257, "RS256"},
		{0, "unknown(0)"},
		{42, "unknown(42)"},
	}
	for _, tt := range tests {
		if got := COSEAlgorithmName(tt.alg); got != tt.want {
			t.Errorf("COSEAlgorithmName(%d) = %q, want %q", tt.alg, got, tt.want)
		}
	}
}

func TestNewCOSEVerifier(t *testing.T) {
	p256 := &testKey(t).PublicKey
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		alg    cose.Algorithm
		key    crypto.PublicKey
		wantOK bool
	}{
		{"ES256", cose.AlgorithmES256, p256, true},
		{"ESP256 on P-256", AlgorithmESP256, p256, true},
		{"ESP256 on P-384", AlgorithmESP256, &p384.PublicKey, false},
		{"ES384", cose.AlgorithmES384, &p384.PublicKey, true},
		{"RS256", cose.AlgorithmRS256, p256, false},
		{"unknown", 42, p256, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := NewCOSEVerifier(tt.alg, tt.key)
			if (err == nil) != tt.wantOK {
				t.Fatalf("NewCOSEVerifier error = %v, want ok %v", err, tt.wantOK)
			}
			if err == nil && v.Algorithm() != tt.alg {
				t.Errorf("Algorithm() = %d, want %d", v.Algorithm(), tt.alg)
			}
		})
	}
}

// HAIP 1.0 §7 allows -9 for the mandatory ECDSA P-256 suite.
func TestVerifyAcceptsESP256(t *testing.T) {
	key := testKey(t)
	signer, err := cose.NewSigner(cose.AlgorithmES256, key)
	if err != nil {
		t.Fatal(err)
	}
	msg := cose.Sign1Message{
		Headers: cose.Headers{Protected: cose.ProtectedHeader{cose.HeaderLabelAlgorithm: AlgorithmESP256}},
		Payload: []byte("mso"),
	}
	if err := msg.Sign(rand.Reader, nil, esp256Signer{signer}); err != nil {
		t.Fatal(err)
	}
	raw, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatal(err)
	}
	result := Verify(&Document{IssuerAuth: &IssuerAuth{RawCOSE: raw}}, &key.PublicKey)
	if !result.SignatureValid || result.Algorithm != "ESP256" {
		t.Fatalf("Verify = %+v, want a valid ESP256 signature", result)
	}
}

// esp256Signer produces the ES256 signature under the ESP256 label, which
// go-cose does not know.
type esp256Signer struct{ cose.Signer }

func (esp256Signer) Algorithm() cose.Algorithm { return AlgorithmESP256 }

func TestConvertCBORMapToStringKeys(t *testing.T) {
	m := map[any]any{
		"str_key": "value1",
		42:        "value2",
		true:      "value3",
	}
	result := convertCBORMapToStringKeys(m)

	if result["str_key"] != "value1" {
		t.Errorf("expected str_key=value1, got %v", result["str_key"])
	}
	if result["42"] != "value2" {
		t.Errorf("expected 42=value2, got %v", result["42"])
	}
	if result["true"] != "value3" {
		t.Errorf("expected true=value3, got %v", result["true"])
	}
}

func TestConvertCBORValue(t *testing.T) {
	if got := convertCBORValue("hello"); got != "hello" {
		t.Errorf("expected string passthrough, got %v", got)
	}
	if got := convertCBORValue(42); got != 42 {
		t.Errorf("expected int passthrough, got %v", got)
	}
	if got := convertCBORValue(nil); got != nil {
		t.Errorf("expected nil passthrough, got %v", got)
	}

	arr := convertCBORValue([]any{"a", "b"})
	if result, ok := arr.([]any); !ok || len(result) != 2 {
		t.Errorf("expected 2-element array, got %v", arr)
	}

	nested := convertCBORValue(map[any]any{1: "one"})
	if m, ok := nested.(map[string]any); !ok || m["1"] != "one" {
		t.Errorf("expected map with string keys, got %v", nested)
	}
}

func TestDecodeCBOR(t *testing.T) {
	// 0x18 0x2A is the unsigned integer 42.
	got, err := decodeCBOR([]byte{0x18, 0x2a})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != int64(42) {
		t.Errorf("expected 42, got %v (%T)", got, got)
	}

	_, err = decodeCBOR([]byte{0xff, 0xff})
	if err == nil {
		t.Error("expected error for invalid CBOR")
	}
}

func TestParseDeviceSigned(t *testing.T) {
	ds := map[any]any{
		"deviceAuth": map[any]any{
			"key": "value",
		},
	}
	result := parseDeviceSigned(ds)
	if result.DeviceAuth == nil {
		t.Fatal("expected DeviceAuth to be set")
	}
	if result.DeviceAuth["key"] != "value" {
		t.Errorf("expected key=value, got %v", result.DeviceAuth["key"])
	}

	result2 := parseDeviceSigned(map[any]any{})
	if result2.DeviceAuth != nil {
		t.Errorf("expected nil DeviceAuth, got %v", result2.DeviceAuth)
	}
}

func TestVerify_NilIssuerAuth(t *testing.T) {
	doc := &Document{
		DocType:    "test",
		IssuerAuth: nil,
	}

	result := Verify(doc, nil)

	if result.SignatureValid {
		t.Error("expected invalid signature for nil issuerAuth")
	}
	if len(result.Errors) == 0 {
		t.Error("expected error about missing issuerAuth")
	}
}

// Verify must handle a nil document without a panic.
func TestVerify_NilDocument(t *testing.T) {
	result := Verify(nil, nil)

	if result == nil {
		t.Fatal("Verify(nil) returned no result")
	}
	if result.SignatureValid {
		t.Error("a nil document reported a valid signature")
	}
	if len(result.Errors) == 0 {
		t.Error("a nil document reported no error")
	}
}
