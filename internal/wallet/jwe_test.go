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
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vp"
)

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

	params := &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{ClientMetadata: map[string]any{
		"jwks": map[string]any{
			"keys": []any{map[string]any{
				"kty": "EC", "crv": "P-256", "use": "enc", "alg": "ECDH-ES",
				"kid": "verifier-key", "x": shortX, "y": fullY,
			}},
		},
	}}}

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
