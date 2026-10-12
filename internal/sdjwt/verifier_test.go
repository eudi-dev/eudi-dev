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

package sdjwt

import (
	"crypto"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
)

func generateTestSDJWT(t *testing.T, cfg mock.SDJWTConfig) *Token {
	t.Helper()
	raw, err := mock.GenerateSDJWT(cfg)
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}
	token, err := Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return token
}

func TestVerify(t *testing.T) {
	key1, _ := mock.GenerateKey()
	key2, _ := mock.GenerateKey()
	future := time.Now().Add(1 * time.Hour)

	tests := []struct {
		name            string
		cfg             mock.SDJWTConfig
		verifyKey       crypto.PublicKey
		modifyToken     func(tok *Token)
		wantSigValid    bool
		wantExpired     bool
		wantNotYetValid bool
		wantErrors      bool
	}{
		{
			name: "valid ES256 signature",
			cfg: mock.SDJWTConfig{
				Issuer: "https://issuer.example", VCT: "urn:test:1",
				ExpiresIn: 24 * time.Hour, Claims: mock.DefaultClaims, Key: key1,
			},
			verifyKey:    &key1.PublicKey,
			wantSigValid: true,
		},
		{
			name: "wrong key",
			cfg: mock.SDJWTConfig{
				Issuer: "https://issuer.example", VCT: "urn:test:1",
				ExpiresIn: 24 * time.Hour, Claims: mock.DefaultClaims, Key: key1,
			},
			verifyKey:    &key2.PublicKey,
			wantSigValid: false,
		},
		{
			name: "expired token",
			cfg: mock.SDJWTConfig{
				Issuer: "https://issuer.example", VCT: "urn:test:1",
				ExpiresIn: -1 * time.Hour, Claims: mock.DefaultClaims, Key: key1,
			},
			verifyKey:    &key1.PublicKey,
			wantSigValid: true,
			wantExpired:  true,
		},
		{
			name: "not yet valid",
			cfg: mock.SDJWTConfig{
				Issuer: "https://issuer.example", VCT: "urn:test:1",
				ExpiresIn: 24 * time.Hour, NotBefore: &future,
				Claims: mock.DefaultClaims, Key: key1,
			},
			verifyKey:       &key1.PublicKey,
			wantSigValid:    true,
			wantNotYetValid: true,
		},
		{
			name: "unsupported algorithm",
			cfg: mock.SDJWTConfig{
				Issuer: "https://issuer.example", VCT: "urn:test:1",
				ExpiresIn: 24 * time.Hour, Claims: mock.DefaultClaims, Key: key1,
			},
			verifyKey:    &key1.PublicKey,
			modifyToken:  func(tok *Token) { tok.Header["alg"] = "none" },
			wantSigValid: false,
			wantErrors:   true,
		},
		{
			name: "time claims present",
			cfg: mock.SDJWTConfig{
				Issuer: "https://issuer.example", VCT: "urn:test:1",
				ExpiresIn: 24 * time.Hour, Claims: mock.DefaultClaims, Key: key1,
			},
			verifyKey:    &key1.PublicKey,
			wantSigValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token := generateTestSDJWT(t, tt.cfg)
			if tt.modifyToken != nil {
				tt.modifyToken(token)
			}

			result := Verify(token, tt.verifyKey)

			if result.SignatureValid != tt.wantSigValid {
				t.Errorf("SignatureValid = %v, want %v (errors: %v)", result.SignatureValid, tt.wantSigValid, result.Errors)
			}
			if result.Expired != tt.wantExpired {
				t.Errorf("Expired = %v, want %v", result.Expired, tt.wantExpired)
			}
			if result.NotYetValid != tt.wantNotYetValid {
				t.Errorf("NotYetValid = %v, want %v", result.NotYetValid, tt.wantNotYetValid)
			}
			if tt.wantErrors && len(result.Errors) == 0 {
				t.Error("expected errors, got none")
			}

			if tt.name == "time claims present" {
				if result.IssuedAt == nil {
					t.Error("expected IssuedAt to be set")
				}
				if result.ExpiresAt == nil {
					t.Error("expected ExpiresAt to be set")
				}
			}
			if tt.name == "valid ES256 signature" {
				if result.Algorithm != "ES256" {
					t.Errorf("expected algorithm ES256, got %q", result.Algorithm)
				}
				if result.Issuer != "https://issuer.example" {
					t.Errorf("expected issuer https://issuer.example, got %q", result.Issuer)
				}
			}
		})
	}
}

func TestVerify_InvalidJWTStructure(t *testing.T) {
	token := &Token{
		Raw:     "not-a-jwt",
		Header:  map[string]any{"alg": "ES256"},
		Payload: map[string]any{},
	}

	result := Verify(token, nil)

	if result.SignatureValid {
		t.Error("expected invalid signature for malformed JWT")
	}
	if len(result.Errors) == 0 {
		t.Error("expected errors for invalid JWT structure")
	}
}
