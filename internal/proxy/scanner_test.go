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
	"testing"
)

func TestScanCEK(t *testing.T) {
	tests := []struct {
		name    string
		line    string
		wantCEK string
	}{
		{
			name:    "wallet-style CEK log",
			line:    `2026/01/15 14:32:05 [VP] JWE content encryption key for proxy debugging: dGhpcyBpcyBhIHRlc3Qga2V5MTIz`,
			wantCEK: "dGhpcyBpcyBhIHRlc3Qga2V5MTIz",
		},
		{
			name:    "generic CEK log",
			line:    `CEK: abcdef0123456789ABCDEF`,
			wantCEK: "abcdef0123456789ABCDEF",
		},
		{
			name:    "content encryption key label",
			line:    `Content Encryption Key derived: AAAAAAAAAAAAAAAA_-test`,
			wantCEK: "AAAAAAAAAAAAAAAA_-test",
		},
		{
			name:    "no CEK",
			line:    `2026/01/15 14:32:05 Starting server on port 8080`,
			wantCEK: "",
		},
		{
			name:    "case insensitive cek",
			line:    `cek value: AAAAAAAAAAAAAAAA`,
			wantCEK: "AAAAAAAAAAAAAAAA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := NewOutputScanner()
			s.Scan(tt.line)
			if got := s.LastCEK(); got != tt.wantCEK {
				t.Errorf("LastCEK() = %q, want %q", got, tt.wantCEK)
			}
		})
	}
}

func TestScanCEKLastWins(t *testing.T) {
	s := NewOutputScanner()
	s.Scan(`CEK: firstkey1234567890`)
	s.Scan(`CEK: secondkey123456789`)
	if got := s.LastCEK(); got != "secondkey123456789" {
		t.Errorf("LastCEK() = %q, want last key", got)
	}
}

func TestScanJWK(t *testing.T) {
	s := NewOutputScanner()
	line := `Verifier key: {"kty":"EC","crv":"P-256","x":"abc","y":"def","d":"privatekeyvalue"}`
	s.Scan(line)

	jwk := s.LastJWK()
	if jwk == "" {
		t.Fatal("expected JWK to be stored")
	}
	if !contains(jwk, `"d":"privatekeyvalue"`) {
		t.Errorf("expected JWK to contain private key, got %q", jwk)
	}
}

func TestScanJWKKeycloakFormat(t *testing.T) {
	s := NewOutputScanner()
	line := `2026-03-02 10:15:59,849 TRACE [de.arbeitsagentur.keycloak.oid4vp.service] Generated ephemeral encryption key: kid=9eabcc30, jwk={"kty":"EC","d":"soZ-J57DCNYJZ5k_0aUQopc7ehTAhab0da6-Cs4jRr0","crv":"P-256","kid":"9eabcc30","x":"TAEcOVsZF8NTgBoJoTSZlaFU_RTHcJZni63UiyB4_vQ","y":"1g_bke-8_ZPWtPFohNeBM0hHqX69oSu_yUE4Sfp5AFk","alg":"ECDH-ES"}`
	s.Scan(line)

	jwk := s.LastJWK()
	if jwk == "" {
		t.Fatal("expected JWK to be stored from keycloak log line")
	}
	if !contains(jwk, `"d":"soZ-J57DCNYJZ5k_0aUQopc7ehTAhab0da6-Cs4jRr0"`) {
		t.Errorf("expected JWK to contain private key d, got %q", jwk)
	}
}

func TestScanJWKLastWins(t *testing.T) {
	s := NewOutputScanner()
	s.Scan(`Key1: {"kty":"EC","crv":"P-256","x":"a","y":"b","d":"first"}`)
	s.Scan(`Key2: {"kty":"EC","crv":"P-256","x":"c","y":"d","d":"second"}`)
	if !contains(s.LastJWK(), `"d":"second"`) {
		t.Errorf("expected last JWK to win, got %q", s.LastJWK())
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}
func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
