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

package coseutil

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"

	"github.com/veraison/go-cose"
)

func TestAlgorithmName(t *testing.T) {
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
		if got := AlgorithmName(tt.alg); got != tt.want {
			t.Errorf("AlgorithmName(%d) = %q, want %q", tt.alg, got, tt.want)
		}
	}
}

func TestNewVerifier(t *testing.T) {
	p256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256 := &p256Key.PublicKey
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
		{"ESP256 on P-256", ESP256, p256, true},
		{"ESP256 on P-384", ESP256, &p384.PublicKey, false},
		{"ES384", cose.AlgorithmES384, &p384.PublicKey, true},
		{"RS256", cose.AlgorithmRS256, p256, false},
		{"unknown", 42, p256, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v, err := NewVerifier(tt.alg, tt.key)
			if (err == nil) != tt.wantOK {
				t.Fatalf("NewVerifier error = %v, want ok %v", err, tt.wantOK)
			}
			if err == nil && v.Algorithm() != tt.alg {
				t.Errorf("Algorithm() = %d, want %d", v.Algorithm(), tt.alg)
			}
		})
	}
}
