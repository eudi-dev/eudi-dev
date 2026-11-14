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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"reflect"
	"testing"
	"time"
)

func TestNameHeader(t *testing.T) {
	named := NameHeader(map[string]any{"1": int64(-7), "4": []byte("key-1"), "99": "left alone"})

	if named["alg"] != "ES256" {
		t.Errorf("alg = %v, want ES256", named["alg"])
	}
	if _, ok := named["kid"]; !ok {
		t.Errorf("kid was not named: %v", named)
	}
	if named["99"] != "left alone" {
		t.Errorf("an unknown label was not passed through: %v", named)
	}
}

func TestNameHeaderIsEmptyForAnEmptyHeader(t *testing.T) {
	if got := NameHeader(nil); got != nil {
		t.Errorf("NameHeader(nil) = %v, want nil", got)
	}
}

func TestNameHeaderKeepsAnUnknownAlgorithm(t *testing.T) {
	named := NameHeader(map[string]any{"1": int64(-999)})

	if named["alg"] != int64(-999) {
		t.Errorf("alg = %v, want the raw identifier", named["alg"])
	}
}

// x509.CreateCertificate takes the issuer from the parent certificate. A
// separate IACA gives the leaf a distinct issuer name.
func testCertDER(t *testing.T) []byte {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test IACA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		Subject:      pkix.Name{CommonName: "Test Document Signer"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// Certificates become base64 x5c entries, also when they do not parse.
func TestNameHeaderEncodesCertificates(t *testing.T) {
	der := testCertDER(t)
	encoded := base64.StdEncoding.EncodeToString(der)
	tests := map[string]struct {
		value any
		want  any
	}{
		"a single certificate":      {value: der, want: []any{encoded}},
		"a chain of several":        {value: []any{der, der}, want: []any{encoded, encoded}},
		"bytes that do not parse":   {value: []byte("nonsense"), want: []any{base64.StdEncoding.EncodeToString([]byte("nonsense"))}},
		"a value that is not bytes": {value: 42, want: 42},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			named := NameHeader(map[string]any{"33": tc.value})
			if !reflect.DeepEqual(named["x5chain"], tc.want) {
				t.Errorf("x5chain = %#v, want %#v", named["x5chain"], tc.want)
			}
		})
	}
}

func TestNameKey(t *testing.T) {
	named := NameKey(map[string]any{
		"1":  int64(2),
		"-1": int64(1),
		"-2": []byte{1, 2, 3},
		"-3": []byte{4, 5, 6},
		"3":  int64(-7),
	})

	if named["kty"] != "EC2" {
		t.Errorf("kty = %v, want EC2", named["kty"])
	}
	if named["crv"] != "P-256" {
		t.Errorf("crv = %v, want P-256", named["crv"])
	}
	if named["alg"] != "ES256" {
		t.Errorf("alg = %v, want ES256", named["alg"])
	}
	if named["x"] != base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}) {
		t.Errorf("x = %v, want it base64url encoded", named["x"])
	}
	if named["y"] != base64.RawURLEncoding.EncodeToString([]byte{4, 5, 6}) {
		t.Errorf("y = %v, want it base64url encoded", named["y"])
	}
}

func TestNameKeyIsEmptyForAnEmptyKey(t *testing.T) {
	if got := NameKey(map[string]any{}); got != nil {
		t.Errorf("NameKey({}) = %v, want nil", got)
	}
}

func TestNameKeyKeepsUnknownValues(t *testing.T) {
	named := NameKey(map[string]any{"1": int64(99), "-1": int64(99), "77": "other"})

	if named["kty"] != int64(99) {
		t.Errorf("kty = %v, want the raw value", named["kty"])
	}
	if named["crv"] != int64(99) {
		t.Errorf("crv = %v, want the raw value", named["crv"])
	}
	if named["77"] != "other" {
		t.Errorf("unknown label = %v, want it passed through", named["77"])
	}
}

// CBOR decoders can use different Go integer types for the same value.
func TestCOSEInt(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want int64
	}{
		{"int64", int64(-7), -7},
		{"uint64", uint64(7), 7},
		{"int", -35, -35},
		{"not a number", "ES256", 0},
		{"nil", nil, 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := coseInt(tt.in); got != tt.want {
				t.Errorf("coseInt(%#v) = %d, want %d", tt.in, got, tt.want)
			}
		})
	}
}
