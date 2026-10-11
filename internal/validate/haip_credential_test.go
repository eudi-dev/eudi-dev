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

package validate

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
)

// HAIP §6.1.1 forbids a self-signed certificate for the credential's signer.
// A self-signed end-entity leaf must be detected.
func TestSelfSignedCertificate(t *testing.T) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating CA key: %v", err)
	}
	caCert, err := mock.GenerateCACert(caKey)
	if err != nil {
		t.Fatalf("generating CA: %v", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating leaf key: %v", err)
	}
	caSignedLeaf, err := mock.GenerateLeafCertWithOptions(caKey, caCert, &leafKey.PublicKey, mock.LeafCertOptions{})
	if err != nil {
		t.Fatalf("generating CA-signed leaf: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "self-signed leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &leafKey.PublicKey, leafKey)
	if err != nil {
		t.Fatalf("generating self-signed leaf: %v", err)
	}
	selfSignedLeaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing self-signed leaf: %v", err)
	}

	for _, tc := range []struct {
		name string
		cert *x509.Certificate
		want bool
	}{
		{"self-signed CA", caCert, true},
		{"self-signed leaf", selfSignedLeaf, true},
		{"CA-signed leaf", caSignedLeaf, false},
		{"nil", nil, false},
	} {
		if got := SelfSignedCertificate(tc.cert); got != tc.want {
			t.Errorf("SelfSignedCertificate(%s) = %v, want %v", tc.name, got, tc.want)
		}
	}
}

// HAIP 1.0 §6.1 requires a status claim to contain status_list. A W3C
// StatusList2021Entry is a finding. A status_list or a missing status is fine.
func TestHAIPCredentialFindings_StatusList(t *testing.T) {
	w3c := map[string]any{"status": map[string]any{"type": "StatusList2021Entry", "statusListIndex": "0"}}
	if findings := HAIPCredentialFindings(map[string]any{}, w3c); !containsSubstr(findings, "not a Token Status List") {
		t.Fatalf("expected a §6.1 status finding, got %v", findings)
	}

	ietf := map[string]any{"status": map[string]any{"status_list": map[string]any{"uri": "https://issuer/sl", "idx": 0}}}
	if findings := HAIPCredentialFindings(map[string]any{}, ietf); containsSubstr(findings, "Token Status List") {
		t.Fatalf("a status_list status should raise no status finding, got %v", findings)
	}

	if findings := HAIPCredentialFindings(map[string]any{}, map[string]any{}); containsSubstr(findings, "Token Status List") {
		t.Fatalf("no status claim should raise no status finding, got %v", findings)
	}
}

func containsSubstr(findings []string, sub string) bool {
	for _, f := range findings {
		if strings.Contains(f, sub) {
			return true
		}
	}
	return false
}
