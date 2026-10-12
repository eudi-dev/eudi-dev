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
	"crypto/x509"
	"encoding/pem"
	"slices"
	"strings"
	"testing"
)

func TestIssuerURLFromBaseURL(t *testing.T) {
	got, err := IssuerURLFromBaseURL("http://host.docker.internal:8085/wallet", 8086)
	if err != nil {
		t.Fatalf("IssuerURLFromBaseURL: %v", err)
	}
	if got != "https://host.docker.internal:8086" {
		t.Fatalf("expected https://host.docker.internal:8086, got %s", got)
	}
}

// An issuer reached by IP address gets the address as an iPAddress SAN. A TLS
// client matches the address against that SAN.
func TestIssuerTLSCertificateNamesAnIPHostAsAnAddress(t *testing.T) {
	certPEM, _, err := generateIssuerTLSCertificatePEMWithCA("192.0.2.7", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if err := cert.VerifyHostname("192.0.2.7"); err != nil {
		t.Errorf("certificate does not cover its IP host: %v", err)
	}
	if slices.Contains(cert.DNSNames, "192.0.2.7") {
		t.Errorf("DNSNames = %v, want the IP address only among the IP SANs", cert.DNSNames)
	}
}

// Each credential type gets its own configuration id, so no type hides
// another in the issuer metadata.
func TestSanitizeMetadataIDKeepsTypesApart(t *testing.T) {
	long := "https://credentials.example/types/" + strings.Repeat("x", 40)
	types := []string{"urn:a.b", "urn:a:b", "urn_a_b", "a", ":a", long + "1", long + "2"}
	seen := map[string]string{}
	for _, typ := range types {
		id := sanitizeMetadataID(typ)
		if other, taken := seen[id]; taken {
			t.Errorf("%q and %q share the id %q", other, typ, id)
		}
		seen[id] = typ
		if len(id) > 50 {
			t.Errorf("id %q of %q is longer than 50 characters", id, typ)
		}
	}
	if got := sanitizeMetadataID("urn:eudi:pid:1"); got != "urn_eudi_pid_1" {
		t.Errorf("sanitizeMetadataID(urn:eudi:pid:1) = %q, want the readable urn_eudi_pid_1", got)
	}
}
