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

package registrar

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
)

func testAccessCSR(t *testing.T, key *ecdsa.PrivateKey) string {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}))
}

func TestAccessCertificateRequestsTheRegistrarRefuses(t *testing.T) {
	w := generateTestWallet(t)
	id := registerTestRelyingParty(t, w).Identifier[0].Identifier
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	p384Key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	for _, tc := range []struct {
		name string
		req  AccessCertificateRequest
		want string
	}{
		{"unregistered", AccessCertificateRequest{Identifier: "LEIXG-1", CSR: testAccessCSR(t, key)}, "not registered"},
		{"no CSR", AccessCertificateRequest{Identifier: id}, "not a PEM certificate request"},
		{"P-384 key", AccessCertificateRequest{Identifier: id, CSR: testAccessCSR(t, p384Key)}, "not a P-256 key"},
		{"long validity", AccessCertificateRequest{Identifier: id, CSR: testAccessCSR(t, key), Validity: "9000h"}, "at most"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := w.IssueAccessCertificate(tc.req); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
		})
	}
}

func TestAccessCertificateDNSNamesAreChecked(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"*.shop.example", "shop example", "-shop.example"} {
		if _, err := w.IssueAccessCertificate(AccessCertificateRequest{Identifier: rp.Identifier[0].Identifier, CSR: testAccessCSR(t, key), DNSNames: []string{name}}); err == nil || !strings.Contains(err.Error(), "not a DNS name") {
			t.Errorf("%q: error %v, want a DNS name error", name, err)
		}
	}
}

// ETSI TS 119 411-8 V1.1.1 GEN-6.6.1-07 puts a support website in a
// uniformResourceIdentifier and an email address in an rfc822Name.
func TestTheSupportContactIsASubjectAlternativeName(t *testing.T) {
	w := generateTestWallet(t)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for contact, want := range map[string]string{
		"https://shop.example/help":   "URI https://shop.example/help",
		"support@shop.example":        "email support@shop.example",
		"mailto:support@shop.example": "email support@shop.example",
	} {
		rp, err := w.RegisterRelyingParty(WalletRelyingParty{TradeName: "Shop " + contact, Services: []WalletRelyingPartyService{{SupportURI: contact, IntendedUses: []IntendedUse{ageCheckUse("Age check")}}}})
		if err != nil {
			t.Fatalf("%s: %v", contact, err)
		}
		issued, err := w.IssueAccessCertificate(AccessCertificateRequest{Identifier: rp.Identifier[0].Identifier, CSR: testAccessCSR(t, key)})
		if err != nil {
			t.Fatalf("%s: %v", contact, err)
		}
		block, _ := pem.Decode([]byte(issued.Certificate))
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, u := range cert.URIs {
			names = append(names, "URI "+u.String())
		}
		for _, e := range cert.EmailAddresses {
			names = append(names, "email "+e)
		}
		if len(names) != 1 || names[0] != want {
			t.Errorf("%s: subject alternative names %v, want %s", contact, names, want)
		}
	}
	if _, err := w.RegisterRelyingParty(WalletRelyingParty{TradeName: "Shop", Services: []WalletRelyingPartyService{{SupportURI: "call us"}}}); err == nil || !strings.Contains(err.Error(), "support contact") {
		t.Errorf("error %v, want the support contact refused", err)
	}
}
