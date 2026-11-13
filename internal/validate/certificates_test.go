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
	"crypto/x509"
	"encoding/pem"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/certchain"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

type testChain struct {
	leaf, ca, other *x509.Certificate
}

func newTestChain(t *testing.T) testChain {
	t.Helper()
	caKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ca, err := mock.GenerateNamedCACert(caKey, "CA")
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := mock.GenerateLeafCertWithOptions(caKey, ca, &leafKey.PublicKey, mock.LeafCertOptions{CommonName: "Leaf", CRLDistributionPoints: []string{"https://ca.example/crl"}})
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	other, err := mock.GenerateNamedCACert(otherKey, "Other CA")
	if err != nil {
		t.Fatal(err)
	}
	return testChain{leaf: leaf, ca: ca, other: other}
}

func pemOf(certs ...*x509.Certificate) string {
	var b strings.Builder
	for _, c := range certs {
		b.Write(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
	}
	return b.String()
}

func TestCredentialReadsPastedCertificates(t *testing.T) {
	chain := newTestChain(t)

	result, err := Credential(pemOf(chain.leaf, chain.ca), Trust{}, Options{Offline: true})
	if err != nil {
		t.Fatal(err)
	}

	if result.Format != FormatX509 || len(result.Certificates) != 2 || !result.Certificates[0].Equal(chain.leaf) {
		t.Fatalf("format %s with %d certificates, want the leaf and the CA", result.Format, len(result.Certificates))
	}
	for _, name := range []string{CheckExpiry, CheckSignature} {
		if c, _ := result.Find(name); c.Status != Pass {
			t.Errorf("%s check %+v, want pass", name, c)
		}
	}
}

func TestCredentialNamesABrokenPastedCertificate(t *testing.T) {
	chain := newTestChain(t)
	broken := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: chain.ca.Raw[:len(chain.ca.Raw)-8]}))

	_, err := Credential(pemOf(chain.leaf)+broken, Trust{}, Options{Offline: true})

	if err == nil || !strings.HasPrefix(err.Error(), "certificate 2 of 2: ") {
		t.Errorf("error %v, want the parse error of certificate 2", err)
	}
}

func TestCertificateChecks(t *testing.T) {
	chain := newTestChain(t)
	tests := []struct {
		name      string
		certs     []*x509.Certificate
		now       time.Time
		check     string
		status    string
		detailHas string
	}{
		{"chain", []*x509.Certificate{chain.leaf, chain.ca}, time.Time{}, CheckSignature, Pass, "Each certificate is signed by the next one"},
		{"self-signed", []*x509.Certificate{chain.ca}, time.Time{}, CheckSignature, Pass, "self-signed"},
		{"leaf alone", []*x509.Certificate{chain.leaf}, time.Time{}, CheckSignature, Skipped, "Needs the issuer certificate"},
		{"wrong issuer", []*x509.Certificate{chain.leaf, chain.other}, time.Time{}, CheckSignature, Fail, "Certificate 1 is not signed by certificate 2"},
		{"root first", []*x509.Certificate{chain.ca, chain.leaf}, time.Time{}, CheckSignature, Fail, "A chain lists the leaf first"},
		{"valid", []*x509.Certificate{chain.leaf}, time.Time{}, CheckExpiry, Pass, "Valid until"},
		{"expired", []*x509.Certificate{chain.leaf, chain.ca}, chain.leaf.NotAfter.Add(time.Hour), CheckExpiry, Fail, "Certificate 1 expired"},
		{"not yet valid", []*x509.Certificate{chain.leaf}, chain.leaf.NotBefore.Add(-time.Hour), CheckExpiry, Fail, "Certificate 1 is not valid before"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := Certificates(tt.certs, Trust{}, Options{Offline: true, Now: tt.now})
			c, ok := result.Find(tt.check)
			if !ok || c.Status != tt.status || !strings.Contains(c.Detail, tt.detailHas) {
				t.Errorf("%s check %+v, want %s with %q", tt.check, c, tt.status, tt.detailHas)
			}
		})
	}
}

func TestPastedCertificatesGetTheRevocationCheck(t *testing.T) {
	chain := newTestChain(t)
	var read []*x509.Certificate
	trust := Trust{CertificateProblems: func(certs []*x509.Certificate) []certchain.RevocationProblem {
		read = certs
		return nil
	}}

	result := Certificates([]*x509.Certificate{chain.leaf, chain.ca}, trust, Options{})

	if c, _ := result.Find(CheckCertificates); c.Status != Pass || len(read) != 2 {
		t.Errorf("revocation check %+v after reading %d certificates, want pass after reading the chain", c, len(read))
	}
}
