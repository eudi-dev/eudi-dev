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

package provider

import (
	"crypto/x509"
	"encoding/asn1"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtemplate"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/storage"
)

type testRoot struct{ root Root }

func (r testRoot) Root() Root { return r.root }

func newTestSigner(t *testing.T) *Signer {
	t.Helper()
	caKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ca, err := mock.GenerateRootCACert(caKey)
	if err != nil {
		t.Fatal(err)
	}
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	keys := NewKeys(storage.NewMemory(), "", nil)
	leaf, err := keys.Certificate(caKey, ca, &issuerKey.PublicKey, mock.LeafCertOptions{}, false)
	if err != nil {
		t.Fatal(err)
	}
	return NewSigner(keys, testRoot{Root{IssuerKey: issuerKey, CAKey: caKey, Chain: []*x509.Certificate{leaf, ca}, IssuerURL: "https://wallet.example"}})
}

func extension(cert *x509.Certificate, id asn1.ObjectIdentifier) (bool, bool) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(id) {
			return true, ext.Critical
		}
	}
	return false, false
}

// ETSI EN 319 412-2 V2.5.1 GEN-4.3.3-2, through ETSI TS 119 412-6 V1.2.1
// PID-4.1-01 and WAL-5.1-01: "The certificate policies extension shall be
// present and shall contain the identifier of at least one certificate
// policy".
func TestTheProviderSignersNameACertificatePolicy(t *testing.T) {
	s := newTestSigner(t)
	pidKey, pid, err := s.ForList(CategoryList(credtemplate.CategoryPID), "", credtype.FormatSDJWT)
	if err != nil {
		t.Fatal(err)
	}
	walletKey, wallet, err := s.WalletProvider()
	if err != nil {
		t.Fatal(err)
	}
	if pidKey.Equal(walletKey) {
		t.Fatal("the PID and wallet provider signers share a key")
	}
	for name, cert := range map[string]*x509.Certificate{"PID": pid[0], "wallet provider": wallet[0]} {
		if len(cert.Policies) != 1 || !cert.Policies[0].Equal(mock.TestCertificatePolicy) {
			t.Errorf("%s signer policies %v, want %v", name, cert.Policies, mock.TestCertificatePolicy)
		}
	}
}

// ETSI EN 319 412-2 V2.5.1 GEN-4.3.10-1: the extended key usage "shall not
// be marked critical". ISO/IEC 18013-5 Table B.3 requires a critical mdlDS
// extended key usage of an mdoc document signer, so only that certificate
// has one.
func TestOnlyTheMdocSignerHasACriticalExtendedKeyUsage(t *testing.T) {
	s := newTestSigner(t)
	mdocKey, mdoc, err := s.ForList(CategoryList(credtemplate.CategoryPID), "", credtype.FormatMDOC)
	if err != nil {
		t.Fatal(err)
	}
	sdjwtKey, sdjwt, err := s.ForList(CategoryList(credtemplate.CategoryPID), "", credtype.FormatSDJWT)
	if err != nil {
		t.Fatal(err)
	}
	if !mdocKey.Equal(sdjwtKey) || !mdoc[1].Equal(sdjwt[1]) {
		t.Error("the two PID signer certificates differ in key or provider CA")
	}
	eku := asn1.ObjectIdentifier{2, 5, 29, 37}
	if present, critical := extension(mdoc[0], eku); !present || !critical {
		t.Errorf("mdoc document signer extended key usage present %t critical %t", present, critical)
	}
	if present, critical := extension(sdjwt[0], eku); present && critical {
		t.Error("the SD-JWT VC signer has a critical extended key usage")
	}
}
