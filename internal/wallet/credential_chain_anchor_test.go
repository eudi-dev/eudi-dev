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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func anchorTestCertificate(t *testing.T, name string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: parent == nil, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	signer, issuer := key, template
	if parent != nil {
		signer, issuer = parentKey, parent
	}
	der, err := x509.CreateCertificate(rand.Reader, template, issuer, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert, key
}

func TestChainAnchorFindsTheListedIssuerOfTheChain(t *testing.T) {
	ca, caKey := anchorTestCertificate(t, "Issuer CA", nil, nil)
	other, _ := anchorTestCertificate(t, "Other CA", nil, nil)
	leaf, _ := anchorTestCertificate(t, "Issuer", ca, caKey)

	if got := chainAnchor([]*x509.Certificate{leaf}, []*x509.Certificate{other, ca}); got == nil || !got.Equal(ca) {
		t.Errorf("anchor = %v, want the issuer CA", got)
	}
	if got := chainAnchor([]*x509.Certificate{leaf}, []*x509.Certificate{other}); got != nil {
		t.Errorf("anchor = %v, want none for an unrelated list", got)
	}
	if got := chainAnchor([]*x509.Certificate{leaf, ca}, []*x509.Certificate{ca}); got != nil {
		t.Errorf("anchor = %v, want none when the chain holds it", got)
	}
}
