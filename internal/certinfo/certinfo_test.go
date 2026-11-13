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

package certinfo

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net/url"
	"slices"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

func TestDescribeAnAccessCertificate(t *testing.T) {
	caKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ca, err := mock.GenerateNamedCACert(caKey, "Access CA")
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := mock.GenerateLeafCertWithOptions(caKey, ca, &leafKey.PublicKey, mock.LeafCertOptions{
		CommonName:             "Shop",
		Country:                "DE",
		Organization:           "Shop GmbH",
		OrganizationalUnit:     "checkout",
		OrganizationIdentifier: "NTRDE-HRB1",
		Role:                   mock.AccessCertificate,
		DNSNames:               []string{"shop.example"},
		URIs:                   []*url.URL{{Scheme: "https", Host: "shop.example"}},
		CRLDistributionPoints:  []string{"https://ca.example/crl"},
	})
	if err != nil {
		t.Fatal(err)
	}

	got := Describe(cert)

	if want := "C=DE, O=Shop GmbH, OU=checkout, CN=Shop, organizationIdentifier=NTRDE-HRB1"; got.Subject != want {
		t.Errorf("subject %q, want %q", got.Subject, want)
	}
	if got.Issuer != Describe(ca).Subject {
		t.Errorf("issuer %q, want the CA subject %q", got.Issuer, Describe(ca).Subject)
	}
	if got.SelfSigned || got.CA {
		t.Errorf("self-signed %v, CA %v, want an end entity", got.SelfSigned, got.CA)
	}
	if got.PublicKey != "EC P-256" || got.SignatureAlgorithm != "ECDSA-SHA256" {
		t.Errorf("key %q, signature %q", got.PublicKey, got.SignatureAlgorithm)
	}
	if !slices.Equal(got.KeyUsage, []string{"digitalSignature"}) {
		t.Errorf("key usage %v", got.KeyUsage)
	}
	if !slices.Equal(got.SubjectAltNames, []string{"DNS:shop.example", "URI:https://shop.example"}) {
		t.Errorf("subject alt names %v", got.SubjectAltNames)
	}
	if !slices.Equal(got.Policies, []string{"0.4.0.194118.1.2"}) {
		t.Errorf("policies %v", got.Policies)
	}
	if !slices.Equal(got.CRLDistribution, []string{"https://ca.example/crl"}) {
		t.Errorf("CRL distribution points %v", got.CRLDistribution)
	}
	if got.SubjectKeyID != hex.EncodeToString(cert.SubjectKeyId) || got.AuthorityKeyID != hex.EncodeToString(ca.SubjectKeyId) {
		t.Errorf("key ids %s / %s", got.SubjectKeyID, got.AuthorityKeyID)
	}
	if fingerprint := sha256.Sum256(cert.Raw); got.SHA256Fingerprint != hex.EncodeToString(fingerprint[:]) {
		t.Errorf("fingerprint %s", got.SHA256Fingerprint)
	}
	if block, _ := pem.Decode([]byte(got.PEM)); block == nil || string(block.Bytes) != string(cert.Raw) {
		t.Errorf("PEM %q is not the certificate", got.PEM)
	}
	if !slices.ContainsFunc(got.Extensions, func(e Extension) bool { return e.Name == "certificatePolicies" && e.OID == "2.5.29.32" }) {
		t.Errorf("extensions %+v, want certificatePolicies", got.Extensions)
	}
}

func TestDescribeACAAndADocumentSigner(t *testing.T) {
	caKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	ca, err := mock.GenerateNamedCACert(caKey, "IACA")
	if err != nil {
		t.Fatal(err)
	}
	signerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := mock.GenerateLeafCertWithOptions(caKey, ca, &signerKey.PublicKey, mock.LeafCertOptions{MdocDocumentSigner: true})
	if err != nil {
		t.Fatal(err)
	}

	root := Describe(ca)
	if !root.SelfSigned || !root.CA || root.MaxPathLength == nil || *root.MaxPathLength != 0 {
		t.Errorf("CA: self-signed %v, CA %v, path length %v", root.SelfSigned, root.CA, root.MaxPathLength)
	}
	if !slices.Contains(root.KeyUsage, "keyCertSign") {
		t.Errorf("CA key usage %v", root.KeyUsage)
	}
	if usage := Describe(signer).ExtendedKeyUsage; !slices.Equal(usage, []string{"mdlDS"}) {
		t.Errorf("document signer extended key usage %v, want mdlDS", usage)
	}
	if got := DescribeAll([]*x509.Certificate{signer, ca}); len(got) != 2 || got[1].Subject != root.Subject {
		t.Errorf("chain %+v, want the signer and then the CA", got)
	}
}

func TestSelfSignedEndEntity(t *testing.T) {
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "verifier.example"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		DNSNames:              []string{"verifier.example"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}

	if got := Describe(cert); !got.SelfSigned || got.CA {
		t.Errorf("self-signed %v, CA %v, want a self-signed end entity", got.SelfSigned, got.CA)
	}
}

func TestDistinguishedNameEscapesValues(t *testing.T) {
	commonName := asn1.ObjectIdentifier{2, 5, 4, 3}
	organization := asn1.ObjectIdentifier{2, 5, 4, 10}
	unit := asn1.ObjectIdentifier{2, 5, 4, 11}
	raw, err := asn1.Marshal(pkix.RDNSequence{
		{{Type: organization, Value: "Shop, Inc."}},
		{{Type: unit, Value: "a+b"}, {Type: commonName, Value: "#1 "}},
		{{Type: asn1.ObjectIdentifier{2, 5, 4, 45}, Value: asn1.BitString{Bytes: []byte{0x80}, BitLength: 1}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := distinguishedName(raw, pkix.Name{}), `O=Shop\, Inc., CN=\#1\ +OU=a\+b, 2.5.4.45=#03020780`; got != want {
		t.Errorf("name %q, want %q", got, want)
	}
}
