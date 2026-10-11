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

package mock

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/keys"
)

func TestGenerateKey_ReturnsP256(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if key.Curve != elliptic.P256() {
		t.Errorf("expected P-256 curve, got %s", key.Curve.Params().Name)
	}
}

func TestGenerateKey_UniqueKeys(t *testing.T) {
	key1, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	key2, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if key1.Equal(key2) {
		t.Error("two generated keys should not be identical")
	}
}

func TestPublicKeyJWK_ValidJSON(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	jwkStr := PublicKeyJWK(&key.PublicKey)

	var jwk map[string]string
	if err := json.Unmarshal([]byte(jwkStr), &jwk); err != nil {
		t.Fatalf("PublicKeyJWK returned invalid JSON: %v", err)
	}

	if jwk["kty"] != "EC" {
		t.Errorf("expected kty EC, got %s", jwk["kty"])
	}
	if jwk["crv"] != "P-256" {
		t.Errorf("expected crv P-256, got %s", jwk["crv"])
	}
	if jwk["x"] == "" {
		t.Error("missing x coordinate")
	}
	if jwk["y"] == "" {
		t.Error("missing y coordinate")
	}
	if _, ok := jwk["d"]; ok {
		t.Error("public JWK should not contain d parameter")
	}
}

func TestPublicKeyJWK_RoundTripParse(t *testing.T) {
	key, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	jwkStr := PublicKeyJWK(&key.PublicKey)

	parsed, err := keys.ParsePublicKey([]byte(jwkStr))
	if err != nil {
		t.Fatalf("ParsePublicKey from JWK: %v", err)
	}

	if parsed == nil {
		t.Fatal("parsed key is nil")
	}
}

func mustCertPair(t *testing.T, opts LeafCertOptions) (*x509.Certificate, *x509.Certificate) {
	t.Helper()
	caKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	caCert, err := GenerateCACert(caKey)
	if err != nil {
		t.Fatalf("GenerateCACert: %v", err)
	}
	leafKey, err := GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	leaf, err := GenerateLeafCertWithOptions(caKey, caCert, &leafKey.PublicKey, opts)
	if err != nil {
		t.Fatalf("GenerateLeafCertWithOptions: %v", err)
	}
	return caCert, leaf
}

func findExtension(cert *x509.Certificate, id asn1.ObjectIdentifier) (pkix.Extension, bool) {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal(id) {
			return ext, true
		}
	}
	return pkix.Extension{}, false
}

// TestGenerateCACert_IACAProfile checks the IACA root certificate profile of
// ISO/IEC 18013-5 Table B.1.
func TestGenerateCACert_IACAProfile(t *testing.T) {
	caCert, _ := mustCertPair(t, LeafCertOptions{})

	if got := caCert.Subject.Country; len(got) != 1 || got[0] != DefaultCertificateCountry {
		t.Errorf("subject country = %v, want [%s]", got, DefaultCertificateCountry)
	}
	if caCert.Subject.CommonName == "" {
		t.Error("subject commonName is empty")
	}
	if caCert.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Errorf("keyUsage = %v, want keyCertSign|cRLSign only", caCert.KeyUsage)
	}
	if !caCert.IsCA || !caCert.BasicConstraintsValid {
		t.Error("basicConstraints with cA=true is required")
	}
	if caCert.MaxPathLen != 0 || !caCert.MaxPathLenZero {
		t.Errorf("pathLenConstraint = %d (zero=%v), want an explicit 0", caCert.MaxPathLen, caCert.MaxPathLenZero)
	}
	if caCert.SerialNumber.Sign() != 1 {
		t.Error("serial number must be positive")
	}
	if len(caCert.SerialNumber.Bytes()) > 20 {
		t.Error("serial number must be at most 20 octets")
	}
	ian, ok := findExtension(caCert, asn1.ObjectIdentifier{2, 5, 29, 18})
	if !ok {
		t.Fatal("issuer alternative name extension is required")
	}
	if ian.Critical {
		t.Error("issuer alternative name must be non-critical")
	}
	if !bytes.Contains(ian.Value, []byte(issuerContactURI)) {
		t.Errorf("issuer alternative name does not carry the issuer contact URI %s", issuerContactURI)
	}
	wantSKI, err := subjectKeyIdentifier(caCert.PublicKey.(*ecdsa.PublicKey))
	if err != nil {
		t.Fatalf("subjectKeyIdentifier: %v", err)
	}
	if !bytes.Equal(caCert.SubjectKeyId, wantSKI) {
		t.Error("subject key identifier is not the SHA-1 hash of the subject public key")
	}
}

// TestGenerateLeafCert_DocumentSignerProfile checks the document signer
// certificate profile of ISO/IEC 18013-5 Table B.3.
func TestGenerateLeafCert_DocumentSignerProfile(t *testing.T) {
	caCert, leaf := mustCertPair(t, LeafCertOptions{
		CRLDistributionPoints: []string{"https://localhost:8086/api/crl"},
	})

	if got := leaf.Subject.Country; len(got) != 1 || got[0] != DefaultCertificateCountry {
		t.Errorf("subject country = %v, want [%s]", got, DefaultCertificateCountry)
	}
	if leaf.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("keyUsage = %v, want digitalSignature only", leaf.KeyUsage)
	}
	if leaf.BasicConstraintsValid {
		t.Error("an end-entity document signer certificate carries no basicConstraints")
	}
	wantSKI, err := subjectKeyIdentifier(leaf.PublicKey.(*ecdsa.PublicKey))
	if err != nil {
		t.Fatalf("subjectKeyIdentifier: %v", err)
	}
	if !bytes.Equal(leaf.SubjectKeyId, wantSKI) {
		t.Error("subject key identifier is not the SHA-1 hash of the subject public key")
	}
	if !bytes.Equal(leaf.AuthorityKeyId, caCert.SubjectKeyId) {
		t.Error("authority key identifier must carry the CA's subject key identifier")
	}
	eku, ok := findExtension(leaf, asn1.ObjectIdentifier{2, 5, 29, 37})
	if !ok {
		t.Fatal("extended key usage extension is required")
	}
	if !eku.Critical {
		t.Error("extended key usage must be critical")
	}
	foundMdlDS := false
	for _, oid := range leaf.UnknownExtKeyUsage {
		if oid.Equal(oidMdlDocumentSigner) {
			foundMdlDS = true
		}
	}
	if !foundMdlDS {
		t.Errorf("extended key usage must contain the mdlDS purpose %v", oidMdlDocumentSigner)
	}
	if got := leaf.CRLDistributionPoints; len(got) != 1 || got[0] != "https://localhost:8086/api/crl" {
		t.Errorf("CRL distribution points = %v, want the wallet CRL URL", got)
	}
	ian, ok := findExtension(leaf, asn1.ObjectIdentifier{2, 5, 29, 18})
	if !ok {
		t.Fatal("issuer alternative name extension is required")
	}
	if ian.Critical {
		t.Error("issuer alternative name must be non-critical")
	}
	if validity := leaf.NotAfter.Sub(leaf.NotBefore); validity > 457*24*time.Hour {
		t.Errorf("validity %v exceeds the 457-day maximum", validity)
	}
	for _, ext := range leaf.Extensions {
		if !ext.Critical {
			continue
		}
		if !ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 15}) && !ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 37}) {
			t.Errorf("extension %v is critical, only keyUsage and extendedKeyUsage may be", ext.Id)
		}
	}
}

func TestGenerateLeafCert_CountryFollowsOption(t *testing.T) {
	_, leaf := mustCertPair(t, LeafCertOptions{Country: "DE"})
	if got := leaf.Subject.Country; len(got) != 1 || got[0] != "DE" {
		t.Errorf("subject country = %v, want [DE]", got)
	}
}
