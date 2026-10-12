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
	"encoding/base64"
	"math/big"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
	"github.com/eudi-dev/eudi-dev/v3/internal/mdoc"
)

func generateCACert(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	return caCert, caKey, caDER
}

func generateLeafCert(t *testing.T, caCert *x509.Certificate, caKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
	t.Helper()
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}

	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	return leafCert, leafKey, leafDER
}

func TestValidateCertChain_ValidChain(t *testing.T) {
	caCert, caKey, caDER := generateCACert(t)
	_, _, leafDER := generateLeafCert(t, caCert, caKey)

	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	tlCerts := []lote.CertInfo{
		{PublicKey: caCert.PublicKey, Raw: caDER},
	}

	key, err := ValidateCertChain([]*x509.Certificate{leafCert}, tlCerts)
	if err != nil {
		t.Fatalf("ValidateCertChain() error: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestValidateCertChain_InvalidChain(t *testing.T) {
	caCert, caKey, _ := generateCACert(t)
	_, _, leafDER := generateLeafCert(t, caCert, caKey)

	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	_, _, otherCADER := generateCACert(t)
	otherCACert, _ := x509.ParseCertificate(otherCADER)

	tlCerts := []lote.CertInfo{
		{PublicKey: otherCACert.PublicKey, Raw: otherCADER},
	}

	_, err = ValidateCertChain([]*x509.Certificate{leafCert}, tlCerts)
	if err == nil {
		t.Error("expected error for untrusted chain")
	}
}

func TestValidateCertChain_WithIntermediate(t *testing.T) {
	rootCert, rootKey, rootDER := generateCACert(t)

	intKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "Test Intermediate CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	intDER, err := x509.CreateCertificate(rand.Reader, intTemplate, rootCert, &intKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	intCert, _ := x509.ParseCertificate(intDER)

	_, _, leafDER := generateLeafCert(t, intCert, intKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	tlCerts := []lote.CertInfo{
		{PublicKey: rootCert.PublicKey, Raw: rootDER},
	}

	key, err := ValidateCertChain([]*x509.Certificate{leafCert, intCert}, tlCerts)
	if err != nil {
		t.Fatalf("ValidateCertChain() error: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestValidateCertChain_InvalidTrustListCert(t *testing.T) {
	caCert, caKey, _ := generateCACert(t)
	_, _, leafDER := generateLeafCert(t, caCert, caKey)
	leafCert, _ := x509.ParseCertificate(leafDER)

	tlCerts := []lote.CertInfo{
		{PublicKey: nil, Raw: []byte("not a certificate")},
	}

	_, err := ValidateCertChain([]*x509.Certificate{leafCert}, tlCerts)
	if err == nil {
		t.Error("expected error when trust list has no valid certs")
	}
}

func TestExtractAndValidateX5C_NoX5C(t *testing.T) {
	header := map[string]any{"alg": "ES256"}
	key, err := ExtractAndValidateX5C(header, []lote.CertInfo{{Raw: []byte("x")}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != nil {
		t.Error("expected nil key when no x5c header")
	}
}

func TestExtractAndValidateX5C_EmptyTrustList(t *testing.T) {
	header := map[string]any{"x5c": []any{"abc"}}
	key, err := ExtractAndValidateX5C(header, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != nil {
		t.Error("expected nil key when no trust list certs")
	}
}

func TestExtractAndValidateX5C_NonStringEntry(t *testing.T) {
	header := map[string]any{"x5c": []any{12345}}
	tlCerts := []lote.CertInfo{{Raw: []byte("x")}}

	_, err := ExtractAndValidateX5C(header, tlCerts)
	if err == nil {
		t.Error("expected error for non-string x5c entry")
	}
}

func TestExtractAndValidateX5C_InvalidBase64(t *testing.T) {
	header := map[string]any{"x5c": []any{"not-valid-base64!!!"}}
	tlCerts := []lote.CertInfo{{Raw: []byte("x")}}

	_, err := ExtractAndValidateX5C(header, tlCerts)
	if err == nil {
		t.Error("expected error for invalid base64")
	}
}

func TestExtractAndValidateX5C_ValidBase64InvalidDER(t *testing.T) {
	header := map[string]any{"x5c": []any{"bm90IGEgY2VydA=="}}
	tlCerts := []lote.CertInfo{{Raw: []byte("x")}}

	_, err := ExtractAndValidateX5C(header, tlCerts)
	if err == nil {
		t.Error("expected error for invalid DER data")
	}
}

func TestExtractAndValidateX5C_ValidChain(t *testing.T) {
	caCert, caKey, caDER := generateCACert(t)
	_, _, leafDER := generateLeafCert(t, caCert, caKey)

	// RFC 7515 §4.1.6: x5c entries are base64 (not base64url) DER, leaf first.
	leafB64 := base64.StdEncoding.EncodeToString(leafDER)
	caB64 := base64.StdEncoding.EncodeToString(caDER)

	header := map[string]any{
		"x5c": []any{leafB64, caB64},
	}
	tlCerts := []lote.CertInfo{
		{PublicKey: caCert.PublicKey, Raw: caDER},
	}

	key, err := ExtractAndValidateX5C(header, tlCerts)
	if err != nil {
		t.Fatalf("ExtractAndValidateX5C() error: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
	if _, ok := key.(*ecdsa.PublicKey); !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", key)
	}
}

func TestExtractX5CLeafKey_WorksWithoutTrustList(t *testing.T) {
	caCert, caKey, caDER := generateCACert(t)
	leafCert, _, leafDER := generateLeafCert(t, caCert, caKey)

	header := map[string]any{
		"x5c": []any{
			base64.StdEncoding.EncodeToString(leafDER),
			base64.StdEncoding.EncodeToString(caDER),
		},
	}

	key, err := ExtractX5CLeafKey(header)
	if err != nil {
		t.Fatalf("ExtractX5CLeafKey() error: %v", err)
	}
	leafPub, ok := key.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", key)
	}
	if !leafPub.Equal(leafCert.PublicKey) {
		t.Error("expected the leaf certificate's key, got a different key")
	}

	if key, err := ExtractX5CLeafKey(map[string]any{}); err != nil || key != nil {
		t.Errorf("expected nil, nil without x5c, got %v, %v", key, err)
	}
}

func TestExtractAndValidateMDOCX5Chain_NilIssuerAuth(t *testing.T) {
	doc := &mdoc.Document{}
	key, err := ExtractAndValidateMDOCX5Chain(doc, []lote.CertInfo{{Raw: []byte("x")}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != nil {
		t.Error("expected nil key for nil IssuerAuth")
	}
}

func TestExtractAndValidateMDOCX5Chain_NilUnprotectedHeader(t *testing.T) {
	doc := &mdoc.Document{
		IssuerAuth: &mdoc.IssuerAuth{},
	}
	key, err := ExtractAndValidateMDOCX5Chain(doc, []lote.CertInfo{{Raw: []byte("x")}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != nil {
		t.Error("expected nil key for nil UnprotectedHeader")
	}
}

func TestExtractAndValidateMDOCX5Chain_NoX5Chain(t *testing.T) {
	doc := &mdoc.Document{
		IssuerAuth: &mdoc.IssuerAuth{
			UnprotectedHeader: map[any]any{
				int64(1): "something else",
			},
		},
	}
	key, err := ExtractAndValidateMDOCX5Chain(doc, []lote.CertInfo{{Raw: []byte("x")}})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != nil {
		t.Error("expected nil key when no x5chain key")
	}
}

func TestExtractAndValidateMDOCX5Chain_SingleCert(t *testing.T) {
	caCert, _, caDER := generateCACert(t)

	doc := &mdoc.Document{
		IssuerAuth: &mdoc.IssuerAuth{
			UnprotectedHeader: map[any]any{
				int64(33): caDER,
			},
		},
	}
	tlCerts := []lote.CertInfo{
		{PublicKey: caCert.PublicKey, Raw: caDER},
	}

	key, err := ExtractAndValidateMDOCX5Chain(doc, tlCerts)
	if err != nil {
		t.Fatalf("ExtractAndValidateMDOCX5Chain() error: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestExtractAndValidateMDOCX5Chain_CertArray(t *testing.T) {
	caCert, caKey, caDER := generateCACert(t)
	_, _, leafDER := generateLeafCert(t, caCert, caKey)

	doc := &mdoc.Document{
		IssuerAuth: &mdoc.IssuerAuth{
			UnprotectedHeader: map[any]any{
				int64(33): []any{leafDER, caDER},
			},
		},
	}
	tlCerts := []lote.CertInfo{
		{PublicKey: caCert.PublicKey, Raw: caDER},
	}

	key, err := ExtractAndValidateMDOCX5Chain(doc, tlCerts)
	if err != nil {
		t.Fatalf("ExtractAndValidateMDOCX5Chain() error: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestExtractAndValidateMDOCX5Chain_UnsupportedType(t *testing.T) {
	doc := &mdoc.Document{
		IssuerAuth: &mdoc.IssuerAuth{
			UnprotectedHeader: map[any]any{
				int64(33): "not bytes",
			},
		},
	}
	tlCerts := []lote.CertInfo{
		{Raw: []byte("x")},
	}

	// RFC 9360 §2 allows a byte string or an array of byte strings.
	if _, err := ExtractAndValidateMDOCX5Chain(doc, tlCerts); err == nil {
		t.Error("a text x5chain was accepted")
	}
}

func TestExtractAndValidateMDOCX5Chain_Uint64Key(t *testing.T) {
	caCert, _, caDER := generateCACert(t)

	doc := &mdoc.Document{
		IssuerAuth: &mdoc.IssuerAuth{
			UnprotectedHeader: map[any]any{
				uint64(33): caDER,
			},
		},
	}
	tlCerts := []lote.CertInfo{
		{PublicKey: caCert.PublicKey, Raw: caDER},
	}

	key, err := ExtractAndValidateMDOCX5Chain(doc, tlCerts)
	if err != nil {
		t.Fatalf("ExtractAndValidateMDOCX5Chain() error: %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
}

func TestExtractAndValidateMDOCX5Chain_EmptyTrustList(t *testing.T) {
	_, _, caDER := generateCACert(t)

	doc := &mdoc.Document{
		IssuerAuth: &mdoc.IssuerAuth{
			UnprotectedHeader: map[any]any{
				int64(33): caDER,
			},
		},
	}

	key, err := ExtractAndValidateMDOCX5Chain(doc, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if key != nil {
		t.Error("expected nil key for empty trust list")
	}
}
