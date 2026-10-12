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

// Package validate verifies X.509 certificate chains against trust list anchors.
package validate

import (
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/eudi-dev/eudi-dev/v2/internal/format"
	"github.com/eudi-dev/eudi-dev/v2/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v2/internal/trustlist"
)

func ValidateCertChain(certs []*x509.Certificate, tlCerts []trustlist.CertInfo) (crypto.PublicKey, error) {
	leaf := certs[0]

	roots := x509.NewCertPool()
	for _, ci := range tlCerts {
		tlCert, err := x509.ParseCertificate(ci.Raw)
		if err != nil {
			continue
		}
		roots.AddCert(tlCert)
	}

	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}

	_, err := leaf.Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	if err != nil {
		return nil, fmt.Errorf("certificate chain not trusted: %w", err)
	}

	return leaf.PublicKey, nil
}

// ExtractAndValidateX5C extracts the leaf certificate public key from a JWT x5c header
// and validates that the certificate chain is anchored in the trust list.
// Returns nil, nil if no x5c header is present.
func ExtractAndValidateX5C(header map[string]any, tlCerts []trustlist.CertInfo) (crypto.PublicKey, error) {
	if len(tlCerts) == 0 {
		return nil, nil
	}
	certs, err := parseX5CCerts(header)
	if err != nil || len(certs) == 0 {
		return nil, err
	}
	return ValidateCertChain(certs, tlCerts)
}

// ExtractX5CLeafKey returns the public key of the first x5c certificate
// without validating the chain. It allows offline signature checks without
// trust anchors. Such a check proves integrity only.
// Returns nil, nil if no x5c header is present.
func ExtractX5CLeafKey(header map[string]any) (crypto.PublicKey, error) {
	certs, err := parseX5CCerts(header)
	if err != nil || len(certs) == 0 {
		return nil, err
	}
	return certs[0].PublicKey, nil
}

// X5CCertificates returns the x5c certificates of a JOSE header, leaf first.
// It returns nothing when the header has none. It is the JOSE counterpart of
// ExtractMDOCX5ChainCertificates.
func X5CCertificates(header map[string]any) ([]*x509.Certificate, error) {
	return parseX5CCerts(header)
}

func parseX5CCerts(header map[string]any) ([]*x509.Certificate, error) {
	x5cRaw, ok := header["x5c"].([]any)
	if !ok || len(x5cRaw) == 0 {
		return nil, nil
	}

	var certs []*x509.Certificate
	for _, entry := range x5cRaw {
		b64, ok := entry.(string)
		if !ok {
			return nil, fmt.Errorf("x5c entry is not a string")
		}
		der, err := format.DecodeBase64Std(b64)
		if err != nil {
			return nil, fmt.Errorf("decoding x5c certificate: %w", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parsing x5c certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// ExtractAndValidateMDOCX5Chain extracts the leaf certificate public key from a COSE
// x5chain (label 33) in the unprotected header and validates the chain against the trust list.
// Returns nil, nil if no x5chain is present.
func ExtractAndValidateMDOCX5Chain(doc *mdoc.Document, tlCerts []trustlist.CertInfo) (crypto.PublicKey, error) {
	if len(tlCerts) == 0 {
		return nil, nil
	}
	certs, err := parseMDOCX5ChainCerts(doc)
	if err != nil || len(certs) == 0 {
		return nil, err
	}
	return ValidateCertChain(certs, tlCerts)
}

// ExtractMDOCX5ChainLeafKey returns the public key of the first x5chain
// certificate without validating the chain. It serves offline signature checks
// without trust anchors. Returns nil, nil if no x5chain is present.
func ExtractMDOCX5ChainLeafKey(doc *mdoc.Document) (crypto.PublicKey, error) {
	certs, err := parseMDOCX5ChainCerts(doc)
	if err != nil || len(certs) == 0 {
		return nil, err
	}
	return certs[0].PublicKey, nil
}

// ExtractMDOCX5ChainCertificates returns the certificates in the x5chain
// header (label 33) of an mdoc.
func ExtractMDOCX5ChainCertificates(doc *mdoc.Document) ([]*x509.Certificate, error) {
	return parseMDOCX5ChainCerts(doc)
}

// parseMDOCX5ChainCerts decodes the certificates of a COSE x5chain (label 33)
// in the unprotected header.
func parseMDOCX5ChainCerts(doc *mdoc.Document) ([]*x509.Certificate, error) {
	if doc.IssuerAuth == nil || doc.IssuerAuth.UnprotectedHeader == nil {
		return nil, nil
	}

	x5chainRaw, ok := doc.IssuerAuth.UnprotectedHeader[int64(33)]
	if !ok {
		x5chainRaw, ok = doc.IssuerAuth.UnprotectedHeader[uint64(33)]
		if !ok {
			return nil, nil
		}
	}

	// RFC 9360 §2 allows a single certificate as a bare byte string or an array of them.
	var certDERs [][]byte
	switch v := x5chainRaw.(type) {
	case []byte:
		certDERs = append(certDERs, v)
	case []any:
		for _, entry := range v {
			if b, ok := entry.([]byte); ok {
				certDERs = append(certDERs, b)
			}
		}
	default:
		return nil, nil
	}

	if len(certDERs) == 0 {
		return nil, nil
	}

	var certs []*x509.Certificate
	for _, der := range certDERs {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parsing x5chain certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}
