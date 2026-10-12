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

// Package validate verifies credential signatures, certificate chains and issuer
// metadata, and checks issued credentials against HAIP 1.0.
package validate

import (
	"crypto"
	"crypto/x509"
	"fmt"

	"github.com/eudi-dev/eudi-dev/v3/internal/certchain"
	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
	"github.com/eudi-dev/eudi-dev/v3/internal/mdoc"
)

// ValidateCertChain checks that the leaf certs[0] chains to one of the trust
// list certificates and returns its public key.
func ValidateCertChain(certs []*x509.Certificate, tlCerts []lote.CertInfo) (crypto.PublicKey, error) {
	anchors, err := lote.Certificates(tlCerts)
	if err != nil {
		return nil, err
	}
	leaf, err := certchain.Verify(certs, anchors)
	if err != nil {
		return nil, fmt.Errorf("certificate chain not trusted: %w", err)
	}
	return leaf.PublicKey, nil
}

// ExtractAndValidateX5C extracts the leaf certificate public key from a JWT x5c header
// and validates that the certificate chain is anchored in the trust list.
// Returns nil, nil if no x5c header is present.
func ExtractAndValidateX5C(header map[string]any, tlCerts []lote.CertInfo) (crypto.PublicKey, error) {
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
// It returns nothing when the header has none.
func X5CCertificates(header map[string]any) ([]*x509.Certificate, error) {
	return parseX5CCerts(header)
}

func parseX5CCerts(header map[string]any) ([]*x509.Certificate, error) {
	return certchain.FromX5C(header["x5c"])
}

// ExtractAndValidateMDOCX5Chain extracts the leaf certificate public key from the
// COSE x5chain (label 33) and validates the chain against the trust list.
// Returns nil, nil if no x5chain is present.
func ExtractAndValidateMDOCX5Chain(doc *mdoc.Document, tlCerts []lote.CertInfo) (crypto.PublicKey, error) {
	if len(tlCerts) == 0 {
		return nil, nil
	}
	certs, err := parseMDOCX5ChainCerts(doc)
	if err != nil || len(certs) == 0 {
		return nil, err
	}
	return ValidateCertChain(certs, tlCerts)
}

// ExtractMDOCX5ChainCertificates returns the certificates in the x5chain
// header (label 33) of an mdoc.
func ExtractMDOCX5ChainCertificates(doc *mdoc.Document) ([]*x509.Certificate, error) {
	return parseMDOCX5ChainCerts(doc)
}

// parseMDOCX5ChainCerts reads the x5chain of the MSO's COSE_Sign1.
func parseMDOCX5ChainCerts(doc *mdoc.Document) ([]*x509.Certificate, error) {
	if doc == nil || doc.IssuerAuth == nil {
		return nil, nil
	}
	return certchain.FromCOSE(doc.IssuerAuth.ProtectedHeader, doc.IssuerAuth.UnprotectedHeader)
}
