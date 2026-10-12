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

// Package certchain reads certificate chains from JOSE and COSE messages and
// verifies them against trust anchors.
package certchain

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
)

// coseX5Chain is the x5chain header label of RFC 9360 §2.
const coseX5Chain = 33

// Verify checks that the leaf chain[0] chains to one of the anchors, with the
// rest of the chain as intermediates. It returns the leaf.
func Verify(chain, anchors []*x509.Certificate) (*x509.Certificate, error) {
	if len(chain) == 0 {
		return nil, errors.New("no certificate")
	}
	if len(anchors) == 0 {
		return nil, errors.New("no trust anchor")
	}
	roots := x509.NewCertPool()
	for _, anchor := range anchors {
		roots.AddCert(anchor)
	}
	intermediates := x509.NewCertPool()
	for _, cert := range chain[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := chain[0].Verify(x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		return nil, err
	}
	return chain[0], nil
}

// FromX5C reads a JOSE x5c value, leaf first. RFC 7515 §4.1.6 makes it an
// array of base64 (not base64url) encoded DER certificates. A missing or empty
// value gives no certificates. A malformed entry is an error.
func FromX5C(value any) ([]*x509.Certificate, error) {
	var entries []string
	switch v := value.(type) {
	case nil:
		return nil, nil
	case []string:
		entries = v
	case []any:
		for _, entry := range v {
			s, ok := entry.(string)
			if !ok {
				return nil, fmt.Errorf("an x5c entry is a %T, RFC 7515 §4.1.6 requires a base64 string", entry)
			}
			entries = append(entries, s)
		}
	default:
		return nil, fmt.Errorf("the x5c header is a %T, RFC 7515 §4.1.6 requires an array", value)
	}
	certs := make([]*x509.Certificate, 0, len(entries))
	for _, b64 := range entries {
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

// FromCOSE reads the x5chain header (RFC 9360 §2) of a COSE message, leaf
// first. RFC 9360 §2 requires integrity protection of the end-entity
// certificate, so the protected bucket counts first. ISO 18013-5 §9.1.2.4
// places the chain of an MSO in the unprotected bucket. A header without
// x5chain gives no certificates. A malformed entry is an error.
func FromCOSE(protected, unprotected map[any]any) ([]*x509.Certificate, error) {
	value, present := headerValue(protected, coseX5Chain)
	if !present {
		value, present = headerValue(unprotected, coseX5Chain)
	}
	if !present {
		return nil, nil
	}

	// RFC 9360 §2: "If a single certificate is conveyed, it is placed in a
	// CBOR byte string. If multiple certificates are conveyed, a CBOR array of
	// byte strings is used".
	var ders [][]byte
	switch v := value.(type) {
	case []byte:
		ders = [][]byte{v}
	case [][]byte:
		ders = v
	case []any:
		for _, entry := range v {
			der, ok := entry.([]byte)
			if !ok {
				return nil, fmt.Errorf("an x5chain entry is a %T, RFC 9360 §2 requires a byte string", entry)
			}
			ders = append(ders, der)
		}
	default:
		return nil, fmt.Errorf("the x5chain header is a %T, RFC 9360 §2 requires a byte string or an array of them", value)
	}

	certs := make([]*x509.Certificate, 0, len(ders))
	for _, der := range ders {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, fmt.Errorf("parsing x5chain certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// headerValue looks up an integer COSE header label. A CBOR decoder gives a
// label as int64 or uint64, depending on its options.
func headerValue(h map[any]any, label int64) (any, bool) {
	for k, v := range h {
		switch key := k.(type) {
		case int64:
			if key == label {
				return v, true
			}
		case uint64:
			if key == uint64(label) {
				return v, true
			}
		case int:
			if int64(key) == label {
				return v, true
			}
		}
	}
	return nil, false
}

// OrganizationIdentifier returns the organizationIdentifier attribute (OID
// 2.5.4.97) of the certificate's subject.
func OrganizationIdentifier(cert *x509.Certificate) string {
	for _, attribute := range cert.Subject.Names {
		if attribute.Type.String() == "2.5.4.97" {
			value, _ := attribute.Value.(string)
			return value
		}
	}
	return ""
}

// WithoutSelfSignedAnchor removes a terminal self-signed root certificate from
// a chain for JOSE headers or JWK metadata.
func WithoutSelfSignedAnchor(chain []*x509.Certificate) []*x509.Certificate {
	if len(chain) == 0 {
		return nil
	}
	out := make([]*x509.Certificate, len(chain))
	copy(out, chain)
	last := out[len(out)-1]
	if bytes.Equal(last.RawSubject, last.RawIssuer) && last.CheckSignatureFrom(last) == nil {
		return out[:len(out)-1]
	}
	return out
}

// X5C is the x5c header value of a chain: base64 DER certificates, leaf
// first, without a self-signed anchor. A chain of only the anchor keeps it.
func X5C(certs []*x509.Certificate) []string {
	chain := WithoutSelfSignedAnchor(certs)
	if len(chain) == 0 && len(certs) > 0 {
		chain = certs
	}
	x5c := make([]string, 0, len(chain))
	for _, cert := range chain {
		x5c = append(x5c, base64.StdEncoding.EncodeToString(cert.Raw))
	}
	return x5c
}
