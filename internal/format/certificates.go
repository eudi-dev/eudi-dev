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

package format

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// Certificates reads X.509 certificates in the forms people copy them: PEM
// blocks, an x5c array (RFC 7515 §4.1.6) or one x5c entry, and DER in base64,
// base64url or hex. PEM blocks other than certificates, such as the key next
// to a certificate, are skipped. Every certificate must parse.
func Certificates(input string) ([]*x509.Certificate, error) {
	input = strings.TrimSpace(input)
	switch {
	case input == "":
		return nil, errNoCertificate
	case strings.Contains(input, "-----BEGIN CERTIFICATE-----"):
		return pemCertificates(input)
	case strings.HasPrefix(input, "["):
		var entries []string
		if json.Unmarshal([]byte(input), &entries) != nil || len(entries) == 0 {
			return nil, errNoCertificate
		}
		certs := make([]*x509.Certificate, 0, len(entries))
		for i, entry := range entries {
			cert, err := derCertificate(entry)
			if errors.Is(err, errNoCertificate) {
				// Arrays of other values, such as a vp_token, are not x5c.
				return nil, err
			}
			if err != nil {
				return nil, &CertificateError{Index: i + 1, Count: len(entries), Err: err}
			}
			certs = append(certs, cert)
		}
		return certs, nil
	}
	cert, err := derCertificate(input)
	if err != nil {
		return nil, err
	}
	return []*x509.Certificate{cert}, nil
}

var errNoCertificate = errors.New("the input is not a certificate")

// CertificateError reports a PEM CERTIFICATE block or an x5c entry that
// doesn't parse. A bare base64 value that fails to parse can be another
// format, such as an mdoc, so it gives a plain parse error instead.
type CertificateError struct {
	// Index counts from 1 in the order of the input.
	Index, Count int
	Err          error
}

func (e *CertificateError) Error() string {
	return fmt.Sprintf("certificate %d of %d: %v", e.Index, e.Count, e.Err)
}

func (e *CertificateError) Unwrap() error { return e.Err }

func pemCertificates(input string) ([]*x509.Certificate, error) {
	// Splitting at each marker keeps the numbering right when a block's base64
	// is broken, because pem.Decode skips such a block without an error.
	const marker = "-----BEGIN CERTIFICATE-----"
	blocks := strings.Split(input, marker)[1:]
	certs := make([]*x509.Certificate, 0, len(blocks))
	for i, text := range blocks {
		block, _ := pem.Decode([]byte(marker + text))
		if block == nil {
			return nil, &CertificateError{Index: i + 1, Count: len(blocks), Err: errors.New("the PEM block doesn't decode")}
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, &CertificateError{Index: i + 1, Count: len(blocks), Err: err}
		}
		certs = append(certs, cert)
	}
	return certs, nil
}

// derCertificate tries hex, base64 and base64url. Only bytes that start with
// an ASN.1 SEQUENCE (X.690 §8.9, tag 0x30) count as a certificate. For such
// bytes it returns the parse error, so the user learns, for example, that the
// curve is unsupported. Hex comes first because hex digits are base64
// characters too, while base64 DER starts with "MI", which is not hex.
func derCertificate(encoded string) (*x509.Certificate, error) {
	encoded = strings.Join(strings.Fields(encoded), "")
	var parseErr error
	for _, decode := range []func(string) ([]byte, error){hex.DecodeString, DecodeBase64Std, DecodeBase64URL} {
		der, err := decode(encoded)
		if err != nil || len(der) == 0 || der[0] != 0x30 {
			continue
		}
		cert, err := x509.ParseCertificate(der)
		if err == nil {
			return cert, nil
		}
		if parseErr == nil {
			parseErr = err
		}
	}
	if parseErr == nil {
		return nil, errNoCertificate
	}
	return nil, parseErr
}
