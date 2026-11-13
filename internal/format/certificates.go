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
		for _, entry := range entries {
			cert, err := derCertificate(entry)
			if err != nil {
				return nil, err
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

func pemCertificates(input string) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := []byte(input)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, errNoCertificate
	}
	return certs, nil
}

// derCertificate gives the parse error of the first encoding that decodes,
// so a certificate with an unsupported curve names that curve. Hex comes
// first because hex digits are base64 characters too, while base64 DER
// starts with "MI", which is not hex.
func derCertificate(encoded string) (*x509.Certificate, error) {
	encoded = strings.Join(strings.Fields(encoded), "")
	var parseErr error
	for _, decode := range []func(string) ([]byte, error){hex.DecodeString, DecodeBase64Std, DecodeBase64URL} {
		der, err := decode(encoded)
		if err != nil {
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
