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

package keys

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"

	"github.com/eudi-dev/eudi-dev/v2/internal/format"
)

// CertificatePEMToJWKS converts one or more PEM certificates into a JWKS JSON
// document. The public key of the first certificate becomes the JWK. The full
// chain is embedded as x5c.
func CertificatePEMToJWKS(pemData []byte) ([]byte, error) {
	certs, err := ParseCertificatesPEM(pemData)
	if err != nil {
		return nil, err
	}
	jwk, err := CertificateJWK(certs)
	if err != nil {
		return nil, err
	}
	out, err := json.MarshalIndent(map[string]any{"keys": []any{jwk}}, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("encoding JWKS: %w", err)
	}
	return append(out, '\n'), nil
}

// CertificateJWK builds a public JWK for the first certificate in the chain. It
// embeds the whole chain as x5c and the leaf hash as x5t#S256.
func CertificateJWK(certs []*x509.Certificate) (map[string]any, error) {
	if len(certs) == 0 {
		return nil, fmt.Errorf("no certificates found")
	}
	leaf := certs[0]

	jwk, alg, err := publicKeyJWKParams(leaf.PublicKey)
	if err != nil {
		return nil, err
	}

	kid, err := jwkThumbprint(jwk)
	if err != nil {
		return nil, err
	}
	jwk["kid"] = kid
	jwk["use"] = "sig"
	jwk["alg"] = alg

	x5c := make([]string, len(certs))
	for i, cert := range certs {
		x5c[i] = base64.StdEncoding.EncodeToString(cert.Raw)
	}
	jwk["x5c"] = x5c
	leafSum := sha256.Sum256(leaf.Raw)
	jwk["x5t#S256"] = format.EncodeBase64URL(leafSum[:])
	return jwk, nil
}

func publicKeyJWKParams(pub any) (map[string]any, string, error) {
	switch key := pub.(type) {
	case *ecdsa.PublicKey:
		var crv, alg string
		switch key.Curve {
		case elliptic.P256():
			crv, alg = "P-256", "ES256"
		case elliptic.P384():
			crv, alg = "P-384", "ES384"
		case elliptic.P521():
			crv, alg = "P-521", "ES512"
		default:
			return nil, "", fmt.Errorf("unsupported EC curve: %s", key.Curve.Params().Name)
		}
		x, y, err := format.ECPublicCoords(key)
		if err != nil {
			return nil, "", err
		}
		return map[string]any{
			"kty": "EC",
			"crv": crv,
			"x":   format.EncodeBase64URL(x),
			"y":   format.EncodeBase64URL(y),
		}, alg, nil
	case *rsa.PublicKey:
		return map[string]any{
			"kty": "RSA",
			"n":   format.EncodeBase64URL(key.N.Bytes()),
			"e":   format.EncodeBase64URL(bigEndianInt(key.E)),
		}, "RS256", nil
	default:
		return nil, "", fmt.Errorf("unsupported certificate public key type %T", pub)
	}
}

// jwkThumbprint computes the RFC 7638 thumbprint over the required members.
func jwkThumbprint(jwk map[string]any) (string, error) {
	var canonical string
	switch jwk["kty"] {
	case "EC":
		canonical = fmt.Sprintf(`{"crv":%q,"kty":"EC","x":%q,"y":%q}`, jwk["crv"], jwk["x"], jwk["y"])
	case "RSA":
		canonical = fmt.Sprintf(`{"e":%q,"kty":"RSA","n":%q}`, jwk["e"], jwk["n"])
	default:
		return "", fmt.Errorf("unsupported JWK key type: %v", jwk["kty"])
	}
	sum := sha256.Sum256([]byte(canonical))
	return format.EncodeBase64URL(sum[:]), nil
}

func bigEndianInt(n int) []byte {
	var out []byte
	for n > 0 {
		out = append([]byte{byte(n & 0xff)}, out...)
		n >>= 8
	}
	if out == nil {
		out = []byte{0}
	}
	return out
}

func ParseCertificatesPEM(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
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
			return nil, fmt.Errorf("parsing certificate: %w", err)
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no PEM certificates found")
	}
	return certs, nil
}
