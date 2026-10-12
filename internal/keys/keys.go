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

// Package keys loads cryptographic keys from PEM and JWK files.
package keys

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	josev4 "github.com/go-jose/go-jose/v4"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
)

// DIDReference detects DID key references so callers can tell them apart from
// missing keys. The toolkit resolves issuer keys through x5c (HAIP 1.0 §6.1.1) or
// HTTPS issuer metadata (SD-JWT VC). See docs/adr/0013-only-the-eudi-stack-is-supported.md.
func DIDReference(identifiers ...string) string {
	for _, identifier := range identifiers {
		trimmed := strings.TrimSpace(identifier)
		if strings.HasPrefix(trimmed, "did:") {
			return trimmed
		}
	}
	return ""
}

func LoadPublicKey(path string) (crypto.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}
	return ParsePublicKey(data)
}

func LoadPrivateKey(path string) (crypto.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}
	return ParsePrivateKey(data)
}

func ParsePrivateKey(data []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block != nil {
		return parsePEMPrivateBlock(block)
	}
	return ParseJWKPrivate(data)
}

func parsePEMPrivateBlock(block *pem.Block) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("unable to parse PEM private key (tried PKCS#8, EC, PKCS#1)")
}

// ParseJWKPrivate reads a private key from a JWK document. It repairs short EC
// coordinates because a private JWK is the operator's own key file. Public keys
// from peers go through ParseJWK. It follows the spec strictly.
func ParseJWKPrivate(data []byte) (crypto.PrivateKey, error) {
	var jwk josev4.JSONWebKey
	if err := jwk.UnmarshalJSON(padECCoordinates(data)); err != nil {
		return nil, fmt.Errorf("not a valid PEM or JWK: %w", err)
	}
	switch key := jwk.Key.(type) {
	case *ecdsa.PrivateKey:
		return key, nil
	case *rsa.PrivateKey:
		return key, nil
	case *ecdsa.PublicKey, *rsa.PublicKey:
		return nil, fmt.Errorf("JWK carries no private key parameters")
	default:
		return nil, fmt.Errorf("unsupported JWK key type: %T", jwk.Key)
	}
}

func ParsePublicKey(data []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block != nil {
		return parsePEMBlock(block)
	}
	return ParseJWK(data)
}

func parsePEMBlock(block *pem.Block) (crypto.PublicKey, error) {
	switch block.Type {
	case "PUBLIC KEY", "EC PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)
	case "CERTIFICATE":
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return cert.PublicKey, nil
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		key, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("unsupported PEM block type: %s", block.Type)
		}
		return key, nil
	}
}

// ParseJWKLenient reads a public key from a JWK whose EC coordinates may be
// shorter than RFC 7518 §6.2.1.2 requires. It reports whether it repaired one.
// Only debug mode uses it. Strict mode calls ParseJWK.
func ParseJWKLenient(data []byte) (crypto.PublicKey, bool, error) {
	key, err := ParseJWK(data)
	if err == nil {
		return key, false, nil
	}
	repaired := padECCoordinates(data)
	if bytes.Equal(repaired, data) {
		return nil, false, err
	}
	key, err = ParseJWK(repaired)
	if err != nil {
		return nil, false, err
	}
	return key, true, nil
}

var ecCurveSizes = map[string]int{"P-256": 32, "P-384": 48, "P-521": 66}

// padECCoordinates left pads short EC coordinates to the curve width. Code that
// writes big.Int.Bytes() directly drops a zero leading byte. RFC 7518 §6.2.1.2
// disallows that and go-jose enforces it. The caller decides whether to repair.
func padECCoordinates(data []byte) []byte {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return data
	}
	if kty, _ := doc["kty"].(string); kty != "EC" {
		return data
	}
	crv, _ := doc["crv"].(string)
	size, ok := ecCurveSizes[crv]
	if !ok {
		return data
	}
	changed := false
	for _, field := range []string{"x", "y", "d"} {
		encoded, ok := doc[field].(string)
		if !ok {
			continue
		}
		raw, err := format.DecodeBase64URL(encoded)
		if err != nil || len(raw) >= size {
			continue
		}
		padded := make([]byte, size)
		copy(padded[size-len(raw):], raw)
		doc[field] = format.EncodeBase64URL(padded)
		changed = true
	}
	if !changed {
		return data
	}
	repaired, err := json.Marshal(doc)
	if err != nil {
		return data
	}
	return repaired
}

// ParseJWK reads a public key from a JWK document. It returns only EC and RSA
// keys. go-jose also decodes OKP and symmetric keys, and no caller handles them.
func ParseJWK(data []byte) (crypto.PublicKey, error) {
	var jwk josev4.JSONWebKey
	if err := jwk.UnmarshalJSON(data); err != nil {
		return nil, fmt.Errorf("not a valid PEM or JWK: %w", err)
	}
	switch key := jwk.Key.(type) {
	case *ecdsa.PublicKey:
		return key, nil
	case *rsa.PublicKey:
		return key, nil
	case *ecdsa.PrivateKey:
		return &key.PublicKey, nil
	case *rsa.PrivateKey:
		return &key.PublicKey, nil
	default:
		return nil, fmt.Errorf("unsupported JWK key type: %T", jwk.Key)
	}
}
