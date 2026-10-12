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

package wallet

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"math/big"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jwe"
	"github.com/eudi-dev/eudi-dev/v3/internal/keys"
)

// EncryptJWEWithContentType encrypts with ECDH-ES (internal/jwe). The wallet
// implements only direct key agreement. Another alg is refused, so the header
// always matches the encryption.
func EncryptJWEWithContentType(payload []byte, recipientKey *ecdsa.PublicKey, kid string, alg string, enc string, cty string, apu, apv []byte) (string, []byte, error) {
	if alg != jwe.AlgECDHES {
		return "", nil, fmt.Errorf("unsupported key management alg %q: the wallet encrypts with ECDH-ES", alg)
	}
	return jwe.EncryptECDHES(payload, recipientKey, kid, enc, cty, apu, apv)
}

func rsaPublicKeyFromJWK(jwk map[string]any) (*rsa.PublicKey, error) {
	nB64, _ := jwk["n"].(string)
	eB64, _ := jwk["e"].(string)
	if nB64 == "" || eB64 == "" {
		return nil, fmt.Errorf("RSA JWK missing n or e")
	}
	nBytes, err := format.DecodeBase64URL(nB64)
	if err != nil {
		return nil, fmt.Errorf("decoding n: %w", err)
	}
	eBytes, err := format.DecodeBase64URL(eB64)
	if err != nil {
		return nil, fmt.Errorf("decoding e: %w", err)
	}
	e := 0
	for _, b := range eBytes {
		e = e<<8 | int(b)
	}
	if e < 2 {
		return nil, fmt.Errorf("RSA exponent is too small")
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}, nil
}

// ecdsaPublicKeyFromJWK reads a peer's P-256 encryption key from a JWK. RFC 7518
// does not allow a coordinate shorter than the curve size. Strict mode refuses
// such a key. Debug mode pads the coordinate and reports a finding.
func ecdsaPublicKeyFromJWK(mode ValidationMode, xB64, yB64 string) (*ecdsa.PublicKey, string, error) {
	doc, err := json.Marshal(map[string]string{
		"kty": "EC", "crv": "P-256", "x": xB64, "y": yB64,
	})
	if err != nil {
		return nil, "", fmt.Errorf("encoding JWK: %w", err)
	}

	if mode == ValidationModeStrict {
		parsed, err := keys.ParseJWK(doc)
		if err != nil {
			return nil, "", err
		}
		key, ok := parsed.(*ecdsa.PublicKey)
		if !ok {
			return nil, "", fmt.Errorf("JWK is not an EC key")
		}
		return key, "", nil
	}

	parsed, repaired, err := keys.ParseJWKLenient(doc)
	if err != nil {
		return nil, "", err
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok {
		return nil, "", fmt.Errorf("JWK is not an EC key")
	}
	finding := ""
	if repaired {
		finding = "encryption JWK has an EC coordinate narrower than P-256 requires (RFC 7518 6.2.1.2). It was left padded to read the key"
	}
	return key, finding, nil
}
