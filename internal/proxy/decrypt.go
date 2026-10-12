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

package proxy

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"fmt"

	"github.com/eudi-dev/eudi-dev/v2/internal/jwe"
	"github.com/eudi-dev/eudi-dev/v2/internal/keys"
)

// DecryptJWEWithCEK decrypts a compact JWE with a known content encryption key.
// The wallet sends the CEK in a debug header so the proxy can decrypt JARM
// responses.
func DecryptJWEWithCEK(compact string, cek []byte) ([]byte, error) {
	return jwe.DecryptWithCEK(compact, cek)
}

func DecryptJWEWithJWK(compact string, jwkJSON string) ([]byte, error) {
	key, err := parseECPrivateKeyJWK(jwkJSON)
	if err != nil {
		return nil, fmt.Errorf("parsing JWK private key: %w", err)
	}
	return jwe.Decrypt(compact, key)
}

func parseECPrivateKeyJWK(jwkJSON string) (*ecdh.PrivateKey, error) {
	parsed, err := keys.ParseJWKPrivate([]byte(jwkJSON))
	if err != nil {
		return nil, err
	}
	ecKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("unsupported key type: %T", parsed)
	}
	return ecKey.ECDH()
}
