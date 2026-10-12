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

package oid4vp

import (
	"github.com/eudi-dev/eudi-dev/v3/internal/jwe"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
)

// FindEncryptionJWK returns the first encryption JWK in client_metadata.jwks
// that the wallet can encrypt to (OID4VP 1.0 §8.3).
func FindEncryptionJWK(reqObj *oid4vc.RequestObjectJWT, clientMetadata map[string]any) map[string]any {
	return firstJWK(EncryptionJWKS(reqObj, clientMetadata))
}

func EncryptionJWKS(reqObj *oid4vc.RequestObjectJWT, clientMetadata map[string]any) any {
	if reqObj != nil && reqObj.Payload != nil {
		if clientMeta, ok := reqObj.Payload["client_metadata"].(map[string]any); ok {
			return clientMeta["jwks"]
		}
	}
	if clientMetadata != nil {
		return clientMetadata["jwks"]
	}
	return nil
}

// firstJWK returns the first usable encryption key in a JWKS ({"keys": [...]}).
// It skips keys with an unsupported kty or curve and keys marked for signing
// (RFC 7517 §5).
func firstJWK(jwksVal any) map[string]any {
	jwks, ok := jwksVal.(map[string]any)
	if !ok {
		return nil
	}
	keysSlice, ok := jwks["keys"].([]any)
	if !ok || len(keysSlice) == 0 {
		return nil
	}
	// Prefer an EC key. ECDH-ES on P-256 is the OID4VP baseline and the only
	// option HAIP allows. RSA-OAEP is the fallback.
	var fallback map[string]any
	for _, entry := range keysSlice {
		jwk, ok := entry.(map[string]any)
		if !ok || !usableEncryptionJWK(jwk) {
			continue
		}
		if kty, _ := jwk["kty"].(string); kty == "EC" {
			return jwk
		}
		if fallback == nil {
			fallback = jwk
		}
	}
	return fallback
}

func usableEncryptionJWK(jwk map[string]any) bool {
	if use, ok := jwk["use"].(string); ok && use != "enc" {
		return false
	}
	return EncryptableKeyMaterial(jwk) && ImplementsKeyAlg(jwk)
}

// ImplementsKeyAlg reports whether the wallet implements the key's alg.
// OID4VP 1.0 §8.3: "The alg parameter MUST be present in the JWKs. The JWE alg
// algorithm used MUST be equal to the alg value of the chosen jwk." The wallet
// does direct key agreement with EC keys and key wrapping with RSA keys.
func ImplementsKeyAlg(jwk map[string]any) bool {
	alg, _ := jwk["alg"].(string)
	switch kty, _ := jwk["kty"].(string); kty {
	case "EC":
		return alg == jwe.AlgECDHES
	case "RSA":
		return alg == "RSA-OAEP" || alg == "RSA-OAEP-256"
	default:
		return false
	}
}

func EncryptableKeyMaterial(jwk map[string]any) bool {
	switch kty, _ := jwk["kty"].(string); kty {
	case "EC":
		if crv, ok := jwk["crv"].(string); ok && crv != "P-256" {
			return false
		}
		x, _ := jwk["x"].(string)
		y, _ := jwk["y"].(string)
		return x != "" && y != ""
	case "RSA":
		n, _ := jwk["n"].(string)
		e, _ := jwk["e"].(string)
		return n != "" && e != ""
	default:
		return false
	}
}
