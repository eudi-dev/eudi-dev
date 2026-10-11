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
	"crypto/rand"
	"crypto/rsa"
	"math/big"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
)

func TestFirstJWKSkipsUnusableKeys(t *testing.T) {
	usable := map[string]any{
		"kty": "EC", "crv": "P-256", "use": "enc", "alg": "ECDH-ES",
		"kid": "usable", "x": "8Yrbbg", "y": "V2Ki0w",
	}
	jwks := map[string]any{
		"keys": []any{
			map[string]any{"kty": "AKP", "alg": "ML-KEM-9999", "kid": "unusable-pq-enc-key", "use": "enc", "pub": "cGxhY2Vob2xkZXI"},
			map[string]any{"kty": "OIDF-CONFORMANCE-UNSUPPORTED", "alg": "OIDF-CONFORMANCE-UNSUPPORTED", "kid": "unusable-unknown-enc-key", "use": "enc"},
			usable,
		},
	}
	got := firstJWK(jwks)
	if got == nil {
		t.Fatal("expected the usable key to be found")
	}
	if kid, _ := got["kid"].(string); kid != "usable" {
		t.Fatalf("expected kid 'usable', got %q", kid)
	}

	jwks = map[string]any{
		"keys": []any{
			map[string]any{"kty": "EC", "crv": "P-256", "use": "sig", "kid": "sig-key", "x": "8Yrbbg", "y": "V2Ki0w"},
		},
	}
	if got := firstJWK(jwks); got != nil {
		t.Fatalf("expected no usable key, got %v", got)
	}
}

// When a verifier offers both an EC and an RSA key, the wallet uses the EC key.
// ECDH-ES is the OID4VP baseline and the only option HAIP allows.
func TestFindEncryptionJWKPrefersECOverRSA(t *testing.T) {
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	ecJWK := map[string]any{"kty": "EC", "crv": "P-256", "use": "enc", "alg": "ECDH-ES", "kid": "ec", "x": "8Yrbbg", "y": "V2Ki0w"}
	meta := map[string]any{"jwks": map[string]any{"keys": []any{
		rsaEncJWK(&rsaPriv.PublicKey, "RSA-OAEP"),
		ecJWK,
	}}}
	jwk := FindEncryptionJWK(nil, meta)
	if kty, _ := jwk["kty"].(string); kty != "EC" {
		t.Fatalf("expected the EC key to be preferred, got kty %q", kty)
	}
}

func TestHaipEncryptionKeyViolationsRSA(t *testing.T) {
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	meta := map[string]any{"jwks": map[string]any{"keys": []any{rsaEncJWK(&rsaPriv.PublicKey, "RSA-OAEP")}}}
	violations := haipEncryptionKeyViolations(nil, meta)
	if len(violations) == 0 {
		t.Fatal("HAIP must flag an RSA response encryption key")
	}

	ecJWK := map[string]any{"kty": "EC", "crv": "P-256", "use": "enc", "alg": "ECDH-ES", "kid": "ec", "x": "8Yrbbg", "y": "V2Ki0w"}
	ecMeta := map[string]any{"jwks": map[string]any{"keys": []any{ecJWK}}}
	if v := haipEncryptionKeyViolations(nil, ecMeta); len(v) != 0 {
		t.Fatalf("an EC P-256 key is HAIP-conformant, got %v", v)
	}
}

func rsaEncJWK(pub *rsa.PublicKey, alg string) map[string]any {
	return map[string]any{
		"kty": "RSA", "use": "enc", "alg": alg, "kid": "verifier-enc-1",
		"n": format.EncodeBase64URL(pub.N.Bytes()),
		"e": format.EncodeBase64URL(big.NewInt(int64(pub.E)).Bytes()),
	}
}
