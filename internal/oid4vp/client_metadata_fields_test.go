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
	"reflect"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
)

var walletEncKey = map[string]any{"kty": "EC", "crv": "P-256", "x": "eA", "y": "eQ", "alg": "ECDH-ES", "use": "enc", "kid": "outer"}

func TestClientMetadataFieldErrors(t *testing.T) {
	for _, tt := range []struct {
		name string
		meta map[string]any
		want string
	}{
		{"jwks is a string", map[string]any{"jwks": "keys"}, "client_metadata.jwks must be an object"},
		{"jwks without keys", map[string]any{"jwks": map[string]any{}}, "client_metadata.jwks.keys must be present"},
		{"keys is an object", map[string]any{"jwks": map[string]any{"keys": map[string]any{}}}, "client_metadata.jwks.keys must be an array"},
		{"key is a string", map[string]any{"jwks": map[string]any{"keys": []any{walletEncKey, "k"}}}, "client_metadata.jwks.keys[1] must be an object"},
		{"enc values is a string", map[string]any{"encrypted_response_enc_values_supported": "A128GCM"}, "client_metadata.encrypted_response_enc_values_supported must be an array"},
		{"enc value is a number", map[string]any{"encrypted_response_enc_values_supported": []any{"A128GCM", 1.0}}, "client_metadata.encrypted_response_enc_values_supported[1] must be a string"},
		{"vp_formats_supported is an array", map[string]any{"vp_formats_supported": []any{}}, "client_metadata.vp_formats_supported must be an object"},
		{"format entry is a string", map[string]any{"vp_formats_supported": map[string]any{"dc+sd-jwt": "ES256"}}, "client_metadata.vp_formats_supported.dc+sd-jwt must be an object"},
		{"jwt_vc_json alg_values is a string", map[string]any{"vp_formats_supported": map[string]any{"jwt_vc_json": map[string]any{"alg_values": "ES256"}}}, "client_metadata.vp_formats_supported.jwt_vc_json.alg_values must be an array"},
		{"ldp_vc cryptosuite is a number", map[string]any{"vp_formats_supported": map[string]any{"ldp_vc": map[string]any{"cryptosuite_values": []any{1.0}}}}, "client_metadata.vp_formats_supported.ldp_vc.cryptosuite_values[0] must be a string"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateAuthorizationRequest(Checks{}, redirectRequest(func(r *Request) { r.ClientMetadata = tt.meta }))
			want := "authorization request validation failed: " + tt.want
			if err == nil || err.Error() != want {
				t.Errorf("err = %v, want %q", err, want)
			}
		})
	}
}

func TestClientMetadataAcceptsWellFormedFields(t *testing.T) {
	meta := map[string]any{
		"jwks": map[string]any{"keys": []any{walletEncKey}},
		"encrypted_response_enc_values_supported": []any{"A128GCM", "A256GCM"},
		"vp_formats_supported": map[string]any{
			"dc+sd-jwt":     map[string]any{"sd-jwt_alg_values": []any{"ES256"}, "kb-jwt_alg_values": []any{"ES256"}},
			"mso_mdoc":      map[string]any{"issuerauth_alg_values": []any{-7.0}},
			"x-proprietary": map[string]any{"alg_values": 7.0},
		},
	}
	findings, err := ValidateAuthorizationRequest(Checks{Strict: true}, redirectRequest(func(r *Request) { r.ClientMetadata = meta }))
	if err != nil || len(findings) != 0 {
		t.Errorf("findings %v err %v, want the metadata accepted", findings, err)
	}
}

// A signed request carries its client_metadata in the Request Object. The
// Request Object replaces the outer parameters (RFC 9101 §6.3).
func TestClientMetadataComesFromTheRequestObject(t *testing.T) {
	innerKey := map[string]any{"kty": "EC", "crv": "P-256", "x": "aW4", "y": "aW4", "alg": "ECDH-ES", "kid": "inner"}
	reqObj := &oid4vc.RequestObjectJWT{Payload: map[string]any{"client_metadata": map[string]any{
		"client_name": "Inner Verifier",
		"jwks":        map[string]any{"keys": []any{innerKey}},
	}}}
	outer := map[string]any{"client_name": "Outer Verifier", "jwks": map[string]any{"keys": []any{walletEncKey}}}

	if got := FindEncryptionJWK(reqObj, outer); !reflect.DeepEqual(got, innerKey) {
		t.Errorf("encryption key = %v, want the Request Object key", got)
	}
	if got := FindEncryptionJWK(nil, outer); !reflect.DeepEqual(got, walletEncKey) {
		t.Errorf("encryption key = %v, want the outer key", got)
	}
	if got := FindEncryptionJWK(&oid4vc.RequestObjectJWT{Payload: map[string]any{}}, outer); !reflect.DeepEqual(got, walletEncKey) {
		t.Errorf("encryption key = %v, want the outer key for a Request Object without client_metadata", got)
	}
	if got := EncryptionJWKS(nil, nil); got != nil {
		t.Errorf("jwks = %v, want none without metadata", got)
	}

	signed := &Request{AuthorizationRequest: oid4vc.AuthorizationRequest{RequestObject: reqObj, ClientMetadata: outer}}
	if got := ClientMetadataName(signed); got != "Inner Verifier" {
		t.Errorf("client_name = %q, want the Request Object name", got)
	}
	unsigned := &Request{AuthorizationRequest: oid4vc.AuthorizationRequest{ClientMetadata: outer}}
	if got := ClientMetadataName(unsigned); got != "Outer Verifier" {
		t.Errorf("client_name = %q, want the outer name", got)
	}
	jsonRequest := &Request{RequestPayload: map[string]any{"client_metadata": map[string]any{"client_name": "JSON Verifier"}}}
	if got := ClientMetadataName(jsonRequest); got != "JSON Verifier" {
		t.Errorf("client_name = %q, want the JSON request name", got)
	}
	if got := ClientMetadataName(nil); got != "" {
		t.Errorf("client_name = %q without a request", got)
	}
}

// OID4VP 1.0 §8.3: "The alg parameter MUST be present in the JWKs."
func TestImplementsKeyAlg(t *testing.T) {
	for _, tt := range []struct {
		jwk  map[string]any
		want bool
	}{
		{map[string]any{"kty": "EC", "alg": "ECDH-ES"}, true},
		{map[string]any{"kty": "EC", "alg": "ECDH-ES+A128KW"}, false},
		{map[string]any{"kty": "EC"}, false},
		{map[string]any{"kty": "RSA", "alg": "RSA-OAEP"}, true},
		{map[string]any{"kty": "RSA", "alg": "RSA-OAEP-256"}, true},
		{map[string]any{"kty": "RSA", "alg": "RSA1_5"}, false},
		{map[string]any{"kty": "OKP", "alg": "ECDH-ES"}, false},
	} {
		if got := ImplementsKeyAlg(tt.jwk); got != tt.want {
			t.Errorf("ImplementsKeyAlg(%v) = %v, want %v", tt.jwk, got, tt.want)
		}
	}
}

func TestEncryptableKeyMaterial(t *testing.T) {
	for _, tt := range []struct {
		jwk  map[string]any
		want bool
	}{
		{map[string]any{"kty": "EC", "crv": "P-256", "x": "eA", "y": "eQ"}, true},
		{map[string]any{"kty": "EC", "x": "eA", "y": "eQ"}, true},
		{map[string]any{"kty": "EC", "crv": "P-384", "x": "eA", "y": "eQ"}, false},
		{map[string]any{"kty": "EC", "crv": "P-256", "x": "eA"}, false},
		{map[string]any{"kty": "RSA", "n": "bg", "e": "AQAB"}, true},
		{map[string]any{"kty": "RSA", "n": "bg"}, false},
		{map[string]any{"kty": "oct", "k": "aw"}, false},
	} {
		if got := EncryptableKeyMaterial(tt.jwk); got != tt.want {
			t.Errorf("EncryptableKeyMaterial(%v) = %v, want %v", tt.jwk, got, tt.want)
		}
	}
}
