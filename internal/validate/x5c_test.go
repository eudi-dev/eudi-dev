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

package validate

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
	"github.com/eudi-dev/eudi-dev/v3/pkg/sdjwt"
)

func TestExtractAndValidateJWKX5C(t *testing.T) {
	caCert, caKey, caDER := generateCACert(t)
	_, _, leafDER := generateLeafCert(t, caCert, caKey)
	anchors := []lote.CertInfo{{Subject: caCert.Subject.String(), PublicKey: caCert.PublicKey, Raw: caDER}}

	leafB64 := base64.StdEncoding.EncodeToString(leafDER)
	caB64 := base64.StdEncoding.EncodeToString(caDER)

	t.Run("a chain that reaches a trust anchor", func(t *testing.T) {
		key, err := extractAndValidateJWKX5C(map[string]any{"x5c": []any{leafB64, caB64}}, anchors)
		if err != nil {
			t.Fatalf("extractAndValidateJWKX5C: %v", err)
		}
		if key == nil {
			t.Error("no key returned for a chain that validates")
		}
	})

	// Without anchors the x5c is ignored.
	t.Run("no trust anchors", func(t *testing.T) {
		key, err := extractAndValidateJWKX5C(map[string]any{"x5c": []any{leafB64}}, nil)
		if err != nil {
			t.Fatalf("extractAndValidateJWKX5C: %v", err)
		}
		if key != nil {
			t.Error("a chain was trusted with no anchors to check it against")
		}
	})

	t.Run("a JWK without x5c", func(t *testing.T) {
		key, err := extractAndValidateJWKX5C(map[string]any{"kty": "EC"}, anchors)
		if err != nil || key != nil {
			t.Errorf("key = %v, err = %v, want both empty", key, err)
		}
	})

	t.Run("an empty x5c", func(t *testing.T) {
		key, err := extractAndValidateJWKX5C(map[string]any{"x5c": []any{}}, anchors)
		if err != nil || key != nil {
			t.Errorf("key = %v, err = %v, want both empty", key, err)
		}
	})

	t.Run("an x5c entry that is not base64", func(t *testing.T) {
		_, err := extractAndValidateJWKX5C(map[string]any{"x5c": []any{"!!! not base64 !!!"}}, anchors)
		if err == nil || !strings.Contains(err.Error(), "decoding x5c certificate") {
			t.Errorf("error = %v, want a decoding failure", err)
		}
	})

	t.Run("an x5c entry that is not a certificate", func(t *testing.T) {
		notACert := base64.StdEncoding.EncodeToString([]byte("nope"))
		_, err := extractAndValidateJWKX5C(map[string]any{"x5c": []any{notACert}}, anchors)
		if err == nil || !strings.Contains(err.Error(), "parsing x5c certificate") {
			t.Errorf("error = %v, want a parse failure", err)
		}
	})

	t.Run("a malformed x5c", func(t *testing.T) {
		if _, err := extractAndValidateJWKX5C(map[string]any{"x5c": 42}, anchors); err == nil {
			t.Error("a scalar x5c was accepted")
		}
	})
}

// Metadata resolution needs an HTTPS issuer and a signature. SD-JWT VC §4.2
// only recommends a kid.
func TestCanResolveJWTIssuerMetadata(t *testing.T) {
	full := func() *sdjwt.Token {
		return &sdjwt.Token{
			Header:    map[string]any{"kid": "key-1", "alg": "ES256"},
			Payload:   map[string]any{"iss": "https://issuer.example"},
			Signature: []byte{1, 2, 3},
		}
	}

	if !CanResolveJWTIssuerMetadata(full()) {
		t.Error("a token with everything needed was refused")
	}

	tests := []struct {
		name   string
		mutate func(*sdjwt.Token)
	}{
		{"no issuer", func(tok *sdjwt.Token) { delete(tok.Payload, "iss") }},
		{"a plain http issuer", func(tok *sdjwt.Token) { tok.Payload["iss"] = "http://issuer.example" }},
		{"an issuer that is not a URL", func(tok *sdjwt.Token) { tok.Payload["iss"] = "did:example:123" }},
		{"alg none", func(tok *sdjwt.Token) { tok.Header["alg"] = "none" }},
		{"alg NONE in any case", func(tok *sdjwt.Token) { tok.Header["alg"] = "NoNe" }},
		{"no signature", func(tok *sdjwt.Token) { tok.Signature = nil }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tok := full()
			tt.mutate(tok)
			if CanResolveJWTIssuerMetadata(tok) {
				t.Error("resolution was reported as possible")
			}
		})
	}

	if CanResolveJWTIssuerMetadata(nil) {
		t.Error("a nil token was reported as resolvable")
	}
}
