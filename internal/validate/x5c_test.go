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

	"github.com/eudi-dev/eudi-dev/v2/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v2/internal/sdjwt"
	"github.com/eudi-dev/eudi-dev/v2/internal/trustlist"
)

// A JWK's x5c arrives from JSON as []any and from Go code as []string. Both
// must read the same.
func TestNormalizeX5CEntries(t *testing.T) {
	t.Run("a slice of strings", func(t *testing.T) {
		got, err := normalizeX5CEntries([]string{"a", "b"})
		if err != nil {
			t.Fatalf("normalizeX5CEntries: %v", err)
		}
		if len(got) != 2 || got[0] != "a" || got[1] != "b" {
			t.Errorf("entries = %v", got)
		}
	})

	t.Run("a slice of any, as JSON decodes it", func(t *testing.T) {
		got, err := normalizeX5CEntries([]any{"a", "b"})
		if err != nil {
			t.Fatalf("normalizeX5CEntries: %v", err)
		}
		if len(got) != 2 || got[0] != "a" {
			t.Errorf("entries = %v", got)
		}
	})

	t.Run("an entry that is not a string", func(t *testing.T) {
		if _, err := normalizeX5CEntries([]any{"a", 42}); err == nil {
			t.Error("a non-string x5c entry was accepted")
		}
	})

	t.Run("not an array at all", func(t *testing.T) {
		if _, err := normalizeX5CEntries("just a string"); err == nil {
			t.Error("a scalar x5c was accepted")
		}
	})
}

func TestExtractAndValidateJWKX5C(t *testing.T) {
	caCert, caKey, caDER := generateCACert(t)
	_, _, leafDER := generateLeafCert(t, caCert, caKey)
	anchors := []trustlist.CertInfo{{Subject: caCert.Subject.String(), PublicKey: caCert.PublicKey, Raw: caDER}}

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
		if err == nil || !strings.Contains(err.Error(), "decoding jwk x5c certificate") {
			t.Errorf("error = %v, want a decoding failure", err)
		}
	})

	t.Run("an x5c entry that is not a certificate", func(t *testing.T) {
		notACert := base64.StdEncoding.EncodeToString([]byte("nope"))
		_, err := extractAndValidateJWKX5C(map[string]any{"x5c": []any{notACert}}, anchors)
		if err == nil || !strings.Contains(err.Error(), "parsing jwk x5c certificate") {
			t.Errorf("error = %v, want a parse failure", err)
		}
	})

	t.Run("a malformed x5c", func(t *testing.T) {
		if _, err := extractAndValidateJWKX5C(map[string]any{"x5c": 42}, anchors); err == nil {
			t.Error("a scalar x5c was accepted")
		}
	})
}

// Metadata resolution needs an HTTPS issuer, a key ID and a signature.
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
		{"no kid", func(tok *sdjwt.Token) { delete(tok.Header, "kid") }},
		{"a blank kid", func(tok *sdjwt.Token) { tok.Header["kid"] = "   " }},
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

func TestFindIssuerMetadataJWK(t *testing.T) {
	doc := func(keys ...any) map[string]any {
		return map[string]any{"jwks": map[string]any{"keys": keys}}
	}

	t.Run("matches on kid", func(t *testing.T) {
		got, err := findIssuerMetadataJWK(doc(
			map[string]any{"kid": "one", "kty": "EC"},
			map[string]any{"kid": "two", "kty": "EC"},
		), "two")
		if err != nil {
			t.Fatalf("findIssuerMetadataJWK: %v", err)
		}
		if got["kid"] != "two" {
			t.Errorf("kid = %v, want two", got["kid"])
		}
	})

	// An empty kid selects the first key, which a single-key metadata document
	// relies on.
	t.Run("an empty kid takes the first key", func(t *testing.T) {
		got, err := findIssuerMetadataJWK(doc(map[string]any{"kid": "one"}), "")
		if err != nil {
			t.Fatalf("findIssuerMetadataJWK: %v", err)
		}
		if got["kid"] != "one" {
			t.Errorf("kid = %v, want one", got["kid"])
		}
	})

	t.Run("a kid nothing matches", func(t *testing.T) {
		if _, err := findIssuerMetadataJWK(doc(map[string]any{"kid": "one"}), "other"); err == nil {
			t.Error("an unmatched kid was accepted")
		}
	})

	t.Run("entries that are not objects are skipped", func(t *testing.T) {
		got, err := findIssuerMetadataJWK(doc("not an object", map[string]any{"kid": "one"}), "one")
		if err != nil {
			t.Fatalf("findIssuerMetadataJWK: %v", err)
		}
		if got["kid"] != "one" {
			t.Errorf("kid = %v", got["kid"])
		}
	})

	t.Run("no jwks", func(t *testing.T) {
		if _, err := findIssuerMetadataJWK(map[string]any{}, "one"); err == nil {
			t.Error("a document without jwks was accepted")
		}
	})

	t.Run("jwks without keys", func(t *testing.T) {
		if _, err := findIssuerMetadataJWK(map[string]any{"jwks": map[string]any{}}, "one"); err == nil {
			t.Error("a jwks without keys was accepted")
		}
	})

	t.Run("an empty key set", func(t *testing.T) {
		if _, err := findIssuerMetadataJWK(doc(), "one"); err == nil {
			t.Error("an empty key set was accepted")
		}
	})
}

// COSE decoders return the x5chain label as an int64 or a uint64. A single
// certificate is a bare byte string.
func TestExtractMDOCX5ChainCertificates(t *testing.T) {
	caCert, caKey, caDER := generateCACert(t)
	_, _, leafDER := generateLeafCert(t, caCert, caKey)

	withHeader := func(header map[any]any) *mdoc.Document {
		return &mdoc.Document{IssuerAuth: &mdoc.IssuerAuth{UnprotectedHeader: header}}
	}

	t.Run("a single certificate under an int64 label", func(t *testing.T) {
		certs, err := ExtractMDOCX5ChainCertificates(withHeader(map[any]any{int64(33): leafDER}))
		if err != nil {
			t.Fatalf("ExtractMDOCX5ChainCertificates: %v", err)
		}
		if len(certs) != 1 {
			t.Fatalf("certificates = %d, want 1", len(certs))
		}
	})

	t.Run("a chain under a uint64 label", func(t *testing.T) {
		certs, err := ExtractMDOCX5ChainCertificates(withHeader(map[any]any{uint64(33): []any{leafDER, caDER}}))
		if err != nil {
			t.Fatalf("ExtractMDOCX5ChainCertificates: %v", err)
		}
		if len(certs) != 2 {
			t.Fatalf("certificates = %d, want 2", len(certs))
		}
	})

	t.Run("no issuer authentication", func(t *testing.T) {
		certs, err := ExtractMDOCX5ChainCertificates(&mdoc.Document{})
		if err != nil || certs != nil {
			t.Errorf("certs = %v, err = %v, want both empty", certs, err)
		}
	})

	t.Run("no x5chain in the header", func(t *testing.T) {
		certs, err := ExtractMDOCX5ChainCertificates(withHeader(map[any]any{int64(1): int64(-7)}))
		if err != nil || certs != nil {
			t.Errorf("certs = %v, err = %v, want both empty", certs, err)
		}
	})

	t.Run("an x5chain of an unexpected shape", func(t *testing.T) {
		certs, err := ExtractMDOCX5ChainCertificates(withHeader(map[any]any{int64(33): "a string"}))
		if err != nil || certs != nil {
			t.Errorf("certs = %v, err = %v, want both empty", certs, err)
		}
	})

	t.Run("bytes that are not a certificate", func(t *testing.T) {
		if _, err := ExtractMDOCX5ChainCertificates(withHeader(map[any]any{int64(33): []byte("nope")})); err == nil {
			t.Error("unparseable DER was accepted")
		}
	})
}
