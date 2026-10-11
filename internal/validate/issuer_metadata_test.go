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
	"crypto"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/jws"
	"github.com/dominikschlosser/eudi-dev/v3/internal/lote"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/sdjwt"
)

func newIssuerMetadataServer(t *testing.T, issuer string, jwks []map[string]any) *httptest.Server {
	t.Helper()
	return httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/jwt-vc-issuer" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": issuer,
			"jwks":   map[string]any{"keys": jwks},
		})
	}))
}

func TestVerifyJWTSignature_UsesIssuerMetadata(t *testing.T) {
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	srv := newIssuerMetadataServer(t, "", nil)
	defer srv.Close()

	issuer := srv.URL
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/jwt-vc-issuer" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": issuer,
			"jwks":   map[string]any{"keys": []any{mock.SigningJWKMap(&key.PublicKey)}},
		})
	})

	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    issuer,
		VCT:       "urn:test",
		ExpiresIn: time.Hour,
		Claims:    map[string]any{"given_name": "Erika"},
		Key:       key,
	})
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}

	token, err := sdjwt.Parse(raw)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}

	result, source, err := VerifyJWTSignature(token, nil, nil)
	if err != nil {
		t.Fatalf("VerifyJWTSignature: %v", err)
	}
	if result == nil {
		t.Fatal("expected verify result")
	}
	if !result.SignatureValid {
		t.Fatalf("expected signature valid, got errors: %v", result.Errors)
	}
	if !strings.Contains(source, "issuer metadata") {
		t.Fatalf("expected issuer metadata source, got %q", source)
	}
}

// SD-JWT VC §4.2 only recommends a kid. Without one, every key of the JWK Set
// is a candidate.
func TestVerifyJWTSignature_UsesIssuerMetadataWithoutKid(t *testing.T) {
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	other, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": issuer,
			"jwks":   map[string]any{"keys": []any{mock.SigningJWKMap(&other.PublicKey), mock.SigningJWKMap(&key.PublicKey)}},
		})
	}))
	defer srv.Close()
	issuer = srv.URL

	jwt, err := jws.Sign(map[string]any{"alg": "ES256", "typ": "dc+sd-jwt"}, map[string]any{"iss": issuer, "vct": "urn:test"}, key)
	if err != nil {
		t.Fatal(err)
	}
	token, err := sdjwt.Parse(jwt + "~")
	if err != nil {
		t.Fatal(err)
	}

	result, source, err := VerifyJWTSignature(token, nil, nil, srv.Client())
	if err != nil {
		t.Fatalf("VerifyJWTSignature: %v", err)
	}
	if result == nil || !result.SignatureValid || source != "issuer metadata" {
		t.Fatalf("result = %+v via %q, want a valid signature via issuer metadata", result, source)
	}
}

// A supplied key is the whole trust. When it does not verify, the issuer
// metadata does not stand in for it.
func TestVerifyJWTSignature_SuppliedKeyIsNotReplacedByIssuerMetadata(t *testing.T) {
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	other, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	var issuer string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": issuer,
			"jwks":   map[string]any{"keys": []any{mock.SigningJWKMap(&key.PublicKey)}},
		})
	}))
	defer srv.Close()
	issuer = srv.URL
	token := tenantToken(t, issuer, key)

	result, source, err := VerifyJWTSignature(token, []crypto.PublicKey{&other.PublicKey}, nil, srv.Client())
	if err != nil {
		t.Fatalf("VerifyJWTSignature: %v", err)
	}
	if result == nil || result.SignatureValid || source != SourceProvidedKey {
		t.Fatalf("result = %+v via %q, want the supplied key to fail", result, source)
	}
}

// newX5CToken uses an unreachable issuer, so a pass proves offline verification
// with the embedded chain.
func newX5CToken(t *testing.T) (*sdjwt.Token, []lote.CertInfo) {
	t.Helper()
	caCert, caKey, caDER := generateCACert(t)
	leafCert, leafKey, _ := generateLeafCert(t, caCert, caKey)

	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://localhost:1",
		VCT:       "urn:test:x5c",
		ExpiresIn: time.Hour,
		Claims:    map[string]any{"given_name": "Erika"},
		Key:       leafKey,
		CertChain: []*x509.Certificate{leafCert, caCert},
	})
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}
	token, err := sdjwt.Parse(raw)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}
	anchors := []lote.CertInfo{{PublicKey: caCert.PublicKey, Raw: caDER}}
	return token, anchors
}

func TestVerifyJWTSignature_X5CLeafOfflineWithoutTrustList(t *testing.T) {
	token, _ := newX5CToken(t)

	result, source, err := VerifyJWTSignature(token, nil, nil)
	if err != nil {
		t.Fatalf("VerifyJWTSignature: %v", err)
	}
	if result == nil || !result.SignatureValid {
		t.Fatalf("expected valid signature via x5c leaf, got %+v", result)
	}
	if source != SourceX5CLeaf {
		t.Fatalf("expected source %q, got %q", SourceX5CLeaf, source)
	}
}

func TestVerifyJWTSignature_X5CChainOutranksLeaf(t *testing.T) {
	token, anchors := newX5CToken(t)

	result, source, err := VerifyJWTSignature(token, nil, anchors)
	if err != nil {
		t.Fatalf("VerifyJWTSignature: %v", err)
	}
	if result == nil || !result.SignatureValid {
		t.Fatalf("expected valid signature via x5c chain, got %+v", result)
	}
	if source != "x5c chain" {
		t.Fatalf("expected x5c chain source, got %q", source)
	}
}

func TestVerifyJWTSignature_UnmatchedTrustListDoesNotFallBackToLeaf(t *testing.T) {
	token, _ := newX5CToken(t)

	// A trust list that does not anchor the chain must fail verification. The
	// leaf-only check applies only without a trust list.
	otherCA, _, otherDER := generateCACert(t)
	foreign := []lote.CertInfo{{PublicKey: otherCA.PublicKey, Raw: otherDER}}

	result, source, err := VerifyJWTSignature(token, nil, foreign)
	if err == nil && result != nil && result.SignatureValid && source == SourceX5CLeaf {
		t.Fatal("leaf-only pass despite an explicit trust list")
	}
}

// With a trusted list, a bare metadata key of the issuer's host is not an
// anchor. Only a key whose x5c chains to the list counts.
func TestVerifyJWTSignature_TrustListIgnoresAnUnanchoredMetadataKey(t *testing.T) {
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	srv := newIssuerMetadataServer(t, "", nil)
	defer srv.Close()
	issuer := srv.URL
	srv.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": issuer,
			"jwks":   map[string]any{"keys": []any{mock.SigningJWKMap(&key.PublicKey)}},
		})
	})
	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{Issuer: issuer, VCT: "urn:test", ExpiresIn: time.Hour, Claims: map[string]any{"given_name": "Erika"}, Key: key})
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}
	token, err := sdjwt.Parse(raw)
	if err != nil {
		t.Fatalf("sdjwt.Parse: %v", err)
	}
	otherCA, _, otherDER := generateCACert(t)
	anchors := []lote.CertInfo{{PublicKey: otherCA.PublicKey, Raw: otherDER}}

	result, source, _ := VerifyJWTSignature(token, nil, anchors)
	if result != nil && result.SignatureValid {
		t.Errorf("signature valid via %q, want no pass without an anchored key", source)
	}
}
