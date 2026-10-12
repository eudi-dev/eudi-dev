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
	"crypto/ecdsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
)

// SD-JWT VC §4 forms the metadata location "by inserting the well-known
// string /.well-known/jwt-vc-issuer between the host component and the path
// component (if any) of the iss claim value in the JWT", and §4.1 removes any
// terminating slash from the path first.
func TestJWTVCIssuerMetadataURL(t *testing.T) {
	tests := []struct {
		iss     string
		want    string
		wantErr bool
	}{
		{iss: "https://example.com", want: "https://example.com/.well-known/jwt-vc-issuer"},
		{iss: "https://example.com/", want: "https://example.com/.well-known/jwt-vc-issuer"},
		{iss: "https://example.com/tenant/1234", want: "https://example.com/.well-known/jwt-vc-issuer/tenant/1234"},
		{iss: "https://example.com/tenant/1234/", want: "https://example.com/.well-known/jwt-vc-issuer/tenant/1234"},
		{iss: "https://example.com:8443/tenant", want: "https://example.com:8443/.well-known/jwt-vc-issuer/tenant"},
		{iss: "http://example.com", wantErr: true},
		{iss: "https://example.com/tenant?x=1", wantErr: true},
		{iss: "https://example.com/tenant#frag", wantErr: true},
		{iss: "not-a-url", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.iss, func(t *testing.T) {
			got, err := JWTVCIssuerMetadataURL(tt.iss)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("JWTVCIssuerMetadataURL(%q) = %q, want an error", tt.iss, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("JWTVCIssuerMetadataURL(%q): %v", tt.iss, err)
			}
			if got != tt.want {
				t.Errorf("JWTVCIssuerMetadataURL(%q) = %q, want %q", tt.iss, got, tt.want)
			}
		})
	}
}

func tenantToken(t *testing.T, issuer string, key *ecdsa.PrivateKey) *sdjwt.Token {
	t.Helper()
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
	return token
}

func TestResolveJWTIssuerMetadataKeys_TenantScopedIssuer(t *testing.T) {
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	var issuer string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/jwt-vc-issuer/tenant/1234" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": issuer,
			"jwks":   map[string]any{"keys": []any{mock.SigningJWKMap(&key.PublicKey)}},
		})
	}))
	defer srv.Close()
	issuer = srv.URL + "/tenant/1234"

	token := tenantToken(t, issuer, key)
	resolved, source, err := ResolveJWTIssuerMetadataKeys(token, nil)
	if err != nil {
		t.Fatalf("ResolveJWTIssuerMetadataKeys: %v", err)
	}
	if len(resolved) == 0 {
		t.Fatal("expected a key from the tenant-scoped metadata")
	}
	if !strings.Contains(source, "issuer metadata") {
		t.Fatalf("source = %q, want it to name the issuer metadata", source)
	}
}

// SD-JWT VC §4.2: "JWT VC Issuer Metadata MUST include either jwks_uri or
// jwks in their JWT VC Issuer Metadata, but not both."
func TestResolveJWTIssuerMetadataKeys_JWKSURI(t *testing.T) {
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	var issuer, jwksURI string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/jwt-vc-issuer/tenant/1234":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":   issuer,
				"jwks_uri": jwksURI,
			})
		case "/keys.jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []any{mock.SigningJWKMap(&key.PublicKey)},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	issuer = srv.URL + "/tenant/1234"
	jwksURI = srv.URL + "/keys.jwks"

	token := tenantToken(t, issuer, key)
	resolved, _, err := ResolveJWTIssuerMetadataKeys(token, nil)
	if err != nil {
		t.Fatalf("ResolveJWTIssuerMetadataKeys: %v", err)
	}
	if len(resolved) == 0 {
		t.Fatal("expected a key from the referenced JWK Set")
	}
}

func TestResolveJWTIssuerMetadataKeys_RejectsMalformedMetadata(t *testing.T) {
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	jwks := map[string]any{"keys": []any{mock.SigningJWKMap(&key.PublicKey)}}

	tests := []struct {
		name     string
		document func(issuer string) map[string]any
		want     string
	}{
		{
			// §4.2: "JWT VC Issuer Metadata MUST include either jwks_uri or
			// jwks in their JWT VC Issuer Metadata, but not both."
			name: "both jwks and jwks_uri",
			document: func(issuer string) map[string]any {
				return map[string]any{"issuer": issuer, "jwks": jwks, "jwks_uri": "https://example.com/keys.jwks"}
			},
			want: "both",
		},
		{
			// §4.2 marks the issuer member REQUIRED.
			name: "no issuer member",
			document: func(string) map[string]any {
				return map[string]any{"jwks": jwks}
			},
			want: "issuer",
		},
		{
			// §4.3: "The issuer value returned MUST be identical to the iss
			// value of the Issuer-signed JWT."
			name: "issuer differs by a trailing slash",
			document: func(issuer string) map[string]any {
				return map[string]any{"issuer": issuer + "/", "jwks": jwks}
			},
			want: "mismatch",
		},
		{
			name: "neither jwks nor jwks_uri",
			document: func(issuer string) map[string]any {
				return map[string]any{"issuer": issuer}
			},
			want: "neither",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var issuer string
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/.well-known/jwt-vc-issuer/tenant/1234" {
					http.NotFound(w, r)
					return
				}
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(tt.document(issuer))
			}))
			defer srv.Close()
			issuer = srv.URL + "/tenant/1234"

			token := tenantToken(t, issuer, key)
			resolved, _, err := ResolveJWTIssuerMetadataKeys(token, nil)
			if err == nil {
				t.Fatalf("ResolveJWTIssuerMetadataKeys accepted the document and returned %v", resolved)
			}
			if !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want it to mention %q", err, tt.want)
			}
		})
	}
}
