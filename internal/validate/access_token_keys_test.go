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

	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

// authorizationServer serves its metadata at metadataPath and its JWK Set at
// /jwks. It fails the test when a client asks for JWT VC Issuer Metadata.
func authorizationServer(t *testing.T, key *ecdsa.PrivateKey, issuerPath, metadataPath string) (*httptest.Server, string) {
	t.Helper()
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasPrefix(r.URL.Path, "/.well-known/jwt-vc-issuer"):
			t.Errorf("the access token key was looked up at %s", r.URL.Path)
			http.NotFound(w, r)
		case r.URL.Path == metadataPath:
			_ = json.NewEncoder(w).Encode(map[string]any{"issuer": srv.URL + issuerPath, "jwks_uri": srv.URL + "/jwks"})
		case r.URL.Path == "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{mock.SigningJWKMap(&key.PublicKey)}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, srv.URL + issuerPath
}

func accessToken(t *testing.T, issuer string, key *ecdsa.PrivateKey) string {
	t.Helper()
	now := time.Now()
	// RFC 9068 §2.1: typ at+jwt, §2.2: iss, exp, aud, sub, client_id, iat, jti.
	raw, err := jws.Sign(map[string]any{"alg": jws.AlgES256, "typ": "at+jwt"}, map[string]any{
		"iss": issuer, "exp": now.Add(time.Hour).Unix(), "iat": now.Unix(),
		"aud": "https://rs.example", "sub": "alice", "client_id": "wallet", "jti": "1",
	}, key)
	if err != nil {
		t.Fatalf("signing the access token: %v", err)
	}
	return raw
}

func TestAnAccessTokenIsVerifiedWithTheAuthorizationServerKeys(t *testing.T) {
	for name, metadataPath := range map[string]string{
		"RFC 8414 metadata":        "/.well-known/oauth-authorization-server/realms/demo",
		"OpenID Connect Discovery": "/realms/demo/.well-known/openid-configuration",
	} {
		t.Run(name, func(t *testing.T) {
			key, err := mock.GenerateKey()
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			srv, issuer := authorizationServer(t, key, "/realms/demo", metadataPath)
			result := validated(t, accessToken(t, issuer, key), Trust{HTTPClient: srv.Client()}, Options{})
			got := mustFind(t, result, CheckSignature)
			if got.Status != Pass || !strings.Contains(got.Detail, "authorization server metadata") {
				t.Errorf("signature = %+v, want valid via the authorization server metadata", got)
			}
		})
	}
}

func TestAnAuthorizationServerWithAnotherIssuerIsNotUsed(t *testing.T) {
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	srv, issuer := authorizationServer(t, key, "/realms/other", "/.well-known/oauth-authorization-server/realms/demo")
	token := accessToken(t, strings.Replace(issuer, "/realms/other", "/realms/demo", 1), key)
	got := mustFind(t, validated(t, token, Trust{HTTPClient: srv.Client()}, Options{}), CheckSignature)
	if got.Status == Pass || !strings.Contains(got.Detail, "issuer mismatch") {
		t.Errorf("signature = %+v, want no key from metadata of another issuer", got)
	}
}
