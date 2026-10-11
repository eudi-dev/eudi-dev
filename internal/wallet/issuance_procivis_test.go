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
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// This issuer advertises none for client authentication and rejects attestation
// headers. It advertises DPoP but returns Bearer tokens. Its token endpoint is
// in separate authorization server metadata.
func setupNoneAuthIssuer(t *testing.T, w *Wallet, gotAttestation *bool) (*httptest.Server, string) {
	t.Helper()

	credRaw := generateTestCredential(t, w)

	var serverURL string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":     serverURL,
				"authorization_servers": []string{serverURL},
				"credential_endpoint":   serverURL + "/credential",
				"nonce_endpoint":        serverURL + "/nonce",
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{
						"format": "dc+sd-jwt",
						"vct":    "urn:test:credential",
						"scope":  "test-config",
					},
				},
			})

		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server"):
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"issuer":                                serverURL,
				"token_endpoint":                        serverURL + "/token",
				"authorization_endpoint":                serverURL + "/authorize",
				"token_endpoint_auth_methods_supported": []string{"none"},
				"dpop_signing_alg_values_supported":     []string{"ES256"},
				"grant_types_supported":                 []string{"urn:ietf:params:oauth:grant-type:pre-authorized_code"},
			})

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/token"):
			if r.Header.Get("OAuth-Client-Attestation") != "" {
				if gotAttestation != nil {
					*gotAttestation = true
				}
				rw.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(rw).Encode(map[string]string{"error": "invalid_request"})
				return
			}
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			if form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:pre-authorized_code" {
				rw.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(rw).Encode(map[string]string{"error": "unsupported_grant_type"})
				return
			}
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"access_token": "test-access-token",
				"token_type":   "Bearer",
			})

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/nonce"):
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{"c_nonce": "nonce-from-endpoint"})

		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/credential"):
			if r.Header.Get("Authorization") == "" {
				rw.WriteHeader(http.StatusUnauthorized)
				_ = json.NewEncoder(rw).Encode(map[string]string{"error": "invalid_token"})
				return
			}
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"credentials": []any{map[string]any{"credential": credRaw}},
			})

		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	serverURL = srv.URL

	offer := map[string]any{
		"credential_issuer":            serverURL,
		"credential_configuration_ids": []string{"test-config"},
		"grants": map[string]any{
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
				"pre-authorized_code": "test-pre-auth-code",
			},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	offerURI := "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))
	return srv, offerURI
}

// TestProcessCredentialOffer_HAIPAgainstNoneAuthIssuer covers an issuer whose
// token endpoint advertises only the "none" auth method. HAIP 1.0 §4.4.1
// requires client authentication.
//
//   - HAIP in debug mode: the wallet logs a warning and skips client
//     authentication. Issuance completes.
//   - HAIP in strict mode: the wallet still authenticates. The token request
//     fails.
//   - Without HAIP: a plain request completes.
func TestProcessCredentialOffer_HAIPAgainstNoneAuthIssuer(t *testing.T) {
	run := func(t *testing.T, mode ValidationMode, haip bool) (*IssuanceResult, *bool, *Wallet, error) {
		t.Helper()
		w := generateTestWallet(t)
		w.ValidationMode = mode
		w.RequireHAIP = haip
		w.IssuerURL = "https://wallet.example"
		w.BaseURL = "https://wallet.example"

		sentAttestation := false
		srv, offerURI := setupNoneAuthIssuer(t, w, &sentAttestation)
		t.Cleanup(srv.Close)

		result, err := w.ProcessCredentialOffer(offerURI)
		return result, &sentAttestation, w, err
	}

	t.Run("HAIP + debug: warn and proceed without attestation", func(t *testing.T) {
		result, sent, w, err := run(t, ValidationModeDebug, true)
		if err != nil {
			t.Fatalf("HAIP + debug should complete against a none-auth issuer, got %v", err)
		}
		if *sent {
			t.Fatal("wallet must not send client attestation to a none-auth token endpoint in debug")
		}
		if result == nil || result.CredentialID == "" {
			t.Fatal("expected a credential to be imported")
		}
		if !hasWarningContaining(w, "unauthenticated access") {
			t.Error("expected a warning that the issuer offers only unauthenticated access")
		}
	})

	t.Run("HAIP + strict: attest and fail", func(t *testing.T) {
		_, sent, _, err := run(t, ValidationModeStrict, true)
		if err == nil {
			t.Fatal("HAIP + strict should fail against a none-auth issuer")
		}
		if !*sent {
			t.Fatal("HAIP + strict should still send a client attestation")
		}
	})

	t.Run("no HAIP: plain request completes", func(t *testing.T) {
		result, sent, _, err := run(t, ValidationModeDebug, false)
		if err != nil {
			t.Fatalf("expected issuance to complete without HAIP, got %v", err)
		}
		if *sent {
			t.Fatal("wallet must not authenticate at a none-auth token endpoint")
		}
		if result == nil || result.CredentialID == "" {
			t.Fatal("expected a credential to be imported")
		}
	})
}

func hasWarningContaining(w *Wallet, substr string) bool {
	for _, e := range w.GetLog() {
		if e.Severity == severityWarning && strings.Contains(e.Detail, substr) {
			return true
		}
	}
	return false
}
