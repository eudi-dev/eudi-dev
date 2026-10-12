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

func TestParseVCIVersion(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		want    VCIVersion
		wantErr bool
	}{
		{name: "empty selects the published version", raw: "", want: VCIVersion10},
		{name: "1.0", raw: "1.0", want: VCIVersion10},
		{name: "1.1", raw: "1.1", want: VCIVersion11},
		{name: "a version nobody published", raw: "1.2", wantErr: true},
		{name: "not a version at all", raw: "latest", wantErr: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ParseVCIVersion(tc.raw)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ParseVCIVersion(%q) = %q, want an error", tc.raw, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseVCIVersion(%q) error = %v", tc.raw, err)
			}
			if got != tc.want {
				t.Errorf("ParseVCIVersion(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		})
	}
}

func TestVCIVersionUsesInteractiveAuthorization(t *testing.T) {
	if VCIVersion10.UsesInteractiveAuthorization() {
		t.Error("1.0 must not use interactive authorization")
	}
	if !VCIVersion11.UsesInteractiveAuthorization() {
		t.Error("1.1 must use interactive authorization")
	}
}

// An unset version must use the published version's behavior.
func TestVCIFeatureVersionDefaultsToThePublishedVersion(t *testing.T) {
	w := &Wallet{}
	if got := w.VCIFeatureVersion(); got != VCIVersion10 {
		t.Errorf("VCIFeatureVersion() = %q, want %q", got, VCIVersion10)
	}
}

// The test issuer supports the redirect flow. withChallengeEndpoint also advertises
// Interactive Authorization.
type redirectFlowIssuer struct {
	url             string
	parCalled       bool
	challengeCalled bool
	tokenCalled     bool
}

func newRedirectFlowIssuer(t *testing.T, w *Wallet, withChallengeEndpoint bool) *redirectFlowIssuer {
	t.Helper()

	issuer := &redirectFlowIssuer{}
	credRaw := generateTestCredential(t, w)
	var parState string

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":     issuer.url,
				"authorization_servers": []string{issuer.url},
				"credential_endpoint":   issuer.url + "/credential",
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{
						"format": "dc+sd-jwt",
						"scope":  "test-scope",
					},
				},
			})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server"):
			metadata := map[string]any{
				"issuer":                                issuer.url,
				"authorization_endpoint":                issuer.url + "/authorize",
				"pushed_authorization_request_endpoint": issuer.url + "/par",
				"token_endpoint":                        issuer.url + "/token",
				"token_endpoint_auth_methods_supported": []string{"private_key_jwt"},
				"dpop_signing_alg_values_supported":     []string{"ES256"},
			}
			if withChallengeEndpoint {
				// OpenID4VCI 1.1 §13.3, offered alongside the redirect flow.
				metadata["authorization_challenge_endpoint"] = issuer.url + "/authorize-challenge"
				metadata["require_interactive_authorization"] = false
			}
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(metadata)
		case r.Method == http.MethodPost && r.URL.Path == "/par":
			issuer.parCalled = true
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			parState = form.Get("state")
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"request_uri": issuer.url + "/request-uri/example",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/authorize":
			redirect := w.VCIRedirectURI + "?code=issued-code&state=" + url.QueryEscape(parState)
			http.Redirect(rw, r, redirect, http.StatusFound)
		case r.URL.Path == "/authorize-challenge":
			issuer.challengeCalled = true
			rw.WriteHeader(http.StatusForbidden)
		case r.Method == http.MethodPost && r.URL.Path == "/token":
			issuer.tokenCalled = true
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			// The redirect flow's token request carries the redirect_uri of the
			// authorization request (RFC 6749 §4.1.3).
			if got := form.Get("redirect_uri"); got != w.VCIRedirectURI {
				t.Errorf("token request redirect_uri = %q, want %q", got, w.VCIRedirectURI)
			}
			if got := form.Get("code"); got != "issued-code" {
				t.Errorf("token request code = %q, want issued-code", got)
			}
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"access_token": "test-access-token",
				"token_type":   "Bearer",
				"c_nonce":      "test-c-nonce",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/credential":
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{"credentials": []any{map[string]any{"credential": credRaw}}})
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(server.Close)
	issuer.url = server.URL

	return issuer
}

func redirectFlowOfferURI(issuerURL string) string {
	offer := map[string]any{
		"credential_issuer":            issuerURL,
		"credential_configuration_ids": []string{"test-config"},
		"grants": map[string]any{
			"authorization_code": map[string]any{
				"issuer_state": "issuer-state-1",
			},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	return "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))
}

// A 1.0 wallet must use the redirect flow even when the server also offers Interactive
// Authorization.
func TestAuthorizationCodeOfferAtVCI10IgnoresAnInteractiveAuthorizationOffer(t *testing.T) {
	w := generateTestWallet(t)
	w.VCIClientID = "wallet-client"
	w.VCIRedirectURI = "https://wallet.example/callback"
	w.VCIVersion = VCIVersion10

	issuer := newRedirectFlowIssuer(t, w, true)

	result, err := w.ProcessCredentialOffer(redirectFlowOfferURI(issuer.url))
	if err != nil {
		t.Fatalf("ProcessCredentialOffer() error = %v", err)
	}
	if result.CredentialID == "" {
		t.Fatal("expected imported credential ID")
	}
	if issuer.challengeCalled {
		t.Error("wallet used the authorization challenge endpoint at feature level 1.0")
	}
	if !issuer.tokenCalled {
		t.Error("wallet did not reach the token endpoint")
	}

	// The log explains that the configured version skipped an advertised feature.
	if !hasInteractiveAuthorizationNote(w, "--vci-version 1.1") {
		t.Errorf("no log entry named the declined interactive authorization offer, log: %v", w.Log)
	}
}

// A 1.1 wallet falls back to the redirect flow when the server has no challenge
// endpoint.
func TestAuthorizationCodeOfferAtVCI11WorksWithoutAChallengeEndpoint(t *testing.T) {
	w := generateTestWallet(t)
	w.VCIClientID = "wallet-client"
	w.VCIRedirectURI = "https://wallet.example/callback"
	w.VCIVersion = VCIVersion11

	issuer := newRedirectFlowIssuer(t, w, false)

	result, err := w.ProcessCredentialOffer(redirectFlowOfferURI(issuer.url))
	if err != nil {
		t.Fatalf("ProcessCredentialOffer() error = %v", err)
	}
	if result.CredentialID == "" {
		t.Fatal("expected imported credential ID")
	}
	if issuer.challengeCalled {
		t.Error("wallet called a challenge endpoint the server never published")
	}
	if !issuer.parCalled {
		t.Error("wallet did not push its own authorization request")
	}
	if !issuer.tokenCalled {
		t.Error("wallet did not reach the token endpoint")
	}
	if _, ok := findInteractiveAuthorizationNote(w); ok {
		t.Errorf("logged an interactive authorization note for a server that offers none, log: %v", w.Log)
	}
}

// Warn when the server requires Interactive Authorization but the configured version
// cannot use it.
func TestNoteDeclinedInteractiveAuthorizationNamesARequirement(t *testing.T) {
	w := generateTestWallet(t)
	w.VCIVersion = VCIVersion10

	w.noteDeclinedInteractiveAuthorization(map[string]any{
		"require_interactive_authorization": true,
	}, "https://issuer.example/authorize-challenge")

	entry, ok := findInteractiveAuthorizationNote(w)
	if !ok {
		t.Fatalf("no interactive authorization entry, log: %v", w.Log)
	}
	if !strings.Contains(entry.Detail, "requires interactive authorization") {
		t.Errorf("entry does not say the server requires it: %q", entry.Detail)
	}
	if entry.Details["require_interactive_authorization"] != true {
		t.Errorf("entry details = %v, want require_interactive_authorization", entry.Details)
	}
}

func TestNoteDeclinedInteractiveAuthorizationStaysQuietWithoutAnEndpoint(t *testing.T) {
	w := generateTestWallet(t)
	w.noteDeclinedInteractiveAuthorization(map[string]any{"issuer": "https://issuer.example"}, "")
	if _, ok := findInteractiveAuthorizationNote(w); ok {
		t.Error("logged an interactive authorization note for a server that offers none")
	}
}

func TestConformanceAPICarriesTheVCIFeatureVersion(t *testing.T) {
	srv := newTestServer(t, true)
	srv.defaultConformance.VCIVersion = VCIVersion10
	srv.wallet.VCIVersion = VCIVersion10

	if got := conformanceVCIVersion(t, srv, http.MethodGet, "/api/config", ""); got != "1.0" {
		t.Fatalf("GET /api/config vci_version = %q, want 1.0", got)
	}

	if got := conformanceVCIVersion(t, srv, http.MethodPut, "/api/config/conformance", `{"vci_version":"1.1"}`); got != "1.1" {
		t.Fatalf("PUT vci_version = %q, want 1.1", got)
	}
	if got := srv.wallet.VCIFeatureVersion(); got != VCIVersion11 {
		t.Fatalf("wallet feature version = %q, want 1.1", got)
	}

	req := httptest.NewRequest(http.MethodPut, "/api/config/conformance", strings.NewReader(`{"vci_version":"2.0"}`))
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT of an unknown version = %d, want 400: %s", rec.Code, rec.Body.String())
	}
	if got := srv.wallet.VCIFeatureVersion(); got != VCIVersion11 {
		t.Fatalf("wallet feature version after a refused change = %q, want 1.1", got)
	}

	if got := conformanceVCIVersion(t, srv, http.MethodDelete, "/api/config/conformance", ""); got != "1.0" {
		t.Fatalf("after reset vci_version = %q, want the startup 1.0", got)
	}
}

func TestConformanceAPICarriesTheKeyAttestationLevel(t *testing.T) {
	srv := newTestServer(t, true)

	if got := conformanceField(t, srv, http.MethodPut, "/api/config/conformance", `{"key_attestation_level":"none"}`, "key_attestation_level"); got != "none" {
		t.Fatalf("PUT key_attestation_level = %q, want none", got)
	}
	if got := srv.wallet.KeyAttestationLevelSetting(); got != "none" {
		t.Fatalf("wallet setting = %q, want none", got)
	}

	req := httptest.NewRequest(http.MethodPut, "/api/config/conformance", strings.NewReader(`{"key_attestation_level":"None"}`))
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT of a value Appendix D.2 does not define = %d, want 400: %s", rec.Code, rec.Body.String())
	}

	if got := conformanceField(t, srv, http.MethodDelete, "/api/config/conformance", "", "key_attestation_level"); got != "" {
		t.Fatalf("after reset key_attestation_level = %q, want the startup value", got)
	}
}

func conformanceVCIVersion(t *testing.T, srv *Server, method, path, body string) string {
	t.Helper()
	return conformanceField(t, srv, method, path, body, "vci_version")
}

func conformanceField(t *testing.T, srv *Server, method, path, body, field string) string {
	t.Helper()

	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, path, reader)
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s %s = %d, want 200: %s", method, path, rec.Code, rec.Body.String())
	}
	value, _ := decodeJSON(t, rec)[field].(string)
	return value
}

func findInteractiveAuthorizationNote(w *Wallet) (LogEntry, bool) {
	for _, entry := range w.Log {
		if entry.Details["event"] == "interactive_authorization_offered" {
			return entry, true
		}
	}
	return LogEntry{}, false
}

func hasInteractiveAuthorizationNote(w *Wallet, contains string) bool {
	entry, ok := findInteractiveAuthorizationNote(w)
	return ok && strings.Contains(entry.Detail, contains)
}
