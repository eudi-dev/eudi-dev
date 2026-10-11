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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// RFC 8414 §3.3 requires the metadata issuer to be identical to the
// identifier the metadata was fetched for.
func TestValidateAuthorizationServerIssuerComparesExactly(t *testing.T) {
	if err := validateAuthorizationServerIssuer("https://as.example", map[string]any{"issuer": "https://as.example"}); err != nil {
		t.Fatalf("identical issuer refused: %v", err)
	}
	if err := validateAuthorizationServerIssuer("https://as.example", map[string]any{"issuer": "https://as.example/"}); err == nil {
		t.Fatal("an issuer that differs by a trailing slash was accepted")
	}
}

// The pre-authorized flow uses the authorization server metadata as the
// authorization code flow does, so RFC 8414 §3.3 applies to it too: "If these
// values are not identical, the data contained in the response MUST NOT be
// used."
func TestPreAuthorizedFlowChecksTheAuthorizationServerIssuer(t *testing.T) {
	w := generateTestWallet(t)
	w.ValidationMode = ValidationModeStrict
	var serverURL string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			writeTestJSON(rw, map[string]any{
				"credential_issuer":     serverURL,
				"credential_endpoint":   serverURL + "/credential",
				"authorization_servers": []any{serverURL},
				"credential_configurations_supported": map[string]any{
					"cfg": map[string]any{"format": "dc+sd-jwt", "vct": "urn:test:credential", "scope": "cfg"},
				},
			})
		case strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server"):
			writeTestJSON(rw, map[string]any{
				"issuer":         "https://another-server.example",
				"token_endpoint": serverURL + "/token",
			})
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	serverURL = srv.URL
	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	offer, _ := json.Marshal(map[string]any{
		"credential_issuer":            serverURL,
		"credential_configuration_ids": []string{"cfg"},
		"grants":                       map[string]any{preAuthorizedCodeGrant: map[string]any{"pre-authorized_code": "code"}},
	})
	_, err := w.ProcessCredentialOffer("openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offer)))
	if err == nil || !strings.Contains(err.Error(), "did not match") {
		t.Fatalf("err %v, want the mismatched authorization server issuer refused", err)
	}
}
