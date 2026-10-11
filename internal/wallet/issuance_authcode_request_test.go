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
	"unicode/utf8"
)

// redirectAuthCodeIssuer is an issuer without PAR or DPoP. Its authorization
// endpoint redirects straight back with a code.
type redirectAuthCodeIssuer struct {
	// configuration is the test-config credential configuration.
	configuration map[string]any
	// authorizationQuery is a query the authorization_endpoint carries in
	// its metadata.
	authorizationQuery string
	authMethods        []string
	// asIssuer replaces the issuer of the authorization server metadata.
	asIssuer string

	authQuery  url.Values
	tokenForms []url.Values
}

func (c *redirectAuthCodeIssuer) run(t *testing.T, w *Wallet) error {
	t.Helper()
	w.VCIClientID = "wallet-client"
	w.VCIRedirectURI = "https://wallet.example/callback"
	credRaw := generateTestCredential(t, w)
	var serverURL string

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":     serverURL,
				"authorization_servers": []string{serverURL},
				"credential_endpoint":   serverURL + "/credential",
				"credential_configurations_supported": map[string]any{
					"test-config": c.configuration,
				},
			})
		case strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server"):
			issuer := serverURL
			if c.asIssuer != "" {
				issuer = c.asIssuer
			}
			meta := map[string]any{
				"issuer":                 issuer,
				"authorization_endpoint": serverURL + "/authorize" + c.authorizationQuery,
				"token_endpoint":         serverURL + "/token",
			}
			if c.authMethods != nil {
				meta["token_endpoint_auth_methods_supported"] = c.authMethods
			}
			_ = json.NewEncoder(rw).Encode(meta)
		case r.URL.Path == "/authorize":
			c.authQuery = r.URL.Query()
			http.Redirect(rw, r, w.VCIRedirectURI+"?code=issued-code&state="+url.QueryEscape(c.authQuery.Get("state")), http.StatusFound)
		case r.URL.Path == "/token":
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			c.tokenForms = append(c.tokenForms, form)
			_ = json.NewEncoder(rw).Encode(map[string]any{"access_token": "plain-bearer-token", "token_type": "Bearer"})
		case r.URL.Path == "/credential":
			_ = json.NewEncoder(rw).Encode(map[string]any{"credentials": []any{map[string]any{"credential": credRaw}}})
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	serverURL = srv.URL

	oldClient := httpClient
	httpClient = srv.Client()
	t.Cleanup(func() { httpClient = oldClient })

	offerJSON, _ := json.Marshal(map[string]any{
		"credential_issuer":            serverURL,
		"credential_configuration_ids": []string{"test-config"},
		"grants":                       map[string]any{"authorization_code": map[string]any{}},
	})
	_, err := w.ProcessCredentialOffer("openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON)))
	return err
}

// OID4VCI 1.0 §12.2.4: "If scope is absent, the only way to request the
// Credential is using authorization_details".
func TestAuthCodeWithoutScopeRequestsAuthorizationDetails(t *testing.T) {
	issuer := &redirectAuthCodeIssuer{configuration: map[string]any{"format": "dc+sd-jwt"}}
	if err := issuer.run(t, generateTestWallet(t)); err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
	if issuer.authQuery.Has("scope") {
		t.Errorf("authorization request carried scope %q", issuer.authQuery.Get("scope"))
	}
	var details []map[string]any
	if err := json.Unmarshal([]byte(issuer.authQuery.Get("authorization_details")), &details); err != nil {
		t.Fatalf("authorization_details: %v", err)
	}
	if len(details) != 1 || details[0]["type"] != "openid_credential" || details[0]["credential_configuration_id"] != "test-config" {
		t.Errorf("authorization_details = %v, want one openid_credential entry for test-config", details)
	}
}

// HAIP 1.0 §4.1 requires a scope for every credential configuration.
func TestAuthCodeWithoutScopeUnderHAIP(t *testing.T) {
	metadata := map[string]any{"credential_configurations_supported": map[string]any{"test-config": map[string]any{}}}

	strict := generateTestWallet(t)
	strict.RequireHAIP = true
	strict.ValidationMode = ValidationModeStrict
	if _, err := strict.authorizationCredentialRequest(metadata, "test-config"); err == nil {
		t.Error("strict HAIP accepted a credential configuration without scope")
	}

	debug := generateTestWallet(t)
	debug.RequireHAIP = true
	debug.ValidationMode = ValidationModeDebug
	request, err := debug.authorizationCredentialRequest(metadata, "test-config")
	if err != nil || !request.Has("authorization_details") {
		t.Fatalf("debug HAIP = %v, %v, want authorization_details", request, err)
	}
	if !hasWarningContaining(debug, "HAIP 1.0 §4.1") {
		t.Error("debug HAIP did not report the missing scope")
	}
}

// RFC 6749 §3.1: the authorization endpoint's own query "MUST be retained when
// adding additional query parameters".
func TestAuthorizationRequestKeepsTheEndpointQuery(t *testing.T) {
	issuer := &redirectAuthCodeIssuer{
		configuration:      map[string]any{"format": "dc+sd-jwt", "scope": "test-scope"},
		authorizationQuery: "?tenant=a",
	}
	if err := issuer.run(t, generateTestWallet(t)); err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
	if issuer.authQuery.Get("tenant") != "a" || issuer.authQuery.Get("scope") != "test-scope" {
		t.Errorf("authorization request query = %v, want tenant=a next to the request parameters", issuer.authQuery)
	}
}

// Client authentication goes to the token endpoint. The browser URL of the
// authorization request does not carry the client assertion.
func TestPrivateKeyJWTStaysOutOfTheAuthorizationURL(t *testing.T) {
	issuer := &redirectAuthCodeIssuer{
		configuration: map[string]any{"format": "dc+sd-jwt", "scope": "test-scope"},
		authMethods:   []string{"private_key_jwt"},
	}
	if err := issuer.run(t, generateTestWallet(t)); err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
	if issuer.authQuery.Has("client_assertion") {
		t.Error("the authorization request URL carried the client assertion")
	}
	if len(issuer.tokenForms) != 1 || issuer.tokenForms[0].Get("client_assertion") == "" {
		t.Error("the token request carried no client assertion")
	}
}

// A retry after a DPoP nonce challenge carries a new client assertion, since a
// server may accept a jti only once.
func TestClientAssertionIsFreshOnRetry(t *testing.T) {
	w := generateTestWallet(t)
	var jtis []any
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		jtis = append(jtis, decodeJWTPart(t, r.PostForm.Get("client_assertion"), 1)["jti"])
		rw.Header().Set("Content-Type", "application/json")
		if len(jtis) == 1 {
			rw.Header().Set("DPoP-Nonce", "server-nonce")
			rw.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(rw, `{"error":"use_dpop_nonce"}`)
			return
		}
		_, _ = io.WriteString(rw, `{"access_token":"t"}`)
	}))
	defer srv.Close()

	authenticator := w.clientAuthenticatorFor(&ClientAuthentication{Method: ClientAuthPrivateKeyJWT, Audience: srv.URL}, "wallet-client")
	var nonce string
	if _, err := postFormWithDPoP(srv.Client(), srv.URL, url.Values{"grant_type": {"authorization_code"}}, w.HolderKey, "", &nonce, authenticator); err != nil {
		t.Fatalf("postFormWithDPoP: %v", err)
	}
	if len(jtis) != 2 || jtis[0] == nil || jtis[0] == jtis[1] {
		t.Errorf("client assertion jtis = %v, want two different ones", jtis)
	}
}

// RFC 8414 §3.3: the metadata issuer "MUST be identical" to the identifier it
// was fetched for. Debug mode reports a mismatch and continues. Strict mode
// refuses.
func TestAuthorizationServerIssuerMismatch(t *testing.T) {
	configuration := map[string]any{"format": "dc+sd-jwt", "scope": "test-scope"}

	debug := generateTestWallet(t)
	if err := (&redirectAuthCodeIssuer{configuration: configuration, asIssuer: "https://other.example"}).run(t, debug); err != nil {
		t.Fatalf("debug mode: %v", err)
	}
	if !hasWarningContaining(debug, "https://other.example") {
		t.Error("debug mode did not report the issuer mismatch")
	}

	strict := generateTestWallet(t)
	strict.ValidationMode = ValidationModeStrict
	if err := (&redirectAuthCodeIssuer{configuration: configuration, asIssuer: "https://other.example"}).run(t, strict); err == nil || !strings.Contains(err.Error(), "https://other.example") {
		t.Errorf("strict mode error = %v, want the issuer mismatch refused", err)
	}
}

// An issuer's error body can be any text, so the excerpt keeps whole UTF-8
// characters.
func TestTruncateBodyKeepsWholeCharacters(t *testing.T) {
	got := truncateBody(strings.Repeat("é", 300))
	if !utf8.ValidString(got) || got != strings.Repeat("é", 200)+"..." {
		t.Errorf("truncateBody = %q, want 200 é and ...", got)
	}
}
