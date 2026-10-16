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

package oid4vc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestParseVCIInlineOffer(t *testing.T) {
	offer := `{"credential_issuer":"https://example.com","credential_configuration_ids":["org.iso.18013.5.1.mDL"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"abc123","tx_code":{"input_mode":"numeric","length":6}}}}`
	uri := "openid-credential-offer://?credential_offer=" + url.QueryEscape(offer)

	reqType, result, err := Parse(uri)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reqType != TypeVCI {
		t.Fatalf("expected TypeVCI, got %d", reqType)
	}

	co, ok := result.(*CredentialOffer)
	if !ok {
		t.Fatalf("expected *CredentialOffer, got %T", result)
	}
	if co.CredentialIssuer != "https://example.com" {
		t.Errorf("expected issuer https://example.com, got %s", co.CredentialIssuer)
	}
	if len(co.CredentialConfigurationIDs) != 1 || co.CredentialConfigurationIDs[0] != "org.iso.18013.5.1.mDL" {
		t.Errorf("unexpected credential_configuration_ids: %v", co.CredentialConfigurationIDs)
	}
	if co.Grants.PreAuthorizedCode != "abc123" {
		t.Errorf("expected pre-authorized code abc123, got %s", co.Grants.PreAuthorizedCode)
	}
	if co.Grants.TxCode == nil {
		t.Fatal("expected tx_code to be present")
	}
	if co.Grants.TxCode["input_mode"] != "numeric" {
		t.Errorf("expected input_mode numeric, got %v", co.Grants.TxCode["input_mode"])
	}
}

// TS 119 472-3 V1.1.1 GEN-REQ-4.1-06 defines the EUDI credential offer scheme.
func TestParseEUDICredentialOffer(t *testing.T) {
	offer := `{"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid+sdjwt"]}`
	for _, scheme := range []string{"eu-eaa-offer", "openid-credential-offer", "haip-vci"} {
		t.Run(scheme, func(t *testing.T) {
			kind, parsed, err := Parse(scheme + "://?credential_offer=" + url.QueryEscape(offer))
			if err != nil {
				t.Fatal(err)
			}
			if kind != TypeVCI || parsed.(*CredentialOffer).CredentialConfigurationIDs[0] != "pid+sdjwt" {
				t.Fatalf("credential offer was not preserved: %v", parsed)
			}
		})
	}
}

func TestParseVCIRawJSON(t *testing.T) {
	raw := `{"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid"],"grants":{}}`
	reqType, result, err := Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reqType != TypeVCI {
		t.Fatalf("expected TypeVCI, got %d", reqType)
	}
	co := result.(*CredentialOffer)
	if co.CredentialIssuer != "https://issuer.example" {
		t.Errorf("unexpected issuer: %s", co.CredentialIssuer)
	}
}

func TestParseVCIJWT(t *testing.T) {
	payload := map[string]any{
		"credential_issuer":            "https://jwt-issuer.example",
		"credential_configuration_ids": []string{"pid"},
		"grants":                       map[string]any{},
	}
	jwt := makeTestJWT(map[string]any{"alg": "ES256"}, payload)

	reqType, result, err := Parse(jwt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reqType != TypeVCI {
		t.Fatalf("expected TypeVCI, got %d", reqType)
	}
	co := result.(*CredentialOffer)
	if co.CredentialIssuer != "https://jwt-issuer.example" {
		t.Errorf("unexpected issuer: %s", co.CredentialIssuer)
	}
}

// RFC 3986 §3.1: "schemes are case-insensitive".
func TestParseReadsSchemesWithoutCase(t *testing.T) {
	reqType, _, err := Parse("OPENID4VP://?client_id=https://verifier.example&response_type=vp_token&nonce=abc")
	if err != nil || reqType != TypeVP {
		t.Fatalf("Parse = %d, %v, want a presentation request", reqType, err)
	}
	reqType, _, err = Parse(`OpenID-Credential-Offer://?credential_offer={"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid"]}`)
	if err != nil || reqType != TypeVCI {
		t.Fatalf("Parse = %d, %v, want a credential offer", reqType, err)
	}
}

func TestParseVPInlineParams(t *testing.T) {
	uri := "openid4vp://?client_id=https://verifier.example&response_type=vp_token&nonce=abc&response_mode=direct_post&response_uri=https://verifier.example/cb"

	reqType, result, err := Parse(uri)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reqType != TypeVP {
		t.Fatalf("expected TypeVP, got %d", reqType)
	}

	ar, ok := result.(*AuthorizationRequest)
	if !ok {
		t.Fatalf("expected *AuthorizationRequest, got %T", result)
	}
	if ar.ClientID != "https://verifier.example" {
		t.Errorf("unexpected client_id: %s", ar.ClientID)
	}
	if ar.ResponseType != "vp_token" {
		t.Errorf("unexpected response_type: %s", ar.ResponseType)
	}
	if ar.Nonce != "abc" {
		t.Errorf("unexpected nonce: %s", ar.Nonce)
	}
	if ar.ResponseMode != "direct_post" {
		t.Errorf("unexpected response_mode: %s", ar.ResponseMode)
	}
	if ar.ResponseURI != "https://verifier.example/cb" {
		t.Errorf("unexpected response_uri: %s", ar.ResponseURI)
	}
}

func TestParseVPWithDCQLQuery(t *testing.T) {
	dq := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:test"]}}]}`
	uri := "openid4vp://?client_id=v&response_type=vp_token&dcql_query=" + url.QueryEscape(dq)

	_, result, err := Parse(uri)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ar := result.(*AuthorizationRequest)
	if ar.DCQLQuery == nil {
		t.Fatal("expected dcql_query to be parsed")
	}
	creds, ok := ar.DCQLQuery["credentials"].([]any)
	if !ok || len(creds) == 0 {
		t.Fatal("expected credentials in dcql_query")
	}
}

func TestParseVPDirectJWT(t *testing.T) {
	payload := map[string]any{
		"client_id":     "https://verifier.example",
		"response_type": "vp_token",
		"nonce":         "jwt-nonce",
	}
	jwt := makeTestJWT(map[string]any{"alg": "ES256"}, payload)

	reqType, result, err := Parse(jwt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reqType != TypeVP {
		t.Fatalf("expected TypeVP, got %d", reqType)
	}
	ar := result.(*AuthorizationRequest)
	if ar.ClientID != "https://verifier.example" {
		t.Errorf("unexpected client_id: %s", ar.ClientID)
	}
	if ar.Nonce != "jwt-nonce" {
		t.Errorf("unexpected nonce: %s", ar.Nonce)
	}
	if ar.RequestObject == nil {
		t.Fatal("expected request object to be set")
	}
	if ar.RequestObject.Header["alg"] != "ES256" {
		t.Errorf("unexpected header alg: %v", ar.RequestObject.Header["alg"])
	}
}

func TestParseAlternativeSchemes(t *testing.T) {
	tests := []struct {
		scheme string
	}{
		{"haip-vp://"},
		{"eudi-openid4vp://"},
		{"eu-eaap://"},
	}
	for _, tt := range tests {
		t.Run(tt.scheme, func(t *testing.T) {
			uri := tt.scheme + "?client_id=test&response_type=vp_token"
			reqType, result, err := Parse(uri)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if reqType != TypeVP {
				t.Fatalf("expected TypeVP, got %d", reqType)
			}
			ar := result.(*AuthorizationRequest)
			if ar.ClientID != "test" {
				t.Errorf("unexpected client_id: %s", ar.ClientID)
			}
		})
	}
}

func TestParseHAIPVCIScheme(t *testing.T) {
	offer := `{"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid"],"grants":{}}`
	uri := "haip-vci://?credential_offer=" + url.QueryEscape(offer)

	reqType, result, err := Parse(uri)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reqType != TypeVCI {
		t.Fatalf("expected TypeVCI, got %d", reqType)
	}
	if result.(*CredentialOffer).CredentialIssuer != "https://issuer.example" {
		t.Fatalf("unexpected issuer: %s", result.(*CredentialOffer).CredentialIssuer)
	}
}

func TestParseVPRequestObjectOverridesOuterParams(t *testing.T) {
	payload := map[string]any{
		"client_id":     "https://verifier.example",
		"response_type": "vp_token",
		"response_mode": "direct_post.jwt",
		"response_uri":  "https://verifier.example/request-object",
		"nonce":         "request-object-nonce",
	}
	jwt := makeTestJWT(map[string]any{"alg": "ES256", "typ": "oauth-authz-req+jwt"}, payload)
	uri := "openid4vp://?client_id=https://verifier.example&response_type=vp_token&response_mode=direct_post&response_uri=" +
		url.QueryEscape("https://verifier.example/outer") + "&nonce=outer-nonce&request=" + url.QueryEscape(jwt)

	_, result, err := Parse(uri)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	ar := result.(*AuthorizationRequest)
	if ar.ResponseMode != "direct_post.jwt" {
		t.Errorf("expected request object response_mode, got %s", ar.ResponseMode)
	}
	if ar.ResponseURI != "https://verifier.example/request-object" {
		t.Errorf("expected request object response_uri, got %s", ar.ResponseURI)
	}
	if ar.Nonce != "request-object-nonce" {
		t.Errorf("expected request object nonce, got %s", ar.Nonce)
	}
	if ar.RequestObject == nil || ar.RequestObject.Raw != jwt {
		t.Fatal("expected raw request object to be preserved")
	}
}

func TestParseVPRejectsMismatchedRequestObjectClientID(t *testing.T) {
	payload := map[string]any{
		"client_id":     "https://inner.example",
		"response_type": "vp_token",
	}
	jwt := makeTestJWT(map[string]any{"alg": "ES256"}, payload)
	uri := "openid4vp://?client_id=https://outer.example&request=" + url.QueryEscape(jwt)

	_, _, err := Parse(uri)
	if err == nil {
		t.Fatal("expected client_id mismatch error")
	}
	if got := err.Error(); got == "" || !strings.Contains(got, "client_id") || !strings.Contains(got, "outer") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseVPJSON(t *testing.T) {
	raw := `{"client_id":"https://v.example","response_type":"vp_token","nonce":"n123"}`
	reqType, result, err := Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reqType != TypeVP {
		t.Fatalf("expected TypeVP, got %d", reqType)
	}
	ar := result.(*AuthorizationRequest)
	if ar.ClientID != "https://v.example" {
		t.Errorf("unexpected client_id: %s", ar.ClientID)
	}
}

func TestParseErrorCases(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty", ""},
		{"random string", "not-a-valid-input"},
		{"invalid json", "{broken"},
		{"json without markers", `{"foo":"bar"}`},
		{"legacy haip scheme", "haip://?client_id=test&response_type=vp_token"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := Parse(tt.input)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestParseHTTPURLVCI(t *testing.T) {
	offer := `{"credential_issuer":"https://example.com","credential_configuration_ids":["pid"]}`
	u := "https://issuer.example/offer?credential_offer=" + url.QueryEscape(offer)

	reqType, result, err := Parse(u)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reqType != TypeVCI {
		t.Fatalf("expected TypeVCI, got %d", reqType)
	}
	co := result.(*CredentialOffer)
	if co.CredentialIssuer != "https://example.com" {
		t.Errorf("unexpected issuer: %s", co.CredentialIssuer)
	}
}

func TestParseHTTPURLVP(t *testing.T) {
	u := "https://verifier.example/auth?client_id=test&response_type=vp_token&nonce=n1"

	reqType, result, err := Parse(u)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reqType != TypeVP {
		t.Fatalf("expected TypeVP, got %d", reqType)
	}
	ar := result.(*AuthorizationRequest)
	if ar.ClientID != "test" {
		t.Errorf("unexpected client_id: %s", ar.ClientID)
	}
}

func TestParseVCIWithAuthorizationCodeGrant(t *testing.T) {
	raw := `{"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid"],"grants":{"authorization_code":{"issuer_state":"state123"}}}`
	_, result, err := Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	co := result.(*CredentialOffer)
	if co.Grants.IssuerState != "state123" {
		t.Errorf("expected issuer_state state123, got %s", co.Grants.IssuerState)
	}
}

func TestParseVCIMultipleCredentialConfigs(t *testing.T) {
	raw := `{"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid","mdl","diploma"],"grants":{}}`
	_, result, err := Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	co := result.(*CredentialOffer)
	if len(co.CredentialConfigurationIDs) != 3 {
		t.Fatalf("expected 3 configs, got %d", len(co.CredentialConfigurationIDs))
	}
	expected := []string{"pid", "mdl", "diploma"}
	for i, want := range expected {
		if co.CredentialConfigurationIDs[i] != want {
			t.Errorf("config[%d] = %s, want %s", i, co.CredentialConfigurationIDs[i], want)
		}
	}
}

// OpenID4VCI 1.0 §4.1.1 requires unique ids, so a repeated id is offered once.
func TestParseVCIDeduplicatesConfigurationIDs(t *testing.T) {
	raw := `{"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid","mdl","pid","mdl"]}`
	_, result, err := Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	got := result.(*CredentialOffer).CredentialConfigurationIDs
	if !reflect.DeepEqual(got, []string{"pid", "mdl"}) {
		t.Errorf("CredentialConfigurationIDs = %v, want [pid mdl]", got)
	}
}

// Each offered id makes the wallet resolve metadata and images, so the count
// is capped.
func TestParseVCIRefusesTooManyConfigurationIDs(t *testing.T) {
	ids := make([]string, MaxOfferedConfigurations+1)
	for i := range ids {
		ids[i] = fmt.Sprintf("config-%d", i)
	}
	raw, _ := json.Marshal(map[string]any{"credential_issuer": "https://issuer.example", "credential_configuration_ids": ids})
	if _, _, err := Parse(string(raw)); !errors.Is(err, ErrInvalidCredentialOffer) {
		t.Fatalf("err = %v, want ErrInvalidCredentialOffer", err)
	}

	raw, _ = json.Marshal(map[string]any{"credential_issuer": "https://issuer.example", "credential_configuration_ids": ids[:MaxOfferedConfigurations]})
	if _, _, err := Parse(string(raw)); err != nil {
		t.Fatalf("offer with %d ids: %v", MaxOfferedConfigurations, err)
	}
}

func TestParseVCIFullJSONPreserved(t *testing.T) {
	raw := `{"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid"],"grants":{},"custom_field":"custom_value"}`
	_, result, err := Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	co := result.(*CredentialOffer)
	if co.FullJSON == nil {
		t.Fatal("expected FullJSON to be preserved")
	}
	if co.FullJSON["custom_field"] != "custom_value" {
		t.Errorf("expected custom_field to be preserved, got %v", co.FullJSON["custom_field"])
	}
}

func TestParseVPFullParams(t *testing.T) {
	uri := "openid4vp://?client_id=v&response_type=vp_token&nonce=n&state=s&scope=openid&redirect_uri=https://r.example"

	_, result, err := Parse(uri)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ar := result.(*AuthorizationRequest)
	if ar.State != "s" {
		t.Errorf("state = %s, want s", ar.State)
	}
	if ar.Scope != "openid" {
		t.Errorf("scope = %s, want openid", ar.Scope)
	}
	if ar.RedirectURI != "https://r.example" {
		t.Errorf("redirect_uri = %s, want https://r.example", ar.RedirectURI)
	}
	if ar.FullParams["client_id"] != "v" {
		t.Errorf("FullParams[client_id] = %s, want v", ar.FullParams["client_id"])
	}
	if ar.FullParams["nonce"] != "n" {
		t.Errorf("FullParams[nonce] = %s, want n", ar.FullParams["nonce"])
	}
}

func TestParseVPJWTAutoDetectByResponseType(t *testing.T) {
	payload := map[string]any{
		"response_type": "vp_token",
		"nonce":         "n1",
	}
	jwt := makeTestJWT(map[string]any{"alg": "RS256"}, payload)

	reqType, result, err := Parse(jwt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reqType != TypeVP {
		t.Fatalf("expected TypeVP, got %d", reqType)
	}
	ar := result.(*AuthorizationRequest)
	if ar.ResponseType != "vp_token" {
		t.Errorf("response_type = %s, want vp_token", ar.ResponseType)
	}
}

func TestParseVPJSONWithDCQLQueryCredentials(t *testing.T) {
	raw := `{"client_id":"v","response_type":"vp_token","dcql_query":{"credentials":[{"id":"pid","format":"dc+sd-jwt"}]}}`
	_, result, err := Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ar := result.(*AuthorizationRequest)
	if ar.DCQLQuery == nil {
		t.Fatal("expected dcql_query")
	}
	creds, ok := ar.DCQLQuery["credentials"].([]any)
	if !ok || len(creds) != 1 {
		t.Fatalf("expected 1 credential query, got %v", ar.DCQLQuery["credentials"])
	}
}

func TestParseVPJSONWithDCQLQuery(t *testing.T) {
	raw := `{"client_id":"v","response_type":"vp_token","dcql_query":{"credentials":[]}}`
	_, result, err := Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ar := result.(*AuthorizationRequest)
	if ar.DCQLQuery == nil {
		t.Fatal("expected dcql_query")
	}
}

// OpenID4VCI 1.0 §4.1: the offer carries "either credential_offer or
// credential_offer_uri". §4.1.1 marks pre-authorized_code REQUIRED in the
// pre-authorized grant.
func TestParseRefusesAnAmbiguousOffer(t *testing.T) {
	inline := url.QueryEscape(`{"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid"]}`)
	noCode := url.QueryEscape(`{"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid"],` +
		`"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"tx_code":{}},"authorization_code":{}}}`)
	for name, tt := range map[string]struct{ uri, want string }{
		"both parameters":                     {"openid-credential-offer://?credential_offer=" + inline + "&credential_offer_uri=" + url.QueryEscape("https://issuer.example/offer"), "§4.1 "},
		"pre-authorized grant without a code": {"openid-credential-offer://?credential_offer=" + noCode, "§4.1.1"},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := Parse(tt.uri)
			if !errors.Is(err, ErrInvalidCredentialOffer) || !strings.Contains(err.Error(), tt.want) {
				t.Errorf("err = %v, want an invalid offer citing %s", err, tt.want)
			}
		})
	}
}

func TestParseVCINoCredentialOffer(t *testing.T) {
	uri := "openid-credential-offer://?some_other_param=value"
	_, _, err := Parse(uri)
	if err == nil {
		t.Error("expected error when no credential_offer param")
	}
}

func TestParseWhitespace(t *testing.T) {
	raw := `  {"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid"],"grants":{}}  `
	reqType, _, err := Parse(raw)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if reqType != TypeVCI {
		t.Fatalf("expected TypeVCI, got %d", reqType)
	}
}

func TestParseJWTNoMarkers(t *testing.T) {
	payload := map[string]any{"sub": "user", "iss": "https://example.com"}
	jwt := makeTestJWT(map[string]any{"alg": "ES256"}, payload)
	_, _, err := Parse(jwt)
	if err == nil {
		t.Error("expected error for JWT without VCI/VP markers")
	}
}

func TestParseVPJWTPayloadMerge(t *testing.T) {
	payload := map[string]any{
		"client_id":     "https://verifier.example",
		"response_type": "vp_token",
		"response_mode": "direct_post",
		"nonce":         "n1",
		"state":         "s1",
		"response_uri":  "https://verifier.example/cb",
		"scope":         "openid",
		"dcql_query": map[string]any{
			"credentials": []any{},
		},
	}
	jwt := makeTestJWT(map[string]any{"alg": "ES256"}, payload)

	_, result, err := Parse(jwt)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	ar := result.(*AuthorizationRequest)
	if ar.ResponseMode != "direct_post" {
		t.Errorf("response_mode = %s, want direct_post", ar.ResponseMode)
	}
	if ar.State != "s1" {
		t.Errorf("state = %s, want s1", ar.State)
	}
	if ar.ResponseURI != "https://verifier.example/cb" {
		t.Errorf("response_uri = %s, want https://verifier.example/cb", ar.ResponseURI)
	}
	if ar.Scope != "openid" {
		t.Errorf("scope = %s, want openid", ar.Scope)
	}
	if ar.DCQLQuery == nil {
		t.Fatal("expected dcql_query from JWT payload")
	}
}

func makeTestJWT(header, payload map[string]any) string {
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(h) + "." +
		base64.RawURLEncoding.EncodeToString(p) + "." +
		base64.RawURLEncoding.EncodeToString([]byte("test-signature"))
}

// OID4VP 1.0 §5.10.1: "The Wallet MUST extract the set of Authorization
// Request parameters from the Request Object. The Wallet MUST only use the
// parameters in this Request Object, even if the same parameter was provided
// in an Authorization Request query parameter."
//
// The query string is unsigned.
func TestParseVPQueryParametersNeverOutrankTheRequestObject(t *testing.T) {
	signedQuery := map[string]any{
		"credentials": []any{map[string]any{
			"id":     "pid",
			"format": "dc+sd-jwt",
			"meta":   map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
			"claims": []any{map[string]any{"path": []any{"given_name"}}},
		}},
	}
	payload := map[string]any{
		"client_id":     "https://verifier.example",
		"response_type": "vp_token",
		"response_mode": "direct_post.jwt",
		"response_uri":  "https://verifier.example/signed",
		"nonce":         "signed-nonce",
		"dcql_query":    signedQuery,
	}
	jwt := makeTestJWT(map[string]any{"alg": "ES256", "typ": "oauth-authz-req+jwt"}, payload)

	// Everything an attacker could append to the invocation URL.
	attackerQuery := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["urn:eudi:pid:1"]},` +
		`"claims":[{"path":["given_name"]},{"path":["family_name"]},{"path":["birthdate"]}]}]}`
	uri := "openid4vp://?client_id=https://verifier.example&request=" + url.QueryEscape(jwt) +
		"&dcql_query=" + url.QueryEscape(attackerQuery) +
		"&response_uri=" + url.QueryEscape("https://attacker.example/collect") +
		"&nonce=attacker-nonce&response_mode=direct_post&state=attacker-state"

	_, result, err := Parse(uri)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	ar := result.(*AuthorizationRequest)

	creds, _ := ar.DCQLQuery["credentials"].([]any)
	if len(creds) != 1 {
		t.Fatalf("credentials = %d, want 1", len(creds))
	}
	claims, _ := creds[0].(map[string]any)["claims"].([]any)
	if len(claims) != 1 {
		t.Errorf("claims = %d, want the single claim the Verifier signed for", len(claims))
	}
	if ar.ResponseURI != "https://verifier.example/signed" {
		t.Errorf("response_uri = %q, want the signed one", ar.ResponseURI)
	}
	if ar.Nonce != "signed-nonce" {
		t.Errorf("nonce = %q, want the signed one", ar.Nonce)
	}
	if ar.ResponseMode != "direct_post.jwt" {
		t.Errorf("response_mode = %q, want the signed one", ar.ResponseMode)
	}
	if ar.State != "" {
		t.Errorf("state = %q, want it absent: the Request Object carried none", ar.State)
	}
}

// A parameter missing from the Request Object stays absent.
func TestParseVPDropsQueryParametersTheRequestObjectOmits(t *testing.T) {
	payload := map[string]any{
		"client_id":     "https://verifier.example",
		"response_type": "vp_token",
		"response_mode": "direct_post.jwt",
		"response_uri":  "https://verifier.example/signed",
		"nonce":         "signed-nonce",
	}
	jwt := makeTestJWT(map[string]any{"alg": "ES256", "typ": "oauth-authz-req+jwt"}, payload)
	uri := "openid4vp://?client_id=https://verifier.example&request=" + url.QueryEscape(jwt) +
		"&scope=" + url.QueryEscape("openid pid") +
		"&redirect_uri=" + url.QueryEscape("https://attacker.example/cb") +
		"&client_metadata=" + url.QueryEscape(`{"jwks":{"keys":[]}}`)

	_, result, err := Parse(uri)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	ar := result.(*AuthorizationRequest)

	if ar.Scope != "" {
		t.Errorf("scope = %q, want it absent", ar.Scope)
	}
	if ar.RedirectURI != "" {
		t.Errorf("redirect_uri = %q, want it absent", ar.RedirectURI)
	}
	if ar.ClientMetadata != nil {
		t.Errorf("client_metadata = %v, want it absent", ar.ClientMetadata)
	}
	// The transport parameters are kept.
	if ar.RequestObject == nil {
		t.Error("the raw request object was dropped")
	}
}

// §5.10.1 requires the inner and outer client_id to be identical. A missing
// inner client_id fails that check.
func TestParseVPRejectsARequestObjectWithoutClientID(t *testing.T) {
	jwt := makeTestJWT(map[string]any{"alg": "ES256"}, map[string]any{"response_type": "vp_token"})
	uri := "openid4vp://?client_id=https://outer.example&request=" + url.QueryEscape(jwt)

	if _, _, err := Parse(uri); err == nil {
		t.Fatal("expected a client_id mismatch error")
	}
}

// The same rule applies to an object fetched from request_uri.
func TestParseVPRequestURIObjectOutranksTheQueryString(t *testing.T) {
	payload := map[string]any{
		"client_id":     "https://verifier.example",
		"response_type": "vp_token",
		"response_mode": "direct_post.jwt",
		"response_uri":  "https://verifier.example/signed",
		"nonce":         "signed-nonce",
	}
	jwt := makeTestJWT(map[string]any{"alg": "ES256", "typ": "oauth-authz-req+jwt"}, payload)
	uri := "openid4vp://?client_id=https://verifier.example&request_uri=" +
		url.QueryEscape("https://verifier.example/req") + "&nonce=attacker-nonce"

	_, result, err := ParseWithOptions(uri, ParseOptions{
		FetchRequestURI: func(string, string, string) (string, error) { return jwt, nil },
	})
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	ar := result.(*AuthorizationRequest)
	if ar.Nonce != "signed-nonce" {
		t.Errorf("nonce = %q, want the signed one", ar.Nonce)
	}
	if ar.RequestURI == "" {
		t.Error("request_uri was dropped, it records how the object arrived")
	}
}

// OID4VCI 1.0 §4.1.1: an empty tx_code object still requires a code.
func TestParseEmptyTxCodeRequiresCode(t *testing.T) {
	offer := `{"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid"],"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"abc","tx_code":{}}}}`
	_, result, err := Parse("openid-credential-offer://?credential_offer=" + url.QueryEscape(offer))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	grants := result.(*CredentialOffer).Grants
	if !grants.RequiresTxCode() {
		t.Error("an empty tx_code object must require a transaction code")
	}
	if hint := grants.TxCodeHint(); hint != "" {
		t.Errorf("TxCodeHint = %q, want none for an empty object", hint)
	}
}

func TestTxCodeHint(t *testing.T) {
	for _, tc := range []struct {
		txCode map[string]any
		want   string
	}{
		{map[string]any{"input_mode": "numeric", "length": float64(6)}, "6 numeric characters"},
		{map[string]any{"length": float64(4)}, "4 characters"},
		{map[string]any{"input_mode": "text"}, "text"},
		{map[string]any{"input_mode": "text", "description": " From the letter "}, "From the letter"},
	} {
		if got := (OfferGrants{TxCode: tc.txCode}).TxCodeHint(); got != tc.want {
			t.Errorf("TxCodeHint(%v) = %q, want %q", tc.txCode, got, tc.want)
		}
	}
}
