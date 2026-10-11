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

package proxy

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/jwe"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/web"
)

func TestClassifyVCIMetadata(t *testing.T) {
	e := &TrafficEntry{
		Method:     "GET",
		URL:        "http://issuer.example/.well-known/openid-credential-issuer",
		StatusCode: 200,
	}
	Classify(e)
	if e.Class != ClassVCIMetadata {
		t.Errorf("expected ClassVCIMetadata, got %d (%s)", e.Class, e.ClassLabel)
	}
}

func TestClassifyVCICredentialOffer(t *testing.T) {
	e := &TrafficEntry{
		Method:     "GET",
		URL:        `http://example.com/?credential_offer={"issuer":"test"}`,
		StatusCode: 200,
	}
	Classify(e)
	if e.Class != ClassVCICredentialOffer {
		t.Errorf("expected ClassVCICredentialOffer, got %d (%s)", e.Class, e.ClassLabel)
	}
}

func TestClassifyVCICredentialOfferURI(t *testing.T) {
	e := &TrafficEntry{
		Method:     "GET",
		URL:        "http://example.com/?credential_offer_uri=https://issuer.example/offer/123",
		StatusCode: 200,
	}
	Classify(e)
	if e.Class != ClassVCICredentialOffer {
		t.Errorf("expected ClassVCICredentialOffer, got %d (%s)", e.Class, e.ClassLabel)
	}
}

func TestClassifyVPAuthRequest(t *testing.T) {
	e := &TrafficEntry{
		Method:     "GET",
		URL:        "http://example.com/authorize?client_id=did:web:v&response_type=vp_token&state=s1",
		StatusCode: 200,
	}
	Classify(e)
	if e.Class != ClassVPAuthRequest {
		t.Errorf("expected ClassVPAuthRequest, got %d (%s)", e.Class, e.ClassLabel)
	}
}

func TestClassifyVPRequestObject(t *testing.T) {
	e := &TrafficEntry{
		Method:       "GET",
		URL:          "http://example.com/request/abc",
		StatusCode:   200,
		ResponseBody: "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.signature",
	}
	Classify(e)
	if e.Class != ClassVPRequestObject {
		t.Errorf("expected ClassVPRequestObject, got %d (%s)", e.Class, e.ClassLabel)
	}
}

func TestClassifyVPAuthResponse(t *testing.T) {
	e := &TrafficEntry{
		Method:      "POST",
		URL:         "http://example.com/response",
		RequestBody: "vp_token=eyJ...&state=s1",
		StatusCode:  200,
	}
	Classify(e)
	if e.Class != ClassVPAuthResponse {
		t.Errorf("expected ClassVPAuthResponse, got %d (%s)", e.Class, e.ClassLabel)
	}
}

func TestClassifyVPAuthResponseWithJARM(t *testing.T) {
	e := &TrafficEntry{
		Method:      "POST",
		URL:         "http://example.com/response",
		RequestBody: "response=eyJhbGci.eyJ.sig.enc.tag",
		StatusCode:  200,
	}
	Classify(e)
	if e.Class != ClassVPAuthResponse {
		t.Errorf("expected ClassVPAuthResponse, got %d (%s)", e.Class, e.ClassLabel)
	}
}

func TestClassifyVCITokenRequest(t *testing.T) {
	e := &TrafficEntry{
		Method:      "POST",
		URL:         "http://issuer.example/oauth/token",
		RequestBody: "grant_type=authorization_code&code=abc",
		StatusCode:  200,
	}
	Classify(e)
	if e.Class != ClassVCITokenRequest {
		t.Errorf("expected ClassVCITokenRequest, got %d (%s)", e.Class, e.ClassLabel)
	}
}

func TestClassifyVCICredentialRequest(t *testing.T) {
	e := &TrafficEntry{
		Method:      "POST",
		URL:         "http://issuer.example/credential",
		RequestBody: `{"format":"vc+sd-jwt"}`,
		StatusCode:  200,
	}
	Classify(e)
	if e.Class != ClassVCICredentialRequest {
		t.Errorf("expected ClassVCICredentialRequest, got %d (%s)", e.Class, e.ClassLabel)
	}
}

func TestClassifyVCICredentialRequestPlural(t *testing.T) {
	e := &TrafficEntry{
		Method:      "POST",
		URL:         "http://issuer.example/credentials",
		RequestBody: `{"format":"vc+sd-jwt"}`,
		StatusCode:  200,
	}
	Classify(e)
	if e.Class != ClassVCICredentialRequest {
		t.Errorf("expected ClassVCICredentialRequest, got %d (%s)", e.Class, e.ClassLabel)
	}
}

func TestClassifyVCINonceRequest(t *testing.T) {
	e := &TrafficEntry{
		Method:       "POST",
		URL:          "https://issuer.example/realms/demo/protocol/oid4vc/nonce",
		StatusCode:   200,
		ResponseBody: `{"c_nonce":"nonce-123"}`,
	}
	Classify(e)
	if e.Class != ClassVCINonceRequest {
		t.Errorf("expected ClassVCINonceRequest, got %d (%s)", e.Class, e.ClassLabel)
	}
}

func TestClassifyOIDCMetadata(t *testing.T) {
	e := &TrafficEntry{
		Method:     "GET",
		URL:        "https://issuer.example/.well-known/openid-configuration",
		StatusCode: 200,
	}
	Classify(e)
	if e.Class != ClassOIDCMetadata {
		t.Errorf("expected ClassOIDCMetadata, got %d (%s)", e.Class, e.ClassLabel)
	}
}

func TestClassifyOIDCAuthRequest(t *testing.T) {
	e := &TrafficEntry{
		Method:     "GET",
		URL:        "https://issuer.example/auth?client_id=wallet-app&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&response_type=code&scope=openid&state=s1",
		StatusCode: 302,
	}
	Classify(e)
	if e.Class != ClassOIDCAuthRequest {
		t.Errorf("expected ClassOIDCAuthRequest, got %d (%s)", e.Class, e.ClassLabel)
	}
}

func TestClassifyOIDCTokenRequest(t *testing.T) {
	e := &TrafficEntry{
		Method:       "POST",
		URL:          "https://issuer.example/realms/demo/protocol/openid-connect/token",
		RequestBody:  "grant_type=authorization_code&code=abc&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback",
		StatusCode:   200,
		ResponseBody: `{"access_token":"opaque","id_token":"header.payload.sig"}`,
	}
	Classify(e)
	if e.Class != ClassOIDCTokenRequest {
		t.Errorf("expected ClassOIDCTokenRequest, got %d (%s)", e.Class, e.ClassLabel)
	}
}

func TestClassifyOIDCCallback(t *testing.T) {
	e := &TrafficEntry{
		Method:     "GET",
		URL:        "https://app.example/callback?code=abc&state=s1",
		StatusCode: 302,
	}
	Classify(e)
	if e.Class != ClassOIDCCallback {
		t.Errorf("expected ClassOIDCCallback, got %d (%s)", e.Class, e.ClassLabel)
	}
}

func TestClassifyUnknown(t *testing.T) {
	e := &TrafficEntry{
		Method:     "GET",
		URL:        "http://example.com/favicon.ico",
		StatusCode: 200,
	}
	Classify(e)
	if e.Class != ClassUnknown {
		t.Errorf("expected ClassUnknown, got %d (%s)", e.Class, e.ClassLabel)
	}
}

func TestClassifyUnknownSetsLabel(t *testing.T) {
	e := &TrafficEntry{
		Method:     "GET",
		URL:        "http://example.com/other",
		StatusCode: 200,
	}
	Classify(e)
	if e.ClassLabel != "Unknown" {
		t.Errorf("expected label 'Unknown', got %q", e.ClassLabel)
	}
}

func TestIsJWTBody(t *testing.T) {
	tests := []struct {
		body string
		want bool
	}{
		{"eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.signature", true},
		{"  eyJhbGci.eyJpc3M.sig  ", true}, // with whitespace
		{"not-a-jwt", false},
		{"", false},
		{`{"json":"object"}`, false},
		{"<html>content</html>", false},
		{"a.b.c.d.e", false}, // 5 parts → not 3-part JWT
		{"a..c", false},      // empty middle part
	}

	for _, tt := range tests {
		if got := isJWTBody(tt.body); got != tt.want {
			t.Errorf("isJWTBody(%q) = %v, want %v", tt.body, got, tt.want)
		}
	}
}

func TestIsJWE(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"a.b.c.d.e", true},
		{"header.key.iv.cipher.tag", true},
		{"  a.b.c.d.e  ", true}, // with whitespace
		{"a.b.c", false},        // JWT, not JWE
		{"", false},
		{".b.c.d.e", false}, // empty first part
	}

	for _, tt := range tests {
		if got := isJWE(tt.s); got != tt.want {
			t.Errorf("isJWE(%q) = %v, want %v", tt.s, got, tt.want)
		}
	}
}

func TestHasBodyFieldFormEncoded(t *testing.T) {
	body := "vp_token=abc&state=s1"
	if !hasBodyField(body, "vp_token") {
		t.Error("expected true for vp_token in form body")
	}
	if !hasBodyField(body, "state") {
		t.Error("expected true for state in form body")
	}
	if hasBodyField(body, "nonce") {
		t.Error("expected false for nonce not in form body")
	}
}

func TestHasBodyFieldJSON(t *testing.T) {
	body := `{"vp_token":"abc","presentation_submission":{}}`
	if !hasBodyField(body, "vp_token") {
		t.Error("expected true for vp_token in JSON body")
	}
	if !hasBodyField(body, "presentation_submission") {
		t.Error("expected true for presentation_submission in JSON body")
	}
	if hasBodyField(body, "missing") {
		t.Error("expected false for missing field in JSON body")
	}
}

func TestHasBodyFieldEmpty(t *testing.T) {
	if hasBodyField("", "field") {
		t.Error("expected false for empty body")
	}
}

func TestParseFormOrJSONForm(t *testing.T) {
	result := parseFormOrJSON("grant_type=authorization_code&code=abc123")
	if result["grant_type"] != "authorization_code" {
		t.Errorf("expected grant_type=authorization_code, got %q", result["grant_type"])
	}
	if result["code"] != "abc123" {
		t.Errorf("expected code=abc123, got %q", result["code"])
	}
}

func TestParseFormOrJSONAmbiguousInput(t *testing.T) {
	// url.ParseQuery reads JSON input as a single key holding the entire JSON.
	result := parseFormOrJSON(`{"format":"jwt"}`)
	if len(result) == 0 {
		t.Error("expected non-empty result")
	}
}

func TestParseFormOrJSONInvalidInput(t *testing.T) {
	result := parseFormOrJSON("")
	if len(result) != 0 {
		t.Errorf("expected empty map for empty body, got %v", result)
	}
}

func TestParseFormOrJSONEmpty(t *testing.T) {
	result := parseFormOrJSON("")
	if len(result) != 0 {
		t.Errorf("expected empty map for empty body, got %v", result)
	}
}

func TestTruncate(t *testing.T) {
	if got := format.Truncate("short", 10); got != "short" {
		t.Errorf("expected 'short', got %q", got)
	}
	if got := format.Truncate("a very long string", 5); got != "a ver..." {
		t.Errorf("expected 'a ver...', got %q", got)
	}
	if got := format.Truncate("exact", 5); got != "exact" {
		t.Errorf("expected 'exact', got %q", got)
	}
}

func TestDecodeEntryVPAuthRequest(t *testing.T) {
	e := &TrafficEntry{
		Method:     "GET",
		URL:        "http://example.com/authorize?client_id=did:web:v&response_type=vp_token&nonce=n1&state=s1&response_mode=direct_post&request_uri=http://example.com/req&response_uri=http://example.com/resp",
		StatusCode: 200,
	}
	Classify(e)

	if e.Decoded["client_id"] != "did:web:v" {
		t.Errorf("client_id: got %v", e.Decoded["client_id"])
	}
	if e.Decoded["nonce"] != "n1" {
		t.Errorf("nonce: got %v", e.Decoded["nonce"])
	}
	if e.Decoded["state"] != "s1" {
		t.Errorf("state: got %v", e.Decoded["state"])
	}
	if e.Decoded["response_mode"] != "direct_post" {
		t.Errorf("response_mode: got %v", e.Decoded["response_mode"])
	}
	if e.Decoded["request_uri"] != "http://example.com/req" {
		t.Errorf("request_uri: got %v", e.Decoded["request_uri"])
	}
	if e.Decoded["response_uri"] != "http://example.com/resp" {
		t.Errorf("response_uri: got %v", e.Decoded["response_uri"])
	}
}

func TestDecodeEntryVPAuthRequestDCQL(t *testing.T) {
	dcql := `{"credentials":[{"id":"c1"}]}`
	e := &TrafficEntry{
		Method:     "GET",
		URL:        "http://example.com/authorize?client_id=test&response_type=vp_token&dcql_query=" + dcql,
		StatusCode: 200,
	}
	Classify(e)

	decoded, ok := e.Decoded["dcql_query"].(map[string]any)
	if !ok {
		t.Fatalf("expected dcql_query as map, got %T", e.Decoded["dcql_query"])
	}
	if decoded["credentials"] == nil {
		t.Error("expected credentials in dcql_query")
	}
}

func TestDecodeEntryVPAuthResponse(t *testing.T) {
	e := &TrafficEntry{
		Method:      "POST",
		URL:         "http://example.com/response",
		RequestBody: "vp_token=eyJhbGciOiJFUzI1NiJ9.test.sig&state=s1",
		StatusCode:  200,
	}
	Classify(e)

	if e.Decoded["state"] != "s1" {
		t.Errorf("state: got %v", e.Decoded["state"])
	}
	if e.Decoded["vp_token_preview"] == nil {
		t.Error("expected vp_token_preview")
	}
}

func TestDecodeEntryVCIMetadata(t *testing.T) {
	e := &TrafficEntry{
		Method:       "GET",
		URL:          "http://issuer.example/.well-known/openid-credential-issuer",
		StatusCode:   200,
		ResponseBody: `{"issuer":"http://issuer.example","credential_configurations_supported":{}}`,
	}
	Classify(e)

	meta, ok := e.Decoded["metadata"].(map[string]any)
	if !ok {
		t.Fatal("expected metadata as map")
	}
	if meta["issuer"] != "http://issuer.example" {
		t.Errorf("issuer: got %v", meta["issuer"])
	}
}

func TestDecodeEntryVCITokenRequest(t *testing.T) {
	e := &TrafficEntry{
		Method:       "POST",
		URL:          "http://issuer.example/token",
		RequestBody:  "grant_type=authorization_code&code=abc",
		StatusCode:   200,
		ResponseBody: `{"access_token":"at_123","token_type":"Bearer"}`,
	}
	Classify(e)

	if e.Decoded["grant_type"] != "authorization_code" {
		t.Errorf("grant_type: got %v", e.Decoded["grant_type"])
	}
	resp, ok := e.Decoded["response"].(map[string]any)
	if !ok {
		t.Fatal("expected response as map")
	}
	if resp["access_token"] != "at_123" {
		t.Errorf("access_token: got %v", resp["access_token"])
	}
}

func TestDecodeEntryVCICredentialRequest(t *testing.T) {
	e := &TrafficEntry{
		Method:       "POST",
		URL:          "http://issuer.example/credential",
		RequestBody:  `{"format":"vc+sd-jwt","vct":"pid"}`,
		StatusCode:   200,
		ResponseBody: `{"credential":"abc.def.ghi"}`,
	}
	Classify(e)

	req, ok := e.Decoded["request"].(map[string]any)
	if !ok {
		t.Fatal("expected request as map")
	}
	if req["format"] != "vc+sd-jwt" {
		t.Errorf("format: got %v", req["format"])
	}
	resp, ok := e.Decoded["response"].(map[string]any)
	if !ok {
		t.Fatal("expected response as map")
	}
	if resp["credential"] != "abc.def.ghi" {
		t.Errorf("credential: got %v", resp["credential"])
	}
}

// The proxy holds the response while it classifies, so it validates the
// credential offline. A check that needs the issuer's metadata reports that.
func TestDecodeEntryVCICredentialRequest_ValidatesOffline(t *testing.T) {
	var fetches atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		http.NotFound(w, r)
	}))
	defer srv.Close()

	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cred, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    srv.URL,
		VCT:       "urn:test",
		ExpiresIn: time.Hour,
		Claims:    map[string]any{"given_name": "Erika"},
		Key:       key,
	})
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}

	e := &TrafficEntry{
		Method:       "POST",
		URL:          "http://issuer.example/credential",
		RequestBody:  `{"format":"vc+sd-jwt","vct":"pid"}`,
		StatusCode:   200,
		ResponseBody: `{"credential":"` + cred + `"}`,
	}
	Classify(e)

	decoded, ok := e.Decoded["credential_decoded"].(map[string]any)
	if !ok {
		t.Fatalf("expected credential_decoded map, got %T", e.Decoded["credential_decoded"])
	}
	checks, _ := decoded["validation"].(map[string]any)["checks"].([]web.CheckResult)
	var signature *web.CheckResult
	for i := range checks {
		if checks[i].Name == "signature" {
			signature = &checks[i]
		}
	}
	if signature == nil || !signature.NeedsNetwork {
		t.Fatalf("signature check %+v, want one that needs the network", signature)
	}
	if n := fetches.Load(); n != 0 {
		t.Fatalf("the issuer got %d requests, want none", n)
	}
}

func TestDecodeEntryUnknownReturnsNil(t *testing.T) {
	e := &TrafficEntry{
		Method:     "GET",
		URL:        "http://example.com/favicon.ico",
		StatusCode: 200,
	}
	Classify(e)

	if e.Decoded != nil {
		t.Errorf("expected nil Decoded for unknown class, got %v", e.Decoded)
	}
}

func TestExtractCredentialsVPAuthResponse(t *testing.T) {
	e := &TrafficEntry{
		Method:      "POST",
		URL:         "http://example.com/response",
		RequestBody: "vp_token=credential1&id_token=credential2&state=s1",
		StatusCode:  200,
	}
	Classify(e)

	if len(e.Credentials) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(e.Credentials))
	}
	if e.Credentials[0] != "credential1" {
		t.Errorf("cred[0]: got %q", e.Credentials[0])
	}
	if e.Credentials[1] != "credential2" {
		t.Errorf("cred[1]: got %q", e.Credentials[1])
	}
}

func TestExtractCredentialsVPRequestObject(t *testing.T) {
	jwt := "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJ0ZXN0In0.signature"
	e := &TrafficEntry{
		Method:       "GET",
		URL:          "http://example.com/request/abc",
		StatusCode:   200,
		ResponseBody: jwt,
	}
	Classify(e)

	if len(e.Credentials) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(e.Credentials))
	}
	if e.Credentials[0] != jwt {
		t.Errorf("expected JWT credential, got %q", e.Credentials[0])
	}
}

func TestExtractCredentialsVCICredentialRequest(t *testing.T) {
	e := &TrafficEntry{
		Method:       "POST",
		URL:          "http://issuer.example/credential",
		RequestBody:  `{"format":"vc+sd-jwt"}`,
		StatusCode:   200,
		ResponseBody: `{"credential":"the-credential"}`,
	}
	Classify(e)

	if len(e.Credentials) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(e.Credentials))
	}
	if e.Credentials[0] != "the-credential" {
		t.Errorf("expected 'the-credential', got %q", e.Credentials[0])
	}
}

func TestExtractCredentialsVCIBatchResponse(t *testing.T) {
	e := &TrafficEntry{
		Method:       "POST",
		URL:          "http://issuer.example/credential",
		RequestBody:  `{"format":"vc+sd-jwt"}`,
		StatusCode:   200,
		ResponseBody: `{"credentials":[{"credential":"cred1"},{"credential":"cred2"}]}`,
	}
	Classify(e)

	if len(e.Credentials) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(e.Credentials))
	}
}

func TestExtractCredentialsVCITokenResponse(t *testing.T) {
	accessToken := makeJWS(map[string]any{"alg": "ES256"}, map[string]any{"iss": "https://issuer.example", "sub": "user1"})
	refreshToken := makeJWS(map[string]any{"alg": "ES256"}, map[string]any{"sid": "session1"})
	e := &TrafficEntry{
		Method:       "POST",
		URL:          "http://issuer.example/token",
		RequestBody:  "grant_type=authorization_code&code=abc",
		StatusCode:   200,
		ResponseBody: `{"access_token":"` + accessToken + `","refresh_token":"` + refreshToken + `","token_type":"Bearer","c_nonce":"opaque-nonce","expires_in":3600}`,
	}
	Classify(e)

	if len(e.Credentials) != 2 {
		t.Fatalf("expected 2 credentials (JWT tokens only), got %d", len(e.Credentials))
	}
	if e.Credentials[0] != accessToken {
		t.Errorf("cred[0]: expected access_token JWT")
	}
	if e.Credentials[1] != refreshToken {
		t.Errorf("cred[1]: expected refresh_token JWT")
	}
	if len(e.CredentialLabels) != 2 {
		t.Fatalf("expected 2 labels, got %d", len(e.CredentialLabels))
	}
	if e.CredentialLabels[0] != "access_token" {
		t.Errorf("label[0]: got %q", e.CredentialLabels[0])
	}
	if e.CredentialLabels[1] != "refresh_token" {
		t.Errorf("label[1]: got %q", e.CredentialLabels[1])
	}
}

func TestExtractCredentialsVCITokenResponseOpaqueTokens(t *testing.T) {
	e := &TrafficEntry{
		Method:       "POST",
		URL:          "http://issuer.example/token",
		RequestBody:  "grant_type=authorization_code&code=abc",
		StatusCode:   200,
		ResponseBody: `{"access_token":"opaque-token-string","token_type":"Bearer"}`,
	}
	Classify(e)

	if len(e.Credentials) != 0 {
		t.Errorf("expected 0 credentials for opaque tokens, got %d", len(e.Credentials))
	}
}

func TestExtractCredentialsLabels(t *testing.T) {
	e := &TrafficEntry{
		Method:      "POST",
		URL:         "http://example.com/response",
		RequestBody: "vp_token=credential1&id_token=credential2&state=s1",
		StatusCode:  200,
	}
	Classify(e)

	if len(e.CredentialLabels) != 2 {
		t.Fatalf("expected 2 labels, got %d", len(e.CredentialLabels))
	}
	if e.CredentialLabels[0] != "vp_token" {
		t.Errorf("label[0]: got %q", e.CredentialLabels[0])
	}
	if e.CredentialLabels[1] != "id_token" {
		t.Errorf("label[1]: got %q", e.CredentialLabels[1])
	}
}

func TestExtractCredentialsVPTokenMap(t *testing.T) {
	e := &TrafficEntry{
		Method:      "POST",
		URL:         "http://example.com/response",
		RequestBody: `{"vp_token":{"cred1":["mdoc-credential"],"cred2":"jwt-credential"},"state":"s1"}`,
		StatusCode:  200,
	}
	Classify(e)

	if len(e.Credentials) != 2 {
		t.Fatalf("expected 2 extracted credentials, got %d: %v", len(e.Credentials), e.Credentials)
	}

	seen := make(map[string]string)
	for i, cred := range e.Credentials {
		seen[cred] = e.CredentialLabels[i]
	}
	if seen["mdoc-credential"] != "vp_token.cred1[0]" {
		t.Errorf("expected mdoc label vp_token.cred1[0], got %q", seen["mdoc-credential"])
	}
	if seen["jwt-credential"] != "vp_token.cred2" {
		t.Errorf("expected jwt label vp_token.cred2, got %q", seen["jwt-credential"])
	}
}

func TestExtractCredentialsVPTokenMapFormEncoded(t *testing.T) {
	e := &TrafficEntry{
		Method:      "POST",
		URL:         "http://example.com/response",
		RequestBody: `state=s1&vp_token={"cred1":["mdoc-credential"],"cred2":"jwt-credential"}`,
		StatusCode:  200,
	}
	Classify(e)

	if len(e.Credentials) != 2 {
		t.Fatalf("expected 2 extracted credentials, got %d: %v", len(e.Credentials), e.Credentials)
	}

	seen := make(map[string]string)
	for i, cred := range e.Credentials {
		seen[cred] = e.CredentialLabels[i]
	}
	if seen["mdoc-credential"] != "vp_token.cred1[0]" {
		t.Errorf("expected mdoc label vp_token.cred1[0], got %q", seen["mdoc-credential"])
	}
	if seen["jwt-credential"] != "vp_token.cred2" {
		t.Errorf("expected jwt label vp_token.cred2, got %q", seen["jwt-credential"])
	}
}

func TestExtractCredentialsVPTokenStringifiedMap(t *testing.T) {
	e := &TrafficEntry{
		Method:      "POST",
		URL:         "http://example.com/response",
		RequestBody: `{"vp_token":"{\"cred1\":[\"mdoc-credential\"],\"cred2\":\"jwt-credential\"}","state":"s1"}`,
		StatusCode:  200,
	}
	Classify(e)

	if len(e.Credentials) != 2 {
		t.Fatalf("expected 2 extracted credentials, got %d: %v", len(e.Credentials), e.Credentials)
	}

	seen := make(map[string]string)
	for i, cred := range e.Credentials {
		seen[cred] = e.CredentialLabels[i]
	}
	if seen["mdoc-credential"] != "vp_token.cred1[0]" {
		t.Errorf("expected mdoc label vp_token.cred1[0], got %q", seen["mdoc-credential"])
	}
	if seen["jwt-credential"] != "vp_token.cred2" {
		t.Errorf("expected jwt label vp_token.cred2, got %q", seen["jwt-credential"])
	}
}

func TestExtractCredentialsUnknown(t *testing.T) {
	e := &TrafficEntry{
		Method:     "GET",
		URL:        "http://example.com/other",
		StatusCode: 200,
	}
	Classify(e)

	if len(e.Credentials) != 0 {
		t.Errorf("expected no credentials for unknown class, got %d", len(e.Credentials))
	}
}

func makeJWS(header, payload map[string]any) string {
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	return base64.RawURLEncoding.EncodeToString(h) + "." +
		base64.RawURLEncoding.EncodeToString(p) + ".signature"
}

func TestDecodeJARMResponseJWS(t *testing.T) {
	jws := makeJWS(
		map[string]any{"alg": "ES256", "typ": "JWT"},
		map[string]any{"vp_token": "abc", "state": "s1"},
	)

	decoded := make(map[string]any)
	decodeJARMResponse(jws, "", "", decoded)

	if decoded["response_type"] != "JWS (signed)" {
		t.Errorf("response_type: got %v", decoded["response_type"])
	}
	if decoded["response_header"] == nil {
		t.Error("expected response_header")
	}
	if decoded["response_payload"] == nil {
		t.Error("expected response_payload")
	}
}

func TestDecodeJARMResponseJWE(t *testing.T) {
	header := map[string]any{
		"alg": "ECDH-ES",
		"enc": "A256GCM",
		"kid": "key-1",
		"epk": map[string]any{"kty": "EC", "crv": "P-256", "x": "x", "y": "y"},
		"apu": "sender",
		"apv": "recipient",
	}
	h, _ := json.Marshal(header)
	jwe := base64.RawURLEncoding.EncodeToString(h) + ".enckey.iv.cipher.tag"

	decoded := make(map[string]any)
	decodeJARMResponse(jwe, "", "", decoded)

	if !strings.Contains(decoded["response_type"].(string), "JWE") {
		t.Errorf("expected JWE response type, got %v", decoded["response_type"])
	}
	if decoded["encryption_alg"] != "ECDH-ES" {
		t.Errorf("encryption_alg: got %v", decoded["encryption_alg"])
	}
	if decoded["encryption_enc"] != "A256GCM" {
		t.Errorf("encryption_enc: got %v", decoded["encryption_enc"])
	}
	if decoded["encryption_kid"] != "key-1" {
		t.Errorf("encryption_kid: got %v", decoded["encryption_kid"])
	}
	if decoded["encryption_epk"] == nil {
		t.Error("expected encryption_epk")
	}
	if decoded["encryption_apu"] != "sender" {
		t.Errorf("encryption_apu: got %v", decoded["encryption_apu"])
	}
	if decoded["encryption_apv"] != "recipient" {
		t.Errorf("encryption_apv: got %v", decoded["encryption_apv"])
	}
}

func TestExtractCorrelationKeysVPAuthRequestIncludesRequestURI(t *testing.T) {
	entry := &TrafficEntry{
		Method: "GET",
		URL:    "http://example.com/authorize?client_id=test&response_type=vp_token&request_uri=https%3A%2F%2Fverifier.example%2Freq%2F123",
		Class:  ClassVPAuthRequest,
	}

	keys := ExtractCorrelationKeys(entry)
	if !containsString(keys, "vp:request_uri:https://verifier.example/req/123") {
		t.Fatalf("expected request_uri correlation key, got %v", keys)
	}
}

func TestExtractCorrelationKeysVPAuthResponseUsesDecryptedState(t *testing.T) {
	entry := &TrafficEntry{
		Method:      "POST",
		URL:         "http://example.com/response",
		RequestBody: "response=encrypted-jarm",
		Class:       ClassVPAuthResponse,
		Decoded: map[string]any{
			"response_payload": map[string]any{"state": "request-123"},
		},
	}

	keys := ExtractCorrelationKeys(entry)
	if !containsString(keys, "vp:state:request-123") {
		t.Fatalf("expected decrypted state correlation key, got %v", keys)
	}
}

func TestExtractCorrelationKeysVCITokenResponseIncludesAccessTokenAndCredentialIdentifiers(t *testing.T) {
	entry := &TrafficEntry{
		Method:      "POST",
		URL:         "http://example.com/token",
		RequestBody: "grant_type=authorization_code&code=auth-code-456",
		Class:       ClassVCITokenRequest,
		Decoded: map[string]any{
			"response": map[string]any{
				"access_token": "token-123",
				"authorization_details": []any{
					map[string]any{
						"credential_configuration_id": "membership-credential",
						"credential_identifiers": []any{
							"membership-credential_0000",
						},
					},
				},
			},
		},
	}

	keys := ExtractCorrelationKeys(entry)
	if !containsString(keys, "oauth:code:auth-code-456") {
		t.Fatalf("expected code correlation key, got %v", keys)
	}
	if !containsString(keys, "vci:access_token:token-123") {
		t.Fatalf("expected access token correlation key, got %v", keys)
	}
	if !containsString(keys, "vci:credential_identifier:membership-credential_0000") {
		t.Fatalf("expected credential identifier correlation key, got %v", keys)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestDecodeJARMResponseJWEWithCEK(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := map[string]any{"vp_token": "test-cred", "state": "s1"}
	payloadJSON, _ := json.Marshal(payload)

	jwe, cek, err := jwe.EncryptECDHES(payloadJSON, &key.PublicKey, "kid", "A128GCM", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	cekB64 := base64.RawURLEncoding.EncodeToString(cek)

	decoded := make(map[string]any)
	decodeJARMResponse(jwe, cekB64, "", decoded)

	if decoded["response_type"] != "JWE (decrypted via debug key)" {
		t.Errorf("expected decrypted response_type, got %v", decoded["response_type"])
	}
	responsePayload, ok := decoded["response_payload"].(map[string]any)
	if !ok {
		t.Fatalf("expected response_payload as map, got %T", decoded["response_payload"])
	}
	if responsePayload["vp_token"] != "test-cred" {
		t.Errorf("expected vp_token=test-cred, got %v", responsePayload["vp_token"])
	}
	if responsePayload["state"] != "s1" {
		t.Errorf("expected state=s1, got %v", responsePayload["state"])
	}
	if decoded["encryption_alg"] != "ECDH-ES" {
		t.Errorf("expected encryption_alg=ECDH-ES, got %v", decoded["encryption_alg"])
	}
}

func TestDecodeJARMResponseJWEWithoutCEK(t *testing.T) {
	header := map[string]any{
		"alg": "ECDH-ES",
		"enc": "A128GCM",
	}
	h, _ := json.Marshal(header)
	jwe := base64.RawURLEncoding.EncodeToString(h) + ".enckey.iv.cipher.tag"

	decoded := make(map[string]any)
	decodeJARMResponse(jwe, "", "", decoded)

	if !strings.Contains(decoded["response_type"].(string), "not readable") {
		t.Errorf("expected 'not readable' in response_type without CEK, got %v", decoded["response_type"])
	}
	if decoded["response_payload"] != nil {
		t.Error("expected no response_payload without CEK")
	}
}

func TestDecodeJARMResponseJWEWithJWK(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := map[string]any{"vp_token": "jwk-cred", "state": "s2"}
	payloadJSON, _ := json.Marshal(payload)

	jwe, _, err := jwe.EncryptECDHES(payloadJSON, &key.PublicKey, "kid", "A256GCM", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	x, y, err := format.ECPublicCoords(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	d, err := key.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	jwkJSON, _ := json.Marshal(map[string]string{
		"kty": "EC", "crv": "P-256",
		"x": format.EncodeBase64URL(x),
		"y": format.EncodeBase64URL(y),
		"d": format.EncodeBase64URL(d),
	})

	decoded := make(map[string]any)
	decodeJARMResponse(jwe, "", string(jwkJSON), decoded)

	if decoded["response_type"] != "JWE (decrypted via scanned verifier key)" {
		t.Errorf("expected JWK-decrypted response_type, got %v", decoded["response_type"])
	}
	responsePayload, ok := decoded["response_payload"].(map[string]any)
	if !ok {
		t.Fatalf("expected response_payload as map, got %T", decoded["response_payload"])
	}
	if responsePayload["vp_token"] != "jwk-cred" {
		t.Errorf("expected vp_token=jwk-cred, got %v", responsePayload["vp_token"])
	}
}

func TestExtractJARMCredentialsStringVPToken(t *testing.T) {
	payload := map[string]any{
		"vp_token": "credential-string",
		"state":    "s1",
	}
	creds, labels := extractJARMCredentials(payload)
	if len(creds) != 1 || creds[0] != "credential-string" {
		t.Errorf("expected 1 credential, got %v", creds)
	}
	if labels[0] != "vp_token (JARM)" {
		t.Errorf("label: got %q", labels[0])
	}
}

func TestExtractJARMCredentialsMapVPToken(t *testing.T) {
	payload := map[string]any{
		"vp_token": map[string]any{
			"pid":    []any{"cred-pid"},
			"mdl":    []any{"cred-mdl-0", "cred-mdl-1"},
			"single": "cred-single",
		},
	}
	creds, labels := extractJARMCredentials(payload)
	if len(creds) != 4 {
		t.Fatalf("expected 4 credentials, got %d: %v", len(creds), labels)
	}
	// Extraction iterates over maps, so the credential order varies.
	credSet := make(map[string]bool)
	for _, c := range creds {
		credSet[c] = true
	}
	for _, expected := range []string{"cred-pid", "cred-mdl-0", "cred-mdl-1", "cred-single"} {
		if !credSet[expected] {
			t.Errorf("missing credential %q", expected)
		}
	}
}

func TestExtractJARMCredentialsWithIDToken(t *testing.T) {
	payload := map[string]any{
		"vp_token": "vp-cred",
		"id_token": "id-cred",
	}
	creds, labels := extractJARMCredentials(payload)
	if len(creds) != 2 {
		t.Fatalf("expected 2 credentials, got %d", len(creds))
	}
	labelSet := make(map[string]bool)
	for _, l := range labels {
		labelSet[l] = true
	}
	if !labelSet["vp_token (JARM)"] {
		t.Error("expected vp_token (JARM) label")
	}
	if !labelSet["id_token (JARM)"] {
		t.Error("expected id_token (JARM) label")
	}
}

func TestExtractJARMCredentialsEmpty(t *testing.T) {
	payload := map[string]any{"state": "s1"}
	creds, _ := extractJARMCredentials(payload)
	if len(creds) != 0 {
		t.Errorf("expected 0 credentials, got %d", len(creds))
	}
}

func TestExtractCredentialsFromDecryptedJARM(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := map[string]any{
		"vp_token": map[string]any{
			"pid": []any{"eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig"},
		},
		"state": "s1",
	}
	payloadJSON, _ := json.Marshal(payload)

	jwe, cek, err := jwe.EncryptECDHES(payloadJSON, &key.PublicKey, "kid", "A128GCM", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	cekB64 := base64.RawURLEncoding.EncodeToString(cek)

	e := &TrafficEntry{
		Method:      "POST",
		URL:         "http://example.com/response",
		RequestBody: "response=" + jwe,
		StatusCode:  200,
		DebugJWEKey: cekB64,
	}
	Classify(e)

	found := false
	for _, c := range e.Credentials {
		if c == "eyJhbGciOiJFUzI1NiJ9.eyJzdWIiOiJ0ZXN0In0.sig" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected JARM credential in entry.Credentials, got %v (labels: %v)", e.Credentials, e.CredentialLabels)
	}
}

func TestClassifyVPAuthResponseWithDebugKey(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	payload := map[string]any{"vp_token": "decrypted-token", "state": "s1"}
	payloadJSON, _ := json.Marshal(payload)

	jwe, cek, err := jwe.EncryptECDHES(payloadJSON, &key.PublicKey, "kid", "A128GCM", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}

	cekB64 := base64.RawURLEncoding.EncodeToString(cek)

	e := &TrafficEntry{
		Method:      "POST",
		URL:         "http://example.com/response",
		RequestBody: "response=" + jwe,
		StatusCode:  200,
		DebugJWEKey: cekB64,
	}
	Classify(e)

	if e.Class != ClassVPAuthResponse {
		t.Errorf("expected ClassVPAuthResponse, got %d (%s)", e.Class, e.ClassLabel)
	}
	if e.Decoded["response_type"] != "JWE (decrypted via debug key)" {
		t.Errorf("expected decrypted response_type, got %v", e.Decoded["response_type"])
	}
	responsePayload, ok := e.Decoded["response_payload"].(map[string]any)
	if !ok {
		t.Fatalf("expected response_payload as map, got %T", e.Decoded["response_payload"])
	}
	if responsePayload["vp_token"] != "decrypted-token" {
		t.Errorf("expected vp_token=decrypted-token, got %v", responsePayload["vp_token"])
	}
}

func TestClassifyPOSTRequestObjectWithWalletMetadata(t *testing.T) {
	jwt := makeTestJWT(map[string]any{"alg": "none"}, map[string]any{
		"client_id":    "verifier",
		"wallet_nonce": "test-nonce",
	})

	e := &TrafficEntry{
		Method:       "POST",
		URL:          "http://example.com/request_uri",
		RequestBody:  "wallet_metadata=%7B%22vp_formats_supported%22%3A%7B%7D%7D&wallet_nonce=test-nonce",
		ResponseBody: jwt,
		StatusCode:   200,
	}
	Classify(e)

	if e.Class != ClassVPRequestObject {
		t.Errorf("expected ClassVPRequestObject, got %d (%s)", e.Class, e.ClassLabel)
	}

	if e.Decoded["wallet_nonce"] != "test-nonce" {
		t.Errorf("expected wallet_nonce=test-nonce, got %v", e.Decoded["wallet_nonce"])
	}

	if e.Decoded["wallet_metadata"] == nil {
		t.Error("expected wallet_metadata in decoded")
	}

	if e.Decoded["wallet_nonce_in_response"] != "test-nonce" {
		t.Errorf("expected wallet_nonce_in_response=test-nonce, got %v", e.Decoded["wallet_nonce_in_response"])
	}
}

func TestClassifyVPAuthRequestWithRequestURIMethod(t *testing.T) {
	e := &TrafficEntry{
		Method:     "GET",
		URL:        "http://example.com/authorize?client_id=verifier&response_type=vp_token&request_uri=https%3A%2F%2Fexample.com%2Frequest&request_uri_method=post",
		StatusCode: 302,
	}
	Classify(e)

	if e.Class != ClassVPAuthRequest {
		t.Errorf("expected ClassVPAuthRequest, got %d (%s)", e.Class, e.ClassLabel)
	}

	if e.Decoded["request_uri_method"] != "post" {
		t.Errorf("expected request_uri_method=post, got %v", e.Decoded["request_uri_method"])
	}
}

func TestStatefulClassifierConcurrentClassifyIsRaceFree(t *testing.T) {
	c := NewStatefulClassifier()

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			c.Classify(&TrafficEntry{
				Method:       "GET",
				URL:          fmt.Sprintf("https://issuer.example/%d/.well-known/openid-credential-issuer", i),
				StatusCode:   200,
				ResponseBody: `{"credential_endpoint":"https://issuer.example/cred"}`,
			})
		}(i)
	}
	wg.Wait()
}

func TestStatefulClassifierLearnsVCINonceEndpointFromMetadata(t *testing.T) {
	c := NewStatefulClassifier()

	meta := &TrafficEntry{
		Method:       "GET",
		URL:          "https://issuer.example/.well-known/openid-credential-issuer",
		StatusCode:   200,
		ResponseBody: `{"nonce_endpoint":"https://issuer.example/custom/nonce"}`,
	}
	c.Classify(meta)

	entry := &TrafficEntry{
		Method:       "POST",
		URL:          "https://issuer.example/custom/nonce",
		StatusCode:   200,
		ResponseBody: `{"c_nonce":"nonce-123"}`,
	}
	c.Classify(entry)

	if entry.Class != ClassVCINonceRequest {
		t.Errorf("expected ClassVCINonceRequest, got %d (%s)", entry.Class, entry.ClassLabel)
	}
}

func TestStatefulClassifierLearnsOIDCTokenEndpointFromMetadata(t *testing.T) {
	c := NewStatefulClassifier()

	meta := &TrafficEntry{
		Method:       "GET",
		URL:          "https://issuer.example/.well-known/openid-configuration",
		StatusCode:   200,
		ResponseBody: `{"token_endpoint":"https://issuer.example/custom/token"}`,
	}
	c.Classify(meta)

	entry := &TrafficEntry{
		Method:       "POST",
		URL:          "https://issuer.example/custom/token",
		RequestBody:  "grant_type=authorization_code&code=abc",
		StatusCode:   200,
		ResponseBody: `{"access_token":"opaque","id_token":"header.payload.sig"}`,
	}
	c.Classify(entry)

	if entry.Class != ClassOIDCTokenRequest {
		t.Errorf("expected ClassOIDCTokenRequest, got %d (%s)", entry.Class, entry.ClassLabel)
	}
}

func TestStatefulClassifierLearnsOIDCCallbackFromAuthRequest(t *testing.T) {
	c := NewStatefulClassifier()

	auth := &TrafficEntry{
		Method:     "GET",
		URL:        "https://issuer.example/auth?client_id=wallet-app&redirect_uri=https%3A%2F%2Fapp.example%2Fcallback&response_type=code&scope=openid&state=s1",
		StatusCode: 302,
	}
	c.Classify(auth)

	callback := &TrafficEntry{
		Method:     "GET",
		URL:        "https://app.example/callback?state=s1",
		StatusCode: 302,
	}
	c.Classify(callback)

	if callback.Class != ClassOIDCCallback {
		t.Errorf("expected ClassOIDCCallback, got %d (%s)", callback.Class, callback.ClassLabel)
	}
}

func makeTestJWT(header, payload map[string]any) string {
	h, _ := json.Marshal(header)
	p, _ := json.Marshal(payload)
	return format.EncodeBase64URL(h) + "." + format.EncodeBase64URL(p) + ".testsig"
}
