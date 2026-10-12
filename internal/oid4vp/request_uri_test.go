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

package oid4vp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
)

const sanDNSClientID = "x509_san_dns:verifier.example"

// sanDNSRequestObject signs a Request Object for x509_san_dns:verifier.example
// with a self-signed certificate in x5c. extra adds or replaces claims, and a
// nil value removes one.
func sanDNSRequestObject(t *testing.T, extra map[string]any) string {
	t.Helper()
	key, certB64, _ := testCertWithKeyDER([]string{"verifier.example"})
	claims := map[string]any{
		"client_id":     sanDNSClientID,
		"response_type": "vp_token",
		"response_mode": "direct_post",
		"response_uri":  "https://verifier.example/response",
		"nonce":         "n-1",
		"aud":           SelfIssuedAudience,
		"dcql_query":    sdjwtVCTQuery("urn:eudi:pid:1"),
	}
	for k, v := range extra {
		if v == nil {
			delete(claims, k)
		} else {
			claims[k] = v
		}
	}
	raw, err := jws.Sign(map[string]any{"alg": "ES256", "typ": "oauth-authz-req+jwt", "x5c": []any{certB64}}, claims, key)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

type fetchCall struct{ url, method, clientID string }

func recordingFetcher(body string, err error, calls *[]fetchCall) oid4vc.ParseOptions {
	return oid4vc.ParseOptions{FetchRequestURI: func(u, method, clientID string) (string, error) {
		*calls = append(*calls, fetchCall{u, method, clientID})
		return body, err
	}}
}

// OID4VP 1.0 §5.10: request_uri_method post makes the wallet POST to the
// request_uri. Without the parameter the wallet uses GET.
func TestParseRequestFetchesTheRequestURIWithItsMethod(t *testing.T) {
	raw := sanDNSRequestObject(t, nil)
	for _, tt := range []struct {
		method, want string
	}{
		{"", "get"},
		{"get", "get"},
		{"post", "post"},
	} {
		t.Run(tt.want+"/"+tt.method, func(t *testing.T) {
			var calls []fetchCall
			values := url.Values{"client_id": {sanDNSClientID}, "request_uri": {"https://verifier.example/request/1"}}
			if tt.method != "" {
				values.Set("request_uri_method", tt.method)
			}
			params, err := ParseRequest(values, recordingFetcher(raw, nil, &calls))
			if err != nil {
				t.Fatal(err)
			}
			want := fetchCall{"https://verifier.example/request/1", tt.want, sanDNSClientID}
			if len(calls) != 1 || calls[0] != want {
				t.Fatalf("fetches = %+v, want %+v", calls, want)
			}
			if params.RequestObject == nil || params.RequestObject.Raw != raw {
				t.Fatal("the fetched Request Object is not on the request")
			}
			if params.RequestURIMethod != tt.method || params.RequestURI != "https://verifier.example/request/1" {
				t.Errorf("request_uri %q method %q, want the transport parameters kept", params.RequestURI, params.RequestURIMethod)
			}
			if params.Nonce != "n-1" || params.ResponseURI != "https://verifier.example/response" || params.RequestPayload["aud"] != SelfIssuedAudience {
				t.Errorf("nonce %q response_uri %q payload %v, want the Request Object claims", params.Nonce, params.ResponseURI, params.RequestPayload)
			}
			findings, err := ValidateAuthorizationRequest(Checks{Strict: true}, params)
			if err != nil || len(findings) != 0 {
				t.Errorf("findings %v err %v, want a clean request", findings, err)
			}
		})
	}
}

// RFC 9101 §6.3: "The authorization server MUST only use the parameters in
// the Request Object, even if the same parameter is provided in the query
// parameter."
func TestParseRequestUsesOnlyTheRequestObjectParameters(t *testing.T) {
	raw := sanDNSRequestObject(t, nil)
	var calls []fetchCall
	params, err := ParseRequest(url.Values{
		"client_id":     {sanDNSClientID},
		"request_uri":   {"https://verifier.example/request"},
		"nonce":         {"outer-nonce"},
		"response_mode": {"fragment"},
	}, recordingFetcher(raw, nil, &calls))
	if err != nil {
		t.Fatal(err)
	}
	if params.Nonce != "n-1" || params.ResponseMode != "direct_post" {
		t.Errorf("nonce %q response_mode %q, want the Request Object values", params.Nonce, params.ResponseMode)
	}
}

// OID4VP 1.0: the client_id parameter and the Request Object client_id "MUST
// be identical, including the Client Identifier Prefix."
func TestParseRequestRejectsAMismatchedClientID(t *testing.T) {
	raw := sanDNSRequestObject(t, nil)
	var calls []fetchCall
	_, err := ParseRequest(url.Values{
		"client_id":   {"x509_hash:abc"},
		"request_uri": {"https://verifier.example/request"},
	}, recordingFetcher(raw, nil, &calls))
	if err == nil || !strings.Contains(err.Error(), `parsing request_uri "https://verifier.example/request"`) || !strings.Contains(err.Error(), "does not match outer client_id") {
		t.Errorf("err = %v, want the client_id mismatch", err)
	}
}

func TestParseRequestReportsAFailedFetch(t *testing.T) {
	var calls []fetchCall
	cause := errors.New("connection refused")
	_, err := ParseRequest(url.Values{
		"client_id":   {sanDNSClientID},
		"request_uri": {"https://verifier.example/request"},
	}, recordingFetcher("", cause, &calls))
	if !errors.Is(err, cause) || !strings.Contains(err.Error(), "fetching request_uri") {
		t.Errorf("err = %v, want the fetch error", err)
	}
}

func TestParseRequestReadsAnInlineRequestObject(t *testing.T) {
	raw := sanDNSRequestObject(t, map[string]any{"state": "s-1"})
	params, err := ParseRequest(url.Values{"client_id": {sanDNSClientID}, "request": {raw}}, oid4vc.ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if params.State != "s-1" || params.RequestPayload["state"] != "s-1" {
		t.Errorf("state %q payload %v, want the Request Object state", params.State, params.RequestPayload)
	}
	if _, err := ParseRequest(url.Values{"request": {"a.b"}}, oid4vc.ParseOptions{}); err == nil || !strings.HasPrefix(err.Error(), "parsing request JWT") {
		t.Errorf("err = %v, want the request JWT error", err)
	}
}

func TestParseAuthorizationRequestWithOptions(t *testing.T) {
	raw := sanDNSRequestObject(t, nil)
	parsed, err := ParseAuthorizationRequestWithOptions("  "+raw+"\n", oid4vc.ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ClientID != sanDNSClientID || parsed.RequestObject == nil {
		t.Errorf("client_id %q, want the signed request", parsed.ClientID)
	}

	query := url.Values{"client_id": {"redirect_uri:https://verifier.example/cb"}, "response_type": {"vp_token"}, "nonce": {"n"}}
	parsed, err = ParseAuthorizationRequestWithOptions("openid4vp://authorize?"+query.Encode(), oid4vc.ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if parsed.ClientID != "redirect_uri:https://verifier.example/cb" || parsed.Nonce != "n" {
		t.Errorf("client_id %q nonce %q, want the URI parameters", parsed.ClientID, parsed.Nonce)
	}

	offer := `{"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid"]}`
	if _, err := ParseAuthorizationRequestWithOptions(offer, oid4vc.ParseOptions{}); err == nil || err.Error() != "expected VP authorization request, got VCI" {
		t.Errorf("err = %v, want the VCI rejection", err)
	}
	if _, err := ParseAuthorizationRequestWithOptions("hello", oid4vc.ParseOptions{}); err == nil || !strings.HasPrefix(err.Error(), "parsing authorization request") {
		t.Errorf("err = %v, want the parse error", err)
	}
}

// OID4VP 1.0 §5.10.1 requires application/oauth-authz-req+jwt for POST. RFC
// 9101 §4 also tolerates application/jwt for GET.
func TestValidateRequestURIResponse(t *testing.T) {
	for _, tt := range []struct {
		method, contentType, wantErr string
	}{
		{"post", "application/oauth-authz-req+jwt", ""},
		{"post", "application/oauth-authz-req+jwt; charset=utf-8", ""},
		{"get", "application/oauth-authz-req+jwt", ""},
		{"get", "application/jwt", ""},
		{"", "application/jwt", ""},
		{"post", "application/jwt", `OID4VP 1.0 §5.10.1: the request_uri response Content-Type must be application/oauth-authz-req+jwt, got "application/jwt"`},
		{"post", "", "OID4VP 1.0 §5.10.1: the request_uri response is missing the Content-Type application/oauth-authz-req+jwt"},
		{"get", "", "RFC 9101 §4: the request_uri response is missing the Content-Type application/oauth-authz-req+jwt"},
		{"get", "text/html", `RFC 9101 §4: the request_uri response Content-Type must be application/oauth-authz-req+jwt, got "text/html"`},
		{"get", "application/", "RFC 9101 §4: the request_uri response Content-Type does not parse"},
	} {
		t.Run(tt.method+" "+tt.contentType, func(t *testing.T) {
			err := ValidateRequestURIResponse(tt.method, tt.contentType)
			switch {
			case tt.wantErr == "" && err != nil:
				t.Errorf("err = %v, want the media type accepted", err)
			case tt.wantErr != "" && (err == nil || !strings.HasPrefix(err.Error(), tt.wantErr)):
				t.Errorf("err = %v, want %q", err, tt.wantErr)
			}
		})
	}
}

// wallet_nonce mitigates replay of the Request Object (OID4VP 1.0 §5.10). Each
// call yields a fresh 128-bit value.
func TestGenerateWalletNonce(t *testing.T) {
	first, err := GenerateWalletNonce()
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateWalletNonce()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Errorf("two nonces are both %q", first)
	}
	decoded, err := format.DecodeBase64URL(first)
	if err != nil || len(decoded) != 16 || strings.ContainsAny(first, "+/=") {
		t.Errorf("nonce %q decodes to %d bytes (%v), want 16 bytes of unpadded base64url", first, len(decoded), err)
	}
}

func TestDecryptCompactJWEErrors(t *testing.T) {
	if _, err := DecryptCompactJWE("a.b.c.d.e", nil); err == nil || err.Error() != "decryption requires a private key" {
		t.Errorf("err = %v, want the missing key", err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := DecryptCompactJWE("not-a-jwe", key); err == nil {
		t.Error("a malformed JWE was decrypted")
	}
}
