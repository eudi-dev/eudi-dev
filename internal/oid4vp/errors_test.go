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
	"errors"
	"net/url"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
)

// OID4VP 1.0 §8.5 invalid_request_uri_method: "The value of the
// request_uri_method request parameter is neither get nor post
// (case-sensitive)."
func TestParseErrorCodeNamesAnUnsupportedRequestURIMethod(t *testing.T) {
	fetched := false
	opts := oid4vc.ParseOptions{FetchRequestURI: func(string, string, string) (string, error) {
		fetched = true
		return "", nil
	}}
	_, err := ParseRequest(url.Values{
		"client_id":          {"x509_san_dns:verifier.example"},
		"request_uri":        {"https://verifier.example/request"},
		"request_uri_method": {"POST"},
	}, opts)
	if err == nil {
		t.Fatal("request_uri_method POST was accepted")
	}
	if fetched {
		t.Error("the wallet fetched the request_uri for an unsupported method")
	}
	if code := ParseErrorCode(err); code != ErrorInvalidRequestURIMethod {
		t.Errorf("code = %q, want %q", code, ErrorInvalidRequestURIMethod)
	}
}

func TestParseErrorCodeDefaultsToInvalidRequest(t *testing.T) {
	_, err := ParseRequest(url.Values{"client_id": {"x"}, "request": {"not-a-jwt"}}, oid4vc.ParseOptions{})
	if err == nil {
		t.Fatal("an unreadable request JWT was accepted")
	}
	if code := ParseErrorCode(err); code != ErrorInvalidRequest {
		t.Errorf("code = %q, want %q", code, ErrorInvalidRequest)
	}
	if code := ParseErrorCode(errors.New("anything")); code != ErrorInvalidRequest {
		t.Errorf("code = %q, want %q", code, ErrorInvalidRequest)
	}
}

func TestRefusalCode(t *testing.T) {
	request := func(method string, payload map[string]any, query map[string]string) *Request {
		return &Request{
			AuthorizationRequest: oid4vc.AuthorizationRequest{ClientID: "x509_san_dns:verifier.example", RequestURIMethod: method, FullParams: query},
			RequestPayload:       payload,
		}
	}
	for _, tt := range []struct {
		name string
		req  *Request
		want string
	}{
		{"no request", nil, ErrorInvalidRequest},
		{"plain refusal", request("", nil, nil), ErrorInvalidRequest},
		{"get", request("get", nil, nil), ErrorInvalidRequest},
		{"post", request("post", nil, nil), ErrorInvalidRequest},
		// §8.5: get and post are case-sensitive.
		{"upper case method", request("GET", nil, nil), ErrorInvalidRequestURIMethod},
		{"unknown method", request("put", nil, nil), ErrorInvalidRequestURIMethod},
		// §8.5 invalid_transaction_data covers unsupported transaction data
		// types. This wallet supports none.
		{"transaction_data in the request object", request("", map[string]any{"transaction_data": []any{"e30"}}, nil), ErrorInvalidTransactionData},
		{"transaction_data in the query", request("", nil, map[string]string{"transaction_data": `["e30"]`}), ErrorInvalidTransactionData},
		{"method wins over transaction_data", request("PUT", map[string]any{"transaction_data": []any{"e30"}}, nil), ErrorInvalidRequestURIMethod},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := RefusalCode(tt.req); got != tt.want {
				t.Errorf("RefusalCode = %q, want %q", got, tt.want)
			}
		})
	}
}

// Appendix A.4 returns a DC API error through the API call. Other responses
// need an endpoint of the verifier.
func TestCanDeliverError(t *testing.T) {
	for _, tt := range []struct {
		name string
		req  *Request
		want bool
	}{
		{"no request", nil, false},
		{"response_uri", &Request{AuthorizationRequest: oid4vc.AuthorizationRequest{ResponseMode: "direct_post", ResponseURI: "https://verifier.example/response"}}, true},
		{"redirect_uri", &Request{AuthorizationRequest: oid4vc.AuthorizationRequest{ResponseMode: "fragment", RedirectURI: "https://verifier.example/cb"}}, true},
		{"no endpoint", &Request{AuthorizationRequest: oid4vc.AuthorizationRequest{ResponseMode: "direct_post"}}, false},
		{"dc_api", &Request{AuthorizationRequest: oid4vc.AuthorizationRequest{ResponseMode: "dc_api", ResponseURI: "https://verifier.example/response"}}, false},
		{"dc_api.jwt", &Request{AuthorizationRequest: oid4vc.AuthorizationRequest{ResponseMode: "dc_api.jwt"}}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := CanDeliverError(tt.req); got != tt.want {
				t.Errorf("CanDeliverError = %v, want %v", got, tt.want)
			}
		})
	}
}
