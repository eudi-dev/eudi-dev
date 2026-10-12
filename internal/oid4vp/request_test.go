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
	"net/url"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
)

func TestResponseDestination(t *testing.T) {
	both := &Request{AuthorizationRequest: oid4vc.AuthorizationRequest{ResponseURI: "https://verifier.example/response", RedirectURI: "https://verifier.example/redirect"}}
	if got := both.ResponseDestination(); got != "https://verifier.example/response" {
		t.Errorf("destination = %s, want the response_uri", got)
	}
	redirect := &Request{AuthorizationRequest: oid4vc.AuthorizationRequest{RedirectURI: "https://verifier.example/redirect"}}
	if got := redirect.ResponseDestination(); got != "https://verifier.example/redirect" {
		t.Errorf("destination = %s, want the redirect_uri", got)
	}
}

// The /authorize parameters reach the flow like any other parsed request,
// values with spaces included.
func TestParseRequestKeepsEveryParameter(t *testing.T) {
	values := url.Values{
		"client_id":     {"redirect_uri:https://verifier.example/cb"},
		"response_type": {"vp_token"},
		"response_mode": {"direct_post"},
		"response_uri":  {"https://verifier.example/cb"},
		"nonce":         {"n"},
		"state":         {"a b+c"},
		"scope":         {"openid profile"},
		"dcql_query":    {`{"credentials":[{"id":"q","format":"dc+sd-jwt"}]}`},
	}
	params, err := ParseRequest(values, oid4vc.ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if params.Scope != "openid profile" || params.State != "a b+c" {
		t.Errorf("scope %q state %q", params.Scope, params.State)
	}
	if params.FullParams["scope"] != "openid profile" || params.DCQLQuery == nil {
		t.Errorf("full params %v, dcql %v", params.FullParams, params.DCQLQuery)
	}
	broken, err := ParseRequest(url.Values{"client_id": {"x"}, "dcql_query": {"{"}}, oid4vc.ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ValidateAuthorizationRequest(Checks{}, broken); err == nil {
		t.Error("a broken dcql_query was accepted")
	}
}

func TestResponseTypeContains(t *testing.T) {
	tests := []struct {
		responseType string
		target       string
		want         bool
	}{
		{"vp_token", "vp_token", true},
		{"vp_token", "id_token", false},
		{"vp_token id_token", "vp_token", true},
		{"vp_token id_token", "id_token", true},
		{"id_token", "id_token", true},
		{"id_token", "vp_token", false},
		{"", "vp_token", false},
		{"vp_token  id_token", "id_token", true}, // extra spaces
	}

	for _, tt := range tests {
		got := ResponseTypeContains(tt.responseType, tt.target)
		if got != tt.want {
			t.Errorf("ResponseTypeContains(%q, %q) = %v, want %v", tt.responseType, tt.target, got, tt.want)
		}
	}
}

func TestResponseTypeRequiresVP(t *testing.T) {
	tests := []struct {
		responseType string
		want         bool
	}{
		{"", true},
		{"vp_token", true},
		{"vp_token id_token", true},
		{"id_token", false},
	}

	for _, tt := range tests {
		got := ResponseTypeRequiresVP(tt.responseType)
		if got != tt.want {
			t.Errorf("ResponseTypeRequiresVP(%q) = %v, want %v", tt.responseType, got, tt.want)
		}
	}
}
