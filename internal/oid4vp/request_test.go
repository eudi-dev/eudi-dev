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

	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
)

func TestGetResponseURI_PreferResponseURI(t *testing.T) {
	req := &oid4vc.AuthorizationRequest{
		ResponseURI: "https://verifier.example/response",
		RedirectURI: "https://verifier.example/redirect",
	}
	got := GetResponseURI(req)
	if got != "https://verifier.example/response" {
		t.Errorf("expected response_uri, got %s", got)
	}
}

func TestGetResponseURI_FallbackToRedirect(t *testing.T) {
	req := &oid4vc.AuthorizationRequest{
		RedirectURI: "https://verifier.example/redirect",
	}
	got := GetResponseURI(req)
	if got != "https://verifier.example/redirect" {
		t.Errorf("expected redirect_uri, got %s", got)
	}
}

func TestGetResponseMode_Explicit(t *testing.T) {
	req := &oid4vc.AuthorizationRequest{
		ResponseMode: "direct_post.jwt",
	}
	got := GetResponseMode(req)
	if got != "direct_post.jwt" {
		t.Errorf("expected direct_post.jwt, got %s", got)
	}
}

func TestGetResponseMode_Default(t *testing.T) {
	req := &oid4vc.AuthorizationRequest{}
	got := GetResponseMode(req)
	if got != "direct_post" {
		t.Errorf("expected default direct_post, got %s", got)
	}
}

func TestParseAuthorizationRequestFromParams(t *testing.T) {
	params := url.Values{}
	params.Set("client_id", "https://verifier.example")
	params.Set("response_uri", "https://verifier.example/callback")
	params.Set("response_type", "vp_token")
	params.Set("nonce", "test-nonce")
	params.Set("dcql_query", `{"credentials":[{"id":"pid","format":"dc+sd-jwt"}]}`)

	authReq, err := ParseAuthorizationRequestFromParams(params)
	if err != nil {
		t.Fatalf("ParseAuthorizationRequestFromParams: %v", err)
	}

	if authReq.ClientID != "https://verifier.example" {
		t.Errorf("expected client_id https://verifier.example, got %s", authReq.ClientID)
	}
	if authReq.Nonce != "test-nonce" {
		t.Errorf("expected nonce test-nonce, got %s", authReq.Nonce)
	}
	if authReq.DCQLQuery == nil {
		t.Error("expected non-nil dcql_query")
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
