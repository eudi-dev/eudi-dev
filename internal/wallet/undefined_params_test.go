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
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v2/internal/oid4vc"
)

func TestUndefinedRequestParameterFindings(t *testing.T) {
	t.Run("plain request with undefined parameters", func(t *testing.T) {
		params := &AuthorizationRequestParams{FullParams: map[string]string{
			"client_id":               "x509_san_dns:verifier.example",
			"response_type":           "vp_token",
			"nonce":                   "n-1",
			"presentation_definition": `{}`,
			"my_custom_field":         "x",
		}}
		findings := undefinedRequestParameterFindings(params)
		if len(findings) != 2 {
			t.Fatalf("findings = %v, want 2", findings)
		}
		if !containsSubstring(findings, `"my_custom_field"`) || !containsSubstring(findings, `"presentation_definition"`) {
			t.Errorf("findings = %v, want both undefined parameters named", findings)
		}
	})

	t.Run("signed request object allows JWT claims", func(t *testing.T) {
		params := &AuthorizationRequestParams{RequestObject: &oid4vc.RequestObjectJWT{
			Payload: map[string]any{
				"client_id":        "x509_hash:abc",
				"response_type":    "vp_token",
				"aud":              "https://self-issued.me/v2",
				"iss":              "verifier",
				"exp":              1,
				"client_id_scheme": "x509_san_dns",
			},
		}}
		findings := undefinedRequestParameterFindings(params)
		if len(findings) != 1 || !strings.Contains(findings[0], `"client_id_scheme"`) {
			t.Errorf("findings = %v, want only client_id_scheme flagged", findings)
		}
	})

	t.Run("signed request with undefined outer query parameters", func(t *testing.T) {
		params := &AuthorizationRequestParams{
			RequestObject: &oid4vc.RequestObjectJWT{Payload: map[string]any{
				"client_id": "x509_hash:abc", "response_type": "vp_token",
			}},
			FullParams: map[string]string{
				"client_id":               "x509_hash:abc",
				"request_uri":             "https://verifier.example/ro",
				"presentation_definition": `{}`,
			},
		}
		findings := undefinedRequestParameterFindings(params)
		if len(findings) != 1 || !strings.Contains(findings[0], `"presentation_definition"`) {
			t.Errorf("findings = %v, want the outer presentation_definition flagged", findings)
		}
	})

	t.Run("defined parameters only", func(t *testing.T) {
		params := &AuthorizationRequestParams{FullParams: map[string]string{
			"client_id": "x", "response_type": "vp_token", "nonce": "n",
			"response_uri": "https://v.example/cb", "dcql_query": "{}",
			"state": "s", "request_uri": "https://v.example/ro", "request_uri_method": "post",
		}}
		if findings := undefinedRequestParameterFindings(params); len(findings) != 0 {
			t.Errorf("findings = %v, want none", findings)
		}
	})
}

func TestVerifierResponseUndefinedMembers(t *testing.T) {
	members := func(status int, body string) []string {
		return undefinedResponseMembers(&DirectPostResult{StatusCode: status, Body: body})
	}

	if got := members(200, `{}`); len(got) != 0 {
		t.Errorf("empty object: undefined members = %v, want none", got)
	}
	if got := members(200, `{"redirect_uri":"https://v.example/done"}`); len(got) != 0 {
		t.Errorf("redirect_uri only: undefined members = %v, want none", got)
	}
	got := members(200, `{"status":"OK","session_id":"1","redirect_uri":"https://v.example/done"}`)
	if len(got) != 2 || got[0] != "session_id" || got[1] != "status" {
		t.Errorf("undefined members = %v, want [session_id status]", got)
	}
	// An OAuth error response has its own members and is not a §8.2 body.
	if got := members(400, `{"error":"invalid_request","error_description":"nope"}`); len(got) != 0 {
		t.Errorf("error response: undefined members = %v, want none", got)
	}
}
