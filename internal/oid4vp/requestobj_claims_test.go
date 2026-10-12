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
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
)

func requestWithClaims(alg, responseMode string, claims map[string]any) *Request {
	payload := map[string]any{"client_id": "redirect_uri:https://verifier.example/response"}
	for k, v := range claims {
		payload[k] = v
	}
	return &Request{AuthorizationRequest: oid4vc.AuthorizationRequest{
		ClientID: "redirect_uri:https://verifier.example/response", ResponseType: "vp_token", ResponseMode: responseMode,
		ResponseURI: "https://verifier.example/response", Nonce: "n-1",
		RequestObject: &oid4vc.RequestObjectJWT{Header: map[string]any{"alg": alg}, Payload: payload},
	}}
}

// RFC 7519 §4.1.4 rejects a JWT after its exp, within the clock skew that
// OID4VP 1.0 §12 allows. OID4VP 1.0 §5.8: the aud of a Request Object "MUST be
// "https://self-issued.me/v2", when Static Discovery metadata is used", and
// the wallet publishes no metadata for dynamic discovery.
func TestRequestObjectExpAndAud(t *testing.T) {
	now := time.Now()
	for _, tt := range []struct {
		name   string
		mode   string
		claims map[string]any
		want   string
	}{
		{"current exp and self-issued aud", "direct_post", map[string]any{"exp": float64(now.Add(time.Minute).Unix()), "aud": SelfIssuedAudience}, ""},
		{"aud array with self-issued", "direct_post", map[string]any{"aud": []any{"https://other.example", SelfIssuedAudience}}, ""},
		{"exp within the clock skew", "direct_post", map[string]any{"exp": float64(now.Add(-30 * time.Second).Unix())}, ""},
		{"expired", "direct_post", map[string]any{"exp": float64(now.Add(-time.Hour).Unix())}, "Request Object expired"},
		{"exp not a number", "direct_post", map[string]any{"exp": "tomorrow"}, "NumericDate"},
		{"other aud", "direct_post", map[string]any{"aud": "https://wallet.example"}, "§5.8"},
		{"aud array without self-issued", "direct_post", map[string]any{"aud": []any{"https://wallet.example"}}, "§5.8"},
		{"interactive authorization names no aud", "ia_post", map[string]any{"aud": "https://issuer.example"}, ""},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := strings.Join(requestObjectClaimFindings(requestWithClaims("none", tt.mode, tt.claims)), "\n")
			if tt.want == "" {
				if got != "" {
					t.Fatalf("findings %q, want none", got)
				}
				return
			}
			if !strings.Contains(got, tt.want) {
				t.Fatalf("findings %q, want %q", got, tt.want)
			}
		})
	}
}

// Strict mode refuses an expired Request Object. Debug mode reports it.
func TestExpiredRequestObjectSeverity(t *testing.T) {
	req := requestWithClaims("none", "direct_post", map[string]any{"exp": float64(time.Now().Add(-time.Hour).Unix())})
	findings, err := ValidateAuthorizationRequest(Checks{}, req)
	if err != nil {
		t.Fatalf("debug mode refused the request: %v", err)
	}
	if !containsSubstring(findings, "Request Object expired") {
		t.Errorf("findings %v, want the expired Request Object", findings)
	}
	if _, err := ValidateAuthorizationRequest(Checks{Strict: true}, req); err == nil || !strings.Contains(err.Error(), "Request Object expired") {
		t.Errorf("strict mode: err = %v, want a refusal for the expired Request Object", err)
	}
}

// RFC 9101 §4: a signed Request Object "SHOULD contain the Claims iss (issuer)
// and aud (audience)". A missing aud is a warning in every mode.
func TestMissingAudIsAWarning(t *testing.T) {
	signed := requestWithClaims("ES256", "direct_post", nil)
	if got := missingAudienceAdvisory(signed); !strings.Contains(got, "no aud claim") {
		t.Errorf("advisory = %q, want the missing aud", got)
	}
	for name, req := range map[string]*Request{
		"unsigned":                  requestWithClaims("none", "direct_post", nil),
		"interactive authorization": requestWithClaims("ES256", "ia_post", nil),
		"aud present":               requestWithClaims("ES256", "direct_post", map[string]any{"aud": SelfIssuedAudience}),
	} {
		if got := missingAudienceAdvisory(req); got != "" {
			t.Errorf("%s: advisory = %q, want none", name, got)
		}
	}
}
