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

func TestValidateAuthorizationRequest_StrictRejectsMissingNonce(t *testing.T) {
	params := &AuthorizationRequestParams{
		ClientID:     "redirect_uri:https://verifier.example/response",
		ResponseType: "vp_token",
		ResponseMode: "direct_post",
		ResponseURI:  "https://verifier.example/response",
	}

	_, err := ValidateAuthorizationRequest(ValidationModeStrict, false, params)
	if err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("expected nonce validation error, got %v", err)
	}
}

func TestValidateAuthorizationRequest_DebugAllowsMissingNonce(t *testing.T) {
	params := &AuthorizationRequestParams{
		ClientID:     "redirect_uri:https://verifier.example/response",
		ResponseType: "vp_token",
		ResponseMode: "direct_post",
		ResponseURI:  "https://verifier.example/response",
	}

	if _, err := ValidateAuthorizationRequest(ValidationModeDebug, false, params); err != nil {
		t.Fatalf("expected debug mode to allow missing nonce, got %v", err)
	}
}

func TestValidateAuthorizationRequest_StrictRejectsUnsupportedClientIDPrefix(t *testing.T) {
	params := &AuthorizationRequestParams{
		ClientID:     "invalid_scheme:verifier",
		ResponseType: "vp_token",
		ResponseMode: "direct_post",
		ResponseURI:  "https://verifier.example/response",
		Nonce:        "nonce",
	}

	_, err := ValidateAuthorizationRequest(ValidationModeStrict, false, params)
	if err == nil || !strings.Contains(err.Error(), "unsupported prefix") {
		t.Fatalf("expected unsupported client_id prefix error, got %v", err)
	}
}

func TestValidateAuthorizationRequest_StrictRejectsRedirectURIWithDirectPost(t *testing.T) {
	params := &AuthorizationRequestParams{
		ClientID:     "redirect_uri:https://verifier.example/response",
		ResponseType: "vp_token",
		ResponseMode: "direct_post.jwt",
		ResponseURI:  "https://verifier.example/response",
		RedirectURI:  "https://verifier.example/callback",
		Nonce:        "nonce",
		RequestObject: &oid4vc.RequestObjectJWT{
			Raw: "header.payload.",
			Header: map[string]any{
				"alg": "none",
				"typ": "oauth-authz-req+jwt",
			},
			Payload: map[string]any{},
		},
	}

	_, err := ValidateAuthorizationRequest(ValidationModeStrict, false, params)
	if err == nil || !strings.Contains(err.Error(), "redirect_uri") {
		t.Fatalf("expected redirect_uri validation error, got %v", err)
	}
}

func TestValidateAuthorizationRequest_StrictRejectsRequestObjectTransactionData(t *testing.T) {
	payload := map[string]any{
		"client_id":        "redirect_uri:https://verifier.example/response",
		"response_type":    "vp_token",
		"response_mode":    "direct_post",
		"response_uri":     "https://verifier.example/response",
		"nonce":            "nonce",
		"transaction_data": []any{map[string]any{"type": "unknown"}},
	}
	params := &AuthorizationRequestParams{
		ClientID:       "redirect_uri:https://verifier.example/response",
		ResponseType:   "vp_token",
		ResponseMode:   "direct_post",
		ResponseURI:    "https://verifier.example/response",
		Nonce:          "nonce",
		RequestPayload: payload,
		RequestObject: &oid4vc.RequestObjectJWT{
			Raw:     "header.payload.",
			Header:  map[string]any{"alg": "none", "typ": "oauth-authz-req+jwt"},
			Payload: payload,
		},
	}

	_, err := ValidateAuthorizationRequest(ValidationModeStrict, false, params)
	if err == nil || !strings.Contains(err.Error(), "transaction_data") {
		t.Fatalf("expected transaction_data validation error, got %v", err)
	}
}
