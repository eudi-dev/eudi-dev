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
	"encoding/json"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
	"github.com/eudi-dev/eudi-dev/v3/internal/regcert"
)

func TestValidateAuthorizationRequest_StrictRejectsMissingNonce(t *testing.T) {
	params := &Request{AuthorizationRequest: oid4vc.AuthorizationRequest{ClientID: "redirect_uri:https://verifier.example/response", ResponseType: "vp_token", ResponseMode: "direct_post", ResponseURI: "https://verifier.example/response"}}

	_, err := ValidateAuthorizationRequest(Checks{Strict: true}, params)
	if err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("expected nonce validation error, got %v", err)
	}
}

func TestValidateAuthorizationRequest_DebugAllowsMissingNonce(t *testing.T) {
	params := &Request{AuthorizationRequest: oid4vc.AuthorizationRequest{ClientID: "redirect_uri:https://verifier.example/response", ResponseType: "vp_token", ResponseMode: "direct_post", ResponseURI: "https://verifier.example/response"}}

	findings, err := ValidateAuthorizationRequest(Checks{}, params)
	if err != nil {
		t.Fatalf("expected debug mode to allow missing nonce, got %v", err)
	}
	if !strings.Contains(strings.Join(findings, "\n"), "OID4VP 1.0 §5.2: nonce is required") {
		t.Errorf("findings %q, want the missing nonce reported", findings)
	}
}

func TestValidateAuthorizationRequest_StrictRejectsUnsupportedClientIDPrefix(t *testing.T) {
	params := &Request{AuthorizationRequest: oid4vc.AuthorizationRequest{ClientID: "invalid_scheme:verifier", ResponseType: "vp_token", ResponseMode: "direct_post", ResponseURI: "https://verifier.example/response", Nonce: "nonce"}}

	_, err := ValidateAuthorizationRequest(Checks{Strict: true}, params)
	if err == nil || !strings.Contains(err.Error(), "unsupported prefix") {
		t.Fatalf("expected unsupported client_id prefix error, got %v", err)
	}
}

func TestValidateAuthorizationRequest_StrictRejectsRedirectURIWithDirectPost(t *testing.T) {
	params := &Request{AuthorizationRequest: oid4vc.AuthorizationRequest{ClientID: "redirect_uri:https://verifier.example/response", ResponseType: "vp_token", ResponseMode: "direct_post.jwt", ResponseURI: "https://verifier.example/response", RedirectURI: "https://verifier.example/callback", Nonce: "nonce", RequestObject: &oid4vc.RequestObjectJWT{
		Raw: "header.payload.",
		Header: map[string]any{
			"alg": "none",
			"typ": "oauth-authz-req+jwt",
		},
		Payload: map[string]any{},
	}}}

	_, err := ValidateAuthorizationRequest(Checks{Strict: true}, params)
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
	params := &Request{AuthorizationRequest: oid4vc.AuthorizationRequest{ClientID: "redirect_uri:https://verifier.example/response", ResponseType: "vp_token", ResponseMode: "direct_post", ResponseURI: "https://verifier.example/response", Nonce: "nonce", RequestObject: &oid4vc.RequestObjectJWT{
		Raw:     "header.payload.",
		Header:  map[string]any{"alg": "none", "typ": "oauth-authz-req+jwt"},
		Payload: payload,
	}}, RequestPayload: payload}

	_, err := ValidateAuthorizationRequest(Checks{Strict: true}, params)
	if err == nil || !strings.Contains(err.Error(), "transaction_data") {
		t.Fatalf("expected transaction_data validation error, got %v", err)
	}
}

// OID4VP 1.0 §5.2 marks response_mode REQUIRED.
func TestMissingResponseModeIsAFinding(t *testing.T) {
	params := &Request{AuthorizationRequest: oid4vc.AuthorizationRequest{ClientID: "redirect_uri:https://verifier.example/cb", ResponseType: "vp_token", Nonce: "n", RedirectURI: "https://verifier.example/cb", DCQLQuery: sdjwtVCTQuery("urn:example:x")}}
	findings, err := ValidateAuthorizationRequest(Checks{}, params)
	if err != nil {
		t.Fatalf("debug mode: %v", err)
	}
	if !strings.Contains(strings.Join(findings, "\n"), "response_mode is required") {
		t.Errorf("debug findings %v name no missing response_mode", findings)
	}
	if _, err := ValidateAuthorizationRequest(Checks{Strict: true}, params); err == nil || !strings.Contains(err.Error(), "response_mode is required") {
		t.Errorf("strict mode returned %v, want a refusal for the missing response_mode", err)
	}
}

// All prefix checks read one prefix table, so a reserved or unsupported
// prefix gives one finding.
func TestAClientIDPrefixGivesOneFinding(t *testing.T) {
	for _, clientID := range []string{"origin:https://verifier.example", "openid_federation:https://verifier.example"} {
		params := &Request{AuthorizationRequest: oid4vc.AuthorizationRequest{ClientID: clientID, ResponseType: "vp_token", ResponseMode: "direct_post", Nonce: "n", ResponseURI: "https://verifier.example/r", DCQLQuery: sdjwtVCTQuery("urn:example:x")}}
		findings, err := ValidateAuthorizationRequest(Checks{}, params)
		if err != nil {
			t.Fatalf("%s: %v", clientID, err)
		}
		if len(findings) != 1 {
			t.Errorf("%s: findings %v, want one", clientID, findings)
		}
	}
}

// An unsigned Request Object without typ gets a warning, also in strict mode.
func TestUnsignedRequestObjectWithoutTypIsAWarning(t *testing.T) {
	params := &Request{
		AuthorizationRequest: oid4vc.AuthorizationRequest{ClientID: "redirect_uri:https://verifier.example/r", ResponseType: "vp_token", ResponseMode: "direct_post", Nonce: "n", ResponseURI: "https://verifier.example/r", DCQLQuery: sdjwtVCTQuery("urn:example:x")},
	}
	params.RequestObject = &oid4vc.RequestObjectJWT{Raw: "eyJhbGciOiJub25lIn0.e30.", Header: map[string]any{"alg": "none"}, Payload: map[string]any{}}
	findings, err := ValidateAuthorizationRequest(Checks{Strict: true}, params)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || !strings.Contains(findings[0], "no typ header") {
		t.Errorf("findings = %v, want the missing typ warning", findings)
	}
}

// OID4VP 1.0 Appendix A.3.2.2: in a multi-signed request verifier_info is
// "present only in the protected header of the respective signature object".
func TestMultiSignedRequestReadsVerifierInfoFromTheProtectedHeader(t *testing.T) {
	info := []any{map[string]any{"format": "registration_cert", "data": "x.y.z"}}
	header, _ := json.Marshal(map[string]any{"alg": "ES256", "typ": "oauth-authz-req+jwt", "client_id": "x509_hash:abc", "verifier_info": info})
	payload, _ := json.Marshal(map[string]any{"response_type": "vp_token", "response_mode": "dc_api", "nonce": "n"})
	request := map[string]any{
		"payload":    format.EncodeBase64URL(payload),
		"signatures": []any{map[string]any{"protected": format.EncodeBase64URL(header), "signature": "c2ln"}},
	}

	params, err := parseMultiSignedBrowserAuthorizationRequest(request, oid4vc.ParseOptions{}, "https://verifier.example")
	if err != nil {
		t.Fatalf("parsing: %v", err)
	}
	if entries := regcert.InfoEntries(requestVerifierInfo(params), "verifier_info"); len(entries) != 1 {
		t.Errorf("verifier_info entries = %v, want the one from the protected header", entries)
	}
}

func sdjwtVCTQuery(vct string) map[string]any {
	return map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta":   map[string]any{"vct_values": []any{vct}},
				"claims": []any{map[string]any{"path": []any{"given_name"}}},
			},
		},
	}
}
