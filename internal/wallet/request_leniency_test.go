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
	"encoding/json"
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
)

// OID4VP 1.0 §5.2 marks response_mode REQUIRED.
func TestMissingResponseModeIsAFinding(t *testing.T) {
	params := &AuthorizationRequestParams{
		ClientID:     "redirect_uri:https://verifier.example/cb",
		ResponseType: "vp_token",
		Nonce:        "n",
		RedirectURI:  "https://verifier.example/cb",
		DCQLQuery:    sdjwtVCTQuery("urn:example:x"),
	}
	findings, err := ValidateAuthorizationRequest(ConformanceSettings{ValidationMode: ValidationModeDebug}, params)
	if err != nil {
		t.Fatalf("debug mode: %v", err)
	}
	if !strings.Contains(strings.Join(findings, "\n"), "response_mode is required") {
		t.Errorf("debug findings %v name no missing response_mode", findings)
	}
	if _, err := ValidateAuthorizationRequest(ConformanceSettings{ValidationMode: ValidationModeStrict}, params); err == nil || !strings.Contains(err.Error(), "response_mode is required") {
		t.Errorf("strict mode returned %v, want a refusal for the missing response_mode", err)
	}
}

// One prefix table answers every prefix question, so a reserved or
// unsupported prefix gives one finding.
func TestAClientIDPrefixGivesOneFinding(t *testing.T) {
	for _, clientID := range []string{"origin:https://verifier.example", "openid_federation:https://verifier.example"} {
		params := &AuthorizationRequestParams{
			ClientID: clientID, ResponseType: "vp_token", ResponseMode: "direct_post", Nonce: "n",
			ResponseURI: "https://verifier.example/r", DCQLQuery: sdjwtVCTQuery("urn:example:x"),
		}
		findings, err := ValidateAuthorizationRequest(ConformanceSettings{ValidationMode: ValidationModeDebug}, params)
		if err != nil {
			t.Fatalf("%s: %v", clientID, err)
		}
		if len(findings) != 1 {
			t.Errorf("%s: findings %v, want one", clientID, findings)
		}
	}
}

// OID4VP 1.0 §5: "Wallets MUST NOT process Request Objects where the typ Header
// Parameter is not present". That holds for an unsigned Request Object too.
func TestUnsignedRequestObjectNeedsTyp(t *testing.T) {
	reqObj := &oid4vc.RequestObjectJWT{Header: map[string]any{"alg": "none"}, Payload: map[string]any{}}
	if finding := ValidateRequestObject("redirect_uri:https://verifier.example/cb", reqObj); !strings.Contains(finding, "typ") {
		t.Errorf("finding = %q, want the missing typ", finding)
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
	if entries := infoEntries(requestVerifierInfo(params), "verifier_info"); len(entries) != 1 {
		t.Errorf("verifier_info entries = %v, want the one from the protected header", entries)
	}
}

// OID4VP 1.0 Appendix B.1.1: "Each inner array specifies a set of fully
// expanded types that MUST be present in the fully expanded types in the type
// property of the Verifiable Credential".
func TestEvaluateDCQL_TypeValuesOfAW3CCredential(t *testing.T) {
	w := generateTestWallet(t)
	jwt, err := signJWT(map[string]any{"alg": "ES256", "typ": "JWT"}, map[string]any{
		"vc": map[string]any{"type": []any{"VerifiableCredential", "UniversityDegreeCredential"}},
	}, w.IssuerKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.ImportCredential(jwt); err != nil {
		t.Fatal(err)
	}
	w.ValidationMode = ValidationModeStrict
	for _, tc := range []struct {
		typeValues []any
		want       int
	}{
		{[]any{[]any{"https://www.w3.org/2018/credentials#VerifiableCredential", "https://example.org/examples#UniversityDegreeCredential"}}, 1},
		{[]any{[]any{"https://example.org/examples#BachelorDegree"}, []any{"UniversityDegreeCredential"}}, 1},
		{[]any{[]any{"https://example.org/examples#BachelorDegree"}}, 0},
	} {
		query := map[string]any{"credentials": []any{map[string]any{
			"id": "vc", "format": "jwt_vc_json", "require_cryptographic_holder_binding": false,
			"meta": map[string]any{"type_values": tc.typeValues},
		}}}
		if matches := evaluateDCQL(t, w, query); len(matches) != tc.want {
			t.Errorf("type_values %v: %d matches, want %d", tc.typeValues, len(matches), tc.want)
		}
	}
}
