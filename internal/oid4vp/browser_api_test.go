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
	"reflect"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
)

const callerOrigin = "https://verifier.example"

func browserRequest(protocol string, data any) BrowserAPIRequestEnvelope {
	return BrowserAPIRequestEnvelope{Digital: browserAPIDigitalRequest{Requests: []browserAPICredentialRequest{{Protocol: protocol, Data: data}}}}
}

// OpenID4VP 1.0 Appendix A.2: in an unsigned request the wallet ignores
// client_id and expected_origins and identifies the caller by its origin.
func TestUnsignedBrowserRequestIdentifiesTheCallerByOrigin(t *testing.T) {
	body := browserRequest(browserAPIProtocolUnsigned, map[string]any{
		"client_id":        "x509_san_dns:attacker.example",
		"expected_origins": []any{"https://attacker.example"},
		"response_type":    "vp_token",
		"response_mode":    "dc_api",
		"nonce":            "n-dc",
		"dcql_query":       sdjwtVCTQuery("urn:eudi:pid:1"),
	})
	protocol, params, err := ParseBrowserAPIRequest(body, oid4vc.ParseOptions{}, callerOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if protocol != browserAPIProtocolUnsigned || !params.UnsignedDCAPI || params.RequestOrigin != callerOrigin {
		t.Fatalf("protocol %q unsigned %v origin %q", protocol, params.UnsignedDCAPI, params.RequestOrigin)
	}
	if params.ClientID != "" || params.Nonce != "n-dc" || params.DCQLQuery == nil {
		t.Errorf("client_id %q nonce %q dcql %v, want the request without its client_id", params.ClientID, params.Nonce, params.DCQLQuery)
	}
	findings, err := ValidateAuthorizationRequest(Checks{Strict: true}, params)
	if err != nil || len(findings) != 0 {
		t.Errorf("findings %v err %v, want a valid unsigned DC API request", findings, err)
	}
}

func TestSignedBrowserRequestForms(t *testing.T) {
	raw := sanDNSRequestObject(t, map[string]any{
		"response_mode":    "dc_api",
		"response_uri":     nil,
		"expected_origins": []any{callerOrigin},
	})
	var calls []fetchCall
	opts := recordingFetcher(raw, nil, &calls)
	for name, data := range map[string]any{
		"compact JWT":        raw,
		"request member":     map[string]any{"request": raw},
		"request_uri member": map[string]any{"client_id": sanDNSClientID, "request_uri": "https://verifier.example/request", "request_uri_method": "post"},
	} {
		t.Run(name, func(t *testing.T) {
			protocol, params, err := ParseBrowserAPIRequest(browserRequest(browserAPIProtocolSigned, data), opts, callerOrigin)
			if err != nil {
				t.Fatal(err)
			}
			if protocol != browserAPIProtocolSigned || params.UnsignedDCAPI || params.RequestOrigin != callerOrigin {
				t.Fatalf("protocol %q unsigned %v origin %q", protocol, params.UnsignedDCAPI, params.RequestOrigin)
			}
			if params.ClientID != sanDNSClientID || params.RequestObject == nil || params.RequestObject.Raw != raw {
				t.Fatalf("client_id %q, want the signed request", params.ClientID)
			}
			findings, err := ValidateAuthorizationRequest(Checks{Strict: true}, params)
			if err != nil || len(findings) != 0 {
				t.Errorf("findings %v err %v, want a valid signed DC API request", findings, err)
			}
		})
	}
	if want := (fetchCall{"https://verifier.example/request", "post", sanDNSClientID}); len(calls) != 1 || calls[0] != want {
		t.Errorf("fetches = %+v, want %+v", calls, want)
	}
}

// OpenID4VP 1.0 Appendix A.2: "If the Origin does not match any of the
// entries in expected_origins, the Wallet MUST return an error."
func TestSignedBrowserRequestMustExpectTheCallerOrigin(t *testing.T) {
	raw := sanDNSRequestObject(t, map[string]any{
		"response_mode":    "dc_api.jwt",
		"response_uri":     nil,
		"expected_origins": []any{"https://other.example"},
	})
	_, params, err := ParseBrowserAPIRequest(browserRequest(browserAPIProtocolSigned, raw), oid4vc.ParseOptions{}, callerOrigin)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ValidateAuthorizationRequest(Checks{Strict: true}, params)
	if err == nil || !strings.Contains(err.Error(), `OID4VP 1.0 Appendix A.2: expected_origins must include the caller origin "https://verifier.example"`) {
		t.Errorf("err = %v, want the expected_origins finding", err)
	}
}

func TestBrowserRequestErrors(t *testing.T) {
	directPost := sanDNSRequestObject(t, nil)
	for _, tt := range []struct {
		name string
		body BrowserAPIRequestEnvelope
		want string
	}{
		{"no OpenID4VP protocol", browserRequest("org-iso-mdoc", map[string]any{}), "browser request did not contain a supported OpenID4VP protocol"},
		// Appendix A.2: "The value of the response_mode parameter MUST be
		// dc_api when the response is not encrypted and dc_api.jwt when the
		// response is encrypted".
		{"response_mode direct_post", browserRequest(browserAPIProtocolSigned, directPost), `OID4VP 1.0 Appendix A.2: response_mode must be dc_api or dc_api.jwt over the Digital Credentials API, got "direct_post"`},
		{"signed data is a number", browserRequest(browserAPIProtocolSigned, 42.0), "signed browser request data must be a JWT string or object"},
		{"signed object without request", browserRequest(browserAPIProtocolSigned, map[string]any{"client_id": sanDNSClientID}), "signed browser request must contain request or request_uri"},
		{"signed string is no request", browserRequest(browserAPIProtocolSigned, "garbage"), "parsing authorization request"},
		{"multisigned data is a string", browserRequest(browserAPIProtocolMultiSigned, "x"), "multisigned browser request data must be an object"},
		{"multisigned without request", browserRequest(browserAPIProtocolMultiSigned, map[string]any{}), "multisigned browser request must contain a request object"},
		{"multisigned without signatures", browserRequest(browserAPIProtocolMultiSigned, map[string]any{"request": map[string]any{"payload": "e30"}}), "multisigned browser request must contain payload and signatures"},
		{"multisigned without a usable signature", browserRequest(browserAPIProtocolMultiSigned, map[string]any{"request": map[string]any{
			"payload":    "e30",
			"signatures": []any{"x", map[string]any{"protected": "e30"}, map[string]any{"protected": "!!", "signature": "c2ln"}},
		}}), "multisigned browser request did not contain a parseable signature"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := ParseBrowserAPIRequest(tt.body, oid4vc.ParseOptions{}, callerOrigin)
			if err == nil || !strings.HasPrefix(err.Error(), tt.want) {
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

func TestBrowserRequestUsesTheFirstSupportedProtocol(t *testing.T) {
	body := BrowserAPIRequestEnvelope{Digital: browserAPIDigitalRequest{Requests: []browserAPICredentialRequest{
		{Protocol: "org-iso-mdoc", Data: map[string]any{}},
		{Protocol: browserAPIProtocolUnsigned, Data: map[string]any{"response_type": "vp_token", "response_mode": "dc_api", "nonce": "n"}},
	}}}
	protocol, params, err := ParseBrowserAPIRequest(body, oid4vc.ParseOptions{}, callerOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if protocol != browserAPIProtocolUnsigned || params.Nonce != "n" {
		t.Errorf("protocol %q nonce %q, want the OpenID4VP request", protocol, params.Nonce)
	}
}

// multiSignedRequest returns the JWS JSON serialization of payload with one
// signature per header (OpenID4VP 1.0 Appendix A.3.2).
func multiSignedRequest(t *testing.T, payload map[string]any, headers []map[string]any, key *ecdsa.PrivateKey) map[string]any {
	t.Helper()
	var encodedPayload string
	signatures := make([]any, 0, len(headers))
	for _, header := range headers {
		raw, err := jws.Sign(header, payload, key)
		if err != nil {
			t.Fatal(err)
		}
		parts := strings.Split(raw, ".")
		encodedPayload = parts[1]
		signatures = append(signatures, map[string]any{"protected": parts[0], "signature": parts[2]})
	}
	return map[string]any{"request": map[string]any{"payload": encodedPayload, "signatures": signatures}}
}

// Appendix A.3.2.2: each signature carries its client_id in the protected header.
// The wallet takes the first signature it can verify.
func TestMultiSignedBrowserRequestPicksTheVerifiedSignature(t *testing.T) {
	key, certB64, _ := testCertWithKeyDER([]string{"verifier.example"})
	payload := map[string]any{"response_type": "vp_token", "response_mode": "dc_api", "nonce": "n-multi", "expected_origins": []any{callerOrigin}}
	didHeader := map[string]any{"alg": "ES256", "typ": "oauth-authz-req+jwt", "client_id": "decentralized_identifier:did:web:verifier.example"}
	x509Header := map[string]any{"alg": "ES256", "typ": "oauth-authz-req+jwt", "client_id": sanDNSClientID, "x5c": []any{certB64}}

	data := multiSignedRequest(t, payload, []map[string]any{didHeader, x509Header}, key)
	protocol, params, err := ParseBrowserAPIRequest(browserRequest(browserAPIProtocolMultiSigned, data), oid4vc.ParseOptions{}, callerOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if protocol != browserAPIProtocolMultiSigned || params.ClientID != sanDNSClientID || params.RequestOrigin != callerOrigin || params.Nonce != "n-multi" {
		t.Fatalf("protocol %q client_id %q origin %q nonce %q, want the x509 signature", protocol, params.ClientID, params.RequestOrigin, params.Nonce)
	}
	if signed, detail := ClientAuthState(params); !signed {
		t.Errorf("the chosen signature does not verify: %s", detail)
	}

	// Without a verifiable signature the wallet keeps the first one, and the
	// signature check reports it.
	data = multiSignedRequest(t, payload, []map[string]any{didHeader}, key)
	_, params, err = ParseBrowserAPIRequest(browserRequest(browserAPIProtocolMultiSigned, data), oid4vc.ParseOptions{}, callerOrigin)
	if err != nil {
		t.Fatal(err)
	}
	if params.ClientID != "decentralized_identifier:did:web:verifier.example" {
		t.Fatalf("client_id %q, want the DID signature", params.ClientID)
	}
	if signed, detail := ClientAuthState(params); signed || !strings.Contains(detail, "does not resolve DIDs") {
		t.Errorf("signed %v detail %q, want the unresolved DID", signed, detail)
	}
}

func TestBuildBrowserAPIResult(t *testing.T) {
	vpToken := map[string]any{"vp_token": map[string]any{"pid": []any{"ey..."}}}
	for _, tt := range []struct {
		name     string
		response *AuthorizationResponseEnvelope
		want     any
		wantErr  string
	}{
		{"missing response", nil, nil, "authorization response is missing"},
		{"dc_api", &AuthorizationResponseEnvelope{ResponseMode: "dc_api", Plain: vpToken}, vpToken, ""},
		{"no response mode", &AuthorizationResponseEnvelope{Plain: vpToken}, vpToken, ""},
		{"dc_api.jwt", &AuthorizationResponseEnvelope{ResponseMode: "dc_api.jwt", ResponseJWT: "a.b.c.d.e"}, map[string]any{"response": "a.b.c.d.e"}, ""},
		// Appendix A.4: an error is "an object within the data property" with
		// "a single property with the name error", encrypted mode or not.
		{"dc_api error", &AuthorizationResponseEnvelope{ResponseMode: "dc_api", Plain: map[string]any{"error": "access_denied", "error_description": "user said no", "state": "s"}}, map[string]any{"error": "access_denied"}, ""},
		{"dc_api.jwt error", &AuthorizationResponseEnvelope{ResponseMode: "dc_api.jwt", Plain: map[string]any{"error": "invalid_request", "state": "s"}}, map[string]any{"error": "invalid_request"}, ""},
		{"dc_api.jwt without JWT", &AuthorizationResponseEnvelope{ResponseMode: "dc_api.jwt"}, nil, "dc_api.jwt response is missing response JWT"},
		{"direct_post", &AuthorizationResponseEnvelope{ResponseMode: "direct_post", Plain: vpToken}, nil, `response_mode "direct_post" cannot be returned via Browser API`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			result, err := BuildBrowserAPIResult(browserAPIProtocolSigned, tt.response)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Errorf("err = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if result.Protocol != browserAPIProtocolSigned || !reflect.DeepEqual(result.Data, tt.want) {
				t.Errorf("result = %+v, want data %v", result, tt.want)
			}
		})
	}
}
