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

	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
)

// redirectRequest is a valid unsigned direct_post request. Each case changes
// one parameter.
func redirectRequest(change func(*Request)) *Request {
	params := &Request{AuthorizationRequest: oid4vc.AuthorizationRequest{
		ClientID:     "redirect_uri:https://verifier.example/response",
		ResponseType: "vp_token",
		ResponseMode: "direct_post",
		ResponseURI:  "https://verifier.example/response",
		Nonce:        "n",
		DCQLQuery:    sdjwtVCTQuery("urn:eudi:pid:1"),
	}}
	if change != nil {
		change(params)
	}
	return params
}

func TestAuthorizationRequestSyntaxErrors(t *testing.T) {
	for _, tt := range []struct {
		name   string
		params *Request
		want   string
	}{
		{"missing request", nil, "authorization request is missing"},
		{"missing client_id", redirectRequest(func(r *Request) { r.ClientID = "" }), "missing client_id"},
		{"unknown response_type", redirectRequest(func(r *Request) { r.ResponseType = "code" }), `unsupported response_type value "code"`},
		{"duplicate response_type", redirectRequest(func(r *Request) { r.ResponseType = "vp_token vp_token" }), `response_type "vp_token vp_token" contains duplicate "vp_token"`},
		{"unknown response_mode", redirectRequest(func(r *Request) { r.ResponseMode = "query" }), `unsupported response_mode "query"`},
		{"direct_post without response_uri", redirectRequest(func(r *Request) { r.ResponseURI = "" }), `response_mode "direct_post" requires response_uri`},
		{"direct_post.jwt without response_uri", redirectRequest(func(r *Request) { r.ResponseMode, r.ResponseURI = "direct_post.jwt", "" }), `response_mode "direct_post.jwt" requires response_uri`},
		{"fragment without redirect_uri", redirectRequest(func(r *Request) { r.ResponseMode, r.ResponseURI = "fragment", "" }), `response_mode "fragment" requires redirect_uri`},
		// OID4VP 1.0 §5.1 defines get and post, case-sensitive.
		{"request_uri_method GET", redirectRequest(func(r *Request) { r.RequestURIMethod, r.RequestURI = "GET", "https://verifier.example/ro" }), `unsupported request_uri_method "GET"`},
		{"request_uri_method without request_uri", redirectRequest(func(r *Request) { r.RequestURIMethod = "post" }), "request_uri_method requires request_uri"},
		{"client_metadata is no JSON", redirectRequest(func(r *Request) { r.FullParams = map[string]string{"client_metadata": "{"} }), "parsing client_metadata: not valid JSON"},
		{"relative response_uri", redirectRequest(func(r *Request) { r.ResponseURI = "/response" }), "response_uri must be an absolute URI"},
		{"redirect_uri with another scheme", redirectRequest(func(r *Request) { r.ResponseMode, r.RedirectURI = "fragment", "ftp://verifier.example/cb" }), `redirect_uri must use http or https, got scheme "ftp"`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateAuthorizationRequest(Checks{}, tt.params)
			want := "authorization request validation failed: " + tt.want
			if err == nil || err.Error() != want {
				t.Errorf("err = %v, want %q", err, want)
			}
		})
	}
}

func TestAuthorizationRequestSyntaxAccepts(t *testing.T) {
	for _, tt := range []struct {
		name   string
		params *Request
	}{
		{"direct_post", redirectRequest(nil)},
		{"vp_token id_token", redirectRequest(func(r *Request) { r.ResponseType = "vp_token id_token" })},
		{"request_uri_method post", redirectRequest(func(r *Request) { r.RequestURIMethod, r.RequestURI = "post", "https://verifier.example/ro" })},
		{"fragment", redirectRequest(func(r *Request) {
			r.ClientID, r.ResponseMode, r.ResponseURI, r.RedirectURI = "verifier.example", "fragment", "", "https://verifier.example/cb"
		})},
	} {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := ValidateAuthorizationRequest(Checks{Strict: true}, tt.params)
			if err != nil || len(findings) != 0 {
				t.Errorf("findings %v err %v, want a valid request", findings, err)
			}
		})
	}
}

// OpenID4VCI 1.1 §6.2.1.1 sends an unsigned openid4vp_request during
// issuance. Like an unsigned DC API request it has no client_id, and the
// response goes to the Authorization Challenge Endpoint.
func TestInteractiveAuthorizationRequestNeedsNoClientIDOrResponseURI(t *testing.T) {
	params := redirectRequest(func(r *Request) {
		r.ClientID, r.ResponseMode, r.ResponseURI = "", "ia_post", ""
		r.RequestOrigin = "https://issuer.example"
	})
	findings, err := ValidateAuthorizationRequest(Checks{Strict: true}, params)
	if err != nil || len(findings) != 0 {
		t.Errorf("findings %v err %v, want a valid ia_post request", findings, err)
	}
}

// OpenID4VCI 1.1 §6.2.1.1: "If expected_origins is present, it MUST contain
// only the derived Origin of the Authorization Challenge Endpoint".
func TestInteractiveAuthorizationExpectedOrigins(t *testing.T) {
	for _, tt := range []struct {
		name    string
		origins any
		want    string
	}{
		{"only the endpoint origin", []any{"https://issuer.example"}, ""},
		{"another origin too", []any{"https://issuer.example", "https://other.example"}, `OID4VCI 1.1 §6.2.1.1: expected_origins must contain only "https://issuer.example", the origin of the authorization challenge endpoint, and contains [https://issuer.example https://other.example]`},
		{"another origin", []any{"https://other.example"}, `OID4VCI 1.1 §6.2.1.1: expected_origins must contain only "https://issuer.example"`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			params := redirectRequest(func(r *Request) {
				r.ClientID, r.ResponseMode, r.ResponseURI = "", "ia_post.jwt", ""
				r.RequestOrigin = "https://issuer.example"
				r.RequestPayload = map[string]any{"expected_origins": tt.origins}
			})
			findings, err := ValidateAuthorizationRequest(Checks{}, params)
			if err != nil {
				t.Fatal(err)
			}
			switch {
			case tt.want == "" && len(findings) != 0:
				t.Errorf("findings = %v, want none", findings)
			case tt.want != "" && (len(findings) != 1 || !strings.HasPrefix(findings[0].String(), tt.want)):
				t.Errorf("findings = %v, want %q", findings, tt.want)
			}
		})
	}
}

// OID4VP 1.0 §5.1: "Either a dcql_query or a scope parameter representing a
// DCQL Query MUST be present in the Authorization Request, but not both."
func TestDCQLQueryOrScope(t *testing.T) {
	for _, tt := range []struct {
		name   string
		change func(*Request)
		want   string
	}{
		{"both", func(r *Request) { r.Scope = "pid" }, "OID4VP 1.0 §5.1: dcql_query and scope must not both be present"},
		{"neither", func(r *Request) { r.DCQLQuery = nil }, "OID4VP 1.0 §5.1: a vp_token request must carry either dcql_query or scope"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := ValidateAuthorizationRequest(Checks{}, redirectRequest(tt.change))
			if err != nil {
				t.Fatal(err)
			}
			if len(findings) != 1 || findings[0].String() != tt.want {
				t.Errorf("findings = %v, want %q", findings, tt.want)
			}
		})
	}
	findings, err := ValidateAuthorizationRequest(Checks{}, redirectRequest(func(r *Request) { r.DCQLQuery, r.Scope = nil, "pid" }))
	if err != nil || len(findings) != 0 {
		t.Errorf("findings %v err %v, want a scope request accepted", findings, err)
	}
	// An id_token-only request asks for no presentation.
	findings, err = ValidateAuthorizationRequest(Checks{}, redirectRequest(func(r *Request) { r.DCQLQuery, r.ResponseType = nil, "id_token" }))
	if err != nil || len(findings) != 0 {
		t.Errorf("findings %v err %v, want an id_token request accepted", findings, err)
	}
}

// OID4VP 1.0 §6.1 query errors are request findings.
func TestDCQLQueryFindingsReachTheRequestFindings(t *testing.T) {
	params := redirectRequest(func(r *Request) {
		r.DCQLQuery = map[string]any{"credentials": []any{map[string]any{"id": "pid"}}}
	})
	findings, err := ValidateAuthorizationRequest(Checks{}, params)
	if err != nil {
		t.Fatal(err)
	}
	if !containsSubstring(findings.Texts(), "format") {
		t.Errorf("findings = %v, want the missing format", findings)
	}
	if _, err := ValidateAuthorizationRequest(Checks{Strict: true}, params); err == nil || !strings.Contains(err.Error(), "format") {
		t.Errorf("err = %v, want strict mode to refuse the query", err)
	}
}

// OID4VP 1.0 §10.1 client_id_prefixes_supported. pre-registered stands for
// client identifiers without a prefix.
func TestAdvertisedClientIDPrefixes(t *testing.T) {
	want := []string{"pre-registered", "redirect_uri", "x509_hash", "x509_san_dns"}
	if got := AdvertisedClientIDPrefixes(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("prefixes = %v, want %v", got, want)
	}
}

// OID4VP 1.0 §5.9.3 does not allow a signed request under redirect_uri.
func TestPrecludesSignedRequestObject(t *testing.T) {
	for clientID, want := range map[string]bool{
		"redirect_uri:https://verifier.example/cb":          true,
		"x509_san_dns:verifier.example":                     false,
		"x509_hash:abc":                                     false,
		"decentralized_identifier:did:web:verifier.example": false,
		"verifier.example":                                  false,
	} {
		if got := PrecludesSignedRequestObject(clientID); got != want {
			t.Errorf("PrecludesSignedRequestObject(%q) = %v, want %v", clientID, got, want)
		}
	}
}

func TestClientAuthState(t *testing.T) {
	raw := sanDNSRequestObject(t, nil)
	parsed, err := ParseAuthorizationRequestWithOptions(raw, oid4vc.ParseOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if signed, detail := ClientAuthState(RequestFrom(parsed)); !signed || detail != "" {
		t.Errorf("signed %v detail %q, want a verified signature", signed, detail)
	}

	for _, tt := range []struct {
		name   string
		params *Request
		want   string
	}{
		{"no request", nil, "The request was not a signed request object."},
		{"plain parameters", redirectRequest(nil), "The request was not a signed request object."},
		{"alg none", redirectRequest(func(r *Request) {
			r.RequestObject = &oid4vc.RequestObjectJWT{Raw: "eyJhbGciOiJub25lIn0.e30.", Header: map[string]any{"alg": "none"}}
		}), "The request object is unsigned (alg none)."},
		{"no x5c", redirectRequest(func(r *Request) {
			r.ClientID = sanDNSClientID
			r.RequestObject = &oid4vc.RequestObjectJWT{Raw: "e30.e30.c2ln", Header: map[string]any{"alg": "ES256"}}
		}), "OID4VP 1.0 §5.9.3: Request Object signature verification requires an x5c header"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if signed, detail := ClientAuthState(tt.params); signed || detail != tt.want {
				t.Errorf("signed %v detail %q, want %q", signed, detail, tt.want)
			}
		})
	}
}
