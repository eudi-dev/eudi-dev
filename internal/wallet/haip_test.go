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
	"crypto/x509"
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vp"

	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
)

// The fixture is a real signed request with x509_hash and a CA-issued leaf, so
// the signature and certificate hash checks run against it.
func haipCompliantParams(t *testing.T) (*oid4vp.Request, *oid4vc.RequestObjectJWT) {
	t.Helper()

	_, leafCert, leafKey, _ := authorityChain(t)

	clientID := oid4vp.X509HashClientID(leafCert)
	claims := map[string]any{
		"client_id":        clientID,
		"response_type":    "vp_token",
		"response_mode":    "dc_api.jwt",
		"nonce":            "n-haip",
		"expected_origins": []any{"https://verifier.example"},
	}
	raw, err := oid4vp.SignRequestObjectJWT(claims, leafKey, []*x509.Certificate{leafCert})
	if err != nil {
		t.Fatal(err)
	}
	header, payload, _, err := format.ParseJWTParts(raw)
	if err != nil {
		t.Fatal(err)
	}

	params := &oid4vp.Request{
		ClientID:      clientID,
		ResponseType:  "vp_token",
		ResponseMode:  "dc_api.jwt",
		Nonce:         "n-haip",
		RequestOrigin: "https://verifier.example",
		DCQLQuery: map[string]any{"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"meta":   map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
			},
		}},
		ClientMetadata: map[string]any{
			"encrypted_response_enc_values_supported": []any{"A128GCM", "A256GCM"},
		},
		RequestPayload: payload,
	}
	reqObj := &oid4vc.RequestObjectJWT{Raw: raw, Header: header, Payload: payload}
	return params, reqObj
}

func TestValidateHAIPCompliance(t *testing.T) {
	tests := []struct {
		name           string
		modifyParams   func(p *oid4vp.Request)
		modifyReqObj   func(r *oid4vc.RequestObjectJWT)
		useNilReqObj   bool
		wantViolations int    // minimum expected violations (0 = compliant)
		wantContain    string // substring expected in at least one violation
	}{
		{
			name:           "fully compliant",
			wantViolations: 0,
		},
		{
			name:           "wrong response_mode",
			modifyParams:   func(p *oid4vp.Request) { p.ResponseMode = "direct_post" },
			wantViolations: 1,
			wantContain:    "response_mode",
		},
		{
			name:           "client identifier prefix the profile does not allow",
			modifyParams:   func(p *oid4vp.Request) { p.ClientID = "redirect_uri:https://example.com" },
			wantViolations: 1,
			wantContain:    "Client Identifier Prefix",
		},
		{
			// HAIP §5 permits only x509_hash for signed requests.
			name:           "x509_san_dns is not a HAIP prefix",
			modifyParams:   func(p *oid4vp.Request) { p.ClientID = "x509_san_dns:verifier.example" },
			wantViolations: 1,
			wantContain:    "Client Identifier Prefix",
		},
		{
			// Over the redirect flow a missing Request Object is a violation.
			// Over the Digital Credentials API it is a valid unsigned request
			// (see the next case).
			name: "missing request object (JAR) on the redirect flow",
			modifyParams: func(p *oid4vp.Request) {
				p.ResponseMode = "direct_post.jwt"
				p.RequestOrigin = ""
			},
			useNilReqObj:   true,
			wantViolations: 1,
			wantContain:    "JAR",
		},
		{
			name:           "missing DCQL query",
			modifyParams:   func(p *oid4vp.Request) { p.DCQLQuery = nil },
			wantViolations: 1,
			wantContain:    "DCQL",
		},
		{
			// HAIP §5.2: "The Wallet MUST support unsigned, signed, and
			// multi-signed requests." An unsigned one carries no client_id.
			// The origin reported by the platform identifies the caller.
			name: "unsigned Digital Credentials API request",
			modifyParams: func(p *oid4vp.Request) {
				p.ClientID = ""
				p.UnsignedDCAPI = true
				p.ResponseMode = "dc_api.jwt"
				p.RequestOrigin = "https://wallet.example"
				p.RequestPayload = nil
			},
			useNilReqObj:   true,
			wantViolations: 0,
		},
		{
			// Appendix A.2 of OID4VP: expected_origins "is not for use in
			// unsigned requests and therefore a Wallet MUST ignore this
			// parameter if it is present in an unsigned request". A foreign
			// origin in it is no violation.
			name: "unsigned request carrying expected_origins it does not match",
			modifyParams: func(p *oid4vp.Request) {
				p.ClientID = ""
				p.UnsignedDCAPI = true
				p.ResponseMode = "dc_api.jwt"
				p.RequestOrigin = "https://wallet.example"
				p.RequestPayload = map[string]any{
					"expected_origins": []any{"https://other.example"},
				}
			},
			useNilReqObj:   true,
			wantViolations: 0,
		},
		{
			name: "multiple violations",
			modifyParams: func(p *oid4vp.Request) {
				p.ClientID = "redirect_uri:https://example.com"
				p.ResponseMode = "direct_post"
				p.DCQLQuery = nil
			},
			useNilReqObj:   true,
			wantViolations: 4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params, reqObj := haipCompliantParams(t)
			if tt.modifyParams != nil {
				tt.modifyParams(params)
			}
			if tt.modifyReqObj != nil {
				tt.modifyReqObj(reqObj)
			}
			if tt.useNilReqObj {
				reqObj = nil
			}

			violations := oid4vp.ValidateHAIPCompliance(params, reqObj)

			if tt.wantViolations == 0 {
				if len(violations) != 0 {
					t.Errorf("expected 0 violations, got %d: %v", len(violations), violations)
				}
				return
			}

			if len(violations) < tt.wantViolations {
				t.Errorf("expected at least %d violations, got %d: %v", tt.wantViolations, len(violations), violations)
			}

			if tt.wantContain != "" {
				found := false
				for _, v := range violations {
					if contains(v, tt.wantContain) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected violation containing %q, got: %v", tt.wantContain, violations)
				}
			}
		})
	}
}

func haipCompliantIssuance() (*oid4vc.CredentialOffer, map[string]any) {
	offer := &oid4vc.CredentialOffer{
		CredentialIssuer: "https://issuer.example",
		Grants:           oid4vc.OfferGrants{IssuerState: "abc"},
	}
	meta := map[string]any{
		"authorization_endpoint":                "https://issuer.example/authorize",
		"grant_types_supported":                 []any{"authorization_code"},
		"pushed_authorization_request_endpoint": "https://issuer.example/par",
		"code_challenge_methods_supported":      []any{"S256"},
		"dpop_signing_alg_values_supported":     []any{"ES256"},
		"token_endpoint_auth_methods_supported": []any{"attest_jwt_client_auth"},
	}
	return offer, meta
}

func TestValidateHAIPIssuanceCompliance(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*oid4vc.CredentialOffer, map[string]any)
		wantSub string
	}{
		{name: "compliant issuer"},
		{
			// HAIP 1.0 §4 requires an issuer to support the authorization
			// code flow. It says nothing about the pre-authorized code flow,
			// so an offer using it is not a violation.
			name: "pre-authorized code offer is accepted",
			mutate: func(o *oid4vc.CredentialOffer, _ map[string]any) {
				o.Grants = oid4vc.OfferGrants{PreAuthorizedCode: "code"}
			},
		},
		{
			name: "authorization code offer whose issuer does not advertise the flow",
			mutate: func(_ *oid4vc.CredentialOffer, m map[string]any) {
				m["grant_types_supported"] = []any{"urn:ietf:params:oauth:grant-type:pre-authorized_code"}
			},
			wantSub: "must support the authorization code flow",
		},
		{
			name: "plain http issuer",
			mutate: func(o *oid4vc.CredentialOffer, _ map[string]any) {
				o.CredentialIssuer = "http://issuer.example"
			},
			wantSub: "must be an https URL",
		},
		{
			// HAIP requires the server to offer PAR. It does not require the
			// server to advertise require_pushed_authorization_requests.
			name: "no PAR endpoint for an authorization code offer",
			mutate: func(_ *oid4vc.CredentialOffer, m map[string]any) {
				delete(m, "pushed_authorization_request_endpoint")
			},
			wantSub: "must support pushed authorization requests",
		},
		{
			// §4 scopes PAR to "when using the Authorization Endpoint". A
			// pre-authorized code offer never reaches it. The same holds for
			// PKCE and the authorization code flow support.
			name: "pre-authorized code offer is judged on transport only",
			mutate: func(o *oid4vc.CredentialOffer, m map[string]any) {
				o.Grants = oid4vc.OfferGrants{PreAuthorizedCode: "code"}
				delete(m, "pushed_authorization_request_endpoint")
				m["code_challenge_methods_supported"] = []any{"plain"}
				delete(m, "grant_types_supported")
				delete(m, "dpop_signing_alg_values_supported")
			},
		},
		{
			name: "pre-authorized code offer over plain http is still rejected",
			mutate: func(o *oid4vc.CredentialOffer, _ map[string]any) {
				o.Grants = oid4vc.OfferGrants{PreAuthorizedCode: "code"}
				o.CredentialIssuer = "http://issuer.example"
			},
			wantSub: "must be an https URL",
		},
		{
			name: "no PKCE S256",
			mutate: func(_ *oid4vc.CredentialOffer, m map[string]any) {
				m["code_challenge_methods_supported"] = []any{"plain"}
			},
			wantSub: "advertises PKCE without S256",
		},
		{
			name: "DPoP advertised with no algorithm this wallet can use",
			mutate: func(_ *oid4vc.CredentialOffer, m map[string]any) {
				m["dpop_signing_alg_values_supported"] = []any{"HS256"}
			},
			wantSub: "advertises DPoP without ES256",
		},
		{
			name: "unreadable authorization server metadata",
			mutate: func(_ *oid4vc.CredentialOffer, m map[string]any) {
				for k := range m {
					delete(m, k)
				}
			},
			wantSub: "must support the authorization code flow",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			offer, meta := haipCompliantIssuance()
			if tc.mutate != nil {
				tc.mutate(offer, meta)
			}
			violations := ValidateHAIPIssuanceCompliance(offer, meta)
			if tc.wantSub == "" {
				if len(violations) != 0 {
					t.Fatalf("expected a compliant issuer, got %v", violations)
				}
				return
			}
			if len(violations) == 0 {
				t.Fatalf("expected a violation containing %q, got none", tc.wantSub)
			}
			var found bool
			for _, v := range violations {
				if strings.Contains(v, tc.wantSub) {
					found = true
				}
			}
			if !found {
				t.Errorf("violations %v do not mention %q", violations, tc.wantSub)
			}
		})
	}
}

// A local instance serves plain http on loopback. The profile must stay
// testable against it.
func TestHAIPIssuanceAllowsLoopbackHTTP(t *testing.T) {
	for _, issuer := range []string{"http://localhost:8085/issuer", "http://127.0.0.1:8085/issuer", "https://eudi-test.dev/issuer"} {
		offer, meta := haipCompliantIssuance()
		offer.CredentialIssuer = issuer
		if violations := ValidateHAIPIssuanceCompliance(offer, meta); len(violations) != 0 {
			t.Errorf("issuer %q rejected: %v", issuer, violations)
		}
	}
	offer, meta := haipCompliantIssuance()
	offer.CredentialIssuer = "http://issuer.example/issuer"
	if violations := ValidateHAIPIssuanceCompliance(offer, meta); len(violations) == 0 {
		t.Error("a public plain-http issuer must still be rejected")
	}
}

// A pre-authorized code offer from an issuer that meets the profile must be
// accepted. HAIP 1.0 §4 requires support for the authorization code flow and
// has no rule for the pre-authorized code flow. It scopes PAR to "when using
// the Authorization Endpoint", which this offer never reaches.
func TestHAIPIssuanceAcceptsCompliantPreAuthorizedOffer(t *testing.T) {
	offer := &oid4vc.CredentialOffer{
		CredentialIssuer: "https://issuer.example",
		Grants:           oid4vc.OfferGrants{PreAuthorizedCode: "abc"},
	}
	meta := map[string]any{
		"authorization_endpoint":                "https://issuer.example/authorize",
		"grant_types_supported":                 []any{"authorization_code", "urn:ietf:params:oauth:grant-type:pre-authorized_code"},
		"dpop_signing_alg_values_supported":     []any{"ES256"},
		"token_endpoint_auth_methods_supported": []any{"attest_jwt_client_auth"},
	}
	if violations := ValidateHAIPIssuanceCompliance(offer, meta); len(violations) != 0 {
		t.Errorf("a compliant pre-authorized code offer was rejected: %v", violations)
	}
}

// HAIP requires client authentication. It does not require metadata to
// advertise it, so missing metadata is no violation.
func TestValidateHAIPIssuanceCompliance_SilentClientAuthIsNotAViolation(t *testing.T) {
	offer := &oid4vc.CredentialOffer{
		CredentialIssuer: "https://issuer.example",
		Grants:           oid4vc.OfferGrants{IssuerState: "state"},
	}
	meta := map[string]any{
		"issuer":                                "https://issuer.example",
		"authorization_endpoint":                "https://issuer.example/authorize",
		"pushed_authorization_request_endpoint": "https://issuer.example/par",
		"code_challenge_methods_supported":      []any{"S256"},
		"dpop_signing_alg_values_supported":     []any{"ES256"},
	}

	if violations := ValidateHAIPIssuanceCompliance(offer, meta); len(violations) != 0 {
		t.Errorf("silent client authentication is not a HAIP violation, got %v", violations)
	}
}

// An issuer that supports PAR without advertising
// require_pushed_authorization_requests conforms to HAIP 1.0 §4. RFC 9126
// makes the parameter optional with a default of false.
func TestHAIPIssuanceAcceptsPARWithoutTheRequireFlag(t *testing.T) {
	offer := &oid4vc.CredentialOffer{
		CredentialIssuer: "https://issuer.eudiw.dev",
		Grants:           oid4vc.OfferGrants{IssuerState: "abc"},
	}
	// The authorization server metadata of an ecosystem reference issuer,
	// copied verbatim.
	meta := map[string]any{
		"issuer":                                "https://issuer.eudiw.dev",
		"authorization_endpoint":                "https://issuer.eudiw.dev/authorize",
		"pushed_authorization_request_endpoint": "https://issuer.eudiw.dev/pushed_authorization",
		"grant_types_supported": []any{
			"authorization_code", "implicit",
			"urn:ietf:params:oauth:grant-type:jwt-bearer", "refresh_token",
		},
		"code_challenge_methods_supported": []any{"S256"},
		"dpop_signing_alg_values_supported": []any{
			"RS256", "RS384", "RS512", "ES256", "ES384", "ES512",
			"HS256", "HS384", "HS512", "PS256", "PS384", "PS512",
		},
		// No require_pushed_authorization_requests (optional in RFC 9126).
	}

	if violations := ValidateHAIPIssuanceCompliance(offer, meta); len(violations) > 0 {
		t.Errorf("a server that offers PAR was reported non-compliant: %v", violations)
	}
}

func containsSubstring(values []string, want string) bool {
	for _, value := range values {
		if strings.Contains(value, want) {
			return true
		}
	}
	return false
}

// With --haip every credential of a response follows HAIP 1.0 §6.1.1, also
// the second copy of a batch. Strict mode refuses the response.
func TestStrictHAIPChecksEveryCopyOfABatch(t *testing.T) {
	w := generateTestWalletWithPID(t)
	good := w.GetCredentials()[0].Raw
	key, _ := mock.GenerateKey()
	bare, err := mock.GenerateSDJWT(mock.SDJWTConfig{Issuer: "https://issuer.example", VCT: "urn:eudi:pid:1", ExpiresIn: time.Hour, Claims: map[string]any{"given_name": "Erika"}, Key: key})
	if err != nil {
		t.Fatal(err)
	}
	w.RequireHAIP = true
	w.ValidationMode = ValidationModeStrict
	resp := map[string]any{"credentials": []any{map[string]any{"credential": good}, map[string]any{"credential": bare}}}
	if _, err := w.checkReceivedCredentials(resp, "https://issuer.example"); err == nil || !strings.Contains(err.Error(), "§6.1.1") {
		t.Errorf("err %v, want the §6.1.1 finding for the second copy", err)
	}
}
