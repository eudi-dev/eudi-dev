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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/mock"

	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
)

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

// HAIP 1.0 §7 lists what ES256 must validate: wallet attestations, key
// attestations and jwt proofs. DPoP proofs are not on the list, so an
// authorization server may offer DPoP with other algorithms.
func TestHAIPIssuanceLeavesTheDPoPAlgorithmsOpen(t *testing.T) {
	offer, meta := haipCompliantIssuance()
	meta["dpop_signing_alg_values_supported"] = []any{"ES384"}
	if violations := ValidateHAIPIssuanceCompliance(offer, meta); len(violations) != 0 {
		t.Errorf("violations %v for DPoP with ES384", violations)
	}
}

// HAIP 1.0 §4.1 applies to the issuer metadata whichever grant the offer
// carries: a scope for every credential configuration, and a nonce_endpoint
// when a configuration requires key binding.
func TestHAIPChecksTheIssuerMetadataForBothGrants(t *testing.T) {
	config := map[string]any{"format": "dc+sd-jwt", "vct": "urn:test:credential", "cryptographic_binding_methods_supported": []any{"jwk"}}
	metadata := map[string]any{"credential_configurations_supported": map[string]any{"cfg": config}}
	got := strings.Join(haipIssuerMetadataViolations(metadata, "cfg"), "\n")
	for _, want := range []string{"has no scope", "no nonce_endpoint"} {
		if !strings.Contains(got, want) {
			t.Errorf("violations %q, want %q", got, want)
		}
	}

	for name, grants := range map[string]map[string]any{
		"pre-authorized code": {preAuthorizedCodeGrant: map[string]any{"pre-authorized_code": "code"}},
		"authorization code":  {"authorization_code": map[string]any{"issuer_state": "state"}},
	} {
		t.Run(name, func(t *testing.T) {
			w := generateTestWallet(t)
			w.RequireHAIP = true
			w.ValidationMode = ValidationModeStrict
			var serverURL string
			srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				switch {
				case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
					writeTestJSON(rw, map[string]any{
						"credential_issuer":                   serverURL,
						"credential_endpoint":                 serverURL + "/credential",
						"credential_configurations_supported": map[string]any{"cfg": config},
					})
				case strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server"):
					writeTestJSON(rw, map[string]any{
						"issuer":                                serverURL,
						"token_endpoint":                        serverURL + "/token",
						"authorization_endpoint":                serverURL + "/authorize",
						"pushed_authorization_request_endpoint": serverURL + "/par",
					})
				default:
					rw.WriteHeader(http.StatusNotFound)
				}
			}))
			defer srv.Close()
			serverURL = srv.URL

			offer, _ := json.Marshal(map[string]any{"credential_issuer": serverURL, "credential_configuration_ids": []string{"cfg"}, "grants": grants})
			_, err := w.ProcessCredentialOffer("openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offer)))
			if err == nil || !strings.Contains(err.Error(), "HAIP 1.0 §4.1") {
				t.Errorf("err %v, want the HAIP 1.0 §4.1 refusal", err)
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
