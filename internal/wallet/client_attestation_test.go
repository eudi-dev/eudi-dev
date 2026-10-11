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
)

// TestAttestsClient covers when the wallet authenticates with its wallet
// attestation. The spec uses authorization server metadata as the signal.
// Advertising the method is only a SHOULD, so an override exists
// (draft-ietf-oauth-attestation-based-client-auth-07 §10.1, -08 §9, -10 §8).
func TestAttestsClient(t *testing.T) {
	advertised := map[string]any{
		"token_endpoint_auth_methods_supported": []any{"attest_jwt_client_auth"},
	}
	silent := map[string]any{
		"token_endpoint": "https://issuer.invalid/token",
	}
	otherMethod := map[string]any{
		"token_endpoint_auth_methods_supported": []any{"client_secret_post"},
	}
	explicitNone := map[string]any{
		"token_endpoint_auth_methods_supported": []any{"none"},
	}

	for _, tc := range []struct {
		name  string
		meta  map[string]any
		haip  bool
		force bool
		mode  ValidationMode
		want  bool
	}{
		{"advertised", advertised, false, false, ValidationModeDebug, true},
		{"silent metadata", silent, false, false, ValidationModeDebug, false},
		{"silent metadata, override on", silent, false, true, ValidationModeDebug, true},
		{"another method", otherMethod, false, false, ValidationModeDebug, false},
		{"another method, override on", otherMethod, false, true, ValidationModeDebug, true},
		{"no metadata at all", nil, false, false, ValidationModeDebug, false},
		// HAIP 1.0 §4.4.1 requires client authentication. In strict mode the
		// wallet always attests. In debug mode it attests when the metadata is
		// silent, since every ABCA draft lets an issuer require it without
		// advertising it.
		// An issuer that lists an unauthenticated method gets no attestation,
		// so a non-HAIP issuer stays reachable.
		{"haip strict, silent metadata", silent, true, false, ValidationModeStrict, true},
		{"haip debug, silent metadata attests", silent, true, false, ValidationModeDebug, true},
		{"haip strict, no metadata", nil, true, false, ValidationModeStrict, true},
		{"haip debug, no metadata attests", nil, true, false, ValidationModeDebug, true},
		{"haip strict, explicit none", explicitNone, true, false, ValidationModeStrict, true},
		{"haip debug, explicit none does not attest", explicitNone, true, false, ValidationModeDebug, false},
		{"haip strict, another method", otherMethod, true, false, ValidationModeStrict, true},
		{"haip debug, another method does not attest", otherMethod, true, false, ValidationModeDebug, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := &Wallet{ConformanceSettings: ConformanceSettings{RequireHAIP: tc.haip, ValidationMode: tc.mode}, ForceClientAttestation: tc.force}
			if got := w.attestsClient(tc.meta); got != tc.want {
				t.Errorf("attestsClient = %v, want %v", got, tc.want)
			}
		})
	}
}

// silentAttestationIssuer requires client attestation at its token endpoint
// and advertises nothing about it. A wallet that follows the metadata sends no
// attestation, so only the override reaches this issuer.
func silentAttestationIssuer(t *testing.T, w *Wallet) (*httptest.Server, string, *int) {
	t.Helper()

	credRaw := generateTestCredential(t, w)
	var serverURL string
	attestedRequests := 0

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":     serverURL,
				"credential_endpoint":   serverURL + "/credential",
				"token_endpoint":        serverURL + "/token",
				"authorization_servers": []any{serverURL},
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{"format": "dc+sd-jwt", "vct": "urn:test:credential"},
				},
			})

		case strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server"):
			// There is no token_endpoint_auth_methods_supported. The metadata
			// even claims the pre-authorized grant allows anonymous access.
			json.NewEncoder(rw).Encode(map[string]any{
				"issuer":         serverURL,
				"token_endpoint": serverURL + "/token",
				"pre-authorized_grant_anonymous_access_supported": true,
			})

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/token"):
			attestation := r.Header.Get("OAuth-Client-Attestation")
			pop := r.Header.Get("OAuth-Client-Attestation-PoP")
			if attestation == "" || pop == "" {
				rw.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(rw).Encode(map[string]string{
					"error":             "invalid_client",
					"error_description": "Missing required client attestation parameters",
				})
				return
			}
			attestedRequests++
			if typ := decodeJWTPart(t, attestation, 0)["typ"]; typ != "oauth-client-attestation+jwt" {
				t.Errorf("attestation typ = %v, want oauth-client-attestation+jwt", typ)
			}
			if typ := decodeJWTPart(t, pop, 0)["typ"]; typ != "oauth-client-attestation-pop+jwt" {
				t.Errorf("PoP typ = %v, want oauth-client-attestation-pop+jwt", typ)
			}
			if aud := decodeJWTPart(t, pop, 1)["aud"]; aud != serverURL {
				t.Errorf("PoP aud = %v, want the authorization server %q", aud, serverURL)
			}
			json.NewEncoder(rw).Encode(map[string]any{
				"access_token": "test-access-token", "token_type": "Bearer", "c_nonce": "test-c-nonce",
			})

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/credential"):
			json.NewEncoder(rw).Encode(map[string]any{"credentials": []any{map[string]any{"credential": credRaw}}})

		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	serverURL = srv.URL

	offer := map[string]any{
		"credential_issuer":            serverURL,
		"credential_configuration_ids": []string{"test-config"},
		"grants": map[string]any{
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
				"pre-authorized_code": "test-pre-auth-code",
			},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	return srv, "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON)), &attestedRequests
}

// The issuer rejects requests without an attestation. With --client-attestation
// the same offer completes.
func TestForceClientAttestation_ReachesSilentIssuer(t *testing.T) {
	for _, tc := range []struct {
		name    string
		force   bool
		wantErr string
	}{
		{"off by default", false, "invalid_client"},
		{"forced on", true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := generateTestWallet(t)
			w.ForceClientAttestation = tc.force
			srv, offerURI, attested := silentAttestationIssuer(t, w)
			defer srv.Close()

			oldClient := httpClient
			httpClient = srv.Client()
			defer func() { httpClient = oldClient }()

			_, err := w.ProcessCredentialOffer(offerURI)
			if tc.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("error = %v, want it to mention %q", err, tc.wantErr)
				}
				if *attested != 0 {
					t.Errorf("wallet attested %d times with the override off, want 0", *attested)
				}
				return
			}
			if err != nil {
				t.Fatalf("ProcessCredentialOffer: %v", err)
			}
			if *attested != 1 {
				t.Errorf("issuer saw %d attested token requests, want 1", *attested)
			}
		})
	}
}

// TestHAIPDebugAttestsSilentIssuer covers a HAIP wallet in debug mode against
// an issuer that requires client attestation without advertising it. Every
// ABCA draft makes advertising a SHOULD. The wallet attests anyway and warns about the
// missing advertisement. A non-HAIP wallet needs --client-attestation here.
func TestHAIPDebugAttestsSilentIssuer(t *testing.T) {
	w := generateTestWallet(t)
	w.RequireHAIP = true
	w.ValidationMode = ValidationModeDebug
	w.IssuerURL = "https://wallet.example"
	w.BaseURL = "https://wallet.example"

	srv, offerURI, attested := silentAttestationIssuer(t, w)
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	result, err := w.ProcessCredentialOffer(offerURI)
	if err != nil {
		t.Fatalf("HAIP debug should complete against a silent require-attestation issuer, got %v", err)
	}
	if *attested != 1 {
		t.Errorf("issuer saw %d attested token requests, want 1", *attested)
	}
	if result == nil || result.CredentialID == "" {
		t.Fatal("expected a credential to be imported")
	}
	if !hasWarningContaining(w, "advertises no token endpoint client authentication") {
		t.Error("expected a warning that the issuer does not advertise its client authentication method")
	}
	// OpenID4VCI 1.0 pins draft-07, where §10.1 holds the recommendation.
	if !hasWarningContaining(w, "draft-ietf-oauth-attestation-based-client-auth-07 §10.1") {
		t.Error("expected the warning to cite the pinned ABCA draft and its section")
	}
}

func TestABCAMetadataSection(t *testing.T) {
	for draft, want := range map[int]string{7: "§10.1", 8: "§9", 10: "§8"} {
		if got := abcaMetadataSection(draft); got != want {
			t.Errorf("abcaMetadataSection(%d) = %q, want %q", draft, got, want)
		}
	}
}

// private_key_jwt already authenticates the client. The override adds no
// attestation on top.
func TestForceClientAttestation_DoesNotDisplacePrivateKeyJWT(t *testing.T) {
	w := generateTestWallet(t)
	w.ForceClientAttestation = true
	meta := map[string]any{
		"token_endpoint_auth_methods_supported": []any{"private_key_jwt"},
	}
	if method := detectTokenEndpointAuthMethod(meta); method != "private_key_jwt" {
		t.Fatalf("detected %q, want private_key_jwt", method)
	}
	// attestsClient is true under the override. The authorization code path
	// therefore also checks the detected method.
	if !w.attestsClient(meta) {
		t.Error("override should make attestsClient true even for private_key_jwt metadata")
	}
}

// An advertised attestation method wins over unauthenticated access. The issuer
// decides whether it trusts the attester.
func TestDetectTokenEndpointAuthMethod(t *testing.T) {
	for _, tc := range []struct {
		name    string
		methods []any
		want    string
		attests bool
	}{
		{"attestation alongside an unauthenticated client", []any{"none", "attest_jwt_client_auth"}, "attest_jwt_client_auth", true},
		{"order does not decide it", []any{"attest_jwt_client_auth", "none"}, "attest_jwt_client_auth", true},
		{"attestation alongside the unregistered spelling", []any{"public", "attest_jwt_client_auth"}, "attest_jwt_client_auth", true},
		{"attestation on its own", []any{"attest_jwt_client_auth"}, "attest_jwt_client_auth", true},
		{"nothing but an unauthenticated client", []any{"none"}, "none", false},
		{"nothing but the unregistered spelling", []any{"public"}, "public", false},
		{"private_key_jwt beats an unauthenticated client", []any{"none", "private_key_jwt"}, "private_key_jwt", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := generateTestWallet(t)
			meta := map[string]any{"token_endpoint_auth_methods_supported": tc.methods}
			if got := detectTokenEndpointAuthMethod(meta); got != tc.want {
				t.Errorf("detected %q, want %q", got, tc.want)
			}
			if got := w.attestsClient(meta); got != tc.attests {
				t.Errorf("attestsClient = %v, want %v", got, tc.attests)
			}
		})
	}
}
