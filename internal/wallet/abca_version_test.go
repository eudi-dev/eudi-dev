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
	"slices"
	"sort"
	"strings"
	"testing"
)

// abcaIssuerConfig sets the issuer metadata and authentication challenges for
// one test.
type abcaIssuerConfig struct {
	authMethods []string
	// popMethods is client_attestation_pop_methods_supported. Nil omits the
	// parameter, as a draft-07 or draft-08 server does.
	popMethods []string
	dpop       bool
	// requireCombined refuses a token request that carries a dedicated PoP
	// header or lacks the attestation. A dpop_combined-only server does this.
	requireCombined    bool
	requireAttestation bool
	// challengeValue makes the token endpoint demand a server-provided
	// challenge. The first request gets use_attestation_challenge with this
	// value in the OAuth-Client-Attestation-Challenge header. A dedicated PoP
	// must carry it in its challenge claim (draft-07 §9, draft-08 §8, draft-10
	// §7.2), a combined DPoP proof in its nonce claim (draft-10 §7.3 step 5).
	challengeValue string
	// dpopNonceValue adds this DPoP-Nonce header to the challenge refusal.
	dpopNonceValue string
	// refuseFirstAsStale answers the first token request with
	// use_fresh_attestation. A server sends that error when it considers the
	// attestation too old (§7.4).
	refuseFirstAsStale bool
}

type abcaCapture struct {
	tokenRequests int
	attestations  []string
	pops          []string
	dpops         []string
}

func abcaTestIssuer(t *testing.T, w *Wallet, cfg abcaIssuerConfig) (*httptest.Server, string, *abcaCapture) {
	t.Helper()

	credRaw := generateTestCredential(t, w)
	var serverURL string
	capture := &abcaCapture{}

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
			meta := map[string]any{
				"issuer":                                serverURL,
				"token_endpoint":                        serverURL + "/token",
				"token_endpoint_auth_methods_supported": cfg.authMethods,
			}
			if cfg.popMethods != nil {
				meta["client_attestation_pop_methods_supported"] = cfg.popMethods
			}
			if cfg.dpop {
				meta["dpop_signing_alg_values_supported"] = []any{"ES256"}
			}
			json.NewEncoder(rw).Encode(meta)

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/token"):
			capture.tokenRequests++
			attestation := r.Header.Get("OAuth-Client-Attestation")
			pop := r.Header.Get("OAuth-Client-Attestation-PoP")
			dpop := r.Header.Get("DPoP")
			if attestation != "" {
				capture.attestations = append(capture.attestations, attestation)
			}
			if pop != "" {
				capture.pops = append(capture.pops, pop)
			}
			if dpop != "" {
				capture.dpops = append(capture.dpops, dpop)
			}
			refuse := func(code, description string) {
				rw.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(rw).Encode(map[string]string{"error": code, "error_description": description})
			}
			if cfg.requireAttestation && attestation == "" {
				refuse("invalid_client", "client attestation is required")
				return
			}
			if cfg.requireCombined {
				if pop != "" {
					refuse("invalid_client", "this server takes only dpop_combined proofs, not a dedicated PoP JWT")
					return
				}
				if dpop == "" {
					refuse("invalid_client", "dpop_combined needs a DPoP proof")
					return
				}
			}
			if cfg.refuseFirstAsStale && capture.tokenRequests == 1 {
				refuse("use_fresh_attestation", "the client attestation is not fresh enough")
				return
			}
			if cfg.challengeValue != "" {
				challenge := ""
				if pop != "" {
					challenge, _ = decodeJWTPart(t, pop, 1)["challenge"].(string)
				} else if dpop != "" {
					challenge, _ = decodeJWTPart(t, dpop, 1)["nonce"].(string)
				}
				if challenge != cfg.challengeValue {
					rw.Header().Set("OAuth-Client-Attestation-Challenge", cfg.challengeValue)
					if cfg.dpopNonceValue != "" {
						rw.Header().Set("DPoP-Nonce", cfg.dpopNonceValue)
					}
					rw.WriteHeader(http.StatusUnauthorized)
					json.NewEncoder(rw).Encode(map[string]string{"error": "use_attestation_challenge"})
					return
				}
			}
			tokenType := "Bearer"
			if dpop != "" {
				tokenType = "DPoP"
			}
			json.NewEncoder(rw).Encode(map[string]any{
				"access_token": "test-access-token", "token_type": tokenType, "c_nonce": "test-c-nonce",
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
	return srv, "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON)), capture
}

func runABCAOffer(t *testing.T, w *Wallet, cfg abcaIssuerConfig) (*abcaCapture, error) {
	t.Helper()
	srv, offerURI, capture := abcaTestIssuer(t, w, cfg)
	t.Cleanup(srv.Close)

	_, err := w.ProcessCredentialOffer(offerURI)
	return capture, err
}

// TestAttestationShapeIsDraftUnion checks the emitted shape for each
// OpenID4VCI version. The attestation and its PoP carry the union of the
// claims of the supported drafts. That union is the draft-07 shape. Draft-07
// §5.1/§5.2 require iss in both JWTs and define nbf. Every draft allows extra
// claims in these JWTs (§5.1 and §5.2 rule 1), so one shape verifies under all
// of them.
func TestAttestationShapeIsDraftUnion(t *testing.T) {
	for _, version := range []VCIVersion{VCIVersion10, VCIVersion11} {
		t.Run(string(version), func(t *testing.T) {
			w := generateTestWallet(t)
			w.VCIVersion = version
			w.IssuerURL = "https://wallet.example"
			w.VCIClientID = "test-wallet-client"

			capture, err := runABCAOffer(t, w, abcaIssuerConfig{
				authMethods:        []string{"attest_jwt_client_auth"},
				requireAttestation: true,
			})
			if err != nil {
				t.Fatalf("ProcessCredentialOffer: %v", err)
			}
			if len(capture.attestations) != 1 || len(capture.pops) != 1 {
				t.Fatalf("issuer saw %d attestations and %d PoPs, want 1 and 1", len(capture.attestations), len(capture.pops))
			}

			attestation := decodeJWTPart(t, capture.attestations[0], 1)
			pop := decodeJWTPart(t, capture.pops[0], 1)

			if attestation["iss"] != "https://wallet.example" {
				t.Errorf("attestation iss = %v, want the wallet's issuer URL", attestation["iss"])
			}
			if attestation["sub"] != "test-wallet-client" {
				t.Errorf("attestation sub = %v, want the client_id", attestation["sub"])
			}
			// Draft-07 §5.2 rule 4: the PoP iss is the client of the attestation.
			if pop["iss"] != attestation["sub"] {
				t.Errorf("PoP iss = %v, want the attestation's sub %v", pop["iss"], attestation["sub"])
			}

			// The wallet instance claims of CIR (EU) 2024/2979 Annex Ib
			// C_WIA-1 and C_WIA-2 are extra claims under every draft.
			wantAttestation := []string{"client_status", "cnf", "exp", "iat", "iss", "nbf", "sub", "wallet_link", "wallet_name", "wallet_solution_certification_information", "wallet_version"}
			wantPoP := []string{"aud", "exp", "iat", "iss", "jti", "nbf"}
			if got := sortedKeys(attestation); !slices.Equal(got, wantAttestation) {
				t.Errorf("attestation claims = %v, want exactly %v", got, wantAttestation)
			}
			if got := sortedKeys(pop); !slices.Equal(got, wantPoP) {
				t.Errorf("PoP claims = %v, want exactly %v", got, wantPoP)
			}
		})
	}
}

// A server that offers only draft-10 attest_jwt_client_auth_dpop (§5.2) gets
// the attestation and a DPoP proof without a dedicated PoP. The wallet warns
// when the configured draft predates that method.
func TestCombinedModeAgainstDPoPOnlyServer(t *testing.T) {
	w := generateTestWallet(t)
	w.VCIVersion = VCIVersion11
	w.VCIClientID = "test-wallet-client"

	capture, err := runABCAOffer(t, w, abcaIssuerConfig{
		authMethods:        []string{"attest_jwt_client_auth_dpop"},
		dpop:               true,
		requireAttestation: true,
		requireCombined:    true,
	})
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
	if len(capture.attestations) == 0 {
		t.Error("issuer saw no client attestation")
	}
	if len(capture.pops) != 0 {
		t.Errorf("issuer saw %d dedicated PoP JWTs, want none in combined mode", len(capture.pops))
	}
	if len(capture.dpops) == 0 {
		t.Error("issuer saw no DPoP proof, which is the possession proof in combined mode")
	}
	if !hasWarningContaining(w, "draft-10") {
		t.Error("expected a warning that dpop_combined is a draft-10 mechanism beyond the configured draft")
	}
}

// TestPopMethodsMetadataSelectsCombined covers the draft-10
// client_attestation_pop_methods_supported parameter. A server that lists only
// dpop_combined takes the DPoP proof as the possession proof, so the wallet
// sends no dedicated PoP JWT.
func TestPopMethodsMetadataSelectsCombined(t *testing.T) {
	w := generateTestWallet(t)
	w.VCIVersion = VCIVersion11
	w.VCIClientID = "test-wallet-client"

	capture, err := runABCAOffer(t, w, abcaIssuerConfig{
		authMethods:        []string{"attest_jwt_client_auth"},
		popMethods:         []string{"dpop_combined"},
		dpop:               true,
		requireAttestation: true,
		requireCombined:    true,
	})
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
	if len(capture.attestations) == 0 {
		t.Error("issuer saw no client attestation")
	}
	if len(capture.pops) != 0 {
		t.Errorf("issuer saw %d dedicated PoP JWTs, want none when the server accepts only dpop_combined", len(capture.pops))
	}
}

// After use_attestation_challenge the next PoP carries the
// OAuth-Client-Attestation-Challenge value from the response in its challenge
// claim. Draft-07 §8.1, draft-08 §7.1 and draft-10 §6.2 define the header, and
// each draft's PoP checks the challenge claim. OpenID4VCI 1.0 pins draft-07 and
// 1.1 pins draft-08.
func TestUseAttestationChallengeRetry(t *testing.T) {
	for _, version := range []VCIVersion{VCIVersion10, VCIVersion11} {
		t.Run(string(version), func(t *testing.T) {
			w := generateTestWallet(t)
			w.VCIVersion = version
			w.VCIClientID = "test-wallet-client"

			capture, err := runABCAOffer(t, w, abcaIssuerConfig{
				authMethods:        []string{"attest_jwt_client_auth"},
				requireAttestation: true,
				challengeValue:     "server-challenge-1",
			})
			if err != nil {
				t.Fatalf("ProcessCredentialOffer: %v", err)
			}
			if capture.tokenRequests != 2 {
				t.Fatalf("issuer saw %d token requests, want the refused first and the retried second", capture.tokenRequests)
			}
			if len(capture.pops) == 0 {
				t.Fatal("issuer saw no PoP JWTs")
			}
			last := decodeJWTPart(t, capture.pops[len(capture.pops)-1], 1)
			if last["challenge"] != "server-challenge-1" {
				t.Errorf("retried PoP challenge = %v, want the served challenge", last["challenge"])
			}
		})
	}
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// After use_fresh_attestation the wallet retries once with a fresh attestation
// (§7.4).
func TestUseFreshAttestationRetry(t *testing.T) {
	w := generateTestWallet(t)
	w.VCIVersion = VCIVersion11
	w.VCIClientID = "test-wallet-client"

	capture, err := runABCAOffer(t, w, abcaIssuerConfig{
		authMethods:        []string{"attest_jwt_client_auth"},
		requireAttestation: true,
		refuseFirstAsStale: true,
	})
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
	if capture.tokenRequests != 2 {
		t.Fatalf("issuer saw %d token requests, want the refused first and the retried second", capture.tokenRequests)
	}
	if len(capture.attestations) != 2 || capture.attestations[0] == capture.attestations[1] {
		t.Errorf("retried request must carry a newly minted attestation, got %d attestations", len(capture.attestations))
	}
}

// A challenge from a response header is used once. Later requests fetch a
// challenge from the challenge endpoint.
func TestClientAttestorChallengeUse(t *testing.T) {
	w := generateTestWallet(t)
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		json.NewEncoder(rw).Encode(map[string]any{"attestation_challenge": "endpoint-challenge"})
	}))
	defer srv.Close()

	authenticator := w.clientAuthenticatorFor(&ClientAuthentication{
		Method: ClientAuthAttestation, Audience: "https://as.example",
		ChallengeEndpoint: srv.URL,
	}, "c", w.HolderKey)
	header := http.Header{}
	header.Set("OAuth-Client-Attestation-Challenge", "served-challenge")
	authenticator.observe(header)

	for _, want := range []string{"served-challenge", "endpoint-challenge"} {
		headers, err := authenticator.headers()
		if err != nil {
			t.Fatalf("headers: %v", err)
		}
		pop := decodeJWTPart(t, headers["OAuth-Client-Attestation-PoP"], 1)
		if pop["challenge"] != want {
			t.Errorf("PoP challenge = %v, want %q", pop["challenge"], want)
		}
	}
}

// attest_jwt_client_auth_dpop requires a DPoP proof even when metadata omits DPoP
// algorithms.
func TestCombinedModeWithoutDPoPMetadata(t *testing.T) {
	w := generateTestWallet(t)
	w.VCIVersion = VCIVersion11
	w.VCIClientID = "test-wallet-client"

	capture, err := runABCAOffer(t, w, abcaIssuerConfig{
		authMethods:        []string{"attest_jwt_client_auth_dpop"},
		requireAttestation: true,
		requireCombined:    true,
	})
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
	if len(capture.dpops) == 0 {
		t.Error("issuer saw no DPoP proof, which the combined method makes the possession proof")
	}
	if len(capture.pops) != 0 {
		t.Errorf("issuer saw %d dedicated PoP JWTs, want none in combined mode", len(capture.pops))
	}
}

// The wallet prefers the dedicated PoP when both methods are offered, since it
// works with or without DPoP.
func TestDedicatedPoPPreferredWhenBothMethodsOffered(t *testing.T) {
	w := generateTestWallet(t)
	w.VCIVersion = VCIVersion11
	w.VCIClientID = "test-wallet-client"

	capture, err := runABCAOffer(t, w, abcaIssuerConfig{
		authMethods:        []string{"attest_jwt_client_auth_dpop", "attest_jwt_client_auth"},
		dpop:               true,
		requireAttestation: true,
	})
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
	if len(capture.pops) != 1 {
		t.Errorf("issuer saw %d dedicated PoP JWTs, want the dedicated method used", len(capture.pops))
	}
}

// A refresh keeps the ABCA draft chosen at issuance, even when the wallet
// settings change later.
func TestStoredABCADraftDrivesEmission(t *testing.T) {
	w := generateTestWallet(t)
	w.VCIVersion = VCIVersion11
	w.IssuerURL = "https://wallet.example"

	headers, err := createClientAttestationHeaders(w, &ClientAuthentication{
		Method: ClientAuthAttestation, Audience: "https://as.example", ABCADraft: 7,
	}, "c", "", w.HolderKey)
	if err != nil {
		t.Fatalf("createClientAttestationHeaders: %v", err)
	}
	attestation := decodeJWTPart(t, headers["OAuth-Client-Attestation"], 1)
	pop := decodeJWTPart(t, headers["OAuth-Client-Attestation-PoP"], 1)
	if attestation["iss"] != "https://wallet.example" || pop["iss"] != "c" {
		t.Errorf("stored draft-07 record must emit the draft-07 shape, got attestation iss %v and PoP iss %v", attestation["iss"], pop["iss"])
	}
}

// In combined mode the retried DPoP proof carries the returned challenge in
// its nonce claim (draft-10 §7.3 step 5).
func TestCombinedModeChallengeInDPoPNonce(t *testing.T) {
	w := generateTestWallet(t)
	w.VCIVersion = VCIVersion11
	w.VCIClientID = "test-wallet-client"

	capture, err := runABCAOffer(t, w, abcaIssuerConfig{
		authMethods:        []string{"attest_jwt_client_auth_dpop"},
		dpop:               true,
		requireAttestation: true,
		requireCombined:    true,
		challengeValue:     "combined-challenge-1",
	})
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
	if capture.tokenRequests != 2 {
		t.Fatalf("issuer saw %d token requests, want the refused first and the retried second", capture.tokenRequests)
	}
	last := decodeJWTPart(t, capture.dpops[len(capture.dpops)-1], 1)
	if last["nonce"] != "combined-challenge-1" {
		t.Errorf("retried DPoP proof nonce = %v, want the served challenge", last["nonce"])
	}
}

// A pending attestation challenge takes the nonce claim of a combined DPoP
// proof over a DPoP-Nonce from the same response.
func TestCombinedModeChallengeWinsOverDPoPNonce(t *testing.T) {
	w := generateTestWallet(t)
	w.VCIVersion = VCIVersion11
	w.VCIClientID = "test-wallet-client"

	capture, err := runABCAOffer(t, w, abcaIssuerConfig{
		authMethods:        []string{"attest_jwt_client_auth_dpop"},
		dpop:               true,
		requireAttestation: true,
		requireCombined:    true,
		challengeValue:     "combined-challenge-2",
		dpopNonceValue:     "dpop-nonce-2",
	})
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
	last := decodeJWTPart(t, capture.dpops[len(capture.dpops)-1], 1)
	if last["nonce"] != "combined-challenge-2" {
		t.Errorf("retried DPoP proof nonce = %v, want the attestation challenge", last["nonce"])
	}
}
