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
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
)

// strictPreAuthIssuer serves a pre-authorized_code issuer that can require
// DPoP-bound tokens, client attestation and key attestation in the proof.
// Issuer metadata can ask for all three at once. A wallet that omits one gets
// the same error as from a real issuer.
// proofTypes is "jwt", "attestation" or "both". With "both" the jwt type
// requires a key attestation and the attestation type states no requirement.
func strictPreAuthIssuer(t *testing.T, w *Wallet, requireDPoP, requireClientAttestation, requireKeyAttestation bool, proofTypes string) (*httptest.Server, string) {
	t.Helper()

	credRaw := generateTestCredential(t, w)
	var serverURL string

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		writeErr := func(status int, code, desc string) {
			rw.WriteHeader(status)
			json.NewEncoder(rw).Encode(map[string]string{"error": code, "error_description": desc})
		}

		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			proof := map[string]any{"proof_signing_alg_values_supported": []any{"ES256"}}
			if requireKeyAttestation {
				proof["key_attestations_required"] = map[string]any{
					"key_storage":         []any{"iso_18045_high"},
					"user_authentication": []any{"iso_18045_high"},
				}
			}
			offered := map[string]any{"jwt": proof}
			switch proofTypes {
			case "attestation":
				offered = map[string]any{"attestation": proof}
			case "both":
				offered["attestation"] = map[string]any{"proof_signing_alg_values_supported": []any{"ES256"}}
			}
			json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":         serverURL,
				"credential_endpoint":       serverURL + "/credential",
				"token_endpoint":            serverURL + "/token",
				"authorization_servers":     []any{serverURL},
				"batch_credential_issuance": map[string]any{"batch_size": float64(10)},
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{
						"format":                "dc+sd-jwt",
						"vct":                   "urn:test:credential",
						"scope":                 "test-config",
						"proof_types_supported": offered,
					},
				},
			})

		case strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server"):
			meta := map[string]any{
				"issuer":                                serverURL,
				"token_endpoint":                        serverURL + "/token",
				"authorization_endpoint":                serverURL + "/authorize",
				"pushed_authorization_request_endpoint": serverURL + "/par",
				"require_pushed_authorization_requests": true,
				"code_challenge_methods_supported":      []any{"S256"},
			}
			if requireDPoP {
				meta["dpop_signing_alg_values_supported"] = []any{"ES256"}
			}
			if requireClientAttestation {
				meta["token_endpoint_auth_methods_supported"] = []any{"attest_jwt_client_auth"}
			}
			json.NewEncoder(rw).Encode(meta)

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/token"):
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			if form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:pre-authorized_code" {
				writeErr(http.StatusBadRequest, "unsupported_grant_type", form.Get("grant_type"))
				return
			}
			if requireDPoP && r.Header.Get("DPoP") == "" {
				writeErr(http.StatusBadRequest, "invalid_dpop_proof", "DPoP proof is required")
				return
			}
			if requireClientAttestation {
				if r.Header.Get("OAuth-Client-Attestation") == "" || r.Header.Get("OAuth-Client-Attestation-PoP") == "" {
					writeErr(http.StatusBadRequest, "invalid_client", "wallet attestation is required")
					return
				}
			}
			tokenType := "Bearer"
			if requireDPoP {
				tokenType = "DPoP"
			}
			json.NewEncoder(rw).Encode(map[string]any{
				"access_token": "test-access-token",
				"token_type":   tokenType,
				"c_nonce":      "test-c-nonce",
			})

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/credential"):
			wantAuth := "Bearer test-access-token"
			if requireDPoP {
				wantAuth = "DPoP test-access-token"
				if r.Header.Get("DPoP") == "" {
					writeErr(http.StatusUnauthorized, "invalid_token", "DPoP proof is required")
					return
				}
			}
			if r.Header.Get("Authorization") != wantAuth {
				writeErr(http.StatusUnauthorized, "invalid_token", "expected "+wantAuth)
				return
			}
			if requireKeyAttestation {
				body, _ := io.ReadAll(r.Body)
				var reqBody map[string]any
				json.Unmarshal(body, &reqBody)
				proofs, _ := reqBody["proofs"].(map[string]any)
				// The batch arrives as one proof. Its key attestation lists
				// every batch key with the holder key first, and the issuer
				// issues one credential per attested key. Under the attestation
				// proof type the proof is the attestation itself (Appendix F.3).
				// Otherwise it is a holder-key jwt that carries it (F.1).
				wantType := "attestation"
				if proofTypes == "jwt" {
					wantType = "jwt"
				}
				values, _ := proofs[wantType].([]any)
				if len(proofs) != 1 || len(values) != 1 {
					writeErr(http.StatusBadRequest, "invalid_proof", fmt.Sprintf("got proofs %v, want one %s proof", reqBody["proofs"], wantType))
					return
				}
				attestation, _ := values[0].(string)
				if wantType == "jwt" {
					header := decodeJWTPart(t, attestation, 0)
					if jwk, _ := header["jwk"].(map[string]any); jwk["x"] != mock.SigningJWKMap(&w.HolderKey.PublicKey)["x"] {
						t.Error("the attested proof is not signed by the holder key")
					}
					attestation, _ = header["key_attestation"].(string)
				}
				if attestation == "" {
					writeErr(http.StatusBadRequest, "invalid_proof", "key attestation is required")
					return
				}
				attHeader := decodeJWTPart(t, attestation, 0)
				if attHeader["typ"] != "key-attestation+jwt" {
					t.Errorf("key attestation typ = %v, want key-attestation+jwt", attHeader["typ"])
				}
				attPayload := decodeJWTPart(t, attestation, 1)
				if attPayload["nonce"] != "test-c-nonce" {
					t.Errorf("key attestation nonce = %v, want test-c-nonce", attPayload["nonce"])
				}
				attested, _ := attPayload["attested_keys"].([]any)
				if len(attested) != MaxBatchSize {
					t.Errorf("key attestation attests %d keys, want the batch of %d", len(attested), MaxBatchSize)
				}
				if first, _ := attested[0].(map[string]any); first["x"] != mock.SigningJWKMap(&w.HolderKey.PublicKey)["x"] {
					t.Error("the key attestation does not name the holder key first")
				}
				for _, claim := range []string{"key_storage", "user_authentication"} {
					values, _ := attPayload[claim].([]any)
					if len(values) != 1 || values[0] != "iso_18045_high" {
						t.Errorf("key attestation %s = %v, want the required [iso_18045_high]", claim, attPayload[claim])
					}
				}
				credentials := make([]any, 0, len(attested))
				for _, key := range attested {
					jwk, _ := key.(map[string]any)
					pub, _, err := ecdsaPublicKeyFromJWK(ValidationModeDebug, jwk["x"].(string), jwk["y"].(string))
					if err != nil {
						t.Fatalf("attested key: %v", err)
					}
					credentials = append(credentials, map[string]any{"credential": sdJWTBoundTo(t, w, pub)})
				}
				json.NewEncoder(rw).Encode(map[string]any{"credentials": credentials})
				return
			}
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
	return srv, "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))
}

// Pre-authorized issuance sends DPoP, client attestation and key attestation
// when the issuer requires them.
func TestProcessCredentialOffer_PreAuthHonorsIssuerProtections(t *testing.T) {
	for _, tc := range []struct {
		name                                               string
		requireDPoP, requireClientAttest, requireKeyAttest bool
		proofTypes                                         string
	}{
		{"all", true, true, true, "jwt"},
		{"attestation proof type", true, true, true, "attestation"},
		{"both proof types offered", true, true, true, "both"},
		{"dpop only", true, false, false, "jwt"},
		{"client attestation only", false, true, false, "jwt"},
		{"key attestation only", false, false, true, "jwt"},
		{"none", false, false, false, "jwt"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := generateTestWallet(t)
			srv, offerURI := strictPreAuthIssuer(t, w, tc.requireDPoP, tc.requireClientAttest, tc.requireKeyAttest, tc.proofTypes)
			defer srv.Close()

			result, err := w.ProcessCredentialOffer(offerURI)
			if err != nil {
				t.Fatalf("ProcessCredentialOffer: %v", err)
			}
			if result.CredentialID == "" {
				t.Error("expected a credential to be imported")
			}
			assertImportActivityMatchesStoredCredentials(t, w)
			if !tc.requireKeyAttest {
				return
			}
			creds := w.GetCredentials()
			if len(creds) != MaxBatchSize {
				t.Fatalf("stored %d copies, want the batch of %d", len(creds), MaxBatchSize)
			}
			for i := range creds {
				if creds[i].BatchGroup == "" || creds[i].BatchGroup != creds[0].BatchGroup {
					t.Fatalf("copy %s is not in the batch group", creds[i].ID)
				}
			}
		})
	}
}

// TestIssuanceProofKeys_KeyAttestationCoversBatch covers batch issuance with
// key attestation. The batch keeps one key per copy and the key attestation
// covers all of them (Appendix F.1, HAIP §4.5.1).
func TestIssuanceProofKeys_KeyAttestationCoversBatch(t *testing.T) {
	w := generateTestWallet(t)
	metadata := map[string]any{
		"batch_credential_issuance": map[string]any{"batch_size": float64(10)},
		"credential_configurations_supported": map[string]any{
			"attested": map[string]any{
				"proof_types_supported": map[string]any{
					"jwt": map[string]any{"key_attestations_required": map[string]any{}},
				},
			},
		},
	}

	keys, err := issuanceProofKeys(w.HolderKey, metadata)
	if err != nil {
		t.Fatalf("issuanceProofKeys: %v", err)
	}
	if len(keys) != MaxBatchSize {
		t.Fatalf("batch produced %d proof keys, want %d", len(keys), MaxBatchSize)
	}

	attestation, err := createKeyAttestation(w, metadata, "attested", "nonce-1", keys)
	if err != nil {
		t.Fatalf("createKeyAttestation: %v", err)
	}
	payload := decodeJWTPart(t, attestation, 1)
	attested, _ := payload["attested_keys"].([]any)
	if len(attested) != len(keys) {
		t.Fatalf("key attestation lists %d keys, want every proof key (%d)", len(attested), len(keys))
	}
	for i, key := range keys {
		if got, _ := attested[i].(map[string]any); got["x"] != mock.SigningJWKMap(&key.PublicKey)["x"] {
			t.Errorf("attested key %d is not proof key %d", i, i)
		}
	}
}

// TestCredentialProofType covers the choice between the proof types of
// Appendix F.1 and F.3. The wallet uses attestation when it is the only type
// offered or when the jwt type needs a key attestation anyway. Otherwise it
// uses jwt.
func TestCredentialProofType(t *testing.T) {
	metadataFor := func(proofTypes map[string]any) map[string]any {
		return map[string]any{"credential_configurations_supported": map[string]any{
			"cfg": map[string]any{"proof_types_supported": proofTypes},
		}}
	}
	for _, tc := range []struct {
		name       string
		proofTypes map[string]any
		want       string
	}{
		{"jwt only", map[string]any{"jwt": map[string]any{}}, "jwt"},
		{"attestation only", map[string]any{"attestation": map[string]any{}}, "attestation"},
		{"both, no key attestation", map[string]any{"jwt": map[string]any{}, "attestation": map[string]any{}}, "jwt"},
		{"both, key attestation required", map[string]any{"jwt": map[string]any{"key_attestations_required": map[string]any{}}, "attestation": map[string]any{}}, "attestation"},
		{"nothing offered", nil, "jwt"},
	} {
		if got := credentialProofType(metadataFor(tc.proofTypes), "cfg"); got != tc.want {
			t.Errorf("%s: proof type %q, want %q", tc.name, got, tc.want)
		}
	}
	if _, required := credentialKeyAttestationRequirement(metadataFor(map[string]any{"attestation": map[string]any{}}), "cfg"); !required {
		t.Error("the attestation proof type must carry a key attestation")
	}
}

// The key attestation claims the protection level that KeyAttestationLevel
// selects. The activity log warns when that claim cannot be backed or omits a
// required level.
func TestKeyAttestationClaims(t *testing.T) {
	metadataRequiring := func(requirement map[string]any) map[string]any {
		return map[string]any{"credential_configurations_supported": map[string]any{
			"cfg": map[string]any{"proof_types_supported": map[string]any{
				"jwt": map[string]any{"key_attestations_required": requirement},
			}},
		}}
	}
	requiring := metadataRequiring(map[string]any{"key_storage": []any{"iso_18045_high"}})
	requiringNothing := metadataRequiring(map[string]any{})
	attest := func(t *testing.T, metadata map[string]any, level string) (map[string]any, *Wallet) {
		t.Helper()
		w := generateTestWallet(t)
		w.KeyAttestationLevel = level
		attestation, err := createKeyAttestation(w, metadata, "cfg", "nonce", nil)
		if err != nil {
			t.Fatalf("createKeyAttestation(%q): %v", level, err)
		}
		return decodeJWTPart(t, attestation, 1), w
	}

	payload, w := attest(t, requiring, "")
	if got, _ := payload["key_storage"].([]any); len(got) != 1 || got[0] != "iso_18045_high" || payload["user_authentication"] != nil {
		t.Errorf("default: key_storage = %v, user_authentication = %v, want the required key_storage only", payload["key_storage"], payload["user_authentication"])
	}
	if !hasWarningContaining(w, "can't back") {
		t.Error("default: want the claim marked in the activity log")
	}

	payload, w = attest(t, requiring, "none")
	if payload["key_storage"] != nil || payload["user_authentication"] != nil {
		t.Errorf("none: attestation still claims %v / %v", payload["key_storage"], payload["user_authentication"])
	}
	if !hasWarningContaining(w, "omits") {
		t.Error("none: want the omitted requirement marked in the activity log")
	}

	payload, w = attest(t, requiring, "iso_18045_moderate")
	for _, claim := range keyAttestationClaimNames {
		if got, _ := payload[claim].([]any); len(got) != 1 || got[0] != "iso_18045_moderate" {
			t.Errorf("level: %s = %v, want [iso_18045_moderate]", claim, payload[claim])
		}
	}
	if !hasWarningContaining(w, "can't back") {
		t.Error("level: want the claim marked in the activity log")
	}

	for _, level := range []string{"", "none"} {
		payload, w := attest(t, requiringNothing, level)
		if payload["key_storage"] != nil || hasWarningContaining(w, "key attestation") {
			t.Errorf("level %q without a requirement: claims %v, want no claim and no note", level, payload["key_storage"])
		}
	}

	if _, err := ParseKeyAttestationLevel("None"); err == nil {
		t.Error("ParseKeyAttestationLevel accepted a value Appendix D.2 does not define")
	}
}

// TestProofSigningAlgMustBeListed covers Appendix F.1 and F.3. The
// configuration must list the proof's alg. The wallet signs ES256 only. Strict
// mode refuses a configuration without it and debug mode warns. The warning
// cites HAIP §7 when the profile is on.
func TestProofSigningAlgMustBeListed(t *testing.T) {
	metadata := map[string]any{"credential_configurations_supported": map[string]any{
		"cfg": map[string]any{"proof_types_supported": map[string]any{
			"jwt": map[string]any{"proof_signing_alg_values_supported": []any{"ES384"}},
		}},
	}}
	attempt := credentialRequestAttempt{metadata: metadata, configID: "cfg", issuer: "https://issuer.example"}

	w := generateTestWallet(t)
	w.ValidationMode = ValidationModeStrict
	attempt.proofKeys = []*ecdsa.PrivateKey{w.HolderKey}
	if _, err := w.buildCredentialProofs(attempt, "nonce"); err == nil || !strings.Contains(err.Error(), "ES256") || strings.Contains(err.Error(), "HAIP") {
		t.Fatalf("strict mode without HAIP: err = %v, want the missing ES256 named without a HAIP citation", err)
	}
	w.RequireHAIP = true
	if _, err := w.buildCredentialProofs(attempt, "nonce"); err == nil || !strings.Contains(err.Error(), "HAIP 1.0 §7") {
		t.Fatalf("strict mode with HAIP: err = %v, want HAIP §7 named", err)
	}

	w.ValidationMode = ValidationModeDebug
	proofs, err := w.buildCredentialProofs(attempt, "nonce")
	if err != nil || len(proofs.Values) != 1 {
		t.Fatalf("debug mode: proofs = %v, err = %v, want the proof sent anyway", proofs, err)
	}
	if entries := w.GetLog(); len(entries) == 0 || !strings.Contains(entries[len(entries)-1].Detail, "ES256") {
		t.Fatalf("debug mode: want a warning naming the missing ES256, got %v", entries)
	}
}

// TestAccessTokenScheme covers the Authorization scheme for a token
// response. RFC 9449 §5 marks a DPoP-bound token with token_type "DPoP".
func TestAccessTokenScheme(t *testing.T) {
	for _, tc := range []struct {
		name     string
		resp     map[string]any
		sentDPoP bool
		want     string
	}{
		{"dpop token", map[string]any{"token_type": "DPoP"}, true, "DPoP"},
		{"dpop token lowercase", map[string]any{"token_type": "dpop"}, true, "DPoP"},
		{"bearer token", map[string]any{"token_type": "Bearer"}, false, "Bearer"},
		{"server ignored the proof", map[string]any{"token_type": "Bearer"}, true, "Bearer"},
		{"omitted after a proof", map[string]any{}, true, "DPoP"},
		{"omitted without a proof", map[string]any{}, false, "Bearer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := accessTokenScheme(tc.resp, tc.sentDPoP); got != tc.want {
				t.Errorf("accessTokenScheme = %q, want %q", got, tc.want)
			}
		})
	}
}
