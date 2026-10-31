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
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
)

type mockIssuerOpts struct {
	tokenCNonce   string
	nonceEndpoint bool
	// additionalResponses publishes further configurations, each with its
	// answer. An answer with an error comes with status 400.
	additionalResponses map[string]map[string]any
	// nonceOnlyGET makes the nonce endpoint answer the POST that §7.1 requires
	// with 405 and serve the c_nonce over GET.
	nonceOnlyGET bool
	// captureNotification receives the wallet's Notification Request, so a test
	// can check it against §11.1.
	captureNotification func(*http.Request, []byte)
	// refusesNotification publishes a Notification Endpoint that answers every
	// call with 404.
	refusesNotification       bool
	tokenAuthorizationDetails []any
	// credentialResponse is the JSON answer of the credential endpoint. When
	// nil, the endpoint returns a single SD-JWT credential.
	credentialResponse       map[string]any
	credentialConfigFormat   string
	inspectCredentialRequest func(*testing.T, map[string]any)
	offerViaURI              bool
	// oneShotOfferURI makes the credential_offer_uri succeed once and then
	// return HTTP 400.
	oneShotOfferURI bool
	// secondOffer is served by the credential_offer_uri from the second read
	// on.
	secondOffer            map[string]any
	onOfferFetch           func()
	inspectMetadataRequest func(*testing.T, *http.Request)
	inspectNonceRequest    func(*testing.T, *http.Request)
	// rejectFirstNonce answers the first credential request with the
	// invalid_nonce error of §8.3.1.2.
	rejectFirstNonce bool
	// omitAccessToken drops access_token from the token response. RFC 6749
	// §5.1 requires it.
	omitAccessToken bool
	// omitTokenType drops token_type from the token response. RFC 6749 §5.1
	// also requires it.
	omitTokenType bool
}

func setupMockIssuer(t *testing.T, w *Wallet, opts mockIssuerOpts) (*httptest.Server, string) {
	t.Helper()

	credRaw := generateTestCredential(t, w)

	credResp := opts.credentialResponse
	if credResp == nil {
		credResp = map[string]any{"credentials": []any{map[string]any{"credential": credRaw}}}
	}

	configFormat := opts.credentialConfigFormat
	if configFormat == "" {
		configFormat = "dc+sd-jwt"
	}

	var serverURL string
	var offerFetches int
	var credentialRequests int
	var nonces int
	var offerMu sync.Mutex

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			if opts.inspectMetadataRequest != nil {
				opts.inspectMetadataRequest(t, r)
			}
			meta := map[string]any{
				"credential_issuer":   serverURL,
				"credential_endpoint": serverURL + "/credential",
				"token_endpoint":      serverURL + "/token",
				"display": []any{
					map[string]any{"name": "Test Issuer", "locale": "en-US"},
				},
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{
						"format": configFormat,
						"vct":    "urn:test:credential",
						// §12.2.4 places display and claims inside
						// credential_metadata.
						"credential_metadata": map[string]any{
							"display": []any{
								map[string]any{"name": "Test Credential", "description": "A credential for tests"},
							},
							"claims": []any{
								map[string]any{"path": []any{"given_name"}},
								map[string]any{"path": []any{"address", "locality"}},
							},
						},
					},
				},
			}
			for id := range opts.additionalResponses {
				meta["credential_configurations_supported"].(map[string]any)[id] = map[string]any{"format": configFormat, "vct": "urn:test:credential"}
				meta["deferred_credential_endpoint"] = serverURL + "/deferred"
			}
			if opts.refusesNotification {
				meta["notification_endpoint"] = serverURL + "/notification"
			}
			if opts.nonceEndpoint {
				meta["nonce_endpoint"] = serverURL + "/nonce"
			}
			rw.Header().Set("Content-Type", "application/json")
			json.NewEncoder(rw).Encode(meta)

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/token"):
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			if form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:pre-authorized_code" {
				rw.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(rw).Encode(map[string]string{"error": "unsupported_grant_type"})
				return
			}
			resp := map[string]any{
				"access_token": "test-access-token",
				"token_type":   "Bearer",
			}
			if opts.omitAccessToken {
				delete(resp, "access_token")
			}
			if opts.omitTokenType {
				delete(resp, "token_type")
			}
			if opts.tokenCNonce != "" {
				resp["c_nonce"] = opts.tokenCNonce
			}
			if opts.tokenAuthorizationDetails != nil {
				resp["authorization_details"] = opts.tokenAuthorizationDetails
			}
			rw.Header().Set("Content-Type", "application/json")
			json.NewEncoder(rw).Encode(resp)

		case opts.nonceOnlyGET && r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/nonce"):
			rw.Header().Set("Allow", "GET")
			rw.WriteHeader(http.StatusMethodNotAllowed)

		case strings.HasSuffix(r.URL.Path, "/nonce") && (r.Method == "POST" || (opts.nonceOnlyGET && r.Method == "GET")):
			if opts.inspectNonceRequest != nil {
				opts.inspectNonceRequest(t, r)
			}
			offerMu.Lock()
			nonces++
			current := nonces
			offerMu.Unlock()
			rw.Header().Set("Content-Type", "application/json")
			json.NewEncoder(rw).Encode(map[string]any{"c_nonce": fmt.Sprintf("nonce-from-endpoint-%d", current)})

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/credential"):
			auth := r.Header.Get("Authorization")
			if auth != "Bearer test-access-token" {
				rw.WriteHeader(http.StatusUnauthorized)
				json.NewEncoder(rw).Encode(map[string]string{"error": "invalid_token"})
				return
			}
			offerMu.Lock()
			credentialRequests++
			attempt := credentialRequests
			offerMu.Unlock()
			if opts.additionalResponses != nil {
				var request struct {
					ConfigurationID string `json:"credential_configuration_id"`
				}
				_ = json.NewDecoder(r.Body).Decode(&request)
				if answer, ok := opts.additionalResponses[request.ConfigurationID]; ok {
					rw.Header().Set("Content-Type", "application/json")
					if answer["error"] != nil {
						rw.WriteHeader(http.StatusBadRequest)
					}
					json.NewEncoder(rw).Encode(answer)
					return
				}
			}
			if opts.inspectCredentialRequest != nil {
				body, _ := io.ReadAll(r.Body)
				var reqBody map[string]any
				if err := json.Unmarshal(body, &reqBody); err != nil {
					t.Fatalf("credential request JSON: %v", err)
				}
				opts.inspectCredentialRequest(t, reqBody)
			}
			rw.Header().Set("Content-Type", "application/json")
			if opts.rejectFirstNonce && attempt == 1 {
				rw.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(rw).Encode(map[string]any{
					"error":             "invalid_nonce",
					"error_description": "the challenge in the key proof is stale",
				})
				return
			}
			json.NewEncoder(rw).Encode(credResp)

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/notification"):
			if opts.captureNotification != nil {
				raw, _ := io.ReadAll(r.Body)
				opts.captureNotification(r, raw)
			}
			rw.WriteHeader(http.StatusNotFound)
			json.NewEncoder(rw).Encode(map[string]any{"message": "Could not find any entity of type \"Session\""})

		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/credential-offer"):
			if opts.onOfferFetch != nil {
				opts.onOfferFetch()
			}
			offerMu.Lock()
			offerFetches++
			currentFetch := offerFetches
			offerMu.Unlock()
			if opts.oneShotOfferURI && currentFetch > 1 {
				rw.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(rw).Encode(map[string]string{"error": "offer_expired"})
				return
			}
			if opts.secondOffer != nil && currentFetch > 1 {
				rw.Header().Set("Content-Type", "application/json")
				json.NewEncoder(rw).Encode(opts.secondOffer)
				return
			}
			offer := map[string]any{
				"credential_issuer":            serverURL,
				"credential_configuration_ids": []string{"test-config"},
				"grants": map[string]any{
					"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
						"pre-authorized_code": "test-pre-auth-code",
					},
				},
			}
			rw.Header().Set("Content-Type", "application/json")
			json.NewEncoder(rw).Encode(offer)

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
	offerURI := "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))
	if opts.offerViaURI {
		offerURI = "openid-credential-offer://?credential_offer_uri=" + url.QueryEscape(serverURL+"/credential-offer")
	}

	return srv, offerURI
}

func generateTestCredential(t *testing.T, w *Wallet) string {
	t.Helper()
	return generateTestCredentialOfType(t, w, "TestIssuedCred")
}

func generateTestCredentialOfType(t *testing.T, w *Wallet, vct string) string {
	t.Helper()
	cred, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://test-issuer.example",
		VCT:       vct,
		ExpiresIn: 24 * time.Hour,
		Claims:    map[string]any{"given_name": "Test", "family_name": "User"},
		Key:       w.IssuerKey,
		HolderKey: &w.HolderKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("generating test credential: %v", err)
	}
	return cred
}

func decodeJWTPart(t *testing.T, token string, index int) map[string]any {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected compact JWT, got %q", token)
	}
	if index < 0 || index > 1 {
		t.Fatalf("invalid JWT part index %d", index)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[index])
	if err != nil {
		t.Fatalf("decoding JWT part %d: %v", index, err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("parsing JWT part %d JSON: %v", index, err)
	}
	return out
}

func TestCreateClientAttestationHeaders(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://wallet.example"

	auth := &ClientAuthentication{Method: ClientAuthAttestation, Audience: "https://issuer.example"}
	headers, err := createClientAttestationHeaders(w, auth, "wallet-client", "challenge-123", w.HolderKey)
	if err != nil {
		t.Fatalf("createClientAttestationHeaders: %v", err)
	}

	attestationJWT := headers["OAuth-Client-Attestation"]
	popJWT := headers["OAuth-Client-Attestation-PoP"]
	if attestationJWT == "" || popJWT == "" {
		t.Fatalf("expected both attestation headers, got %v", headers)
	}

	attestationHeader := decodeJWTPart(t, attestationJWT, 0)
	attestationPayload := decodeJWTPart(t, attestationJWT, 1)
	if attestationHeader["typ"] != "oauth-client-attestation+jwt" {
		t.Fatalf("expected oauth client attestation typ, got %v", attestationHeader["typ"])
	}
	// CIR (EU) 2024/2979 Annex Ib FR-WIA-1 with ETSI TS 119 182-1 V1.2.1
	// clause 5.1.11: a JAdES baseline B signature has a signed iat header.
	if _, ok := attestationHeader["iat"].(float64); !ok {
		t.Errorf("attestation header %v, want an iat header parameter", attestationHeader)
	}
	if attestationPayload["iss"] != "https://wallet.example" {
		t.Fatalf("expected attestation iss to use wallet issuer URL, got %v", attestationPayload["iss"])
	}
	if attestationPayload["sub"] != "wallet-client" {
		t.Fatalf("expected attestation sub wallet-client, got %v", attestationPayload["sub"])
	}
	cnf, ok := attestationPayload["cnf"].(map[string]any)
	if !ok {
		t.Fatalf("expected cnf object, got %T", attestationPayload["cnf"])
	}
	jwk, ok := cnf["jwk"].(map[string]any)
	if !ok {
		t.Fatalf("expected cnf.jwk object, got %T", cnf["jwk"])
	}
	if jwk["kty"] != "EC" {
		t.Fatalf("expected holder EC JWK, got %v", jwk["kty"])
	}

	popHeader := decodeJWTPart(t, popJWT, 0)
	popPayload := decodeJWTPart(t, popJWT, 1)
	if popHeader["typ"] != "oauth-client-attestation-pop+jwt" {
		t.Fatalf("expected attestation pop typ, got %v", popHeader["typ"])
	}
	if popPayload["iss"] != "wallet-client" {
		t.Fatalf("expected pop iss wallet-client, got %v", popPayload["iss"])
	}
	if popPayload["aud"] != "https://issuer.example" {
		t.Fatalf("expected pop aud https://issuer.example, got %v", popPayload["aud"])
	}
	if popPayload["challenge"] != "challenge-123" {
		t.Fatalf("expected pop challenge challenge-123, got %v", popPayload["challenge"])
	}
}

func TestCreateClientAttestationHeaders_UniquePoPJTI(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://wallet.example"

	auth := &ClientAuthentication{Method: ClientAuthAttestation, Audience: "https://issuer.example"}
	first, err := createClientAttestationHeaders(w, auth, "wallet-client", "challenge-123", w.HolderKey)
	if err != nil {
		t.Fatalf("first createClientAttestationHeaders: %v", err)
	}
	second, err := createClientAttestationHeaders(w, auth, "wallet-client", "challenge-123", w.HolderKey)
	if err != nil {
		t.Fatalf("second createClientAttestationHeaders: %v", err)
	}

	firstPayload := decodeJWTPart(t, first["OAuth-Client-Attestation-PoP"], 1)
	secondPayload := decodeJWTPart(t, second["OAuth-Client-Attestation-PoP"], 1)
	if firstPayload["jti"] == secondPayload["jti"] {
		t.Fatalf("expected distinct PoP jti values, got %v", firstPayload["jti"])
	}
}

func TestFetchAttestationChallenge_AttestationChallengeField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("expected POST challenge request, got %s", r.Method)
		}
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(map[string]any{
			"attestation_challenge": "challenge-123",
		})
	}))
	defer srv.Close()

	challenge, err := fetchAttestationChallenge(srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("fetchAttestationChallenge: %v", err)
	}
	if challenge != "challenge-123" {
		t.Fatalf("expected challenge-123, got %q", challenge)
	}
}

func TestDoDPoPRequest_RegeneratesAttestationHeadersOnRetry(t *testing.T) {
	w := generateTestWallet(t)

	var mu sync.Mutex
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		value := r.Header.Get("OAuth-Client-Attestation-PoP")
		if value == "" {
			t.Fatal("expected OAuth-Client-Attestation-PoP header")
		}

		mu.Lock()
		seen = append(seen, value)
		attempt := len(seen)
		mu.Unlock()

		if attempt == 1 {
			rw.Header().Set("Content-Type", "application/json")
			rw.Header().Set("DPoP-Nonce", "nonce-1")
			rw.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(rw).Encode(map[string]any{"error": "use_dpop_nonce"})
			return
		}

		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(map[string]any{"ok": true})
	}))
	defer srv.Close()

	nonce := ""
	authenticator := w.clientAuthenticatorFor(&ClientAuthentication{Method: ClientAuthAttestation, Audience: srv.URL}, "wallet-client", w.HolderKey)
	_, _, err := doDPoPRequest(http.MethodPost, srv.URL, "application/json", "", []byte(`{}`), "", "", w.HolderKey, &nonce, authenticator, srv.Client(), nil)
	if err != nil {
		t.Fatalf("doDPoPRequest: %v", err)
	}
	if nonce != "nonce-1" {
		t.Fatalf("expected DPoP nonce to be updated, got %q", nonce)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(seen) != 2 {
		t.Fatalf("expected 2 requests, got %d", len(seen))
	}
	if seen[0] == seen[1] {
		t.Fatal("expected retried request to use a fresh client attestation PoP JWT")
	}
}

func TestCreateCredentialProofHeader_KeyAttestation(t *testing.T) {
	w := generateTestWallet(t)
	metadata := map[string]any{
		"credential_configurations_supported": map[string]any{
			"pid": map[string]any{
				"proof_types_supported": map[string]any{
					"jwt": map[string]any{
						"key_attestations_required": []any{"jwt"},
					},
				},
			},
		},
	}

	keyAttestationJWT, err := createKeyAttestation(w, metadata, "pid", "nonce-123", nil)
	if err != nil {
		t.Fatalf("createKeyAttestation: %v", err)
	}
	if keyAttestationJWT == "" {
		t.Fatal("expected a key attestation")
	}

	keyAttestationHeader := decodeJWTPart(t, keyAttestationJWT, 0)
	keyAttestationPayload := decodeJWTPart(t, keyAttestationJWT, 1)
	if keyAttestationHeader["typ"] != "key-attestation+jwt" {
		t.Fatalf("expected key attestation typ, got %v", keyAttestationHeader["typ"])
	}
	// FR-KA-1 with ETSI TS 119 182-1 V1.2.1 clause 5.1.11.
	if _, ok := keyAttestationHeader["iat"].(float64); !ok {
		t.Errorf("key attestation header %v, want an iat header parameter", keyAttestationHeader)
	}
	// Appendix D.1 with F.1: kid "MUST NOT be present if jwk or x5c is
	// present".
	if _, hasKID := keyAttestationHeader["kid"]; hasKID || keyAttestationHeader["x5c"] == nil {
		t.Errorf("key attestation header %v, want x5c alone to name the signing key", keyAttestationHeader)
	}
	if keyAttestationPayload["nonce"] != "nonce-123" {
		t.Fatalf("expected nonce nonce-123, got %v", keyAttestationPayload["nonce"])
	}
	attestedKeys, ok := keyAttestationPayload["attested_keys"].([]any)
	if !ok || len(attestedKeys) != 1 {
		t.Fatalf("expected one attested key, got %v", keyAttestationPayload["attested_keys"])
	}
}

func TestProcessCredentialOffer_HappyPath(t *testing.T) {
	w := generateTestWallet(t)

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		tokenCNonce: "test-c-nonce",
		inspectCredentialRequest: func(t *testing.T, reqBody map[string]any) {
			t.Helper()
			if _, ok := reqBody["proof"]; ok {
				t.Fatal("credential request must not use legacy proof field")
			}
			proofs, ok := reqBody["proofs"].(map[string]any)
			if !ok {
				t.Fatalf("expected proofs object, got %T", reqBody["proofs"])
			}
			jwts, ok := proofs["jwt"].([]any)
			if !ok || len(jwts) != 1 {
				t.Fatalf("expected single jwt proof, got %v", proofs["jwt"])
			}
			// Without client authentication the pre-authorized exchange is
			// anonymous, so the key proof omits iss (OID4VCI 1.0 Appendix F.1).
			proofJWT, _ := jwts[0].(string)
			if _, present := decodeJWTPart(t, proofJWT, 1)["iss"]; present {
				t.Error("an anonymous pre-authorized flow must omit iss from the key proof")
			}
			if reqBody["credential_configuration_id"] != "test-config" {
				t.Fatalf("expected credential_configuration_id=test-config, got %v", reqBody["credential_configuration_id"])
			}
		},
	})
	defer srv.Close()

	result, err := w.ProcessCredentialOffer(offerURI)
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}

	if result.CredentialID == "" {
		t.Error("expected non-empty credential ID")
	}
	if result.Format != "dc+sd-jwt" {
		t.Errorf("expected format dc+sd-jwt, got %s", result.Format)
	}
	if result.Issuer != srv.URL {
		t.Errorf("expected issuer %s, got %s", srv.URL, result.Issuer)
	}

	creds := w.GetCredentials()
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
	if creds[0].ID != result.CredentialID {
		t.Errorf("credential ID mismatch")
	}

	logs := w.GetLog()
	for _, event := range []string{
		"credential_offer",
		"issuer_metadata_request",
		"issuer_metadata_response",
		"oauth_metadata_request",
		"oauth_metadata_response",
		"token_request",
		"token_response",
		"credential_request",
		"credential_response",
		"credential_imported",
	} {
		assertWalletLogEvent(t, logs, event)
	}
}

// A token response without access_token (RFC 6749 §5.1 requires it) fails with
// that reason before any credential request.
func TestProcessCredentialOffer_MissingAccessToken(t *testing.T) {
	w := generateTestWallet(t)
	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{omitAccessToken: true})
	defer srv.Close()

	_, err := w.ProcessCredentialOffer(offerURI)
	if err == nil || !strings.Contains(err.Error(), "access_token") {
		t.Fatalf("error = %v, want it to name the missing access_token", err)
	}
}

func TestProcessCredentialOffer_NonceFallback(t *testing.T) {
	w := generateTestWallet(t)

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		tokenCNonce:   "",
		nonceEndpoint: true,
	})
	defer srv.Close()

	result, err := w.ProcessCredentialOffer(offerURI)
	if err != nil {
		t.Fatalf("ProcessCredentialOffer with nonce fallback: %v", err)
	}

	if result.CredentialID == "" {
		t.Error("expected non-empty credential ID")
	}

	creds := w.GetCredentials()
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}
}

// A nonce endpoint that answers the required POST with 405 and serves the
// c_nonce over GET deviates from §7.1. Debug mode fetches the nonce over GET,
// warns and completes issuance.
func TestProcessCredentialOffer_NonceEndpointOnlyGET(t *testing.T) {
	w := generateTestWallet(t)

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{nonceEndpoint: true, nonceOnlyGET: true})
	defer srv.Close()

	result, err := w.ProcessCredentialOffer(offerURI)
	if err != nil {
		t.Fatalf("ProcessCredentialOffer against a GET-only nonce endpoint: %v", err)
	}
	if result.CredentialID == "" {
		t.Error("expected the credential to be issued after the GET workaround")
	}

	warned, logged := false, false
	for _, entry := range w.GetLog() {
		if strings.Contains(entry.Detail, "Debug mode uses GET") {
			warned = true
		}
		if strings.Contains(entry.Detail, "Nonce response") {
			logged = true
		}
	}
	if !warned {
		t.Error("the wallet should warn that it used GET as a workaround for the 405")
	}
	if !logged {
		t.Error("the nonce exchange should show in the activity log")
	}
}

// Strict mode reports the POST failure and sends no proof without the required
// nonce.
func TestProcessCredentialOffer_NonceEndpointOnlyGETStrictRefuses(t *testing.T) {
	w := generateTestWallet(t)
	w.ValidationMode = ValidationModeStrict

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{nonceEndpoint: true, nonceOnlyGET: true})
	defer srv.Close()

	_, err := w.ProcessCredentialOffer(offerURI)
	if err == nil || !strings.Contains(err.Error(), "nonce endpoint") {
		t.Fatalf("error = %v, want strict to refuse naming the nonce endpoint", err)
	}
	if len(w.GetCredentials()) != 0 {
		t.Error("strict should not have issued a credential")
	}
}

// §8.3 defines the credentials array of objects as the response shape.
func TestProcessCredentialOffer_CredentialsArray(t *testing.T) {
	w := generateTestWallet(t)
	credRaw := generateTestCredential(t, w)

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		tokenCNonce: "test-c-nonce",
		credentialResponse: map[string]any{
			"credentials": []any{
				map[string]any{"credential": credRaw},
			},
		},
	})
	defer srv.Close()

	result, err := w.ProcessCredentialOffer(offerURI)
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}

	if result.CredentialID == "" {
		t.Error("expected non-empty credential ID")
	}
	if result.Format != "dc+sd-jwt" {
		t.Errorf("expected format dc+sd-jwt, got %s", result.Format)
	}
}

func TestProcessCredentialOffer_AuthCodeRequiresClientConfiguration(t *testing.T) {
	w := generateTestWallet(t)

	var serverURL string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":     serverURL,
				"authorization_servers": []string{serverURL},
				"credential_endpoint":   serverURL + "/credential",
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{
						"format": "dc+sd-jwt",
						"scope":  "test-scope",
					},
				},
			})
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server"):
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"issuer":                                serverURL,
				"authorization_endpoint":                serverURL + "/authorize",
				"pushed_authorization_request_endpoint": serverURL + "/par",
				"token_endpoint":                        serverURL + "/token",
				"token_endpoint_auth_methods_supported": []string{"attest_jwt_client_auth"},
				"dpop_signing_alg_values_supported":     []string{"ES256"},
			})
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	serverURL = srv.URL

	offer := map[string]any{
		"credential_issuer":            serverURL,
		"credential_configuration_ids": []string{"test-config"},
		"grants": map[string]any{
			"authorization_code": map[string]any{
				"issuer_state": "some-state",
			},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	offerURI := "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))

	_, err := w.ProcessCredentialOffer(offerURI)
	if err == nil {
		t.Fatal("expected error when authorization_code flow has no wallet client configuration")
	}
	if !strings.Contains(err.Error(), "configured wallet client_id") {
		t.Errorf("expected error about the missing client_id, got: %v", err)
	}

	// The redirect flow needs a redirect URI. Only interactive authorization
	// works without one.
	w.VCIClientID = "wallet-client"
	_, err = w.ProcessCredentialOffer(offerURI)
	if err == nil {
		t.Fatal("expected error when the authorization_code flow has no redirect_uri")
	}
	if !strings.Contains(err.Error(), "redirect_uri") {
		t.Errorf("expected error about the missing redirect_uri, got: %v", err)
	}
}

func TestProcessCredentialOffer_AuthCodeBrowserFallback(t *testing.T) {
	w := generateTestWallet(t)
	w.VCIClientID = "wallet-client"

	walletSrv := NewServer(w, 0, nil)
	addr, err := walletSrv.ListenAndServeBackground()
	if err != nil {
		t.Fatalf("ListenAndServeBackground: %v", err)
	}
	defer walletSrv.Shutdown()
	w.BaseURL = addr
	w.VCIRedirectURI = addr + "/callback"

	credRaw := generateTestCredential(t, w)
	var (
		serverURL      string
		parState       string
		authorizeCalls atomic.Int32
	)

	issuer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":     serverURL,
				"authorization_servers": []string{serverURL},
				"credential_endpoint":   serverURL + "/credential",
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{
						"format": "dc+sd-jwt",
						"scope":  "test-scope",
					},
				},
			})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server"):
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"issuer":                                         serverURL,
				"authorization_endpoint":                         serverURL + "/authorize",
				"pushed_authorization_request_endpoint":          serverURL + "/par",
				"token_endpoint":                                 serverURL + "/token",
				"token_endpoint_auth_methods_supported":          []string{"private_key_jwt"},
				"dpop_signing_alg_values_supported":              []string{"ES256"},
				"authorization_response_iss_parameter_supported": true,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/par":
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			parState = form.Get("state")
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"request_uri": serverURL + "/request-uri/example",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/authorize":
			authorizeCalls.Add(1)
			http.Redirect(rw, r, serverURL+"/login?state="+url.QueryEscape(parState), http.StatusFound)
		case r.Method == http.MethodGet && r.URL.Path == "/login":
			redirect := w.VCIRedirectURI + "?code=issued-code&state=" + url.QueryEscape(r.URL.Query().Get("state"))
			http.Redirect(rw, r, redirect, http.StatusFound)
		case r.Method == http.MethodPost && r.URL.Path == "/token":
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			if got := form.Get("code"); got != "issued-code" {
				t.Fatalf("token request code = %q, want issued-code", got)
			}
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"access_token": "test-access-token",
				"token_type":   "Bearer",
				"c_nonce":      "test-c-nonce",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/credential":
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{"credentials": []any{map[string]any{"credential": credRaw}}})
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer issuer.Close()
	serverURL = issuer.URL

	// The test plays the browser and visits the authorization URL from the
	// event stream.
	authCh, unsubscribe := w.Consents().SubscribeAuthorization(func(consent.AuthorizationPrompt) bool { return true })
	defer unsubscribe()
	go func() {
		prompt, ok := <-authCh
		if !ok {
			return
		}
		resp, err := issuer.Client().Get(prompt.URL)
		if err == nil && resp != nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()

	offer := map[string]any{
		"credential_issuer":            serverURL,
		"credential_configuration_ids": []string{"test-config"},
		"grants": map[string]any{
			"authorization_code": map[string]any{
				"issuer_state": "issuer-state-1",
			},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	offerURI := "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))

	result, err := w.ProcessCredentialOffer(offerURI)
	if err != nil {
		t.Fatalf("ProcessCredentialOffer() error = %v", err)
	}
	if parState == "" {
		t.Fatal("expected PAR request to include state")
	}
	// RFC 9126 §4: "the client MUST only use a request_uri value once". The
	// browser's request is that use.
	if got := authorizeCalls.Load(); got != 1 {
		t.Errorf("authorization endpoint requested %d times, want the browser's single request", got)
	}
	if result.CredentialID == "" {
		t.Fatal("expected imported credential ID")
	}
}

// When no browser takes the URL, issuance ends without using the request_uri.
func TestRunAuthorizationCodeRequest_NobodyTookTheURL(t *testing.T) {
	w := generateTestWallet(t)
	w.BaseURL = "https://wallet.example"
	const (
		redirectURI = "https://wallet.example/callback"
		state       = "state-1"
	)

	var authorizeCalls atomic.Int32
	authServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		authorizeCalls.Add(1)
		http.Redirect(rw, r, redirectURI+"?code=issued-code&state="+url.QueryEscape(state), http.StatusFound)
	}))
	defer authServer.Close()

	_, err := runAuthorizationCodeRequest(w, authServer.URL+"/authorize", "wallet-client",
		"urn:ietf:params:oauth:request_uri:example", nil, redirectURI, state, "", consent.AuthorizationPrompt{}, false)
	if err == nil {
		t.Fatal("expected the issuance to end when nothing can open the authorization URL")
	}
	if !strings.Contains(err.Error(), "no wallet UI is open to show it") {
		t.Errorf("error = %v, want it to name what is missing", err)
	}
	if got := authorizeCalls.Load(); got != 0 {
		t.Errorf("authorization endpoint requested %d times, want the request_uri left unspent", got)
	}
}

func TestProcessCredentialOffer_AuthCodeDirectRedirect(t *testing.T) {
	w := generateTestWallet(t)
	w.VCIClientID = "wallet-client"
	w.VCIRedirectURI = "https://wallet.example/callback"

	credRaw := generateTestCredential(t, w)
	var (
		serverURL        string
		parState         string
		capturedProofJWT string
	)

	issuer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":     serverURL,
				"authorization_servers": []string{serverURL},
				"credential_endpoint":   serverURL + "/credential",
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{
						"format": "dc+sd-jwt",
						"scope":  "test-scope",
					},
				},
			})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server"):
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"issuer":                                         serverURL,
				"authorization_endpoint":                         serverURL + "/authorize",
				"pushed_authorization_request_endpoint":          serverURL + "/par",
				"token_endpoint":                                 serverURL + "/token",
				"token_endpoint_auth_methods_supported":          []string{"private_key_jwt"},
				"dpop_signing_alg_values_supported":              []string{"ES256"},
				"authorization_response_iss_parameter_supported": true,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/par":
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			parState = form.Get("state")
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"request_uri": serverURL + "/request-uri/example",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/authorize":
			redirect := w.VCIRedirectURI + "?code=issued-code&state=" + url.QueryEscape(parState)
			http.Redirect(rw, r, redirect, http.StatusFound)
		case r.Method == http.MethodPost && r.URL.Path == "/token":
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			if got := form.Get("code"); got != "issued-code" {
				t.Fatalf("token request code = %q, want issued-code", got)
			}
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"access_token": "test-access-token",
				"token_type":   "Bearer",
				"c_nonce":      "test-c-nonce",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/credential":
			body, _ := io.ReadAll(r.Body)
			var reqBody map[string]any
			_ = json.Unmarshal(body, &reqBody)
			if proofs, ok := reqBody["proofs"].(map[string]any); ok {
				if jwts, ok := proofs["jwt"].([]any); ok && len(jwts) > 0 {
					capturedProofJWT, _ = jwts[0].(string)
				}
			}
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{"credentials": []any{map[string]any{"credential": credRaw}}})
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer issuer.Close()
	serverURL = issuer.URL

	authCh, unsubscribe := w.Consents().SubscribeAuthorization(func(consent.AuthorizationPrompt) bool { return true })
	defer unsubscribe()
	defer func() {
		select {
		case prompt := <-authCh:
			t.Errorf("did not expect an interactive sign-in for a direct authorization redirect, got %s", prompt.URL)
		default:
		}
	}()

	offer := map[string]any{
		"credential_issuer":            serverURL,
		"credential_configuration_ids": []string{"test-config"},
		"grants": map[string]any{
			"authorization_code": map[string]any{
				"issuer_state": "issuer-state-1",
			},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	offerURI := "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))

	result, err := w.ProcessCredentialOffer(offerURI)
	if err != nil {
		t.Fatalf("ProcessCredentialOffer() error = %v", err)
	}
	if parState == "" {
		t.Fatal("expected PAR request to include state")
	}
	if result.CredentialID == "" {
		t.Fatal("expected imported credential ID")
	}
	// The authorization code flow identifies the client, so its key proof
	// carries that client as iss (OID4VCI 1.0 Appendix F.1).
	if capturedProofJWT == "" {
		t.Fatal("credential request carried no key proof")
	}
	if got := decodeJWTPart(t, capturedProofJWT, 1)["iss"]; got != "wallet-client" {
		t.Errorf("key proof iss = %v, want the configured client_id wallet-client", got)
	}
}

func TestValidateAuthorizationCodeResponse_StrictRefusesDeviations(t *testing.T) {
	valid := url.Values{"code": {"c"}, "state": {"expected-state"}, "iss": {"https://issuer.example"}}
	tests := []struct {
		name           string
		values         url.Values
		expectedState  string
		expectedIssuer string
		issRequired    bool
		wantErr        string
	}{
		{"valid", valid, "expected-state", "https://issuer.example", true, ""},
		{"missing state", url.Values{"code": {"c"}, "iss": {"https://issuer.example"}}, "expected-state", "https://issuer.example", true, "state"},
		{"state mismatch", url.Values{"code": {"c"}, "state": {"other"}, "iss": {"https://issuer.example"}}, "expected-state", "https://issuer.example", true, "state"},
		{"iss mismatch", url.Values{"code": {"c"}, "state": {"expected-state"}, "iss": {"https://other.example"}}, "expected-state", "https://issuer.example", true, "iss"},
		// RFC 9207 §2.4 compares by simple string comparison, so a trailing
		// slash makes a different issuer.
		{"iss differs by a trailing slash", url.Values{"code": {"c"}, "state": {"expected-state"}, "iss": {"https://issuer.example/"}}, "expected-state", "https://issuer.example", true, "iss"},
		{"missing iss when advertised", url.Values{"code": {"c"}, "state": {"expected-state"}}, "expected-state", "https://issuer.example", true, "iss"},
		{"missing iss when not advertised is fine", url.Values{"code": {"c"}, "state": {"expected-state"}}, "expected-state", "https://issuer.example", false, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := generateTestWallet(t)
			w.ValidationMode = ValidationModeStrict
			err := w.validateAuthorizationCodeResponse(tt.values, tt.expectedState, tt.expectedIssuer, tt.issRequired)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("expected no error, got %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want containing %q", err, tt.wantErr)
			}
		})
	}
}

func TestValidateAuthorizationCodeResponse_DebugWarnsAndProceeds(t *testing.T) {
	w := generateTestWallet(t)
	values := url.Values{"code": {"c"}, "iss": {"https://other.example"}}
	if err := w.validateAuthorizationCodeResponse(values, "expected-state", "https://issuer.example", true); err != nil {
		t.Fatalf("debug should not refuse, got %v", err)
	}
	if findLogEntry(w.GetLog(), "server_deviation") == nil {
		t.Error("debug should warn about the missing state and mismatched iss")
	}
}

func TestProcessCredentialOffer_StrictRejectsAuthorizationServerIssuerMismatchBeforePAR(t *testing.T) {
	w := generateTestWallet(t)
	w.ValidationMode = ValidationModeStrict
	w.VCIClientID = "wallet-client"
	w.VCIRedirectURI = "https://wallet.example/callback"

	var (
		serverURL string
		parCalls  int
	)
	issuer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":     serverURL,
				"authorization_servers": []string{serverURL},
				"credential_endpoint":   serverURL + "/credential",
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{
						"format": "dc+sd-jwt",
						"scope":  "test-scope",
					},
				},
			})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server"):
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"issuer":                                         serverURL + "/wrong",
				"authorization_endpoint":                         serverURL + "/authorize",
				"pushed_authorization_request_endpoint":          serverURL + "/par",
				"token_endpoint":                                 serverURL + "/token",
				"token_endpoint_auth_methods_supported":          []string{"private_key_jwt"},
				"dpop_signing_alg_values_supported":              []string{"ES256"},
				"authorization_response_iss_parameter_supported": true,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/par":
			parCalls++
			rw.WriteHeader(http.StatusBadRequest)
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer issuer.Close()
	serverURL = issuer.URL

	offer := map[string]any{
		"credential_issuer":            serverURL,
		"credential_configuration_ids": []string{"test-config"},
		"grants": map[string]any{
			"authorization_code": map[string]any{
				"issuer_state": "issuer-state-1",
			},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	offerURI := "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))

	_, err := w.ProcessCredentialOffer(offerURI)
	if err == nil || !strings.Contains(err.Error(), "authorization server issuer") {
		t.Fatalf("ProcessCredentialOffer() error = %v, want authorization server issuer error", err)
	}
	if parCalls != 0 {
		t.Fatalf("PAR calls = %d, want 0", parCalls)
	}
}

// RFC 9207 makes iss REQUIRED when the authorization server advertises
// authorization_response_iss_parameter_supported. HAIP 1.0 §4 applies FAPI 2.0.
// There the authorization server "shall return an iss parameter in the
// authorization response" (§5.3.2.2), advertised or not.
func TestProcessCredentialOffer_StrictRejectsMissingAuthorizationResponseIssuerBeforeToken(t *testing.T) {
	t.Run("advertised", func(t *testing.T) { refuseMissingAuthorizationResponseIssuer(t, false) })
	t.Run("HAIP", func(t *testing.T) { refuseMissingAuthorizationResponseIssuer(t, true) })
}

func refuseMissingAuthorizationResponseIssuer(t *testing.T, haip bool) {
	w := generateTestWallet(t)
	w.ValidationMode = ValidationModeStrict
	w.RequireHAIP = haip
	w.VCIClientID = "wallet-client"
	w.VCIRedirectURI = "https://wallet.example/callback"

	var (
		serverURL  string
		parState   string
		tokenCalls int
	)
	issuer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":     serverURL,
				"authorization_servers": []string{serverURL},
				"credential_endpoint":   serverURL + "/credential",
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{
						"format": "dc+sd-jwt",
						"scope":  "test-scope",
					},
				},
			})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server"):
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"issuer":                                         serverURL,
				"authorization_endpoint":                         serverURL + "/authorize",
				"pushed_authorization_request_endpoint":          serverURL + "/par",
				"token_endpoint":                                 serverURL + "/token",
				"token_endpoint_auth_methods_supported":          []string{"private_key_jwt"},
				"dpop_signing_alg_values_supported":              []string{"ES256"},
				"authorization_response_iss_parameter_supported": !haip,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/par":
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			parState = form.Get("state")
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"request_uri": serverURL + "/request-uri/example",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/authorize":
			redirect := w.VCIRedirectURI + "?code=issued-code&state=" + url.QueryEscape(parState)
			http.Redirect(rw, r, redirect, http.StatusFound)
		case r.Method == http.MethodPost && r.URL.Path == "/token":
			tokenCalls++
			rw.WriteHeader(http.StatusBadRequest)
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer issuer.Close()
	serverURL = issuer.URL

	offer := map[string]any{
		"credential_issuer":            serverURL,
		"credential_configuration_ids": []string{"test-config"},
		"grants": map[string]any{
			"authorization_code": map[string]any{
				"issuer_state": "issuer-state-1",
			},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	offerURI := "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))

	_, err := w.ProcessCredentialOffer(offerURI)
	if err == nil || !strings.Contains(err.Error(), "has no iss") {
		t.Fatalf("ProcessCredentialOffer() error = %v, want a refused missing-iss deviation", err)
	}
	if tokenCalls != 0 {
		t.Fatalf("token calls = %d, want 0", tokenCalls)
	}
}

func TestProcessCredentialOffer_TxCodeSentInTokenRequest(t *testing.T) {
	w := generateTestWallet(t)

	credRaw := generateTestCredential(t, w)
	var receivedTxCode string

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			meta := map[string]any{
				"credential_issuer":   "",
				"credential_endpoint": "",
				"token_endpoint":      "",
			}
			rw.Header().Set("Content-Type", "application/json")
			json.NewEncoder(rw).Encode(meta)

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/token"):
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			receivedTxCode = form.Get("tx_code")
			resp := map[string]any{
				"access_token": "test-token",
				"token_type":   "Bearer",
				"c_nonce":      "test-nonce",
			}
			rw.Header().Set("Content-Type", "application/json")
			json.NewEncoder(rw).Encode(resp)

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/credential"):
			rw.Header().Set("Content-Type", "application/json")
			json.NewEncoder(rw).Encode(map[string]any{"credentials": []any{map[string]any{"credential": credRaw}}})

		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	srvURL := srv.URL
	origHandler := srv.Config.Handler
	srv.Config.Handler = http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer") {
			meta := map[string]any{
				"credential_issuer":   srvURL,
				"credential_endpoint": srvURL + "/credential",
				"token_endpoint":      srvURL + "/token",
			}
			rw.Header().Set("Content-Type", "application/json")
			json.NewEncoder(rw).Encode(meta)
			return
		}
		origHandler.ServeHTTP(rw, r)
	})

	offer := map[string]any{
		"credential_issuer":            srvURL,
		"credential_configuration_ids": []string{"test-config"},
		"grants": map[string]any{
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
				"pre-authorized_code": "test-code",
				"tx_code":             map[string]any{"length": 6},
			},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	offerURI := "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))

	_, err := w.ProcessCredentialOfferWithOptions(offerURI, OfferOptions{TxCode: "123456"})
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}

	if receivedTxCode != "123456" {
		t.Errorf("expected tx_code=123456 in token request, got %q", receivedTxCode)
	}
}

func TestProcessCredentialOffer_NoTxCodeWhenNotSet(t *testing.T) {
	w := generateTestWallet(t)

	var receivedForm string

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		tokenCNonce: "test-nonce",
	})
	defer srv.Close()

	origHandler := srv.Config.Handler
	srv.Config.Handler = http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/token") {
			body, _ := io.ReadAll(r.Body)
			receivedForm = string(body)
			r.Body = io.NopCloser(strings.NewReader(receivedForm))
		}
		origHandler.ServeHTTP(rw, r)
	})

	_, err := w.ProcessCredentialOffer(offerURI)
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}

	if strings.Contains(receivedForm, "tx_code") {
		t.Errorf("expected no tx_code in token request when not set, but got: %s", receivedForm)
	}
}

// §8.3: "The elements of the array MUST be objects."
func TestProcessCredentialOffer_RejectsAnArrayOfRawCredentialStrings(t *testing.T) {
	w := generateTestWallet(t)
	credRaw := generateTestCredential(t, w)

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		nonceEndpoint: true,
		credentialResponse: map[string]any{
			"credentials": []any{credRaw},
		},
	})
	defer srv.Close()

	if _, err := w.ProcessCredentialOffer(offerURI); err == nil {
		t.Fatal("a credentials array of bare strings was accepted")
	}
}

// §8.3 defines no top-level credential member.
func TestProcessCredentialOffer_RejectsATopLevelCredentialString(t *testing.T) {
	w := generateTestWallet(t)
	credRaw := generateTestCredential(t, w)

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		nonceEndpoint:      true,
		credentialResponse: map[string]any{"credential": credRaw},
	})
	defer srv.Close()

	if _, err := w.ProcessCredentialOffer(offerURI); err == nil {
		t.Fatal("a top-level credential string was accepted")
	}
}

func TestProcessCredentialOffer_VerifiesViaIssuerMetadata(t *testing.T) {
	w := generateTestWallet(t)

	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	var issuer string
	metaSrv := httptest.NewTLSServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/jwt-vc-issuer" {
			rw.WriteHeader(http.StatusNotFound)
			return
		}
		rw.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(rw).Encode(map[string]any{
			"issuer": issuer,
			"jwks": map[string]any{
				"keys": []any{mock.SigningJWKMap(&key.PublicKey)},
			},
		})
	}))
	defer metaSrv.Close()
	issuer = metaSrv.URL

	credRaw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    issuer,
		VCT:       "TestIssuedCred",
		ExpiresIn: 24 * time.Hour,
		Claims:    map[string]any{"given_name": "Test", "family_name": "User"},
		Key:       key,
		HolderKey: &w.HolderKey.PublicKey,
	})
	if err != nil {
		t.Fatalf("GenerateSDJWT: %v", err)
	}

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		tokenCNonce:        "test-c-nonce",
		credentialResponse: map[string]any{"credentials": []any{map[string]any{"credential": credRaw}}},
	})
	defer srv.Close()

	result, err := w.ProcessCredentialOffer(offerURI)
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}

	if result.VerificationStatus != "pass" {
		t.Fatalf("expected verification pass, got %q (%s)", result.VerificationStatus, result.VerificationDetail)
	}
}

func TestProcessCredentialOffer_UsesCredentialIdentifierFromAuthorizationDetails(t *testing.T) {
	w := generateTestWallet(t)

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		tokenCNonce: "test-c-nonce",
		tokenAuthorizationDetails: []any{
			map[string]any{
				"type":                        "openid_credential",
				"credential_configuration_id": "test-config",
				"credential_identifiers":      []any{"credential-id-123"},
			},
		},
		inspectCredentialRequest: func(t *testing.T, reqBody map[string]any) {
			t.Helper()
			if reqBody["credential_identifier"] != "credential-id-123" {
				t.Fatalf("expected credential_identifier, got %v", reqBody["credential_identifier"])
			}
			if _, ok := reqBody["credential_configuration_id"]; ok {
				t.Fatalf("did not expect credential_configuration_id when credential_identifier is present")
			}
		},
	})
	defer srv.Close()

	if _, err := w.ProcessCredentialOffer(offerURI); err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
}

func authorizedOtherWarnings(w *Wallet) []LogEntry {
	var found []LogEntry
	for _, e := range w.Log {
		if e.Details["event"] == "token_authorizes_other_configuration" {
			found = append(found, e)
		}
	}
	return found
}

// A token response can authorize several configurations. The credential request
// uses the identifier of the offered one.
func TestProcessCredentialOffer_PicksTheIdentifierOfTheOfferedConfiguration(t *testing.T) {
	w := generateTestWallet(t)

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		tokenCNonce: "test-c-nonce",
		tokenAuthorizationDetails: []any{
			map[string]any{"type": "openid_credential", "credential_configuration_id": "other-config", "credential_identifiers": []any{"other-id"}},
			map[string]any{"type": "openid_credential", "credential_configuration_id": "test-config", "credential_identifiers": []any{"offered-id"}},
		},
		inspectCredentialRequest: func(t *testing.T, reqBody map[string]any) {
			t.Helper()
			if reqBody["credential_identifier"] != "offered-id" {
				t.Fatalf("credential_identifier = %v, want the offered configuration's offered-id", reqBody["credential_identifier"])
			}
		},
	})
	defer srv.Close()

	if _, err := w.ProcessCredentialOffer(offerURI); err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
	if warnings := authorizedOtherWarnings(w); len(warnings) != 0 {
		t.Errorf("unexpected warnings: %+v", warnings)
	}
}

// When the token authorizes only another configuration, the wallet warns with
// both configurations before the credential request fails.
func TestProcessCredentialOffer_WarnsWhenTheTokenAuthorizesAnotherConfiguration(t *testing.T) {
	w := generateTestWallet(t)

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		tokenCNonce: "test-c-nonce",
		tokenAuthorizationDetails: []any{
			map[string]any{"type": "openid_credential", "credential_configuration_id": "other-config", "credential_identifiers": []any{"other-id"}},
		},
	})
	defer srv.Close()

	_, _ = w.ProcessCredentialOffer(offerURI)
	warnings := authorizedOtherWarnings(w)
	if len(warnings) != 1 {
		t.Fatalf("warnings = %+v, want one", warnings)
	}
	if !strings.Contains(warnings[0].Detail, `authorizes credential configuration "other-config", not the offered "test-config"`) {
		t.Errorf("warning detail = %q", warnings[0].Detail)
	}
	if warnings[0].Severity != "warning" {
		t.Errorf("severity = %q, want warning", warnings[0].Severity)
	}
}

// The consent dialog shows the offered credential details from the metadata.
// Without metadata the dialog still works.
func TestIssuanceConsentDescribesTheOffer(t *testing.T) {
	srv := newTestServer(t, false)
	issuer, offerURI := setupMockIssuer(t, srv.wallet, mockIssuerOpts{})
	defer issuer.Close()

	req, _, err := generateTestWallet(t).prepareIssuanceConsentRequest(t.Context(), offerURI, "")
	if err != nil {
		t.Fatalf("prepareIssuanceConsentRequest: %v", err)
	}
	details := req.OfferDetails
	if details == nil {
		t.Fatal("the consent request carries no offer details")
	}

	if details.IssuerName != "Test Issuer" {
		t.Errorf("issuer name = %q, want the name from the issuer metadata", details.IssuerName)
	}
	if details.Grant != "pre-authorized code" {
		t.Errorf("grant = %q, want the flow the offer uses", details.Grant)
	}
	if len(details.Credentials) != 1 {
		t.Fatalf("expected one offered credential, got %d", len(details.Credentials))
	}

	cred := details.Credentials[0]
	if cred.ID != "test-config" {
		t.Errorf("configuration id = %q", cred.ID)
	}
	if cred.Name != "Test Credential" || cred.Description != "A credential for tests" {
		t.Errorf("display name/description not taken from the metadata: %+v", cred)
	}
	if cred.Format != "dc+sd-jwt" || cred.VCT != "urn:test:credential" {
		t.Errorf("format/vct not resolved: %+v", cred)
	}
	// Nested claims show as paths in the consent dialog.
	want := []string{"given_name", "address.locality"}
	if len(cred.Claims) != len(want) {
		t.Fatalf("claims = %v, want %v", cred.Claims, want)
	}
	for i, claim := range want {
		if cred.Claims[i] != claim {
			t.Errorf("claim %d = %q, want %q", i, cred.Claims[i], claim)
		}
	}

	if _, ok := consent.NewRuntime().DocFor(req, nil)["offer_details"]; !ok {
		t.Error("offer_details missing from the marshalled consent request")
	}
}

// OpenID4VCI 1.0 §4.1 allows either credential_offer or credential_offer_uri.
// The wallet refuses an offer with both before the consent dialog.
func TestIssuanceConsentRefusesAnOfferWithBothParameters(t *testing.T) {
	offer := url.QueryEscape(`{"credential_issuer":"https://issuer.example","credential_configuration_ids":["pid"]}`)
	uri := "openid-credential-offer://?credential_offer=" + offer + "&credential_offer_uri=" + url.QueryEscape("https://issuer.example/offer")
	req, _, err := generateTestWallet(t).prepareIssuanceConsentRequest(t.Context(), uri, "")
	if req != nil || !errors.Is(err, oid4vc.ErrInvalidCredentialOffer) {
		t.Fatalf("consent request %+v, err %v, want the invalid offer refused", req, err)
	}
}

// An offer by reference is resolved for consent and fetched again after
// approval.
func TestIssuanceConsentResolvesOfferByReference(t *testing.T) {
	srv := newTestServer(t, false)
	fetched := make(chan struct{}, 4)
	issuer, offerURI := setupMockIssuer(t, srv.wallet, mockIssuerOpts{
		offerViaURI:  true,
		onOfferFetch: func() { fetched <- struct{}{} },
	})
	defer issuer.Close()

	req, _, err := generateTestWallet(t).prepareIssuanceConsentRequest(t.Context(), offerURI, "")
	if err != nil {
		t.Fatalf("prepareIssuanceConsentRequest: %v", err)
	}
	select {
	case <-fetched:
	default:
		t.Fatal("the credential_offer_uri should be fetched to describe the offer")
	}

	details := req.OfferDetails
	if details == nil || len(details.Credentials) != 1 {
		t.Fatalf("a by-reference offer should be described like any other: %+v", details)
	}
	if details.Credentials[0].Name != "Test Credential" {
		t.Errorf("display name not resolved: %+v", details.Credentials[0])
	}
}

// When the offer fetch fails, the consent dialog still shows the issuer host
// and the failure.
func TestIssuanceConsentSurvivesUnresolvableOfferURI(t *testing.T) {
	req, _, err := generateTestWallet(t).prepareIssuanceConsentRequest(t.Context(), "openid-credential-offer://?credential_offer_uri=https://issuer.invalid/offer/1", "")
	if err != nil {
		t.Fatalf("prepareIssuanceConsentRequest: %v", err)
	}
	if req.OfferDetails == nil || req.OfferDetails.ResolveError == "" {
		t.Fatalf("the resolve failure should be recorded: %+v", req.OfferDetails)
	}
	if req.ClientID == "" {
		t.Error("the dialog still needs something to name the issuer by")
	}
}

func TestIssuanceConsentSurvivesMissingIssuerMetadata(t *testing.T) {
	offer := `{"credential_issuer":"https://issuer.invalid","credential_configuration_ids":["some-config"],` +
		`"grants":{"urn:ietf:params:oauth:grant-type:pre-authorized_code":{"pre-authorized_code":"abc","tx_code":{"length":6,"input_mode":"numeric"}}}}`
	req, _, err := generateTestWallet(t).prepareIssuanceConsentRequest(t.Context(), "openid-credential-offer://?credential_offer="+url.QueryEscape(offer), "")
	if err != nil {
		t.Fatalf("prepareIssuanceConsentRequest: %v", err)
	}
	details := req.OfferDetails
	if details == nil {
		t.Fatal("no offer details")
	}
	if details.MetadataError == "" {
		t.Error("the unreachable metadata should be recorded, not hidden")
	}
	if len(details.Credentials) != 1 || details.Credentials[0].ID != "some-config" {
		t.Errorf("the offered configuration should still be listed: %+v", details.Credentials)
	}
	if !details.TxCode || details.TxCodeHint != "6 numeric characters" {
		t.Errorf("tx_code requirement not surfaced: %+v", details)
	}
}

func proofNonceOf(t *testing.T, reqBody map[string]any) string {
	t.Helper()
	proofs, _ := reqBody["proofs"].(map[string]any)
	jwts, _ := proofs["jwt"].([]any)
	if len(jwts) == 0 {
		t.Fatalf("credential request carries no key proof: %v", reqBody)
	}
	compact, _ := jwts[0].(string)
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		t.Fatalf("key proof is not a compact JWT: %q", compact)
	}
	payloadJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decoding key proof payload: %v", err)
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		t.Fatalf("parsing key proof payload: %v", err)
	}
	nonce, _ := payload["nonce"].(string)
	return nonce
}

// §8.3.1.2 on invalid_nonce: "at least one of the key proofs contains an
// invalid c_nonce value. The wallet should retrieve a new c_nonce value (refer
// to Section 7)." The wallet fetches a new nonce and retries once.
func TestProcessCredentialOffer_RetriesOnInvalidNonce(t *testing.T) {
	w := generateTestWallet(t)

	var proofNonces []string
	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		nonceEndpoint:    true,
		rejectFirstNonce: true,
		inspectCredentialRequest: func(t *testing.T, reqBody map[string]any) {
			proofNonces = append(proofNonces, proofNonceOf(t, reqBody))
		},
	})
	defer srv.Close()

	result, err := w.ProcessCredentialOffer(offerURI)
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
	if result.CredentialID == "" {
		t.Error("no credential was imported after the retry")
	}
	if len(proofNonces) != 2 {
		t.Fatalf("the issuer saw %d credential requests, want 2: %v", len(proofNonces), proofNonces)
	}
	if proofNonces[0] == proofNonces[1] {
		t.Errorf("the retry reused the rejected challenge %q", proofNonces[0])
	}
	if proofNonces[1] != "nonce-from-endpoint-2" {
		t.Errorf("retry challenge = %q, want the second one from the Nonce Endpoint", proofNonces[1])
	}
}

// §7.1: "The Nonce Endpoint is not a protected resource, meaning the Wallet
// does not need to supply an access token to access it." The wallet sends no
// access token there.
func TestProcessCredentialOffer_NonceRequestIsUnauthenticated(t *testing.T) {
	w := generateTestWallet(t)

	var authorization, dpop string
	var nonceRequests int
	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		nonceEndpoint: true,
		inspectNonceRequest: func(t *testing.T, r *http.Request) {
			nonceRequests++
			authorization = r.Header.Get("Authorization")
			dpop = r.Header.Get("DPoP")
		},
	})
	defer srv.Close()

	if _, err := w.ProcessCredentialOffer(offerURI); err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
	if nonceRequests == 0 {
		t.Fatal("the wallet never asked the Nonce Endpoint")
	}
	if authorization != "" {
		t.Errorf("the nonce request carried Authorization %q", authorization)
	}
	if dpop != "" {
		t.Errorf("the nonce request carried a DPoP proof %q", dpop)
	}
}

// §12.2.2 gives the metadata two media types, application/json and
// application/jwt. application/openidvci-issuer-metadata+jwt is the typ header
// of the signed form (§12.2.3) and no media type.
func TestProcessCredentialOffer_MetadataAcceptHeader(t *testing.T) {
	w := generateTestWallet(t)

	accept := ""
	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		nonceEndpoint: true,
		inspectMetadataRequest: func(t *testing.T, r *http.Request) {
			accept = r.Header.Get("Accept")
		},
	})
	defer srv.Close()

	if _, err := w.ProcessCredentialOffer(offerURI); err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
	if !strings.Contains(accept, "application/json") {
		t.Errorf("Accept = %q, want it to include application/json", accept)
	}
	if !strings.Contains(accept, "application/jwt") {
		t.Errorf("Accept = %q, want it to include application/jwt", accept)
	}
	if strings.Contains(accept, "openidvci-issuer-metadata+jwt") {
		t.Errorf("Accept = %q, which names a media type that does not exist", accept)
	}
}

// §8.2: "The c_nonce value is retrieved from the Nonce Endpoint as defined in
// Section 7." A c_nonce in the token response is a pre-1.0 shape. RFC 6749 §5.1
// makes token_type REQUIRED. Strict mode refuses a response that omits it.
// Debug mode assumes Bearer, since no DPoP was sent, and records the deviation.
func TestProcessCredentialOffer_MissingTokenTypeByValidationMode(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mode    ValidationMode
		wantErr bool
	}{
		{"strict refuses", ValidationModeStrict, true},
		{"debug works around", ValidationModeDebug, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := generateTestWallet(t)
			w.ValidationMode = tc.mode

			srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{omitTokenType: true})
			defer srv.Close()

			_, err := w.ProcessCredentialOffer(offerURI)
			if tc.wantErr {
				if err == nil || !strings.Contains(err.Error(), "token_type") {
					t.Fatalf("error = %v, want it to name the missing token_type", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ProcessCredentialOffer: %v", err)
			}

			found := false
			for _, entry := range w.GetLog() {
				if strings.Contains(entry.Detail, "token_type") {
					found = true
				}
			}
			if !found {
				t.Error("the activity log does not name the missing token_type")
			}
		})
	}
}

func TestProcessCredentialOffer_TokenResponseCNonceByValidationMode(t *testing.T) {
	for _, tc := range []struct {
		name      string
		mode      ValidationMode
		wantNonce string
	}{
		{"strict ignores it", ValidationModeStrict, ""},
		{"debug uses it", ValidationModeDebug, "test-c-nonce"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := generateTestWallet(t)
			w.ValidationMode = tc.mode

			seen := ""
			srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
				tokenCNonce: "test-c-nonce",
				inspectCredentialRequest: func(t *testing.T, reqBody map[string]any) {
					seen = proofNonceOf(t, reqBody)
				},
			})
			defer srv.Close()

			if _, err := w.ProcessCredentialOffer(offerURI); err != nil {
				t.Fatalf("ProcessCredentialOffer: %v", err)
			}
			if seen != tc.wantNonce {
				t.Errorf("proof nonce = %q, want %q", seen, tc.wantNonce)
			}

			found := false
			for _, entry := range w.GetLog() {
				if strings.Contains(entry.Detail, "c_nonce") && strings.Contains(entry.Detail, "token response") {
					found = true
				}
			}
			if !found {
				t.Error("the activity log does not name the issuer as pre-1.0")
			}
		})
	}
}

// Without a published PAR endpoint the wallet sends the plain authorization
// request of RFC 6749 §4.1.1. RFC 9126 §2: "Authorization servers supporting
// PAR SHOULD include the URL of their pushed authorization request endpoint in
// their authorization server metadata document". OpenID4VCI requires neither
// PAR nor DPoP.
func TestProcessCredentialOffer_AuthCodeWithoutPARorDPoP(t *testing.T) {
	w := generateTestWallet(t)
	w.VCIClientID = "wallet-client"
	w.VCIRedirectURI = "https://wallet.example/callback"

	credRaw := generateTestCredential(t, w)
	var (
		serverURL      string
		authQuery      url.Values
		sawPARRequest  bool
		sawDPoPHeader  bool
		tokenAuthState string
	)

	issuer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Header.Get("DPoP") != "" {
			sawDPoPHeader = true
		}
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":     serverURL,
				"authorization_servers": []string{serverURL},
				"credential_endpoint":   serverURL + "/credential",
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{"format": "dc+sd-jwt", "scope": "test-scope"},
				},
			})
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/.well-known/oauth-authorization-server"):
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"issuer":                 serverURL,
				"authorization_endpoint": serverURL + "/authorize",
				"token_endpoint":         serverURL + "/token",
			})
		case r.URL.Path == "/par":
			sawPARRequest = true
			rw.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodGet && r.URL.Path == "/authorize":
			authQuery = r.URL.Query()
			tokenAuthState = authQuery.Get("state")
			http.Redirect(rw, r, w.VCIRedirectURI+"?code=issued-code&state="+url.QueryEscape(tokenAuthState), http.StatusFound)
		case r.Method == http.MethodPost && r.URL.Path == "/token":
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"access_token": "plain-bearer-token",
				"token_type":   "Bearer",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/credential":
			if got := r.Header.Get("Authorization"); got != "Bearer plain-bearer-token" {
				t.Errorf("Authorization = %q, want a bearer token", got)
			}
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"credentials": []any{map[string]any{"credential": credRaw}},
			})
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer issuer.Close()
	serverURL = issuer.URL

	offer := map[string]any{
		"credential_issuer":            serverURL,
		"credential_configuration_ids": []string{"test-config"},
		"grants": map[string]any{
			"authorization_code": map[string]any{"issuer_state": "some-state"},
		},
	}
	offerJSON, err := json.Marshal(offer)
	if err != nil {
		t.Fatal(err)
	}

	result, err := w.ProcessCredentialOffer("openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON)))
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
	if result.CredentialID == "" {
		t.Fatal("no credential was collected")
	}

	if sawPARRequest {
		t.Error("the wallet pushed the request to an endpoint the server does not publish")
	}
	if sawDPoPHeader {
		t.Error("the wallet sent a DPoP proof to a server that advertises no DPoP support")
	}
	for _, key := range []string{"response_type", "client_id", "redirect_uri", "scope", "state", "code_challenge", "code_challenge_method"} {
		if authQuery.Get(key) == "" {
			t.Errorf("the authorization request carried no %s: %v", key, authQuery.Encode())
		}
	}
	if got := authQuery.Get("code_challenge_method"); got != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", got)
	}
	if authQuery.Get("request_uri") != "" {
		t.Error("the authorization request named a request_uri although nothing was pushed")
	}
}

// Without --base-url the wallet accepts /callback on the recorded serving
// origin. The default Docker command depends on this for authorization code
// issuance.
func TestCallbackIsAcceptedOnAWalletWithoutABaseURL(t *testing.T) {
	w := generateTestWallet(t)
	w.BaseURL = ""

	if canUseInteractiveAuthorizationCallback(w, "http://localhost:8085/callback") {
		t.Error("accepted a callback with neither a base URL nor a serving origin")
	}

	w.ServingOrigin = "http://localhost:8085"
	if !canUseInteractiveAuthorizationCallback(w, "http://localhost:8085/callback") {
		t.Error("rejected the callback the serving origin answers on")
	}
	if canUseInteractiveAuthorizationCallback(w, "http://localhost:9999/callback") {
		t.Error("accepted a callback on a port this server does not answer on")
	}

	w.BaseURL = "https://wallet.example"
	if canUseInteractiveAuthorizationCallback(w, "http://localhost:8085/callback") {
		t.Error("accepted a callback that does not match the configured base URL")
	}
}

// §11 makes the Notification Endpoint optional for the wallet, and the wallet
// stores the credential before it notifies. A refused notification leaves the
// credential in place.
func TestProcessCredentialOffer_KeepsCredentialWhenNotificationIsRefused(t *testing.T) {
	w := generateTestWallet(t)
	credRaw := generateTestCredential(t, w)

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		tokenCNonce:         "test-c-nonce",
		refusesNotification: true,
		credentialResponse: map[string]any{
			"credentials":     []any{map[string]any{"credential": credRaw}},
			"notification_id": "notification-the-issuer-will-not-take",
		},
	})
	defer srv.Close()

	result, err := w.ProcessCredentialOffer(offerURI)
	if err != nil {
		t.Fatalf("the issuance failed over a notification: %v", err)
	}
	if result.CredentialID == "" {
		t.Fatal("expected the credential to be issued")
	}
	if creds := w.GetCredentials(); len(creds) != 1 {
		t.Fatalf("holding %d credentials, want the issued one kept", len(creds))
	}

	logs := w.GetLog()
	assertWalletLogEvent(t, logs, "notification_response")
	assertWalletLogEvent(t, logs, "notification_failed")
}

// Notification refusals are explained by the response rules in OpenID4VCI
// §11.3.
func TestReadNotificationRefusal(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int
		body     string
		wantCode string
		wantSays string
	}{
		{"defined 400", 400, `{"error":"invalid_notification_id"}`, "invalid_notification_id", "Notification Error Response (§11.3, invalid_notification_id)"},
		{"rfc 6750 code with a 400", 400, `{"error":"invalid_request"}`, "invalid_request", "RFC 6750 §3.1"},
		{"nothing answered", 0, ``, "", "unreachable"},
		{"read failed on a success", 204, ``, "", "The issuer accepted it"},
		{"other code", 400, `{"error":"session_not_found"}`, "session_not_found", "This response has session_not_found"},
		{"400 with no code", 400, `not json`, "", "This response has none"},
		{"bad token", 401, ``, "", "RFC 6750"},
		{"undefined status", 404, `{"message":"Could not find any entity of type \"Session\""}`, "", "defines no response with status 404"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reading, code := readNotificationRefusal(tc.status, []byte(tc.body))
			if code != tc.wantCode {
				t.Errorf("code = %q, want %q", code, tc.wantCode)
			}
			if !strings.Contains(reading, tc.wantSays) {
				t.Errorf("reading = %q, want it to say %q", reading, tc.wantSays)
			}
		})
	}
}

// OpenID4VCI 1.0 §11.1: a credential the wallet refuses gets the event
// credential_failure.
func TestARefusedCredentialIsNotifiedAsAFailure(t *testing.T) {
	w := generateTestWallet(t)
	var body []byte
	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		tokenCNonce:         "test-c-nonce",
		refusesNotification: true,
		credentialResponse: map[string]any{
			"credentials":     []any{map[string]any{"credential": "not-a-credential"}},
			"notification_id": "refused-1",
		},
		captureNotification: func(r *http.Request, raw []byte) { body = raw },
	})
	defer srv.Close()

	if _, err := w.ProcessCredentialOffer(offerURI); err == nil {
		t.Fatal("the wallet stored an unreadable credential")
	}
	var sent map[string]any
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatalf("no notification sent: %v (%s)", err, body)
	}
	if sent["notification_id"] != "refused-1" || sent["event"] != "credential_failure" {
		t.Errorf("notification %v, want credential_failure for refused-1", sent)
	}
}

// TestDPoPTargetURI checks the htu claim of a DPoP proof. RFC 9449 §4.2 asks
// for the target URI "without query and fragment parts".
func TestDPoPTargetURI(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"https://issuer.example/token", "https://issuer.example/token"},
		{"https://issuer.example/token?tenant=playground", "https://issuer.example/token"},
		{"https://issuer.example/token#frag", "https://issuer.example/token"},
		{"https://issuer.example/token?tenant=a#frag", "https://issuer.example/token"},
		{"https://issuer.example/vci/notification?", "https://issuer.example/vci/notification"},
		{"https://issuer.example:8443/a/b?x=1", "https://issuer.example:8443/a/b"},
	} {
		if got := dpopTargetURI(tc.in); got != tc.want {
			t.Errorf("dpopTargetURI(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestNotificationRequestIsShapedAsSpecified checks the Notification Request
// against §11.1. It is an HTTP POST "with the following parameters in the
// entity-body and using the application/json media type". It carries
// notification_id from the Credential Response and event, and presents the
// Access Token from the Token Endpoint.
func TestNotificationRequestIsShapedAsSpecified(t *testing.T) {
	w := generateTestWallet(t)
	credRaw := generateTestCredential(t, w)

	var method, contentType, authorization string
	var body []byte
	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		tokenCNonce:         "test-c-nonce",
		refusesNotification: true,
		credentialResponse: map[string]any{
			"credentials":     []any{map[string]any{"credential": credRaw}},
			"notification_id": "3fwe98js",
		},
		captureNotification: func(r *http.Request, raw []byte) {
			method, contentType, authorization, body = r.Method, r.Header.Get("Content-Type"), r.Header.Get("Authorization"), raw
		},
	})
	defer srv.Close()

	if _, err := w.ProcessCredentialOffer(offerURI); err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}

	if method != http.MethodPost {
		t.Errorf("method = %s, want POST", method)
	}
	if contentType != "application/json" {
		t.Errorf("Content-Type = %q, want application/json", contentType)
	}
	if authorization != "Bearer test-access-token" {
		t.Errorf("Authorization = %q, want the access token the Token Endpoint issued", authorization)
	}

	var sent map[string]any
	if err := json.Unmarshal(body, &sent); err != nil {
		t.Fatalf("the body is not JSON: %v (%s)", err, body)
	}
	if sent["notification_id"] != "3fwe98js" {
		t.Errorf("notification_id = %v, want the one the Credential Response carried", sent["notification_id"])
	}
	if sent["event"] != "credential_accepted" {
		t.Errorf("event = %v, want credential_accepted for a credential that was stored", sent["event"])
	}
	if len(sent) != 2 {
		t.Errorf("body carries %v, want notification_id and event only", sent)
	}
}
