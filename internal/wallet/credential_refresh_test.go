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
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
)

// renewalIssuerMetadata is served at the Credential Issuer Identifier
// (§12.2.2). Its Nonce Endpoint supplies the proof challenge (§8.2).
func renewalIssuerMetadata(issuer string) map[string]any {
	return map[string]any{
		"credential_issuer":   issuer,
		"credential_endpoint": issuer + "/credential",
		"nonce_endpoint":      issuer + "/nonce",
	}
}

// A renewal keeps the credential ID. Its proof uses a fresh challenge from
// the Nonce Endpoint (OpenID4VCI §8.2).
func TestRenewCredentialKeepsTheIdentity(t *testing.T) {
	w := generateTestWallet(t)
	original := generateTestCredential(t, w)
	renewed := generateTestCredential(t, w)

	var refreshGrants int
	var serverURL string
	var nonceRequests int
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			_ = json.NewEncoder(rw).Encode(renewalIssuerMetadata(serverURL))
		case strings.HasSuffix(r.URL.Path, "/nonce"):
			nonceRequests++
			_ = json.NewEncoder(rw).Encode(map[string]any{"c_nonce": "renewal-nonce"})
		case strings.HasSuffix(r.URL.Path, "/token"):
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != "refresh-1" {
				rw.WriteHeader(http.StatusBadRequest)
				return
			}
			refreshGrants++
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"access_token": "fresh", "token_type": "Bearer",
				"refresh_token": "refresh-2", "expires_in": 300,
			})
		case strings.HasSuffix(r.URL.Path, "/credential"):
			if r.Header.Get("Authorization") != "Bearer fresh" {
				rw.WriteHeader(http.StatusForbidden)
				return
			}
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			proofs, _ := body["proofs"].(map[string]any)
			jwts, _ := proofs["jwt"].([]any)
			if len(jwts) == 0 {
				rw.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(rw).Encode(map[string]any{"error": "invalid_proof"})
				return
			}
			// An OpenID4VCI 1.0 issuer refuses a proof without its nonce.
			if nonce := proofNonce(jwts[0]); nonce != "renewal-nonce" {
				rw.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(rw).Encode(map[string]any{
					"error":             "invalid_nonce",
					"error_description": "proof nonce is " + nonce,
				})
				return
			}
			_ = json.NewEncoder(rw).Encode(map[string]any{"credentials": []any{map[string]any{"credential": renewed}}})
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	serverURL = srv.URL

	imported, err := w.ImportCredential(original)
	if err != nil {
		t.Fatal(err)
	}
	id := imported.ID
	w.rememberRenewal(id, CredentialRenewal{RefreshToken: "refresh-1",
		Issuer: srv.URL, TokenEndpoint: srv.URL + "/token",
		CredentialEndpoint: srv.URL + "/credential", ConfigurationID: "cfg",
	})

	server := NewServer(w, 0, nil)
	before := len(w.GetCredentials())
	result, err := server.RenewCredential(id)
	if err != nil {
		t.Fatalf("RenewCredential: %v", err)
	}

	if result.ID != id {
		t.Errorf("the renewed credential has id %s, want the original %s", result.ID, id)
	}
	if got := len(w.GetCredentials()); got != before {
		t.Errorf("the wallet holds %d credentials, want %d: renewing must replace, not add", got, before)
	}
	stored, ok := w.GetCredential(id)
	if !ok {
		t.Fatal("the credential is gone after renewing it")
	}
	if stored.Raw != renewed {
		t.Error("the stored credential is still the old one")
	}
	// The issuer retires a rotated refresh token.
	if stored.Renewal == nil || stored.Renewal.RefreshToken != "refresh-2" {
		t.Errorf("the rotated refresh token was not stored: %+v", stored.Renewal)
	}
	if refreshGrants != 1 {
		t.Errorf("the issuer saw %d refresh grants, want 1", refreshGrants)
	}
	if nonceRequests != 1 {
		t.Errorf("the renewal asked the Nonce Endpoint %d times, want 1", nonceRequests)
	}
}

func TestRenewCredentialRefusesWithoutARefreshToken(t *testing.T) {
	w := generateTestWallet(t)
	imported, err := w.ImportCredential(generateTestCredential(t, w))
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(w, 0, nil)
	if _, err := server.RenewCredential(imported.ID); err == nil {
		t.Error("a credential with no refresh token was renewed")
	}
}

// One failed renewal does not stop the sweep.
func TestRenewExpiringCredentialsSweep(t *testing.T) {
	w := generateTestWallet(t)

	fresh, err := w.IssueCredential(IssueOptions{
		Format: "sdjwt", VCT: "urn:test:fresh:1",
		Claims: map[string]any{"a": "1"}, ExpiresIn: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	expiring, err := w.IssueCredential(IssueOptions{
		Format: "sdjwt", VCT: "urn:test:expiring:1",
		Claims: map[string]any{"a": "1"}, ExpiresIn: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}

	unreachable := CredentialRenewal{
		Issuer: "https://issuer.example", TokenEndpoint: "https://127.0.0.1:1/token",
		CredentialEndpoint: "https://127.0.0.1:1/credential", RefreshToken: "refresh-1",
	}
	w.rememberRenewal(fresh.Credential.ID, unreachable)
	w.rememberRenewal(expiring.Credential.ID, unreachable)

	server := NewServer(w, 0, nil)
	now := time.Now()
	if err := server.renewExpiringCredentials(now); err != nil {
		t.Fatalf("the sweep reported failure over one credential: %v", err)
	}

	if server.renewalDue(expiring.Credential.ID, now) {
		t.Error("a credential whose renewal just failed is due again immediately")
	}
	if !server.renewalDue(expiring.Credential.ID, now.Add(renewalRetryAfter+time.Second)) {
		t.Error("a failed renewal is never retried")
	}
	if !server.renewalDue(fresh.Credential.ID, now) {
		t.Error("a credential far from expiry was attempted")
	}
}

// Presentation renews a credential near expiry, because the background
// sweep runs only under wallet serve.
// A credential about to expire is renewed before it is presented, and the
// renewal is saved. The renewal calls the issuer, so it runs outside the
// server's store lock.
func TestPresentingRenewsACredentialAboutToExpire(t *testing.T) {
	store, _ := entityStore(t)
	w := generateTestWallet(t)
	server := NewServer(w, 0, nil)
	server.SetStore(store)
	replacement := generateTestCredential(t, w)

	var credentialRequests int
	var renewedUnderLock bool
	var serverURL string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			_ = json.NewEncoder(rw).Encode(renewalIssuerMetadata(serverURL))
		case strings.HasSuffix(r.URL.Path, "/nonce"):
			_ = json.NewEncoder(rw).Encode(map[string]any{"c_nonce": "renewal-nonce"})
		case strings.HasSuffix(r.URL.Path, "/token"):
			_ = json.NewEncoder(rw).Encode(map[string]any{"access_token": "fresh", "token_type": "Bearer"})
		case strings.HasSuffix(r.URL.Path, "/credential"):
			credentialRequests++
			if server.storeSyncMu.TryLock() {
				server.storeSyncMu.Unlock()
			} else {
				renewedUnderLock = true
			}
			_ = json.NewEncoder(rw).Encode(map[string]any{"credentials": []any{map[string]any{"credential": replacement}}})
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	serverURL = srv.URL

	expiring, err := w.IssueCredential(IssueOptions{
		Format: "sdjwt", VCT: "urn:test:expiring:1",
		Claims: map[string]any{"given_name": "Alice"}, ExpiresIn: 20 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	id := expiring.Credential.ID
	w.rememberRenewal(id, CredentialRenewal{RefreshToken: "refresh-1",
		Issuer: srv.URL, TokenEndpoint: srv.URL + "/token", CredentialEndpoint: srv.URL + "/credential",
	})
	if err := store.Save(w); err != nil {
		t.Fatal(err)
	}

	authReq := &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "n", ClientID: "verifier", ResponseType: "vp_token"}}
	if _, err := w.preparePresentation(authReq, []consent.Match{{
		CredentialID: id, QueryID: "q", Format: "dc+sd-jwt", SelectedKeys: []string{"given_name"},
	}}); err != nil {
		t.Fatalf("preparing the presentation: %v", err)
	}

	if credentialRequests != 1 {
		t.Errorf("the issuer saw %d credential requests, want 1", credentialRequests)
	}
	if renewedUnderLock {
		t.Error("the renewal called the issuer while holding the store lock")
	}
	reloaded, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	if stored, _ := reloaded.GetCredential(id); stored.Raw != replacement {
		t.Error("the renewed credential was not saved")
	}
}

// A refresh authenticates the client the same way the original issuance did.
func TestRenewCredentialAuthenticatesTheClient(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://wallet.example"
	original := generateTestCredential(t, w)
	renewed := generateTestCredential(t, w)

	var challenges int
	var sawAttestation, sawPoP, sawAssertion string
	newIssuer := func() *httptest.Server {
		var serverURL string
		mux := http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
			rw.Header().Set("Content-Type", "application/json")
			switch {
			case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
				_ = json.NewEncoder(rw).Encode(renewalIssuerMetadata(serverURL))
			case strings.HasSuffix(r.URL.Path, "/nonce"):
				_ = json.NewEncoder(rw).Encode(map[string]any{"c_nonce": "renewal-nonce"})
			case strings.HasSuffix(r.URL.Path, "/challenge"):
				challenges++
				_ = json.NewEncoder(rw).Encode(map[string]any{"attestation_challenge": "chal-1"})
			case strings.HasSuffix(r.URL.Path, "/token"):
				body, _ := io.ReadAll(r.Body)
				form, _ := url.ParseQuery(string(body))
				sawAttestation = r.Header.Get("OAuth-Client-Attestation")
				sawPoP = r.Header.Get("OAuth-Client-Attestation-PoP")
				sawAssertion = form.Get("client_assertion")
				_ = json.NewEncoder(rw).Encode(map[string]any{
					"access_token": "fresh", "token_type": "Bearer", "expires_in": 300,
				})
			case strings.HasSuffix(r.URL.Path, "/credential"):
				_ = json.NewEncoder(rw).Encode(map[string]any{"credentials": []any{map[string]any{"credential": renewed}}})
			default:
				rw.WriteHeader(http.StatusNotFound)
			}
		})
		srv := httptest.NewServer(mux)
		serverURL = srv.URL
		return srv
	}

	t.Run("wallet attestation", func(t *testing.T) {
		srv := newIssuer()
		defer srv.Close()
		challenges, sawAttestation, sawPoP, sawAssertion = 0, "", "", ""

		imported, err := w.ImportCredential(original)
		if err != nil {
			t.Fatal(err)
		}
		w.rememberRenewal(imported.ID, CredentialRenewal{RefreshToken: "refresh-1",
			Issuer: srv.URL, TokenEndpoint: srv.URL + "/token",
			CredentialEndpoint: srv.URL + "/credential",
			ClientID:           "https://wallet.example",
			ClientAuth: &ClientAuthentication{
				Method:            ClientAuthAttestation,
				Audience:          srv.URL,
				ChallengeEndpoint: srv.URL + "/challenge",
			},
		})
		if _, err := w.RenewCredential(imported.ID); err != nil {
			t.Fatalf("RenewCredential: %v", err)
		}
		if sawAttestation == "" || sawPoP == "" {
			t.Error("the refresh carried no client attestation")
		}
		// A challenge from issuance is stale, so the refresh fetches its own.
		if challenges != 1 {
			t.Errorf("the refresh fetched %d attestation challenges, want 1", challenges)
		}
	})

	t.Run("private_key_jwt", func(t *testing.T) {
		srv := newIssuer()
		defer srv.Close()
		challenges, sawAttestation, sawPoP, sawAssertion = 0, "", "", ""

		imported, err := w.ImportCredential(original)
		if err != nil {
			t.Fatal(err)
		}
		w.rememberRenewal(imported.ID, CredentialRenewal{RefreshToken: "refresh-1",
			Issuer: srv.URL, TokenEndpoint: srv.URL + "/token",
			CredentialEndpoint: srv.URL + "/credential",
			ClientID:           "wallet-1",
			ClientAuth: &ClientAuthentication{
				Method: ClientAuthPrivateKeyJWT, Audience: srv.URL,
			},
		})
		if _, err := w.RenewCredential(imported.ID); err != nil {
			t.Fatalf("RenewCredential: %v", err)
		}
		if sawAssertion == "" {
			t.Error("the refresh carried no client assertion")
		}
		if sawAttestation != "" || sawPoP != "" {
			t.Error("private_key_jwt authenticates in the form, not with an attestation on top")
		}
	})

	t.Run("nothing required", func(t *testing.T) {
		srv := newIssuer()
		defer srv.Close()
		challenges, sawAttestation, sawPoP, sawAssertion = 0, "", "", ""

		imported, err := w.ImportCredential(original)
		if err != nil {
			t.Fatal(err)
		}
		w.rememberRenewal(imported.ID, CredentialRenewal{RefreshToken: "refresh-1",
			Issuer: srv.URL, TokenEndpoint: srv.URL + "/token",
			CredentialEndpoint: srv.URL + "/credential",
		})
		if _, err := w.RenewCredential(imported.ID); err != nil {
			t.Fatalf("RenewCredential: %v", err)
		}
		if sawAttestation != "" || sawAssertion != "" {
			t.Error("an issuer that asked for no client authentication got one anyway")
		}
	})
}

func TestResolveClientAuthentication(t *testing.T) {
	w := generateTestWallet(t)
	ctx := clientAuthContext{
		tokenEndpoint: "https://issuer.example/token",
		oauthMeta: map[string]any{
			"issuer":                                "https://issuer.example",
			"challenge_endpoint":                    "https://issuer.example/challenge",
			"token_endpoint_auth_methods_supported": []any{"attest_jwt_client_auth"},
		},
	}

	auth := w.resolveClientAuthentication(detectTokenEndpointAuthMethod(ctx.oauthMeta), ctx)
	if auth == nil || auth.Method != ClientAuthAttestation {
		t.Fatalf("an attesting issuer resolved to %+v", auth)
	}
	if auth.Audience != "https://issuer.example" || auth.ChallengeEndpoint != "https://issuer.example/challenge" {
		t.Errorf("the attestation does not carry what rebuilding it needs: %+v", auth)
	}

	private := clientAuthContext{tokenEndpoint: ctx.tokenEndpoint, oauthMeta: map[string]any{
		"issuer":                                "https://issuer.example",
		"token_endpoint_auth_methods_supported": []any{"private_key_jwt"},
	}}
	auth = w.resolveClientAuthentication(detectTokenEndpointAuthMethod(private.oauthMeta), private)
	if auth == nil || auth.Method != ClientAuthPrivateKeyJWT {
		t.Fatalf("a private_key_jwt issuer resolved to %+v", auth)
	}

	plain := clientAuthContext{tokenEndpoint: ctx.tokenEndpoint, oauthMeta: map[string]any{}}
	if auth := w.resolveClientAuthentication("", plain); auth != nil {
		t.Errorf("an issuer that asked for nothing resolved to %+v", auth)
	}

	// HAIP in strict mode always authenticates the client, even when the
	// issuer advertises no method.
	w.RequireHAIP = true
	w.ValidationMode = ValidationModeStrict
	if auth := w.resolveClientAuthentication("", plain); auth == nil || auth.Method != ClientAuthAttestation {
		t.Errorf("HAIP strict did not authenticate the client: %+v", auth)
	}

	// In debug mode the wallet still attests and warns. An issuer may require
	// an attestation without advertising it (ABCA-07 §10.1).
	w.ValidationMode = ValidationModeDebug
	if auth := w.resolveClientAuthentication("", plain); auth == nil || auth.Method != ClientAuthAttestation {
		t.Errorf("HAIP debug should attest a silent issuer, got %+v", auth)
	}
	if !hasWarningContaining(w, "advertises no token endpoint client authentication") {
		t.Error("expected a warning about the missing client-authentication advertisement")
	}

	// An issuer that lists only "none" gets no client authentication, with a
	// warning.
	explicitNone := clientAuthContext{tokenEndpoint: ctx.tokenEndpoint, oauthMeta: map[string]any{
		"token_endpoint_auth_methods_supported": []any{"none"},
	}}
	if auth := w.resolveClientAuthentication("", explicitNone); auth != nil {
		t.Errorf("HAIP debug should not attest an explicit-none issuer, got %+v", auth)
	}
	if !hasWarningContaining(w, "unauthenticated access") {
		t.Error("expected a warning about the issuer offering only unauthenticated access")
	}
}

// A refresh error shows the issuer's OAuth error description.
func TestRefreshReportsWhatTheIssuerSaid(t *testing.T) {
	w := generateTestWallet(t)
	var serverURL string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer") {
			_ = json.NewEncoder(rw).Encode(renewalIssuerMetadata(serverURL))
			return
		}
		rw.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(rw).Encode(map[string]any{
			"error":             "invalid_grant",
			"error_description": "Invalid authorization code",
		})
	}))
	defer srv.Close()
	serverURL = srv.URL

	imported, err := w.ImportCredential(generateTestCredential(t, w))
	if err != nil {
		t.Fatal(err)
	}
	w.rememberRenewal(imported.ID, CredentialRenewal{RefreshToken: "refresh-1",
		Issuer: srv.URL, TokenEndpoint: srv.URL + "/token",
		CredentialEndpoint: srv.URL + "/credential",
	})

	_, err = w.RenewCredential(imported.ID)
	if err == nil {
		t.Fatal("a refused refresh reported success")
	}
	want := "renewing the access token: invalid_grant: Invalid authorization code"
	if err.Error() != want {
		t.Errorf("error = %q, want %q", err.Error(), want)
	}
}

// A refresh error without OAuth error fields shows the response body.
func TestRefreshReportsANonOAuthRefusal(t *testing.T) {
	w := generateTestWallet(t)
	var serverURL string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer") {
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(renewalIssuerMetadata(serverURL))
			return
		}
		http.Error(rw, "gateway is on fire", http.StatusBadGateway)
	}))
	defer srv.Close()
	serverURL = srv.URL

	imported, err := w.ImportCredential(generateTestCredential(t, w))
	if err != nil {
		t.Fatal(err)
	}
	w.rememberRenewal(imported.ID, CredentialRenewal{RefreshToken: "refresh-1",
		Issuer: srv.URL, TokenEndpoint: srv.URL + "/token",
		CredentialEndpoint: srv.URL + "/credential",
	})

	_, err = w.RenewCredential(imported.ID)
	if err == nil || !strings.Contains(err.Error(), "gateway is on fire") {
		t.Errorf("error = %v, want the body of a refusal that is not an OAuth error", err)
	}
}

func proofNonce(raw any) string {
	compact, _ := raw.(string)
	parts := strings.Split(compact, ".")
	if len(parts) != 3 {
		return ""
	}
	payloadJSON, err := format.DecodeBase64URL(parts[1])
	if err != nil {
		return ""
	}
	var payload map[string]any
	if err := json.Unmarshal(payloadJSON, &payload); err != nil {
		return ""
	}
	nonce, _ := payload["nonce"].(string)
	return nonce
}

// OpenID4VCI §8.2: credential_identifier is "REQUIRED when an Authorization
// Details of type openid_credential was returned from the Token Response. It
// MUST NOT be used otherwise", and credential_configuration_id "MUST NOT be
// used" when a credential_identifiers parameter was returned.
func TestRenewCredentialNamesTheCredentialTheTokenResponseAllows(t *testing.T) {
	for _, tc := range []struct {
		name                 string
		authorizationDetails []any
		wantIdentifier       string
		wantConfiguration    string
	}{
		{
			name:              "no authorization details",
			wantConfiguration: "cfg",
		},
		{
			name: "credential identifiers returned",
			authorizationDetails: []any{map[string]any{
				"type":                        "openid_credential",
				"credential_configuration_id": "cfg",
				"credential_identifiers":      []any{"dataset-1"},
			}},
			wantIdentifier: "dataset-1",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := generateTestWallet(t)
			original := generateTestCredential(t, w)
			renewed := generateTestCredential(t, w)

			var serverURL string
			var request map[string]any
			srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				rw.Header().Set("Content-Type", "application/json")
				switch {
				case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
					_ = json.NewEncoder(rw).Encode(renewalIssuerMetadata(serverURL))
				case strings.HasSuffix(r.URL.Path, "/nonce"):
					_ = json.NewEncoder(rw).Encode(map[string]any{"c_nonce": "renewal-nonce"})
				case strings.HasSuffix(r.URL.Path, "/token"):
					resp := map[string]any{"access_token": "fresh", "token_type": "Bearer"}
					if tc.authorizationDetails != nil {
						resp["authorization_details"] = tc.authorizationDetails
					}
					_ = json.NewEncoder(rw).Encode(resp)
				case strings.HasSuffix(r.URL.Path, "/credential"):
					_ = json.NewDecoder(r.Body).Decode(&request)
					_ = json.NewEncoder(rw).Encode(map[string]any{"credentials": []any{map[string]any{"credential": renewed}}})
				default:
					rw.WriteHeader(http.StatusNotFound)
				}
			}))
			defer srv.Close()
			serverURL = srv.URL

			imported, err := w.ImportCredential(original)
			if err != nil {
				t.Fatal(err)
			}
			w.rememberRenewal(imported.ID, CredentialRenewal{RefreshToken: "refresh-1",
				Issuer: srv.URL, TokenEndpoint: srv.URL + "/token",
				CredentialEndpoint: srv.URL + "/credential", ConfigurationID: "cfg",
			})
			if _, err := w.RenewCredential(imported.ID); err != nil {
				t.Fatalf("RenewCredential: %v", err)
			}

			identifier, _ := request["credential_identifier"].(string)
			configuration, _ := request["credential_configuration_id"].(string)
			if identifier != tc.wantIdentifier {
				t.Errorf("credential_identifier = %q, want %q", identifier, tc.wantIdentifier)
			}
			if configuration != tc.wantConfiguration {
				t.Errorf("credential_configuration_id = %q, want %q", configuration, tc.wantConfiguration)
			}
		})
	}
}

// A renewal requests a credential, so a strict wallet with --arf checks the
// issuer first and doesn't request it from one without a registration.
func TestStrictARFRefusesARenewalFromAnUnregisteredIssuer(t *testing.T) {
	w := generateTestWallet(t)
	w.RequireARF = true
	w.ValidationMode = ValidationModeStrict
	original := generateTestCredential(t, w)

	var serverURL string
	credentialRequests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			_ = json.NewEncoder(rw).Encode(renewalIssuerMetadata(serverURL))
		case strings.HasSuffix(r.URL.Path, "/token"):
			_ = json.NewEncoder(rw).Encode(map[string]any{"access_token": "fresh", "token_type": "Bearer"})
		case strings.HasSuffix(r.URL.Path, "/credential"):
			credentialRequests++
			rw.WriteHeader(http.StatusInternalServerError)
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	serverURL = srv.URL

	imported, err := w.ImportCredential(original)
	if err != nil {
		t.Fatal(err)
	}
	w.rememberRenewal(imported.ID, CredentialRenewal{RefreshToken: "refresh-1",
		Issuer: srv.URL, TokenEndpoint: srv.URL + "/token",
		CredentialEndpoint: srv.URL + "/credential", ConfigurationID: "cfg",
	})
	_, err = w.RenewCredential(imported.ID)
	if err == nil || !strings.Contains(err.Error(), "ARF ISSU_3") {
		t.Fatalf("RenewCredential: %v, want the ARF findings", err)
	}
	if credentialRequests != 0 {
		t.Errorf("the wallet requested the credential %d times", credentialRequests)
	}
}

// A failed renewal keeps the credential's status. A revoked credential stays
// revoked.
func TestAFailedRenewalKeepsTheStatus(t *testing.T) {
	w := generateTestWallet(t)
	w.IssuerURL = "https://issuer.example"
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	result, err := w.IssueCredential(IssueOptions{Format: "sdjwt", VCT: "urn:example:badge:1", Claims: map[string]any{"level": "gold"}})
	if err != nil {
		t.Fatal(err)
	}
	id := result.Credential.ID
	if _, ok := w.SetCredentialStatus(id, 1); !ok {
		t.Fatal("the credential has no status entry")
	}
	w.rememberRenewal(id, CredentialRenewal{RefreshToken: "refresh-1", Issuer: srv.URL, TokenEndpoint: srv.URL + "/token", CredentialEndpoint: srv.URL + "/credential"})

	if _, err := NewServer(w, 0, nil).RenewCredential(id); err == nil {
		t.Fatal("a refused renewal reported success")
	}
	if entry, _ := w.StatusEntryFor(id); entry.Status != 1 {
		t.Errorf("status %d after the failed renewal, want 1", entry.Status)
	}
}

// Strict --arf checks the issuer before the token request, so a refused
// renewal keeps its refresh token.
func TestStrictARFRefusesARenewalBeforeTheTokenRequest(t *testing.T) {
	w := generateTestWallet(t)
	w.RequireARF = true
	w.ValidationMode = ValidationModeStrict
	var serverURL string
	tokenRequests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/token") {
			tokenRequests++
		}
		_ = json.NewEncoder(rw).Encode(renewalIssuerMetadata(serverURL))
	}))
	defer srv.Close()
	serverURL = srv.URL

	imported, err := w.ImportCredential(generateTestCredential(t, w))
	if err != nil {
		t.Fatal(err)
	}
	w.rememberRenewal(imported.ID, CredentialRenewal{RefreshToken: "refresh-1",
		Issuer: srv.URL, TokenEndpoint: srv.URL + "/token",
		CredentialEndpoint: srv.URL + "/credential", ConfigurationID: "cfg",
	})
	if _, err := w.RenewCredential(imported.ID); err == nil || tokenRequests != 0 {
		t.Errorf("err %v after %d token requests, want the refusal before the first", err, tokenRequests)
	}
}

// Renewing a batch replaces every copy. A copy that kept the old validity
// would still rotate to verifiers.
func TestRenewCredentialRenewsTheWholeBatch(t *testing.T) {
	w := generateTestWallet(t)
	var serverURL string
	var proofsSeen int
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			metadata := renewalIssuerMetadata(serverURL)
			metadata["batch_credential_issuance"] = map[string]any{"batch_size": 10}
			_ = json.NewEncoder(rw).Encode(metadata)
		case strings.HasSuffix(r.URL.Path, "/nonce"):
			_ = json.NewEncoder(rw).Encode(map[string]any{"c_nonce": "renewal-nonce"})
		case strings.HasSuffix(r.URL.Path, "/token"):
			_ = json.NewEncoder(rw).Encode(map[string]any{"access_token": "fresh", "token_type": "Bearer"})
		case strings.HasSuffix(r.URL.Path, "/credential"):
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			proofs, _ := body["proofs"].(map[string]any)
			jwts, _ := proofs["jwt"].([]any)
			proofsSeen = len(jwts)
			credentials := make([]any, 0, len(jwts))
			for _, proof := range jwts {
				jwk, _ := decodeJWTPart(t, proof.(string), 0)["jwk"].(map[string]any)
				pub, _, err := ecdsaPublicKeyFromJWK(ValidationModeDebug, jwk["x"].(string), jwk["y"].(string))
				if err != nil {
					t.Fatalf("proof key: %v", err)
				}
				credentials = append(credentials, map[string]any{"credential": sdJWTBoundTo(t, w, pub)})
			}
			_ = json.NewEncoder(rw).Encode(map[string]any{"credentials": credentials})
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	serverURL = srv.URL

	keys := []*ecdsa.PrivateKey{w.HolderKey, testKey(t), testKey(t)}
	old := map[string]bool{}
	var entries []any
	for _, key := range keys {
		raw := sdJWTBoundTo(t, w, &key.PublicKey)
		old[raw] = true
		entries = append(entries, map[string]any{"credential": raw})
	}
	primary := storeTestResponse(t, w, keys, map[string]any{"credentials": entries})
	w.rememberRenewal(primary.ID, CredentialRenewal{RefreshToken: "refresh-1",
		Issuer: srv.URL, TokenEndpoint: srv.URL + "/token",
		CredentialEndpoint: srv.URL + "/credential", ConfigurationID: "cfg",
	})

	if _, err := w.RenewCredential(primary.ID); err != nil {
		t.Fatalf("RenewCredential: %v", err)
	}
	if proofsSeen != 3 {
		t.Errorf("renewal sent %d proofs, want one per copy of the batch of 3", proofsSeen)
	}
	var group []StoredCredential
	for _, c := range w.GetCredentials() {
		if c.BatchGroup == primary.BatchGroup {
			group = append(group, c)
		}
	}
	if len(group) != 3 {
		t.Fatalf("batch holds %d copies after renewal, want 3", len(group))
	}
	for _, c := range group {
		if old[c.Raw] {
			t.Errorf("copy %s still holds a credential from before the renewal", c.ID)
		}
	}
}

// The issuer retires a rotated refresh token. A renewal that fails after the
// token request keeps the new token in storage, on the CLI as on a server.
func TestLocalRenewalSavesARotatedRefreshTokenAfterAFailure(t *testing.T) {
	store := NewWalletStore(t.TempDir())
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	var serverURL string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			_ = json.NewEncoder(rw).Encode(renewalIssuerMetadata(serverURL))
		case strings.HasSuffix(r.URL.Path, "/token"):
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"access_token": "fresh", "token_type": "Bearer",
				"refresh_token": "refresh-2", "expires_in": 300,
			})
		default:
			rw.WriteHeader(http.StatusInternalServerError)
		}
	}))
	defer srv.Close()
	serverURL = srv.URL

	imported, err := w.ImportCredential(generateTestCredential(t, w))
	if err != nil {
		t.Fatal(err)
	}
	w.rememberRenewal(imported.ID, CredentialRenewal{RefreshToken: "refresh-1", Issuer: srv.URL, TokenEndpoint: srv.URL + "/token", CredentialEndpoint: srv.URL + "/credential", ConfigurationID: "cfg"})
	if err := store.Save(w); err != nil {
		t.Fatal(err)
	}

	if _, err := NewManagement(w, store).RenewCredential(imported.ID); err == nil {
		t.Fatal("the renewal succeeded against a failing credential endpoint")
	}
	reloaded, err := store.LoadOrCreate()
	if err != nil {
		t.Fatal(err)
	}
	cred, ok := reloaded.GetCredential(imported.ID)
	if !ok || cred.Renewal == nil || cred.Renewal.RefreshToken != "refresh-2" {
		t.Fatalf("stored renewal after the failure: %+v", cred.Renewal)
	}
}
