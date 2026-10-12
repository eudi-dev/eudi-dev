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
	"sync"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
)

// deferringIssuer answers HTTP 202 with transaction_id and interval while the
// credential is pending (OpenID4VCI 1.0 §9.2). It releases the credential after
// pendingRounds polls.
func deferringIssuer(t *testing.T, w *Wallet, pendingRounds int, intervalSeconds int) (*httptest.Server, string, func() int) {
	t.Helper()

	credRaw := generateTestCredential(t, w)
	var serverURL string
	var mu sync.Mutex
	polls := 0

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":            serverURL,
				"credential_endpoint":          serverURL + "/credential",
				"deferred_credential_endpoint": serverURL + "/deferred",
				"token_endpoint":               serverURL + "/token",
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{"format": "dc+sd-jwt", "vct": "urn:test:credential"},
				},
			})

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/token"):
			json.NewEncoder(rw).Encode(map[string]any{
				"access_token": "test-access-token", "token_type": "Bearer", "c_nonce": "test-c-nonce",
			})

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/credential"):
			json.NewEncoder(rw).Encode(map[string]any{
				"transaction_id": "test-transaction",
				"interval":       intervalSeconds,
			})

		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/deferred"):
			mu.Lock()
			polls++
			current := polls
			mu.Unlock()

			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			if body["transaction_id"] != "test-transaction" {
				rw.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(rw).Encode(map[string]string{"error": "invalid_transaction_id"})
				return
			}
			if current <= pendingRounds {
				rw.WriteHeader(http.StatusAccepted)
				json.NewEncoder(rw).Encode(map[string]any{
					"transaction_id": "test-transaction",
					"interval":       intervalSeconds,
				})
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
	offerURI := "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))

	return srv, offerURI, func() int {
		mu.Lock()
		defer mu.Unlock()
		return polls
	}
}

func TestProcessCredentialOffer_DeferredWithoutEndpoint(t *testing.T) {
	w := generateTestWallet(t)
	credRaw := generateTestCredential(t, w)
	var serverURL string

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":   serverURL,
				"credential_endpoint": serverURL + "/credential",
				"token_endpoint":      serverURL + "/token",
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{"format": "dc+sd-jwt", "vct": "urn:test:credential"},
				},
			})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/token"):
			json.NewEncoder(rw).Encode(map[string]any{
				"access_token": "t", "token_type": "Bearer", "c_nonce": "n",
			})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/credential"):
			json.NewEncoder(rw).Encode(map[string]any{"transaction_id": "test-transaction"})
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	serverURL = srv.URL
	_ = credRaw

	offer := map[string]any{
		"credential_issuer":            serverURL,
		"credential_configuration_ids": []string{"test-config"},
		"grants": map[string]any{
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
				"pre-authorized_code": "c",
			},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	offerURI := "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	_, err := w.ProcessCredentialOffer(offerURI)
	if err == nil || !strings.Contains(err.Error(), "deferred_credential_endpoint") {
		t.Fatalf("error = %v, want it to name the missing deferred_credential_endpoint", err)
	}
}

func TestDeferredIssuancePending(t *testing.T) {
	for _, tc := range []struct {
		name         string
		out          map[string]any
		wantPending  bool
		wantInterval time.Duration
	}{
		{
			name:        "the transaction handed back with an interval",
			out:         map[string]any{"transaction_id": "t", "interval": float64(3)},
			wantPending: true, wantInterval: 3 * time.Second,
		},
		{
			name:        "the transaction handed back without an interval falls back",
			out:         map[string]any{"transaction_id": "t"},
			wantPending: true, wantInterval: deferredPollInterval,
		},
		{
			name:        "transaction_id alongside a credential is not pending",
			out:         map[string]any{"transaction_id": "t", "credentials": []any{map[string]any{"credential": "abc"}}},
			wantPending: false,
		},
		{
			name:        "a credential is not pending",
			out:         map[string]any{"credentials": []any{map[string]any{"credential": "abc"}}},
			wantPending: false,
		},
		{
			name:        "an error is not pending",
			out:         map[string]any{"error": "invalid_token"},
			wantPending: false,
		},
		{
			name:        "the draft-era issuance_pending error is not a pending signal",
			out:         map[string]any{"error": "issuance_pending", "interval": float64(7)},
			wantPending: false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pending, interval := deferredIssuancePending(tc.out)
			if pending != tc.wantPending {
				t.Fatalf("pending = %v, want %v", pending, tc.wantPending)
			}
			if pending && interval != tc.wantInterval {
				t.Errorf("interval = %s, want %s", interval, tc.wantInterval)
			}
		})
	}
}

// A deferred transaction returns at once, so consent and CLI callers do not
// wait through the issuer's interval.
func TestProcessCredentialOffer_DeferredIsRecordedNotWaitedOut(t *testing.T) {
	w := generateTestWallet(t)
	// The offer flow leaves polling to the background collector.
	srv, offerURI, polls := deferringIssuer(t, w, 1000, 3600)
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	started := time.Now()
	result, err := w.ProcessCredentialOffer(offerURI)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
	if !result.Pending {
		t.Fatalf("result = %+v, want it reported as pending", result)
	}
	if result.TransactionID == "" {
		t.Error("a pending result should carry the transaction id")
	}
	if elapsed > 5*time.Second {
		t.Errorf("the flow took %s, want it to return without waiting out the deferral", elapsed)
	}
	if got := polls(); got != 0 {
		t.Errorf("deferred endpoint was called %d times during the offer flow, want 0", got)
	}
	if got := len(w.DeferredIssuanceList()); got != 1 {
		t.Fatalf("wallet holds %d pending issuances, want 1", got)
	}
	if w.DeferredIssuanceList()[0].Interval() != time.Hour {
		t.Errorf("interval = %s, want the issuer's 1h", w.DeferredIssuanceList()[0].Interval())
	}
}

// Deferral is recorded when the request carried batch proofs too.
func TestProcessCredentialOffer_DeferredWithBatchAdvertised(t *testing.T) {
	w := generateTestWallet(t)
	var serverURL string
	credEndpointCalls := 0

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":            serverURL,
				"credential_endpoint":          serverURL + "/credential",
				"deferred_credential_endpoint": serverURL + "/deferred",
				"token_endpoint":               serverURL + "/token",
				"batch_credential_issuance":    map[string]any{"batch_size": 10},
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{
						"format": "dc+sd-jwt", "vct": "urn:test:credential",
						"proof_types_supported": map[string]any{
							"jwt": map[string]any{
								"proof_signing_alg_values_supported": []any{"ES256"},
								"key_attestations_required": map[string]any{
									"key_storage":         []any{"iso_18045_high"},
									"user_authentication": []any{"iso_18045_high"},
								},
							},
						},
					},
				},
			})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/token"):
			json.NewEncoder(rw).Encode(map[string]any{
				"access_token": "test-access-token", "token_type": "Bearer", "c_nonce": "test-c-nonce",
			})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/credential"):
			credEndpointCalls++
			rw.WriteHeader(http.StatusAccepted)
			json.NewEncoder(rw).Encode(map[string]any{
				"transaction_id": "test-transaction",
				"interval":       3600,
				"c_nonce":        "test-c-nonce",
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
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
				"pre-authorized_code": "test-pre-auth-code",
			},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	offerURI := "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	result, err := w.ProcessCredentialOffer(offerURI)
	if err != nil {
		t.Fatalf("ProcessCredentialOffer: %v", err)
	}
	if !result.Pending {
		t.Fatalf("result = %+v, want it recorded as a pending deferred issuance", result)
	}
	if got := len(w.DeferredIssuanceList()); got != 1 {
		t.Fatalf("wallet holds %d pending issuances, want 1", got)
	}
	if credEndpointCalls != 1 {
		t.Errorf("credential endpoint called %d times, want 1", credEndpointCalls)
	}
}

// A failure after the credential response shows in the activity log.
func TestProcessCredentialOffer_FailureIsLogged(t *testing.T) {
	w := generateTestWallet(t)
	var serverURL string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":   serverURL,
				"credential_endpoint": serverURL + "/credential",
				"token_endpoint":      serverURL + "/token",
				"credential_configurations_supported": map[string]any{
					"test-config": map[string]any{"format": "dc+sd-jwt", "vct": "urn:test:credential"},
				},
			})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/token"):
			json.NewEncoder(rw).Encode(map[string]any{"access_token": "t", "token_type": "Bearer", "c_nonce": "n"})
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/credential"):
			json.NewEncoder(rw).Encode(map[string]any{"unexpected": "shape"})
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
			"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{"pre-authorized_code": "c"},
		},
	}
	offerJSON, _ := json.Marshal(offer)
	offerURI := "openid-credential-offer://?credential_offer=" + url.QueryEscape(string(offerJSON))

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	if _, err := w.ProcessCredentialOffer(offerURI); err == nil {
		t.Fatal("expected the offer to fail")
	}
	found := false
	for _, e := range w.GetLog() {
		if !e.Success && strings.Contains(e.Detail, "did not finish") {
			found = true
		}
	}
	if !found {
		t.Fatal("expected a failed activity log entry naming that issuance did not finish")
	}
}

// Renewal settings stay with the credential, since the issuance flow ends long
// before a refresh is needed.
func TestIssuanceRemembersHowToRenew(t *testing.T) {
	w := generateTestWallet(t)
	credRaw := generateTestCredential(t, w)

	w.Credentials = append(w.Credentials, StoredCredential{ID: "cred-1", Format: "dc+sd-jwt", Raw: credRaw})

	w.rememberRenewal("cred-1", "refresh-1", CredentialRenewal{
		Issuer: "https://issuer.example", TokenEndpoint: "https://issuer.example/token",
		CredentialEndpoint: "https://issuer.example/credential", ConfigurationID: "cfg", UseDPoP: true,
	})
	stored, _ := w.GetCredential("cred-1")
	if !stored.CanRenew() {
		t.Fatalf("the credential cannot be renewed: %+v", stored.Renewal)
	}
	if stored.Renewal.RefreshToken != "refresh-1" {
		t.Errorf("refresh token = %q", stored.Renewal.RefreshToken)
	}

	// Without a refresh token no renewal settings are stored, so the credential
	// does not look renewable.
	w.Credentials = append(w.Credentials, StoredCredential{ID: "cred-2", Format: "dc+sd-jwt", Raw: credRaw})
	w.rememberRenewal("cred-2", "", CredentialRenewal{
		Issuer: "https://issuer.example", TokenEndpoint: "https://issuer.example/token",
		CredentialEndpoint: "https://issuer.example/credential",
	})
	if stored, _ := w.GetCredential("cred-2"); stored.CanRenew() || stored.Renewal != nil {
		t.Error("a credential without a refresh token was recorded as renewable")
	}
}

// §9.1 holds a Deferred Credential Request to the same encryption as the one
// that started the issuance: "The Client MAY encrypt the request when
// encryption_required is false and MUST do so when encryption_required is
// true", and it "MUST [provide its encryption parameters] when
// encryption_required is true. Note that this object will be used for
// encrypting the response, regardless of what was sent in the initial
// Credential Request. If it is not included encryption will not be performed."
// An issuer that requires encryption never answers a plaintext poll with the
// credential.
func TestDeferredCredentialRequestIsEncryptedWhenTheIssuerRequiresIt(t *testing.T) {
	w := generateTestWallet(t)
	credRaw := generateTestCredential(t, w)

	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	pubJWK := mock.PublicKeyJWKMap(&issuerKey.PublicKey)

	var serverURL string
	var contentType string
	var deferredRequest map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":            serverURL,
				"credential_endpoint":          serverURL + "/credential",
				"deferred_credential_endpoint": serverURL + "/deferred",
				"credential_request_encryption": map[string]any{
					"jwks": map[string]any{"keys": []any{map[string]any{
						"kty": pubJWK["kty"], "crv": pubJWK["crv"],
						"x": pubJWK["x"], "y": pubJWK["y"],
						"kid": "issuer-enc-key", "use": "enc", "alg": "ECDH-ES",
					}}},
					"enc_values_supported": []any{"A256GCM"},
					"encryption_required":  true,
				},
				"credential_response_encryption": map[string]any{
					"alg_values_supported": []any{"ECDH-ES"},
					"enc_values_supported": []any{"A128GCM"},
					"encryption_required":  true,
				},
			})

		case strings.HasSuffix(r.URL.Path, "/deferred"):
			contentType = r.Header.Get("Content-Type")
			body, _ := io.ReadAll(r.Body)
			decrypted, err := DecryptCompactJWE(strings.TrimSpace(string(body)), issuerKey)
			if err != nil {
				rw.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(rw).Encode(map[string]any{"error": "invalid_encryption_parameters"})
				return
			}
			_ = json.Unmarshal([]byte(decrypted), &deferredRequest)
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"credentials": []any{map[string]any{"credential": credRaw}},
			})

		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	serverURL = srv.URL

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	server := NewServer(w, 0, func() {})
	pending, err := newDeferredIssuance(deferredContext{
		issuer:           srv.URL,
		configID:         "test-config",
		format:           "dc+sd-jwt",
		deferredEndpoint: srv.URL + "/deferred",
		accessToken:      "test-access-token",
		authScheme:       "Bearer",
		proofKeys:        []*ecdsa.PrivateKey{w.HolderKey},
	}, "test-transaction", time.Second)
	if err != nil {
		t.Fatalf("newDeferredIssuance: %v", err)
	}
	w.AddDeferredIssuance(pending)

	attempt := server.attemptDeferredCollection(*pending)
	if !attempt.Collected {
		t.Fatalf("the deferred credential was not collected: %+v", attempt)
	}
	if contentType != "application/jwt" {
		t.Errorf("Content-Type = %q, want application/jwt: the request must be encrypted", contentType)
	}
	if deferredRequest["transaction_id"] != "test-transaction" {
		t.Errorf("decrypted transaction_id = %v", deferredRequest["transaction_id"])
	}
	if _, present := deferredRequest["credential_response_encryption"]; !present {
		t.Errorf("the deferred request carries no credential_response_encryption: %v", deferredRequest)
	}
}

// Deferred records are saved before a request reload could replace them with
// older state.
func TestReloadKeepsUnpersistedDeferral(t *testing.T) {
	srv := newTestServer(t, true)
	store := NewWalletStore(t.TempDir())
	if _, err := store.LoadOrCreate(); err != nil {
		t.Fatalf("initializing store: %v", err)
	}
	srv.SetStore(store)

	srv.wallet.AddDeferredIssuance(&DeferredIssuance{
		ID:            "pending-1",
		TransactionID: "tx-1",
		Issuer:        "https://issuer.test.example",
		NextAttemptAt: time.Now().Add(time.Minute),
	})

	if err := srv.reloadFromStore(); err != nil {
		t.Fatalf("reloadFromStore: %v", err)
	}

	deferrals := srv.wallet.DeferredIssuanceList()
	if len(deferrals) != 1 || deferrals[0].ID != "pending-1" {
		t.Fatalf("a per-request reload wiped the just-recorded deferral: %+v", deferrals)
	}
}

// Collection resolves the display metadata again when it failed at offer time.
func TestDeferredCollectionRecoversAMissingDisplay(t *testing.T) {
	w := generateTestWallet(t)
	credRaw := generateTestCredential(t, w)

	var serverURL string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		switch {
		case strings.HasSuffix(r.URL.Path, "/.well-known/openid-credential-issuer"):
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":            serverURL,
				"credential_endpoint":          serverURL + "/credential",
				"deferred_credential_endpoint": serverURL + "/deferred",
				"credential_configurations_supported": map[string]any{
					"cfg": map[string]any{
						"format": "dc+sd-jwt",
						"credential_metadata": map[string]any{
							"display": []any{map[string]any{
								"name": "Recovered Card", "locale": "en-US",
								"background_color": "#123456", "text_color": "#ffffff",
							}},
						},
					},
				},
			})
		case strings.HasSuffix(r.URL.Path, "/deferred"):
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"credentials": []any{map[string]any{"credential": credRaw}},
			})
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	serverURL = srv.URL

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	server := NewServer(w, 0, func() {})
	pending, err := newDeferredIssuance(deferredContext{
		issuer:           srv.URL,
		configID:         "cfg",
		format:           "dc+sd-jwt",
		deferredEndpoint: srv.URL + "/deferred",
		accessToken:      "test-access-token",
		authScheme:       "Bearer",
		proofKeys:        []*ecdsa.PrivateKey{w.HolderKey},
	}, "tx", time.Second)
	if err != nil {
		t.Fatalf("newDeferredIssuance: %v", err)
	}
	if pending.Display != nil {
		t.Fatal("precondition: the deferred record should carry no display")
	}
	w.AddDeferredIssuance(pending)

	if attempt := server.attemptDeferredCollection(*pending); !attempt.Collected {
		t.Fatalf("the deferred credential was not collected: %+v", attempt)
	}

	recovered := false
	for _, c := range w.GetCredentials() {
		if c.Display != nil && c.Display.Name == "Recovered Card" {
			recovered = true
		}
	}
	if !recovered {
		t.Fatal("the display was not recovered from the collection-time metadata")
	}
}

// An unchanged wallet file is not parsed again. An unsaved in-memory credential
// that survives the reload shows the file was not reread.
func TestReloadSkipsUnchangedStore(t *testing.T) {
	srv := newTestServer(t, true)
	store := NewWalletStore(t.TempDir())
	if _, err := store.LoadOrCreate(); err != nil {
		t.Fatalf("initializing store: %v", err)
	}
	if err := store.Save(srv.wallet); err != nil {
		t.Fatalf("saving wallet: %v", err)
	}
	srv.SetStore(store)

	if err := srv.reloadFromStore(); err != nil {
		t.Fatalf("reloadFromStore: %v", err)
	}
	before := len(srv.wallet.GetCredentials())

	srv.wallet.appendCredential(StoredCredential{ID: "in-memory", Format: "dc+sd-jwt", Raw: "x~"})

	if err := srv.reloadFromStore(); err != nil {
		t.Fatalf("reloadFromStore: %v", err)
	}
	if got := len(srv.wallet.GetCredentials()); got != before+1 {
		t.Fatalf("an unchanged store was reparsed (dropped the in-memory credential): got %d, want %d", got, before+1)
	}
}
