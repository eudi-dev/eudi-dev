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
	"sync"
	"testing"
	"time"
)

func deferredCollectionIssuer(t *testing.T, credRaw string, pendingRounds, intervalSeconds int) (*httptest.Server, func() int) {
	t.Helper()
	var mu sync.Mutex
	polls := 0

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if serveIssuerMetadata(rw, r) {
			return
		}
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
			// §9.2: "If the Credential Issuer still requires more time, the
			// Deferred Credential Response MUST use the interval and
			// transaction_id parameters [...] and it MUST respond with the HTTP
			// status code 202".
			rw.WriteHeader(http.StatusAccepted)
			json.NewEncoder(rw).Encode(map[string]any{
				"transaction_id": "test-transaction",
				"interval":       intervalSeconds,
			})
			return
		}
		json.NewEncoder(rw).Encode(map[string]any{"credentials": []any{map[string]any{"credential": credRaw}}})
	}))

	return srv, func() int {
		mu.Lock()
		defer mu.Unlock()
		return polls
	}
}

// pendingFor records a deferred issuance by the issuer at the origin of
// endpoint.
func pendingFor(t *testing.T, w *Wallet, endpoint string, intervalSeconds int) *DeferredIssuance {
	t.Helper()
	pending, err := newDeferredIssuance(deferredTransaction{
		transactionID: "test-transaction",
		interval:      time.Duration(intervalSeconds) * time.Second,
		renewal:       CredentialRenewal{Issuer: derivedOrigin(endpoint), ConfigurationID: "test-config"},
		metadata:      map[string]any{"deferred_credential_endpoint": endpoint},
		format:        "dc+sd-jwt",
		grant:         &accessGrant{accessToken: "test-access-token", authScheme: "Bearer"},
		proofKeys:     []*ecdsa.PrivateKey{w.HolderKey},
	})
	if err != nil {
		t.Fatalf("newDeferredIssuance: %v", err)
	}
	return pending
}

// serveIssuerMetadata answers a request for the Credential Issuer Metadata of
// the test issuer that serves r.
func serveIssuerMetadata(rw http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != "/.well-known/openid-credential-issuer" {
		return false
	}
	issuer := "http://" + r.Host
	rw.Header().Set("Content-Type", "application/json")
	json.NewEncoder(rw).Encode(map[string]any{
		"credential_issuer":            issuer,
		"credential_endpoint":          issuer + "/credential",
		"deferred_credential_endpoint": issuer + "/deferred",
	})
	return true
}

func TestCollectDeferredNow_SkipsWhenCollectionInFlight(t *testing.T) {
	w := generateTestWallet(t)
	server := NewServer(w, 0, func() {})
	pending := pendingFor(t, w, "https://issuer.example/deferred", 1)
	w.AddDeferredIssuance(pending)

	if !server.beginDeferredCollection(pending.ID) {
		t.Fatal("expected to acquire the in-flight guard")
	}
	defer server.endDeferredCollection(pending.ID)

	attempt, ok := server.CollectDeferredNow(pending.ID)
	if !ok {
		t.Fatal("CollectDeferredNow should still find the record")
	}
	if !attempt.Pending {
		t.Fatalf("a collect that races an in-flight one should be skipped as pending, got %+v", attempt)
	}
	if got := len(w.GetCredentials()); got != 0 {
		t.Fatalf("no credential should be imported while a collection is in flight, got %d", got)
	}
}

func TestDeferredCollectionInFlightGuard(t *testing.T) {
	s := &Server{}
	if !s.beginDeferredCollection("id-1") {
		t.Fatal("first begin should win")
	}
	if s.beginDeferredCollection("id-1") {
		t.Fatal("second begin for the same id must not win while in flight")
	}
	if !s.beginDeferredCollection("id-2") {
		t.Fatal("a different id should be independent")
	}
	s.endDeferredCollection("id-1")
	if !s.beginDeferredCollection("id-1") {
		t.Fatal("after release the id can be collected again")
	}
}

// The poller collects a deferred credential once the issuer makes it available.
func TestDeferredPoller_CollectsWhenReady(t *testing.T) {
	w := generateTestWallet(t)
	credRaw := generateTestCredential(t, w)
	srv, polls := deferredCollectionIssuer(t, credRaw, 1, 1)
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	saves := 0
	server := NewServer(w, 0, func() { saves++ })
	pending := pendingFor(t, w, srv.URL, 1)
	pending.NextAttemptAt = time.Now().Add(-time.Second)
	w.AddDeferredIssuance(pending)

	server.collectDueDeferredCredentials(time.Now())
	if got := len(w.DeferredIssuanceList()); got != 1 {
		t.Fatalf("after a pending answer the wallet holds %d records, want 1", got)
	}
	if got := len(w.GetCredentials()); got != 0 {
		t.Fatalf("wallet holds %d credentials, want none yet", got)
	}
	rescheduled := w.DeferredIssuanceList()[0]
	if rescheduled.Attempts != 1 {
		t.Errorf("attempts = %d, want 1", rescheduled.Attempts)
	}
	if !rescheduled.NextAttemptAt.After(time.Now()) {
		t.Error("next attempt should have been pushed into the future")
	}

	server.collectDueDeferredCredentials(time.Now())
	if got := polls(); got != 1 {
		t.Errorf("issuer polled %d times, want 1 while the wait is not over", got)
	}

	server.collectDueDeferredCredentials(time.Now().Add(2 * time.Second))
	if got := len(w.DeferredIssuanceList()); got != 0 {
		t.Errorf("wallet still holds %d pending records, want 0", got)
	}
	creds := w.GetCredentials()
	if len(creds) != 1 {
		t.Fatalf("wallet holds %d credentials, want the collected one", len(creds))
	}
	if saves == 0 {
		t.Error("collecting a deferred credential should persist the wallet")
	}
	assertWalletLogEvent(t, w.GetLog(), "credential_imported")
}

// TestDeferredPoller_NotifiesAfterCollecting covers the notification for a
// collected deferred credential. OpenID4VCI 1.0 §8.3 lets the Deferred
// Credential Response carry its own notification_id. The wallet notifies the
// issuer the same way as for an immediately issued credential.
func TestDeferredPoller_NotifiesAfterCollecting(t *testing.T) {
	w := generateTestWallet(t)
	credRaw := generateTestCredential(t, w)

	var mu sync.Mutex
	var notified []string
	var issuerURL string

	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-credential-issuer":
			json.NewEncoder(rw).Encode(map[string]any{
				"credential_issuer":     issuerURL,
				"notification_endpoint": issuerURL + "/notification",
			})
		case "/deferred":
			json.NewEncoder(rw).Encode(map[string]any{
				"credentials":     []any{map[string]any{"credential": credRaw}},
				"notification_id": "deferred-notification",
			})
		case "/notification":
			var body map[string]any
			json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			notified = append(notified, fmt.Sprintf("%v/%v", body["notification_id"], body["event"]))
			mu.Unlock()
			rw.WriteHeader(http.StatusNoContent)
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	issuerURL = srv.URL

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	server := NewServer(w, 0, func() {})
	pending := pendingFor(t, w, srv.URL+"/deferred", 1)
	pending.Issuer = issuerURL
	pending.NextAttemptAt = time.Now().Add(-time.Second)
	w.AddDeferredIssuance(pending)

	server.collectDueDeferredCredentials(time.Now())

	if got := len(w.GetCredentials()); got != 1 {
		t.Fatalf("wallet holds %d credentials, want the collected one", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(notified) != 1 {
		t.Fatalf("notification endpoint called %d times, want 1", len(notified))
	}
	if notified[0] != "deferred-notification/credential_accepted" {
		t.Errorf("notification = %q, want deferred-notification/credential_accepted", notified[0])
	}
}

// Polling stops after a final error and the record keeps the reason.
func TestDeferredPoller_GivesUpOnFatalAnswers(t *testing.T) {
	for _, tc := range []struct {
		name  string
		error string
	}{
		{"rejected token", "invalid_token"},
		{"unknown transaction", "invalid_transaction_id"},
		// §9.3: "A wallet upon receiving this error SHOULD stop making
		// requests to the deferred credential endpoint".
		{"denied request", "credential_request_denied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := generateTestWallet(t)
			srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				if serveIssuerMetadata(rw, r) {
					return
				}
				rw.WriteHeader(http.StatusBadRequest)
				json.NewEncoder(rw).Encode(map[string]string{"error": tc.error})
			}))
			defer srv.Close()

			oldClient := httpClient
			httpClient = srv.Client()
			defer func() { httpClient = oldClient }()

			server := NewServer(w, 0, func() {})
			pending := pendingFor(t, w, srv.URL, 1)
			pending.NextAttemptAt = time.Now().Add(-time.Second)
			w.AddDeferredIssuance(pending)

			server.collectDueDeferredCredentials(time.Now())
			if got := len(w.DeferredIssuanceList()); got != 0 {
				t.Errorf("wallet still holds %d pending records, want it dropped", got)
			}
			assertWalletLogEvent(t, w.GetLog(), "issuance_deferred_abandoned")
		})
	}
}

func TestDeferredPoller_DropsExpiredRecords(t *testing.T) {
	w := generateTestWallet(t)
	polled := false
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		polled = true
		rw.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	server := NewServer(w, 0, func() {})
	pending := pendingFor(t, w, srv.URL, 1)
	pending.CreatedAt = time.Now().Add(-2 * deferredIssuanceMaxAge)
	pending.NextAttemptAt = time.Now().Add(-time.Second)
	w.AddDeferredIssuance(pending)

	server.collectDueDeferredCredentials(time.Now())
	if got := len(w.DeferredIssuanceList()); got != 0 {
		t.Errorf("wallet still holds %d expired records, want 0", got)
	}
	if polled {
		t.Error("an expired record should be dropped without troubling the issuer")
	}
}

// The deferred transaction and its proof keys are saved, so collection resumes
// after a restart.
func TestDeferredIssuance_SurvivesAStoreRoundTrip(t *testing.T) {
	dir := t.TempDir()
	store := NewWalletStore(dir)
	w, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}

	pending := pendingFor(t, w, "https://issuer.example/deferred", 42)
	w.AddDeferredIssuance(pending)
	if err := store.Save(w); err != nil {
		t.Fatalf("Save: %v", err)
	}

	reloaded, err := store.LoadOrCreate()
	if err != nil {
		t.Fatalf("LoadOrCreate after save: %v", err)
	}
	restored := reloaded.DeferredIssuanceList()
	if len(restored) != 1 {
		t.Fatalf("reloaded wallet holds %d pending issuances, want 1", len(restored))
	}
	if restored[0].TransactionID != "test-transaction" {
		t.Errorf("transaction_id = %q, want it preserved", restored[0].TransactionID)
	}
	if restored[0].Interval() != 42*time.Second {
		t.Errorf("interval = %s, want the issuer's 42s", restored[0].Interval())
	}
	keys, err := restored[0].ProofKeys()
	if err != nil {
		t.Fatalf("ProofKeys after reload: %v", err)
	}
	if len(keys) != 1 || !keys[0].PublicKey.Equal(&w.HolderKey.PublicKey) {
		t.Error("the proof key did not survive the round trip")
	}
}

func TestIsRetryableDeferredError(t *testing.T) {
	for _, tc := range []struct {
		name  string
		err   error
		retry bool
	}{
		{"network trouble", errString("connection refused"), true},
		{"server fault", deferredCredentialError{status: 503, description: "upstream unavailable"}, true},
		{"server fault naming a token", deferredCredentialError{status: 502, description: "invalid_token cache unavailable"}, true},
		{"rejected token", deferredCredentialError{status: 401, code: "invalid_token"}, false},
		{"unknown transaction", deferredCredentialError{status: 400, code: "invalid_transaction_id"}, false},
		{"denied request", deferredCredentialError{status: 400, code: "credential_request_denied"}, false},
		{"expired grant", deferredCredentialError{status: 400, code: "invalid_grant", description: "expired"}, false},
		{"refused response", finalDeferredError{errString("plaintext response")}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRetryableDeferredError(tc.err); got != tc.retry {
				t.Errorf("isRetryableDeferredError = %v, want %v", got, tc.retry)
			}
		})
	}
}

type errString string

func (e errString) Error() string { return string(e) }

func TestCollectDeferredNow(t *testing.T) {
	w := generateTestWallet(t)
	credRaw := generateTestCredential(t, w)
	srv, polls := deferredCollectionIssuer(t, credRaw, 1, 30)
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	server := NewServer(w, 0, func() {})
	pending := pendingFor(t, w, srv.URL, 30)
	pending.NextAttemptAt = time.Now().Add(30 * time.Second)
	w.AddDeferredIssuance(pending)

	attempt, ok := server.CollectDeferredNow(pending.ID)
	if !ok {
		t.Fatal("CollectDeferredNow did not find the pending issuance")
	}
	if !attempt.Pending || attempt.Collected {
		t.Fatalf("attempt = %+v, want it reported as still pending", attempt)
	}
	if attempt.Interval != "30s" {
		t.Errorf("interval = %q, want the issuer's 30s", attempt.Interval)
	}
	if polls() != 1 {
		t.Errorf("issuer polled %d times, want 1", polls())
	}

	attempt, ok = server.CollectDeferredNow(pending.ID)
	if !ok {
		t.Fatal("CollectDeferredNow did not find the pending issuance on the second try")
	}
	if !attempt.Collected {
		t.Fatalf("attempt = %+v, want the credential collected", attempt)
	}
	if attempt.Credential == nil || attempt.Credential.ID == "" {
		t.Error("a collected attempt should name the credential it imported")
	}
	if got := len(w.GetCredentials()); got != 1 {
		t.Errorf("wallet holds %d credentials, want the collected one", got)
	}
	if got := len(w.DeferredIssuanceList()); got != 0 {
		t.Errorf("wallet still holds %d pending records, want 0", got)
	}

	if _, ok := server.CollectDeferredNow("no-such-id"); ok {
		t.Error("an unknown id should not report a result")
	}
}

// Abandoning stops local polling without contacting the issuer.
func TestAbandonDeferredNow(t *testing.T) {
	w := generateTestWallet(t)
	polled := false
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		polled = true
		rw.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	saves := 0
	server := NewServer(w, 0, func() { saves++ })
	pending := pendingFor(t, w, srv.URL, 10)
	w.AddDeferredIssuance(pending)

	dropped, ok := server.AbandonDeferredNow(pending.ID)
	if !ok {
		t.Fatal("AbandonDeferredNow did not find the pending issuance")
	}
	if dropped.TransactionID != "test-transaction" {
		t.Errorf("dropped transaction = %q, want it reported back", dropped.TransactionID)
	}
	if got := len(w.DeferredIssuanceList()); got != 0 {
		t.Errorf("wallet still holds %d pending records, want 0", got)
	}
	if polled {
		t.Error("abandoning is the wallet's own decision and must not contact the issuer")
	}
	if saves == 0 {
		t.Error("abandoning should persist the wallet")
	}
	assertWalletLogEvent(t, w.GetLog(), "issuance_deferred_abandoned")

	if _, ok := server.AbandonDeferredNow(pending.ID); ok {
		t.Error("abandoning the same id twice should report nothing to drop")
	}
}

// This test starts the server, since calling the sweep directly cannot show
// that the background loop starts.
func TestDeferredPollerRunsFromTheServer(t *testing.T) {
	w := generateTestWallet(t)
	credRaw := generateTestCredential(t, w)
	srv, polls := deferredCollectionIssuer(t, credRaw, 0, 1)
	defer srv.Close()

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	server := NewServer(w, 0, nil)
	pending := pendingFor(t, w, srv.URL, 1)
	pending.NextAttemptAt = time.Now().Add(-time.Second)
	w.AddDeferredIssuance(pending)

	stop := server.StartBackgroundTasks()
	defer stop()

	// The poller stores the credential before it drops the pending record.
	deadline := time.Now().Add(5 * time.Second)
	for (len(w.GetCredentials()) == 0 || len(w.DeferredIssuanceList()) != 0) && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}

	if got := len(w.GetCredentials()); got != 1 {
		t.Fatalf("the running poller collected %d credentials after %d polls, want 1", got, polls())
	}
	if got := len(w.DeferredIssuanceList()); got != 0 {
		t.Errorf("wallet still holds %d pending records, want 0", got)
	}
}

// Deferred records take their credential type from issuer metadata, since
// offers carry only configuration IDs.
func TestDeferredIssuanceRecordsTheCredentialType(t *testing.T) {
	metadata := map[string]any{
		"credential_configurations_supported": map[string]any{
			"eudi-pid-sd-jwt-bdr-key-attestations": map[string]any{
				"format": "dc+sd-jwt",
				"vct":    "urn:eudi:pid:1",
			},
			"pid-mdoc": map[string]any{
				"format":  "mso_mdoc",
				"doctype": "eu.europa.ec.eudi.pid.1",
			},
		},
	}

	vct, docType := credentialTypeForConfiguration(metadata, "eudi-pid-sd-jwt-bdr-key-attestations")
	if vct != "urn:eudi:pid:1" || docType != "" {
		t.Errorf("sd-jwt configuration resolved to vct=%q doctype=%q", vct, docType)
	}

	vct, docType = credentialTypeForConfiguration(metadata, "pid-mdoc")
	if vct != "" || docType != "eu.europa.ec.eudi.pid.1" {
		t.Errorf("mdoc configuration resolved to vct=%q doctype=%q", vct, docType)
	}

	if vct, docType = credentialTypeForConfiguration(metadata, "unknown"); vct != "" || docType != "" {
		t.Errorf("unknown configuration resolved to vct=%q doctype=%q, want empty", vct, docType)
	}
	if vct, docType = credentialTypeForConfiguration(nil, "any"); vct != "" || docType != "" {
		t.Errorf("missing metadata resolved to vct=%q doctype=%q, want empty", vct, docType)
	}
}

// A rejected token that cannot be refreshed ends collection. Collection may
// outlast an access token by hours.
func TestDeferredGivesUpOnARejectedToken(t *testing.T) {
	for _, status := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		err := fmt.Errorf("deferred credential request: %w", deferredCredentialError{status: status})
		if isRetryableDeferredError(err) || !isAuthorizationRejected(err) {
			t.Errorf("HTTP %d is treated as retryable, so the wallet keeps asking with a token the issuer already refused", status)
		}
	}
	for _, status := range []int{http.StatusInternalServerError, http.StatusBadGateway} {
		if !isRetryableDeferredError(deferredCredentialError{status: status}) {
			t.Errorf("HTTP %d should stay retryable", status)
		}
	}
}

// A collection that starts from an outdated copy of the record does not ask
// the issuer again once the credential is collected.
func TestDeferredCollectionFromAStaleCopyDoesNotCollectTwice(t *testing.T) {
	w := generateTestWallet(t)
	credRaw := generateTestCredential(t, w)
	srv, polls := deferredCollectionIssuer(t, credRaw, 0, 1)
	defer srv.Close()
	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	server := NewServer(w, 0, func() {})
	pending := pendingFor(t, w, srv.URL, 1)
	w.AddDeferredIssuance(pending)
	snapshot := w.DeferredIssuanceList()[0]

	if attempt := server.attemptDeferredCollection(snapshot); !attempt.Collected {
		t.Fatalf("first collection = %+v, want collected", attempt)
	}
	if attempt := server.attemptDeferredCollection(snapshot); attempt.Collected {
		t.Errorf("second collection from the stale copy = %+v, want nothing collected", attempt)
	}
	if got := polls(); got != 1 {
		t.Errorf("issuer saw %d deferred requests, want 1", got)
	}
	if got := len(w.GetCredentials()); got != 1 {
		t.Errorf("wallet holds %d credentials, want 1", got)
	}
}

// §9.2: a response that defers again MUST be a 202 with interval and
// transaction_id. Debug mode keeps polling with a finding. Strict mode stops.
func TestDeferredPendingResponseWithout202(t *testing.T) {
	for _, mode := range []ValidationMode{ValidationModeDebug, ValidationModeStrict} {
		t.Run(string(mode), func(t *testing.T) {
			w := generateTestWallet(t)
			w.ValidationMode = mode
			srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				if serveIssuerMetadata(rw, r) {
					return
				}
				json.NewEncoder(rw).Encode(map[string]any{"transaction_id": "test-transaction"})
			}))
			defer srv.Close()
			oldClient := httpClient
			httpClient = srv.Client()
			defer func() { httpClient = oldClient }()

			server := NewServer(w, 0, func() {})
			pending := pendingFor(t, w, srv.URL, 1)
			w.AddDeferredIssuance(pending)
			attempt := server.attemptDeferredCollection(*pending)
			if mode == ValidationModeStrict {
				if !attempt.Abandoned {
					t.Errorf("strict attempt = %+v, want collection stopped", attempt)
				}
				return
			}
			if !attempt.Pending {
				t.Errorf("debug attempt = %+v, want still pending", attempt)
			}
			if !hasWarningContaining(w, "§9.2") {
				t.Error("debug mode did not report the deviation")
			}
		})
	}
}

// An expired access token is refreshed before collecting a deferred credential.
func TestDeferredCollectionRefreshesAnExpiredToken(t *testing.T) {
	w := generateTestWallet(t)
	credRaw := generateTestCredential(t, w)

	var refreshes, refusedWithOldToken int
	var srvURL string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if serveIssuerMetadata(rw, r) {
			return
		}
		switch {
		case strings.HasSuffix(r.URL.Path, "/token"):
			body, _ := io.ReadAll(r.Body)
			form, _ := url.ParseQuery(string(body))
			if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != "refresh-1" {
				rw.WriteHeader(http.StatusBadRequest)
				return
			}
			refreshes++
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{
				"access_token": "fresh-token", "token_type": "Bearer", "expires_in": 300,
			})
		case strings.HasSuffix(r.URL.Path, "/deferred"):
			if r.Header.Get("Authorization") != "Bearer fresh-token" {
				refusedWithOldToken++
				rw.WriteHeader(http.StatusForbidden)
				return
			}
			rw.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(rw).Encode(map[string]any{"credentials": []any{map[string]any{"credential": credRaw}}})
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	oldClient := httpClient
	httpClient = srv.Client()
	defer func() { httpClient = oldClient }()

	server := NewServer(w, 0, nil)
	pending := pendingFor(t, w, srvURL+"/deferred", 1)
	pending.NextAttemptAt = time.Now().Add(-time.Second)
	pending.AccessToken = "stale-token"
	pending.AuthScheme = "Bearer"
	pending.RefreshToken = "refresh-1"
	pending.TokenEndpoint = srvURL + "/token"
	pending.AccessTokenExpiresAt = time.Now().Add(-time.Minute)
	w.AddDeferredIssuance(pending)

	server.collectDueDeferredCredentials(time.Now())

	if refreshes != 1 {
		t.Errorf("the wallet refreshed %d times, want exactly one renewal", refreshes)
	}
	if refusedWithOldToken != 0 {
		t.Errorf("the wallet spent %d attempts on the expired token before renewing it", refusedWithOldToken)
	}
	if got := len(w.GetCredentials()); got != 1 {
		t.Fatalf("wallet holds %d credentials, want the collected one", got)
	}
	if got := len(w.DeferredIssuanceList()); got != 0 {
		t.Errorf("wallet still holds %d pending records, want 0", got)
	}
}

// A panic in one background task leaves the other tasks running.
func TestBackgroundTaskPanicDoesNotStopTheLoop(t *testing.T) {
	w := generateTestWallet(t)
	server := NewServer(w, 0, nil)

	var logged []string
	server.SetLogger(func(format string, args ...any) {
		logged = append(logged, fmt.Sprintf(format, args...))
	})

	ran := 0
	err := server.runBackgroundTask(backgroundTask{name: "explodes", every: time.Second, run: func(time.Time) error {
		panic("boom")
	}}, time.Now())
	if err == nil {
		t.Error("a panicking task reported success")
	}
	if err != nil && !strings.Contains(err.Error(), "boom") {
		t.Errorf("the panic value is missing from the error: %v", err)
	}
	if err := server.runBackgroundTask(backgroundTask{name: "works", every: time.Second, run: func(time.Time) error {
		ran++
		return nil
	}}, time.Now()); err != nil {
		t.Errorf("a healthy task after a panicking one failed: %v", err)
	}
	if ran != 1 {
		t.Error("a task after a panicking one did not run")
	}
	_ = logged
}

// The loop runs off the request path, so a slow task never delays a caller.
func TestBackgroundTasksRunOffTheRequestPath(t *testing.T) {
	w := generateTestWallet(t)
	server := NewServer(w, 0, nil)

	blocked := make(chan struct{})
	release := make(chan struct{})
	go func() {
		_ = server.runBackgroundTask(backgroundTask{name: "slow", every: time.Second, run: func(time.Time) error {
			close(blocked)
			<-release
			return nil
		}}, time.Now())
	}()
	<-blocked
	defer close(release)

	rec := httptest.NewRecorder()
	server.handleListCredentials(rec, httptest.NewRequest(http.MethodGet, "/api/credentials", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("serving a request during a background task returned %d", rec.Code)
	}
}

// A failed task runs again on the next tick. After repeated failures it is
// logged and abandoned.
func TestFailingBackgroundTaskIsRetriedThenAbandoned(t *testing.T) {
	w := generateTestWallet(t)
	server := NewServer(w, 0, nil)
	var logged []string
	server.SetLogger(func(format string, args ...any) {
		logged = append(logged, fmt.Sprintf(format, args...))
	})

	attempts := 0
	failing := backgroundTask{name: "always fails", every: time.Hour, run: func(time.Time) error {
		attempts++
		return fmt.Errorf("nope")
	}}

	// Calling the scheduler directly keeps ticker timing out of the test.
	state := taskState{}
	now := time.Now()
	for range maxTaskFailures + 3 {
		if state.abandoned {
			continue
		}
		if state.failures == 0 && !state.lastRun.IsZero() && now.Sub(state.lastRun) < failing.every {
			continue
		}
		state.lastRun = now
		if err := server.runBackgroundTask(failing, now); err != nil {
			state.failures++
			if state.failures >= maxTaskFailures {
				state.abandoned = true
			}
		}
		now = now.Add(backgroundTick)
	}

	if attempts != maxTaskFailures {
		t.Errorf("the task ran %d times, want %d: an hourly task that fails must retry on the next tick and stop at the limit", attempts, maxTaskFailures)
	}
	if !state.abandoned {
		t.Error("the task was never abandoned, so it would retry forever")
	}
	_ = logged
}

// OpenID4VCI 1.0 §9.1 applies the encryption rules of the Credential Request
// to the Deferred Credential Request, and the issuer checks need the metadata
// too. Without usable metadata the poller retries later in every mode instead
// of sending the request.
func TestDeferredCollectionWaitsForUsableMetadata(t *testing.T) {
	for _, mode := range []ValidationMode{ValidationModeStrict, ValidationModeDebug} {
		t.Run(string(mode), func(t *testing.T) {
			w := generateTestWallet(t)
			w.ValidationMode = mode
			polls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/.well-known/openid-credential-issuer" {
					rw.WriteHeader(http.StatusNotFound)
					return
				}
				polls++
				rw.WriteHeader(http.StatusAccepted)
			}))
			defer srv.Close()
			oldClient := httpClient
			httpClient = srv.Client()
			defer func() { httpClient = oldClient }()

			server := NewServer(w, 0, nil)
			pending := pendingFor(t, w, srv.URL+"/deferred", 1)
			pending.NextAttemptAt = time.Now().Add(-time.Second)
			w.AddDeferredIssuance(pending)

			server.collectDueDeferredCredentials(time.Now())
			if polls != 0 {
				t.Errorf("the wallet sent %d deferred requests without the issuer metadata", polls)
			}
			if list := w.DeferredIssuanceList(); len(list) != 1 || list[0].Attempts != 1 {
				t.Errorf("records %+v, want the issuance rescheduled", list)
			}
		})
	}
}
