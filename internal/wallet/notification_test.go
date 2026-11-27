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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
)

// notificationIssuer is a mock issuer with a Notification Endpoint that
// accepts every notification. sent returns the Notification Requests it
// received.
func notificationIssuer(t *testing.T, w *Wallet) (offerURI string, sent func() []map[string]any) {
	t.Helper()
	return notificationIssuerWith(t, w, mockIssuerOpts{acceptsNotification: true})
}

func notificationIssuerWith(t *testing.T, w *Wallet, opts mockIssuerOpts) (offerURI string, sent func() []map[string]any) {
	t.Helper()
	var mu sync.Mutex
	var bodies []map[string]any
	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		tokenCNonce:         "test-c-nonce",
		refusesNotification: opts.refusesNotification,
		acceptsNotification: opts.acceptsNotification,
		credentialResponse: map[string]any{
			"credentials":     []any{map[string]any{"credential": generateTestCredential(t, w)}},
			"notification_id": "note-1",
		},
		captureNotification: func(_ *http.Request, raw []byte) {
			var body map[string]any
			_ = json.Unmarshal(raw, &body)
			mu.Lock()
			bodies = append(bodies, body)
			mu.Unlock()
		},
	})
	t.Cleanup(srv.Close)
	return offerURI, func() []map[string]any {
		mu.Lock()
		defer mu.Unlock()
		return append([]map[string]any(nil), bodies...)
	}
}

// OpenID4VCI 1.0 §11.1: credential_failure tells the issuer that the
// issuance was unsuccessful, so the wallet keeps nothing.
func TestAChosenFailureLeavesTheCredentialOutAndTellsTheIssuer(t *testing.T) {
	w := generateTestWallet(t)
	offerURI, sent := notificationIssuer(t, w)

	result, err := w.ProcessCredentialOfferWithOptions(offerURI, OfferOptions{
		Notification: &oid4vc.Notification{Event: oid4vc.NotificationFailure, EventDescription: "Storage is full"},
	})
	if err != nil {
		t.Fatalf("ProcessCredentialOfferWithOptions: %v", err)
	}
	if !result.Discarded || result.CredentialID != "" {
		t.Fatalf("result = %+v, want a discarded credential without an ID", result)
	}
	if result.Notification == nil || result.Notification.Event != oid4vc.NotificationFailure {
		t.Fatalf("result notification = %+v, want credential_failure", result.Notification)
	}
	if creds := w.GetCredentials(); len(creds) != 0 {
		t.Fatalf("wallet holds %d credentials, want none", len(creds))
	}
	bodies := sent()
	if len(bodies) != 1 {
		t.Fatalf("issuer received %d notifications, want 1", len(bodies))
	}
	if bodies[0]["notification_id"] != "note-1" || bodies[0]["event"] != oid4vc.NotificationFailure || bodies[0]["event_description"] != "Storage is full" {
		t.Fatalf("notification = %v, want credential_failure with its description for note-1", bodies[0])
	}
	assertWalletLogEvent(t, w.GetLog(), "credential_discarded")
}

// A chosen credential_accepted stores the credential as usual and sends the
// chosen description.
func TestAChosenAcceptedEventStoresTheCredential(t *testing.T) {
	w := generateTestWallet(t)
	offerURI, sent := notificationIssuer(t, w)

	result, err := w.ProcessCredentialOfferWithOptions(offerURI, OfferOptions{
		Notification: &oid4vc.Notification{Event: oid4vc.NotificationAccepted, EventDescription: "Stored on the test device"},
	})
	if err != nil {
		t.Fatalf("ProcessCredentialOfferWithOptions: %v", err)
	}
	if result.Discarded || result.CredentialID == "" {
		t.Fatalf("result = %+v, want a stored credential", result)
	}
	if creds := w.GetCredentials(); len(creds) != 1 {
		t.Fatalf("wallet holds %d credentials, want the issued one", len(creds))
	}
	if bodies := sent(); len(bodies) != 1 || bodies[0]["event_description"] != "Stored on the test device" {
		t.Fatalf("notifications = %v, want credential_accepted with its description", bodies)
	}
}

// A chosen event that the issuer refuses still discards the credential. The
// result names no notification, because the issuer did not accept it.
func TestARefusedChosenFailureStillDiscardsTheCredential(t *testing.T) {
	w := generateTestWallet(t)
	offerURI, sent := notificationIssuerWith(t, w, mockIssuerOpts{refusesNotification: true})

	result, err := w.ProcessCredentialOfferWithOptions(offerURI, OfferOptions{
		Notification: &oid4vc.Notification{Event: oid4vc.NotificationFailure},
	})
	if err != nil {
		t.Fatalf("ProcessCredentialOfferWithOptions: %v", err)
	}
	if !result.Discarded || result.Notification != nil {
		t.Fatalf("result = %+v, want a discarded credential and no accepted notification", result)
	}
	if creds := w.GetCredentials(); len(creds) != 0 {
		t.Fatalf("wallet holds %d credentials, want none", len(creds))
	}
	if bodies := sent(); len(bodies) != 1 || bodies[0]["event"] != oid4vc.NotificationFailure {
		t.Fatalf("notifications = %v, want one credential_failure", bodies)
	}
	assertWalletLogEvent(t, w.GetLog(), "notification_failed")
}

// ADR-0011: on a shared wallet the override of one browser does not reach
// the offer of another.
func TestTheNotificationOverrideGoesToTheBrowserThatSetIt(t *testing.T) {
	srv := newTestServer(t, true)
	as := func(who caller, path, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		who.apply(req)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}
	alice, bob := caller{owner: "alice"}, caller{cookie: "bob"}
	if rec := as(alice, "/api/next-notification", `{"event":"credential_failure"}`); rec.Code != http.StatusOK {
		t.Fatalf("next-notification: %d %s", rec.Code, rec.Body.String())
	}

	bobOffer, bobSent := notificationIssuer(t, srv.wallet)
	if rec := as(bob, "/api/offers", `{"uri":"`+bobOffer+`"}`); rec.Code != http.StatusOK || decodeJSON(t, rec)["discarded"] == true {
		t.Fatalf("bob's offer: %d %s, want a stored credential", rec.Code, rec.Body.String())
	}
	if bodies := bobSent(); len(bodies) != 1 || bodies[0]["event"] != oid4vc.NotificationAccepted {
		t.Fatalf("bob's notifications = %v, want credential_accepted", bodies)
	}

	aliceOffer, aliceSent := notificationIssuer(t, srv.wallet)
	if rec := as(alice, "/api/offers", `{"uri":"`+aliceOffer+`"}`); rec.Code != http.StatusOK || decodeJSON(t, rec)["discarded"] != true {
		t.Fatalf("alice's offer: %d %s, want a discarded credential", rec.Code, rec.Body.String())
	}
	if bodies := aliceSent(); len(bodies) != 1 || bodies[0]["event"] != oid4vc.NotificationFailure {
		t.Fatalf("alice's notifications = %v, want credential_failure", bodies)
	}
}

// The override of POST /api/next-notification answers one offer without a
// dialog. The next offer sends credential_accepted again.
func TestTheNotificationOverrideAnswersOneOffer(t *testing.T) {
	w := generateTestWallet(t)
	w.Consents().SetNextNotification(nil, &oid4vc.Notification{Event: oid4vc.NotificationDeleted})

	first, sentFirst := notificationIssuer(t, w)
	result, err := w.ProcessCredentialOffer(first)
	if err != nil {
		t.Fatalf("first offer: %v", err)
	}
	if !result.Discarded {
		t.Fatalf("first result = %+v, want it discarded by the override", result)
	}
	if bodies := sentFirst(); len(bodies) != 1 || bodies[0]["event"] != oid4vc.NotificationDeleted {
		t.Fatalf("first notifications = %v, want credential_deleted", bodies)
	}

	second, sentSecond := notificationIssuer(t, w)
	if result, err = w.ProcessCredentialOffer(second); err != nil || result.Discarded {
		t.Fatalf("second offer = %+v, %v, want a stored credential", result, err)
	}
	if bodies := sentSecond(); len(bodies) != 1 || bodies[0]["event"] != oid4vc.NotificationAccepted {
		t.Fatalf("second notifications = %v, want credential_accepted", bodies)
	}
}

// §11 makes the Notification Endpoint optional. A chosen event for an issuer
// without one still discards, and the log says that nothing was sent.
func TestAChosenEventWithoutANotificationEndpointIsLogged(t *testing.T) {
	w := generateTestWallet(t)
	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		tokenCNonce: "test-c-nonce",
		credentialResponse: map[string]any{
			"credentials": []any{map[string]any{"credential": generateTestCredential(t, w)}},
		},
	})
	defer srv.Close()

	result, err := w.ProcessCredentialOfferWithOptions(offerURI, OfferOptions{
		Notification: &oid4vc.Notification{Event: oid4vc.NotificationFailure},
	})
	if err != nil {
		t.Fatalf("ProcessCredentialOfferWithOptions: %v", err)
	}
	if !result.Discarded || result.Notification != nil {
		t.Fatalf("result = %+v, want a discarded credential and no notification", result)
	}
	assertWalletLogEvent(t, w.GetLog(), "notification_skipped")
}

// The interactive dialog starts with the override and sends what the user
// approves with.
func TestTheOfferDialogSendsTheApprovedNotification(t *testing.T) {
	srv := newTestServer(t, false)
	offerURI, sent := notificationIssuer(t, srv.wallet)
	before := len(srv.wallet.GetCredentials())

	if rec := serverRequest(t, srv, "POST", "/api/next-notification", `{"event":"credential_failure","event_description":"Busy"}`); rec.Code != http.StatusOK {
		t.Fatalf("setting the override: %d %s", rec.Code, rec.Body.String())
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- serverRequest(t, srv, "POST", "/api/offers", `{"uri":"`+offerURI+`","interactive":true}`)
	}()
	pending := waitForPendingRequest(t, srv.wallet)
	if pending.Notification == nil || pending.Notification.Event != oid4vc.NotificationFailure || pending.Notification.EventDescription != "Busy" {
		t.Fatalf("dialog notification = %+v, want the override", pending.Notification)
	}

	approve := serverRequest(t, srv, "POST", "/api/requests/"+pending.ID+"/approve", `{"notification":{"event":"credential_accepted"}}`)
	if approve.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", approve.Code, approve.Body.String())
	}
	<-done

	if got := len(srv.wallet.GetCredentials()); got != before+1 {
		t.Fatalf("wallet holds %d credentials, want %d with the approved one", got, before+1)
	}
	if bodies := sent(); len(bodies) != 1 || bodies[0]["event"] != oid4vc.NotificationAccepted || bodies[0]["event_description"] != nil {
		t.Fatalf("notifications = %v, want credential_accepted without a description", bodies)
	}
}

// An approval without a notification sends the event the dialog shows.
func TestAnApprovalWithoutANotificationSendsThePreset(t *testing.T) {
	srv := newTestServer(t, false)
	offerURI, sent := notificationIssuer(t, srv.wallet)
	before := len(srv.wallet.GetCredentials())

	serverRequest(t, srv, "POST", "/api/next-notification", `{"event":"credential_deleted"}`)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- serverRequest(t, srv, "POST", "/api/offers", `{"uri":"`+offerURI+`","interactive":true}`)
	}()
	pending := waitForPendingRequest(t, srv.wallet)

	approve := serverRequest(t, srv, "POST", "/api/requests/"+pending.ID+"/approve", "{}")
	if approve.Code != http.StatusOK || decodeJSON(t, approve)["discarded"] != true {
		t.Fatalf("approve: %d %s, want a discarded credential", approve.Code, approve.Body.String())
	}
	<-done

	if got := len(srv.wallet.GetCredentials()); got != before {
		t.Fatalf("wallet holds %d credentials, want %d", got, before)
	}
	if bodies := sent(); len(bodies) != 1 || bodies[0]["event"] != oid4vc.NotificationDeleted {
		t.Fatalf("notifications = %v, want credential_deleted", bodies)
	}
}

func TestTheNotificationAPIsRefuseInvalidInput(t *testing.T) {
	srv := newTestServer(t, false)
	cases := []struct {
		name, path, body string
	}{
		{"an unknown event", "/api/next-notification", `{"event":"credential_stored"}`},
		{"a quote in the description", "/api/next-notification", `{"event":"credential_failure","event_description":"say \"no\""}`},
		{"an unknown event for an offer", "/api/offers", `{"uri":"openid-credential-offer://x","notification":{"event":"stored"}}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if rec := serverRequest(t, srv, "POST", tc.path, tc.body); rec.Code != http.StatusBadRequest {
				t.Fatalf("%s answered %d, want 400: %s", tc.path, rec.Code, rec.Body.String())
			}
		})
	}
	if rec := serverRequest(t, srv, "DELETE", "/api/next-notification", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("clearing the override: %d, want 204", rec.Code)
	}
}

// A presentation has no Notification Endpoint, so its approval refuses one.
func TestApprovingAPresentationRefusesANotification(t *testing.T) {
	srv := newTestServer(t, false)
	verifier := newCaptureVerifier(t)
	go authorizeRequest(t, srv, presentationParams(t, verifier.URL))
	pending := waitForPendingRequest(t, srv.wallet)

	rec := serverRequest(t, srv, "POST", "/api/requests/"+pending.ID+"/approve", `{"notification":{"event":"credential_accepted"}}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("approve answered %d, want 400: %s", rec.Code, rec.Body.String())
	}
	serverRequest(t, srv, "POST", "/api/requests/"+pending.ID+"/deny", "")
}

// A deferred issuance keeps the chosen event until the credential arrives.
// OpenID4VCI 1.0 §9.2 lets the Deferred Credential Response carry the
// notification_id.
func TestADeferredCredentialIsDiscardedWithTheChosenEvent(t *testing.T) {
	w := generateTestWallet(t)
	credRaw := generateTestCredential(t, w)
	var mu sync.Mutex
	var notified []map[string]any
	var issuerURL string
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-credential-issuer":
			_ = json.NewEncoder(rw).Encode(map[string]any{"credential_issuer": issuerURL, "notification_endpoint": issuerURL + "/notification"})
		case "/deferred":
			_ = json.NewEncoder(rw).Encode(map[string]any{"credentials": []any{map[string]any{"credential": credRaw}}, "notification_id": "deferred-note"})
		case "/notification":
			var body map[string]any
			_ = json.NewDecoder(r.Body).Decode(&body)
			mu.Lock()
			notified = append(notified, body)
			mu.Unlock()
			rw.WriteHeader(http.StatusNoContent)
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	issuerURL = srv.URL

	server := NewServer(w, 0, func() {})
	pending := pendingFor(t, w, srv.URL+"/deferred", 1)
	pending.Issuer = issuerURL
	pending.NextAttemptAt = time.Now().Add(-time.Second)
	pending.Notification = &oid4vc.Notification{Event: oid4vc.NotificationDeleted}
	w.AddDeferredIssuance(pending)

	server.collectDueDeferredCredentials(time.Now())

	if got := len(w.GetCredentials()); got != 0 {
		t.Fatalf("wallet holds %d credentials, want none", got)
	}
	if got := len(w.DeferredIssuanceList()); got != 0 {
		t.Fatalf("%d deferred issuances left, want the discarded one removed", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(notified) != 1 || notified[0]["notification_id"] != "deferred-note" || notified[0]["event"] != oid4vc.NotificationDeleted {
		t.Fatalf("notifications = %v, want credential_deleted for deferred-note", notified)
	}
}
