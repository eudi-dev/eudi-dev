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
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/apierror"
	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

func pidAuthorizeQuery(t *testing.T) string {
	t.Helper()
	verifier := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(verifier.Close)
	dcql, _ := json.Marshal(map[string]any{"credentials": []any{map[string]any{
		"id":     "pid",
		"format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
	}}})
	return url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"nonce":         {"nonce"},
		"state":         {"state"},
		"response_uri":  {verifier.URL},
		"dcql_query":    {string(dcql)},
	}.Encode()
}

func requireBusy(t *testing.T, name string, rec *httptest.ResponseRecorder) {
	t.Helper()
	var body apierror.Body
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != http.StatusServiceUnavailable || body.Error != apierror.TemporarilyUnavailable || rec.Header().Get("Retry-After") == "" {
		t.Errorf("%s: %d %s, Retry-After %q, want 503 temporarily_unavailable with Retry-After", name, rec.Code, rec.Body.String(), rec.Header().Get("Retry-After"))
	}
}

// Each request that waits for consent holds a flow until it times out. With
// the maximum number waiting, the wallet refuses to start another flow.
func TestServerRefusesFlowsWhileTooManyConsentsWait(t *testing.T) {
	srv := newTestServer(t, false)
	srv.wallet.Consents().SetMaxPending(1)
	if err := srv.wallet.Consents().Create(&consent.Request{ID: "waiting", Type: consent.TypePresentation, Status: consent.StatusPending}); err != nil {
		t.Fatal(err)
	}

	query := pidAuthorizeQuery(t)
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/authorize?"+query, nil))
	requireBusy(t, "presentation", rec)

	browser := httptest.NewRequest(http.MethodGet, "/authorize?"+query, nil)
	browser.Header.Set("Accept", "text/html")
	rec = httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, browser)
	requireBusy(t, "browser presentation", rec)

	issuer, offerURI := setupMockIssuer(t, srv.wallet, mockIssuerOpts{})
	defer issuer.Close()
	body, _ := json.Marshal(map[string]any{"uri": offerURI, "interactive": true})
	requireBusy(t, "offer", serverRequest(t, srv, http.MethodPost, "/api/offers", string(body)))

	if pending := srv.wallet.Consents().Pending(); len(pending) != 1 {
		t.Errorf("%d requests wait, want only the first", len(pending))
	}
}

// Visitors of a public demo share the wallet, so it lets fewer flows wait.
func TestDemoLowersTheConsentCap(t *testing.T) {
	srv := newTestServer(t, false)
	if got := srv.wallet.Consents().MaxPending(); got != consent.DefaultMaxPending {
		t.Fatalf("cap %d, want %d", got, consent.DefaultMaxPending)
	}
	if err := srv.SetDemo(DemoOptions{}); err != nil {
		t.Fatal(err)
	}
	if got := srv.wallet.Consents().MaxPending(); got != maxDemoPendingConsents {
		t.Errorf("demo cap %d, want %d", got, maxDemoPendingConsents)
	}
	if got := srv.wallet.Consents().MaxPendingPerOwner(); got != maxDemoPendingConsentsPerOwner {
		t.Errorf("demo cap per owner %d, want %d", got, maxDemoPendingConsentsPerOwner)
	}
}

// One visitor cannot take every waiting slot. Requests without an owner share
// one count, so the next unowned flow is refused while another owner still
// gets a slot.
func TestServerRefusesFlowsBeyondTheOwnerCap(t *testing.T) {
	srv := newTestServer(t, false)
	srv.wallet.Consents().SetMaxPendingPerOwner(1)
	if err := srv.wallet.Consents().Create(consent.NewRequest(consent.TypePresentation, "")); err != nil {
		t.Fatal(err)
	}

	query := pidAuthorizeQuery(t)
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/authorize?"+query, nil))
	requireBusy(t, "unowned presentation", rec)

	if err := srv.wallet.Consents().Create(consent.NewRequest(consent.TypePresentation, "visitor")); err != nil {
		t.Fatalf("another owner: %v", err)
	}
	if err := srv.wallet.Consents().Create(consent.NewRequest(consent.TypePresentation, "visitor")); !errors.Is(err, consent.ErrTooManyPending) {
		t.Errorf("second request of the same owner: %v, want ErrTooManyPending", err)
	}
}

// A flow that waits for sign-in at the issuer counts against its owner too.
func TestRunOfferRefusesSignInsBeyondTheOwnerCap(t *testing.T) {
	srv := newTestServer(t, false)
	srv.wallet.Consents().SetMaxPendingPerOwner(1)
	srv.trackPendingOffer(&pendingOffer{ID: "waiting", Owner: "visitor", CreatedAt: time.Now()})

	if _, _, err := srv.runOffer("not an offer", OfferOptions{Owner: "visitor"}); !errors.Is(err, consent.ErrTooManyPending) {
		t.Errorf("second sign-in of the same owner: %v, want ErrTooManyPending", err)
	}
	if _, _, err := srv.runOffer("not an offer", OfferOptions{Owner: "other"}); errors.Is(err, consent.ErrTooManyPending) {
		t.Errorf("another owner was refused: %v", err)
	}
}

// Giving up the sign-in ends the wait at once. Only the browser that started
// the flow can end it.
func TestCancellingASignInEndsTheFlow(t *testing.T) {
	srv := newTestServer(t, false)
	srv.wallet.BaseURL = "http://localhost:8085"
	flowOwner := "visitor"
	cancelled := make(chan struct{})
	p := &pendingOffer{ID: "offer", Owner: flowOwner, CreatedAt: time.Now(), cancelled: cancelled}
	srv.trackPendingOffer(p)
	prompts, unsubscribe := srv.wallet.Consents().SubscribeAuthorization(func(consent.AuthorizationPrompt) bool { return true })
	defer unsubscribe()
	outcome := make(chan error, 1)
	go func() {
		_, err := runAuthorizationCodeRequest(srv.wallet, "https://issuer.example/authorize", "client", "urn:request", nil,
			srv.wallet.BaseURL+"/callback", "state", "", consent.AuthorizationPrompt{Cancelled: cancelled}, false)
		p.complete(nil, err)
		outcome <- err
	}()
	<-prompts

	cancel := func(owner string) int {
		req := httptest.NewRequest(http.MethodDelete, "/api/offers/offer", nil)
		req.Header.Set("X-Eudi-Owner", owner)
		rec := httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		return rec.Code
	}
	if code := cancel("someone-else"); code != http.StatusNotFound {
		t.Errorf("another owner got %d, want 404", code)
	}
	for range 2 {
		if code := cancel(flowOwner); code != http.StatusNoContent {
			t.Errorf("the owner got %d, want 204", code)
		}
	}
	select {
	case err := <-outcome:
		if !errors.Is(err, errSignInCancelled) {
			t.Errorf("flow ended with %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the flow kept waiting")
	}
	rec := serverRequest(t, srv, http.MethodGet, "/api/offers/offer", "")
	var body struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body.Status != "cancelled" {
		t.Errorf("status %q (%v), want cancelled", body.Status, err)
	}
}
