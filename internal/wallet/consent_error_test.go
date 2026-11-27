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

	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
)

func TestDenyWithAChosenErrorSendsItToTheVerifier(t *testing.T) {
	srv := newTestServer(t, false)
	verifier := newCaptureVerifier(t)

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- authorizeRequest(t, srv, presentationParams(t, verifier.URL)) }()
	pending := waitForPendingRequest(t, srv.wallet)

	denyRec := serverRequest(t, srv, "POST", "/api/requests/"+pending.ID+"/deny",
		`{"error":"invalid_transaction_data","error_description":"The amount is too high"}`)
	if denyRec.Code != http.StatusOK {
		t.Fatalf("deny failed: %d %s", denyRec.Code, denyRec.Body.String())
	}
	<-done

	got := verifier.received(t)
	if got.Get("error") != "invalid_transaction_data" || got.Get("error_description") != "The amount is too high" {
		t.Fatalf("verifier received %v, want invalid_transaction_data with its description", got)
	}
}

func TestDenyWithoutABodySendsAccessDenied(t *testing.T) {
	srv := newTestServer(t, false)
	verifier := newCaptureVerifier(t)

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- authorizeRequest(t, srv, presentationParams(t, verifier.URL)) }()
	pending := waitForPendingRequest(t, srv.wallet)

	if denyRec := serverRequest(t, srv, "POST", "/api/requests/"+pending.ID+"/deny", ""); denyRec.Code != http.StatusOK {
		t.Fatalf("deny failed: %d %s", denyRec.Code, denyRec.Body.String())
	}
	<-done

	got := verifier.received(t)
	if got.Get("error") != "access_denied" || got.Get("error_description") != "User denied presentation" {
		t.Fatalf("verifier received %v, want access_denied", got)
	}
}

func TestDenyRefusesADescriptionWithoutAnError(t *testing.T) {
	srv := newTestServer(t, false)
	verifier := newCaptureVerifier(t)

	go authorizeRequest(t, srv, presentationParams(t, verifier.URL))
	pending := waitForPendingRequest(t, srv.wallet)

	denyRec := serverRequest(t, srv, "POST", "/api/requests/"+pending.ID+"/deny", `{"error_description":"no code"}`)
	if denyRec.Code != http.StatusBadRequest {
		t.Fatalf("deny answered %d, want 400: %s", denyRec.Code, denyRec.Body.String())
	}
	if req, _ := srv.wallet.Consents().Get(pending.ID); req.Status != consent.StatusPending {
		t.Fatalf("request status %q, want it still pending", req.Status)
	}
	serverRequest(t, srv, "POST", "/api/requests/"+pending.ID+"/deny", "")
}

// OpenID4VCI 1.0 gives the wallet no error response for an offer it declines.
func TestDenyRefusesAnErrorForACredentialOffer(t *testing.T) {
	srv := newTestServer(t, false)
	offer := consent.NewRequest(consent.TypeIssuance, "")
	if err := srv.wallet.Consents().Create(offer); err != nil {
		t.Fatalf("creating the offer consent: %v", err)
	}

	denyRec := serverRequest(t, srv, "POST", "/api/requests/"+offer.ID+"/deny", `{"error":"access_denied"}`)
	if denyRec.Code != http.StatusBadRequest {
		t.Fatalf("deny answered %d, want 400: %s", denyRec.Code, denyRec.Body.String())
	}
}

// With a person deciding, the override fills the dialog. The person still
// chooses the answer.
func TestNextErrorFillsTheInteractiveDialog(t *testing.T) {
	srv := newTestServer(t, false)
	verifier := newCaptureVerifier(t)
	serverRequest(t, srv, "POST", "/api/next-error", `{"error":"wallet_unavailable","error_description":"Busy"}`)

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- authorizeRequest(t, srv, presentationParams(t, verifier.URL)) }()
	pending := waitForPendingRequest(t, srv.wallet)

	doc := srv.wallet.Consents().DocFor(pending, nil)
	want := &consent.NextErrorOverride{Error: "wallet_unavailable", ErrorDescription: "Busy"}
	if got, _ := doc["next_error"].(*consent.NextErrorOverride); got == nil || *got != *want {
		t.Fatalf("dialog next_error = %v, want %v", doc["next_error"], want)
	}

	approveRec := serverRequest(t, srv, "POST", "/api/requests/"+pending.ID+"/approve", "{}")
	if approveRec.Code != http.StatusOK {
		t.Fatalf("approve failed: %d %s", approveRec.Code, approveRec.Body.String())
	}
	if rec := <-done; decodeJSON(t, rec)["status"] != "submitted" {
		t.Fatalf("presentation answered %s, want submitted", rec.Body.String())
	}
	if verifier.received(t).Get("vp_token") == "" {
		t.Fatal("verifier received no vp_token after approval")
	}

	// The dialog used the override up.
	go authorizeRequest(t, srv, presentationParams(t, verifier.URL))
	next := waitForPendingRequest(t, srv.wallet)
	if _, ok := srv.wallet.Consents().DocFor(next, nil)["next_error"]; ok {
		t.Fatal("the next dialog still offers the override")
	}
	serverRequest(t, srv, "POST", "/api/requests/"+next.ID+"/deny", "")
}

// A deny without a body sends the error that the dialog shows. A deny with a
// body without an error sends access_denied.
func TestDenyWithoutABodySendsTheNextError(t *testing.T) {
	for _, tc := range []struct {
		name, body, wantError string
	}{
		{"no body", "", "wallet_unavailable"},
		{"an empty body", "{}", "access_denied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := newTestServer(t, false)
			verifier := newCaptureVerifier(t)
			serverRequest(t, srv, "POST", "/api/next-error", `{"error":"wallet_unavailable","error_description":"Busy"}`)

			done := make(chan *httptest.ResponseRecorder, 1)
			go func() { done <- authorizeRequest(t, srv, presentationParams(t, verifier.URL)) }()
			pending := waitForPendingRequest(t, srv.wallet)

			if denyRec := serverRequest(t, srv, "POST", "/api/requests/"+pending.ID+"/deny", tc.body); denyRec.Code != http.StatusOK {
				t.Fatalf("deny failed: %d %s", denyRec.Code, denyRec.Body.String())
			}
			<-done
			if got := verifier.received(t).Get("error"); got != tc.wantError {
				t.Fatalf("verifier received %q, want %s", got, tc.wantError)
			}
		})
	}
}

func TestDCAPIDenyWithAChosenErrorReturnsIt(t *testing.T) {
	srv := newTestServer(t, false)
	body, err := json.Marshal(map[string]any{
		"digital": map[string]any{
			"requests": []any{
				map[string]any{"protocol": "openid4vp-v1-unsigned", "data": map[string]any{
					"response_type": "vp_token",
					"response_mode": "dc_api",
					"nonce":         "browser-nonce",
					"dcql_query":    pidDCQLQuery(),
				}},
			},
		},
	})
	if err != nil {
		t.Fatalf("marshaling browser request: %v", err)
	}

	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		req := httptest.NewRequest("POST", "/api/dc-api", strings.NewReader(string(body)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Origin", "https://rp.example")
		rec := httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		done <- rec
	}()
	pending := waitForPendingRequest(t, srv.wallet)

	if !pending.DCAPI {
		t.Fatal("the dialog does not know the request came through the Digital Credentials API")
	}
	if denyRec := serverRequest(t, srv, "POST", "/api/requests/"+pending.ID+"/deny", `{"error":"invalid_client","error_description":"Unknown verifier"}`); denyRec.Code != http.StatusOK {
		t.Fatalf("deny failed: %d %s", denyRec.Code, denyRec.Body.String())
	}
	rec := <-done
	data, _ := decodeJSON(t, rec)["data"].(map[string]any)
	// OpenID4VP 1.0 Appendix A.4 returns the error code alone.
	if len(data) != 1 || data["error"] != "invalid_client" {
		t.Fatalf("browser result %s, want only the error invalid_client", rec.Body.String())
	}
}

// OpenID4VCI 1.1 §6.2.1.1 sends the error to the issuer in openid4vp_response.
func TestInteractiveAuthorizationSendsTheChosenError(t *testing.T) {
	w := newInteractiveWallet(t)
	w.AutoAccept = false
	issuer := newInteractiveIssuer(t, w)

	go func() {
		pending := waitForPendingRequest(t, w)
		if pending.Type != consent.TypeIssuancePresentation {
			t.Errorf("pending request type %q, want %q", pending.Type, consent.TypeIssuancePresentation)
		}
		if _, ok := w.Consents().Resolve(pending.ID, consent.StatusDenied); !ok {
			t.Error("the presentation consent was already resolved")
		}
		pending.ResultCh <- consent.Result{Error: &consent.NextErrorOverride{Error: "invalid_scope", ErrorDescription: "Not this one"}}
	}()
	if _, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url)); err != nil {
		t.Fatalf("ProcessCredentialOffer() error = %v", err)
	}

	response := interactionResponse(t, issuer)
	if response["error"] != "invalid_scope" || response["error_description"] != "Not this one" {
		t.Fatalf("openid4vp_response = %v, want invalid_scope with its description", response)
	}
}

// Auto-accept answers the issuer's presentation with the override itself.
func TestInteractiveAuthorizationAnswersWithTheNextErrorInAutoAccept(t *testing.T) {
	w := newInteractiveWallet(t)
	issuer := newInteractiveIssuer(t, w)
	w.Consents().SetNextError(nil, &consent.NextErrorOverride{Error: "wallet_unavailable"})

	if _, err := w.ProcessCredentialOffer(interactiveOfferURI(issuer.url)); err != nil {
		t.Fatalf("ProcessCredentialOffer() error = %v", err)
	}

	if got := interactionResponse(t, issuer)["error"]; got != "wallet_unavailable" {
		t.Fatalf("openid4vp_response error = %v, want wallet_unavailable", got)
	}
}

func interactionResponse(t *testing.T, issuer *interactiveIssuer) map[string]any {
	t.Helper()
	var response map[string]any
	if err := json.Unmarshal([]byte(issuer.intermediateForm.Get("openid4vp_response")), &response); err != nil {
		t.Fatalf("openid4vp_response is not a JSON object: %v", err)
	}
	return response
}

func presentationParams(t *testing.T, verifierURL string) url.Values {
	t.Helper()
	return url.Values{
		"client_id":     {"https://verifier.example"},
		"response_type": {"vp_token"},
		"nonce":         {"nonce"},
		"state":         {"state"},
		"response_uri":  {verifierURL},
		"dcql_query":    {dcqlQueryParam(t, pidDCQLQuery())},
	}
}

// ADR-0011: on a shared wallet the error override of one browser does not
// answer the presentation of another.
func TestTheNextErrorGoesToTheBrowserThatSetIt(t *testing.T) {
	srv := newTestServer(t, true)
	as := func(who caller, req *http.Request) *httptest.ResponseRecorder {
		t.Helper()
		who.apply(req)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}
	alice, bob := caller{cookie: "alice"}, caller{cookie: "bob"}
	set := httptest.NewRequest(http.MethodPost, "/api/next-error", strings.NewReader(`{"error":"wallet_unavailable"}`))
	set.Header.Set("Content-Type", "application/json")
	if rec := as(alice, set); rec.Code != http.StatusOK {
		t.Fatalf("next-error: %d %s", rec.Code, rec.Body.String())
	}

	bobVerifier := newCaptureVerifier(t)
	as(bob, httptest.NewRequest(http.MethodGet, "/authorize?"+presentationParams(t, bobVerifier.URL).Encode(), nil))
	if got := bobVerifier.received(t); got.Get("vp_token") == "" || got.Get("error") != "" {
		t.Fatalf("bob's verifier received %v, want a vp_token", got)
	}

	aliceVerifier := newCaptureVerifier(t)
	as(alice, httptest.NewRequest(http.MethodGet, "/authorize?"+presentationParams(t, aliceVerifier.URL).Encode(), nil))
	if got := aliceVerifier.received(t).Get("error"); got != "wallet_unavailable" {
		t.Fatalf("alice's verifier received error %q, want wallet_unavailable", got)
	}
}

// A tab that the CLI opened sends the browser's cookie and the CLI's owner.
// The dialog of a later flow with only the cookie still offers its override,
// and the dialog of another browser does not.
func TestTheNextErrorFillsOnlyTheDialogOfItsBrowser(t *testing.T) {
	srv := newTestServer(t, false)
	verifier := newCaptureVerifier(t)
	as := func(who caller, req *http.Request) *httptest.ResponseRecorder {
		t.Helper()
		who.apply(req)
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}
	set := httptest.NewRequest(http.MethodPost, "/api/next-error", strings.NewReader(`{"error":"wallet_unavailable"}`))
	set.Header.Set("Content-Type", "application/json")
	if rec := as(caller{cookie: "alice", owner: "alice-cli"}, set); rec.Code != http.StatusOK {
		t.Fatalf("next-error: %d %s", rec.Code, rec.Body.String())
	}

	dialogOf := func(who caller) map[string]any {
		t.Helper()
		go as(who, httptest.NewRequest(http.MethodGet, "/authorize?"+presentationParams(t, verifier.URL).Encode(), nil))
		pending := waitForPendingRequest(t, srv.wallet)
		doc := srv.wallet.Consents().DocFor(pending, nil)
		if rec := as(who, httptest.NewRequest(http.MethodPost, "/api/requests/"+pending.ID+"/deny", nil)); rec.Code != http.StatusOK {
			t.Fatalf("deny: %d %s", rec.Code, rec.Body.String())
		}
		return doc
	}
	if got, ok := dialogOf(caller{cookie: "bob"})["next_error"]; ok {
		t.Fatalf("bob's dialog offers %v, want no error", got)
	}
	if got, _ := dialogOf(caller{cookie: "alice"})["next_error"].(*consent.NextErrorOverride); got == nil || got.Error != "wallet_unavailable" {
		t.Fatalf("alice's dialog offers %v, want wallet_unavailable", got)
	}
}
