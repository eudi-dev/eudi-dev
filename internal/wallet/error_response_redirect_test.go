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
	"reflect"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
)

// OpenID4VP 1.0 §8.2: "If the Response URI has successfully processed the
// Authorization Response or Authorization Error Response, it MUST respond with an
// HTTP status code of 200 [...] When this parameter [redirect_uri] is present the
// Wallet MUST redirect the user agent to this URI."

const verifierContinueURI = "https://verifier.example/continue?error=access_denied"

func TestDenyFollowsTheVerifierRedirect(t *testing.T) {
	srv := newTestServer(t, false)
	verifier := newRedirectingVerifier(t, verifierContinueURI)

	rec := browserGet(t, srv, presentationAuthorizePath(t, verifier.URL))
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d: %s", rec.Code, rec.Body.String())
	}
	pending := waitForPendingRequest(t, srv.wallet)

	denyRec := browserAnswer(t, srv, rec, "/api/requests/"+pending.ID+"/deny", "")
	if denyRec.Code != http.StatusOK {
		t.Fatalf("deny failed: %d %s", denyRec.Code, denyRec.Body.String())
	}
	if got := verifier.received(t).Get("error"); got != "access_denied" {
		t.Fatalf("verifier received error %q, want access_denied", got)
	}
	result := decodeJSON(t, denyRec)
	if result["status"] != "denied" {
		t.Fatalf("status %v, want denied", result["status"])
	}
	if result["redirect_uri"] != verifierContinueURI {
		t.Fatalf("deny response redirect_uri %v, want %s", result["redirect_uri"], verifierContinueURI)
	}
}

// A request pasted into the wallet UI waits for consent in the same API call.
func TestDenyOfAPastedRequestReturnsTheVerifierRedirect(t *testing.T) {
	srv := newTestServer(t, false)
	verifier := newRedirectingVerifier(t, verifierContinueURI)

	body, err := json.Marshal(map[string]any{
		"uri":         strings.Replace(presentationAuthorizePath(t, verifier.URL), "/authorize", "openid4vp://authorize", 1),
		"interactive": true,
	})
	if err != nil {
		t.Fatalf("marshaling body: %v", err)
	}
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- serverRequest(t, srv, "POST", "/api/presentations", string(body)) }()

	pending := waitForPendingRequest(t, srv.wallet)
	denyRec := serverRequest(t, srv, "POST", "/api/requests/"+pending.ID+"/deny", "")
	// The verifier accepted the error response, so the answer names only the
	// outcome and the redirect.
	want := map[string]any{"status": "denied", "redirect_uri": verifierContinueURI}
	if got := decodeJSON(t, denyRec); !reflect.DeepEqual(got, want) {
		t.Fatalf("deny response %v, want %v", got, want)
	}

	rec := <-done
	if got := decodeJSON(t, rec)["redirect_uri"]; got != verifierContinueURI {
		t.Fatalf("presentation response redirect_uri %v, want %s", got, verifierContinueURI)
	}
}

func TestNoMatchBrowserNavigationFollowsTheVerifierRedirect(t *testing.T) {
	srv := newTestServer(t, true)
	verifier := newRedirectingVerifier(t, verifierContinueURI)

	rec := browserGet(t, srv, "/authorize?"+unsatisfiableRequest(t, verifier.URL).Encode())

	if got := verifier.received(t).Get("error"); got != "access_denied" {
		t.Fatalf("verifier received error %q, want access_denied", got)
	}
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != verifierContinueURI {
		t.Fatalf("Location %q, want %s", got, verifierContinueURI)
	}
}

func TestNoMatchAPIResponseCarriesTheVerifierRedirect(t *testing.T) {
	srv := newTestServer(t, true)
	verifier := newRedirectingVerifier(t, verifierContinueURI)

	body, err := json.Marshal(map[string]any{
		"uri":         "openid4vp://authorize?" + unsatisfiableRequest(t, verifier.URL).Encode(),
		"interactive": true,
	})
	if err != nil {
		t.Fatalf("marshaling body: %v", err)
	}
	rec := serverRequest(t, srv, "POST", "/api/presentations", string(body))

	result := decodeJSON(t, rec)
	if result["status"] != "no_match" {
		t.Fatalf("status %v, want no_match", result["status"])
	}
	if result["redirect_uri"] != verifierContinueURI {
		t.Fatalf("redirect_uri %v, want %s", result["redirect_uri"], verifierContinueURI)
	}
}

func TestNextErrorOverrideAPIResponseCarriesTheVerifierRedirect(t *testing.T) {
	srv := newTestServer(t, true)
	verifier := newRedirectingVerifier(t, verifierContinueURI)
	srv.wallet.Consents().SetNextError(&consent.NextErrorOverride{Error: "access_denied"})

	rec := serverRequest(t, srv, "GET", presentationAuthorizePath(t, verifier.URL), "")

	if got := verifier.received(t).Get("error"); got != "access_denied" {
		t.Fatalf("verifier received error %q, want access_denied", got)
	}
	if got := decodeJSON(t, rec)["redirect_uri"]; got != verifierContinueURI {
		t.Fatalf("redirect_uri %v, want %s", got, verifierContinueURI)
	}
}

func TestAutoAcceptedAPIResponseCarriesTheVerifierRedirect(t *testing.T) {
	srv := newTestServer(t, true)
	verifier := newRedirectingVerifier(t, "https://verifier.example/continue?code=xyz")

	rec := serverRequest(t, srv, "GET", presentationAuthorizePath(t, verifier.URL), "")

	result := decodeJSON(t, rec)
	if result["status"] != "submitted" {
		t.Fatalf("status %v, want submitted", result["status"])
	}
	if result["redirect_uri"] != "https://verifier.example/continue?code=xyz" {
		t.Fatalf("redirect_uri %v, want the verifier's", result["redirect_uri"])
	}
}

// "If the response does not contain the redirect_uri parameter, the Wallet is not
// required to perform any further steps."
func TestDenyWithoutAVerifierRedirectStaysInTheWallet(t *testing.T) {
	srv := newTestServer(t, false)
	verifier := newCaptureVerifier(t)

	rec := browserGet(t, srv, presentationAuthorizePath(t, verifier.URL))
	pending := waitForPendingRequest(t, srv.wallet)

	denyRec := browserAnswer(t, srv, rec, "/api/requests/"+pending.ID+"/deny", "")
	if denyRec.Code != http.StatusOK {
		t.Fatalf("deny failed: %d %s", denyRec.Code, denyRec.Body.String())
	}
	if got := verifier.received(t).Get("error"); got != "access_denied" {
		t.Fatalf("verifier received error %q, want access_denied", got)
	}
	result := decodeJSON(t, denyRec)
	if _, ok := result["redirect_uri"]; result["status"] != "denied" || ok {
		t.Fatalf("deny response %v, want status denied without a redirect_uri", result)
	}
}

// API clients read a missing redirect_uri as no redirect.
func TestAutoAcceptedAPIResponseWithoutAVerifierRedirect(t *testing.T) {
	srv := newTestServer(t, true)
	verifier := newCaptureVerifier(t)

	rec := serverRequest(t, srv, "GET", presentationAuthorizePath(t, verifier.URL), "")

	result := decodeJSON(t, rec)
	if _, ok := result["redirect_uri"]; result["status"] != "submitted" || ok {
		t.Fatalf("response %v, want status submitted without a redirect_uri", result)
	}
}

func TestNoMatchBrowserNavigationWithoutAVerifierRedirectLandsOnTheWalletUI(t *testing.T) {
	srv := newTestServer(t, true)
	verifier := newCaptureVerifier(t)

	rec := browserGet(t, srv, "/authorize?"+unsatisfiableRequest(t, verifier.URL).Encode())

	if got := verifier.received(t).Get("error"); got != "access_denied" {
		t.Fatalf("verifier received error %q, want access_denied", got)
	}
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("expected 303, got %d: %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Location"); got != "/" {
		t.Fatalf("Location %q, want the wallet UI", got)
	}
}

// The override answers only a valid request. An invalid one gets no response
// at its response_uri (OpenID4VP 1.0 §8.5), and the override waits for the
// next request.
func TestNextErrorOverrideSkipsAnInvalidRequest(t *testing.T) {
	srv := newTestServer(t, true)
	verifier := newRedirectingVerifier(t, verifierContinueURI)
	srv.wallet.Consents().SetNextError(&consent.NextErrorOverride{Error: "access_denied"})

	valid := presentationAuthorizePath(t, verifier.URL)
	invalid, err := url.Parse(valid)
	if err != nil {
		t.Fatal(err)
	}
	q := invalid.Query()
	q.Set("response_mode", "unknown")
	invalid.RawQuery = q.Encode()
	if rec := serverRequest(t, srv, "GET", invalid.String(), ""); rec.Code != http.StatusBadRequest {
		t.Fatalf("invalid request answered %d %s, want 400", rec.Code, rec.Body.String())
	}

	serverRequest(t, srv, "GET", valid, "")
	if got := verifier.received(t).Get("error"); got != "access_denied" {
		t.Fatalf("verifier received error %q, want the override on the valid request", got)
	}
}
