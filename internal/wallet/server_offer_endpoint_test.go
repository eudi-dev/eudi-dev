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
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestCredentialOfferEndpoint_MissingParams(t *testing.T) {
	srv := newTestServer(t, true)

	w := serverRequest(t, srv, "GET", "/credential-offer", "")
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d: %s", w.Code, w.Body.String())
	}
}

func TestCredentialOfferEndpoint_CredentialOfferByValue(t *testing.T) {
	srv := newTestServer(t, true)

	issuer, offerURI := setupMockIssuer(t, srv.wallet, mockIssuerOpts{})
	defer issuer.Close()

	parsed, err := url.Parse(offerURI)
	if err != nil {
		t.Fatalf("parsing offer URI: %v", err)
	}
	credentialOffer := parsed.Query().Get("credential_offer")
	if credentialOffer == "" {
		t.Fatal("mock offer URI has no credential_offer parameter")
	}

	before := len(srv.wallet.GetCredentials())
	rec := serverRequest(t, srv, "GET", "/credential-offer?credential_offer="+url.QueryEscape(credentialOffer), "")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	after := len(srv.wallet.GetCredentials())
	if after != before+1 {
		t.Fatalf("expected one imported credential, got before=%d after=%d", before, after)
	}
}

func TestCredentialOfferEndpoint_CredentialOfferByReference(t *testing.T) {
	srv := newTestServer(t, true)

	issuer, offerURI := setupMockIssuer(t, srv.wallet, mockIssuerOpts{offerViaURI: true})
	defer issuer.Close()

	parsed, err := url.Parse(offerURI)
	if err != nil {
		t.Fatalf("parsing offer URI: %v", err)
	}
	offerRef := parsed.Query().Get("credential_offer_uri")
	if offerRef == "" {
		t.Fatal("mock offer URI has no credential_offer_uri parameter")
	}

	before := len(srv.wallet.GetCredentials())
	rec := serverRequest(t, srv, "GET", "/credential-offer?credential_offer_uri="+url.QueryEscape(offerRef), "")

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	after := len(srv.wallet.GetCredentials())
	if after != before+1 {
		t.Fatalf("expected one imported credential, got before=%d after=%d", before, after)
	}
}

// Profile overrides run on a wallet clone. Deferred issuances must reach the server's
// wallet so its poller can collect them (OpenID4VCI 1.0 §9.3).
func TestDeferredIssuanceSurvivesAProfileOverride(t *testing.T) {
	w := generateTestWallet(t)
	issuer, offerURI, _ := deferringIssuer(t, w, 1, 1)
	defer issuer.Close()

	server := NewServer(w, 0, nil)
	body, err := json.Marshal(map[string]any{"uri": offerURI, "mode": "debug", "haip": false})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/offers", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleOfferAPI(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("offer response = %d, want 202 for a deferred credential (body %s)", rec.Code, rec.Body.String())
	}
	if got := len(w.DeferredIssuanceList()); got != 1 {
		t.Fatalf("the server's own wallet holds %d deferred records, want 1: the poller only reads this one", got)
	}
}
