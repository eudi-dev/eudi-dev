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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
)

func issuanceEnvelope(t *testing.T, data string) browserIssuanceEnvelope {
	t.Helper()
	var body browserIssuanceEnvelope
	raw := `{"digital":{"requests":[{"protocol":"other","data":{}},{"protocol":"openid4vci-v1","data":` + data + `}]}}`
	if err := json.Unmarshal([]byte(raw), &body); err != nil {
		t.Fatal(err)
	}
	return body
}

// OpenID4VCI 1.0 §4.1.1: "The Wallet MUST ignore any unrecognized parameters."
func TestABrowserOfferIsACredentialOffer(t *testing.T) {
	uri, err := issuanceEnvelope(t, `{"credential_issuer": "https://issuer.example", "credential_configuration_ids": ["ticket"], "unrecognized": {}}`).offer()
	if err != nil {
		t.Fatal(err)
	}
	_, parsed, err := oid4vc.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	offer, ok := parsed.(*oid4vc.CredentialOffer)
	if !ok || offer.CredentialIssuer != "https://issuer.example" {
		t.Errorf("offer = %+v", parsed)
	}
}

// W3C Digital Credentials §7.6.2: data is an object.
func TestABrowserOfferNeedsAnObject(t *testing.T) {
	if _, err := issuanceEnvelope(t, `"openid-credential-offer://"`).offer(); err == nil {
		t.Error("a string was accepted as offer")
	}
}

func TestTheIssuanceEndpointNeedsASupportedProtocol(t *testing.T) {
	srv := newTestServer(t, true)
	body := `{"digital":{"requests":[{"protocol":"openid4vci","data":{}}]}}`
	if w := serverRequest(t, srv, http.MethodPost, "/api/dc-api/create", body); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "openid4vci-v1") {
		t.Errorf("status %d: %s", w.Code, w.Body)
	}
}

// A web page can post without a preflight. With auto-accept that must not issue.
func TestTheIssuanceEndpointRefusesWebPages(t *testing.T) {
	srv := newTestServer(t, true)
	req := httptest.NewRequest(http.MethodPost, "/api/dc-api/create", strings.NewReader(`{}`))
	req.Header.Set("Origin", "https://attacker.example")
	rec := httptest.NewRecorder()
	srv.handleBrowserIssuanceAPI(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("status %d: %s", rec.Code, rec.Body)
	}
}

func signInAnswer(t *testing.T, p *pendingOffer) *offerAnswer {
	t.Helper()
	answer := &offerAnswer{}
	writeJSON(answer, http.StatusAccepted, p.authorizationRequiredBody())
	return answer
}

// No wallet page is open to show the sign-in of an auto-accepted call.
func TestAnAutoAcceptingWalletRefusesASignInAtOnce(t *testing.T) {
	srv := newTestServer(t, true)
	srv.wallet.SetAutoAccept(true)
	offer := &pendingOffer{ID: "offer", cancelled: make(chan struct{})}
	srv.trackPendingOffer(offer)
	rec := httptest.NewRecorder()
	srv.writeBrowserIssuanceResult(t.Context(), rec, "", signInAnswer(t, offer))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "sign-in") {
		t.Errorf("status %d: %s", rec.Code, rec.Body)
	}
	select {
	case <-offer.cancelled:
	default:
		t.Error("the sign-in keeps waiting")
	}
}

func TestAClosedCallEndsTheSignIn(t *testing.T) {
	srv := newTestServer(t, true)
	srv.wallet.SetAutoAccept(false)
	offer := &pendingOffer{ID: "offer", cancelled: make(chan struct{})}
	srv.trackPendingOffer(offer)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	rec := httptest.NewRecorder()
	srv.writeBrowserIssuanceResult(ctx, rec, "", signInAnswer(t, offer))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status %d: %s", rec.Code, rec.Body)
	}
	select {
	case <-offer.cancelled:
	default:
		t.Error("the sign-in keeps waiting")
	}
}

func TestTheIssuanceEndpointAcknowledgesTheCredential(t *testing.T) {
	srv := newTestServer(t, true)
	mock, offerURI := setupMockIssuer(t, srv.wallet, mockIssuerOpts{tokenCNonce: "nonce"})
	defer mock.Close()
	parsed, err := url.Parse(offerURI)
	if err != nil {
		t.Fatal(err)
	}
	body := `{"digital":{"requests":[{"protocol":"openid4vci-v1","data":` + parsed.Query().Get("credential_offer") + `}]}}`
	before := len(srv.wallet.Credentials)
	w := serverRequest(t, srv, http.MethodPost, "/api/dc-api/create", body)
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body)
	}
	if strings.TrimSpace(w.Body.String()) != `{"data":{},"protocol":"openid4vci-v1"}` {
		t.Errorf("result %s", w.Body)
	}
	if len(srv.wallet.Credentials) != before+1 {
		t.Errorf("stored %d credentials, want %d", len(srv.wallet.Credentials), before+1)
	}
}
