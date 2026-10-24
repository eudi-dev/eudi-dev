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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
)

// An interactive issuance reads a credential_offer_uri twice. The first read
// fills the consent dialog. The second runs when the user approves. OpenID4VCI
// 1.0 §4.1.3 allows this, since the wallet fetches "unless it is already
// cached". An issuer that serves an offer once answers the second read with an
// error. The user approved the offer shown in the dialog, so the flow continues
// with it and logs a warning.
func TestApprovingAnOfferSurvivesASingleUseOfferURI(t *testing.T) {
	w := generateTestWallet(t)

	var offerFetches int
	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		offerViaURI:     true,
		oneShotOfferURI: true,
		onOfferFetch:    func() { offerFetches++ },
	})
	defer srv.Close()

	consentReq, _, err := generateTestWallet(t).prepareIssuanceConsentRequest(t.Context(), offerURI, "")
	if err != nil {
		t.Fatalf("preparing the consent request: %v", err)
	}
	if consentReq.ResolvedOffer == nil {
		t.Fatal("the consent dialog resolved no offer to carry into the approval")
	}

	result, err := w.ProcessCredentialOfferWithOptions(offerURI, OfferOptions{
		ResolvedOffer: consentReq.ResolvedOffer,
	})
	if err != nil {
		t.Fatalf("issuance failed on an offer the wallet had already resolved: %v", err)
	}
	if result.CredentialID == "" {
		t.Error("no credential was imported")
	}
	if offerFetches != 2 {
		t.Errorf("the offer URI was read %d times, want the dialog's read and the approval's attempt", offerFetches)
	}

	// The log shows the failed second fetch so users can spot issuers that
	// serve an offer once.
	var warned bool
	for _, entry := range w.GetLog() {
		if entry.Severity == severityWarning && strings.Contains(entry.Detail, "credential_offer_uri") {
			warned = true
		}
	}
	if !warned {
		t.Error("nothing in the activity log says the offer could not be read again")
	}
}

// Without a previously approved copy, a failed offer fetch ends issuance.
func TestAnUnreadableOfferURIStillFailsWithoutAResolvedOffer(t *testing.T) {
	w := generateTestWallet(t)

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{offerViaURI: true, oneShotOfferURI: true})
	defer srv.Close()

	if _, err := w.ProcessCredentialOffer(offerURI); err != nil {
		t.Fatalf("the first read should succeed: %v", err)
	}
	if _, err := w.ProcessCredentialOffer(offerURI); err == nil {
		t.Fatal("an offer the wallet cannot read and never resolved was accepted")
	}
}

// Approval in the UI completes issuance from the approved offer when the issuer
// refuses a second fetch.
func TestApproveRequestCompletesWhenTheIssuerServesTheOfferOnce(t *testing.T) {
	w := generateTestWallet(t)

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{offerViaURI: true, oneShotOfferURI: true})
	defer srv.Close()

	server := NewServer(w, 0, nil)

	consentReq, _, err := generateTestWallet(t).prepareIssuanceConsentRequest(t.Context(), offerURI, "")
	if err != nil {
		t.Fatalf("preparing the consent request: %v", err)
	}
	w.Consents().Create(consentReq)

	done := make(chan struct{})
	go func() {
		defer close(done)
		server.awaitOfferConsent(context.Background(), noopResponseWriter{}, consentReq, "test issuer", OfferOptions{})
	}()

	consentReq.ResultCh <- consent.Result{Approved: true}
	submission := <-consentReq.SubmissionCh
	<-done

	if submission.Error != "" {
		t.Fatalf("approving an offer the issuer serves once failed: %s", submission.Error)
	}
	if len(w.GetCredentials()) != 1 {
		t.Errorf("got %d credentials, want the approved one", len(w.GetCredentials()))
	}
}

// The user approved the original offer only. A changed offer in the second
// fetch does not replace it.
func TestASwappedOfferDoesNotReplaceTheApprovedOne(t *testing.T) {
	w := generateTestWallet(t)

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		offerViaURI: true,
		secondOffer: map[string]any{
			"credential_issuer":            "https://elsewhere.example",
			"credential_configuration_ids": []string{"other-config"},
			"grants": map[string]any{
				"urn:ietf:params:oauth:grant-type:pre-authorized_code": map[string]any{
					"pre-authorized_code": "someone-elses-code",
				},
			},
		},
	})
	defer srv.Close()

	consentReq, _, err := generateTestWallet(t).prepareIssuanceConsentRequest(t.Context(), offerURI, "")
	if err != nil {
		t.Fatalf("preparing the consent request: %v", err)
	}

	result, err := w.ProcessCredentialOfferWithOptions(offerURI, OfferOptions{
		ResolvedOffer: consentReq.ResolvedOffer,
	})
	if err != nil {
		t.Fatalf("issuance failed: %v", err)
	}
	if result.Issuer != srv.URL {
		t.Errorf("issued from %s, want the approved issuer %s", result.Issuer, srv.URL)
	}

	var warned bool
	for _, entry := range w.GetLog() {
		if entry.Severity == severityWarning && strings.Contains(entry.Detail, "elsewhere.example") {
			warned = true
		}
	}
	if !warned {
		t.Error("nothing in the activity log says the offer changed")
	}
}

// An error body with HTTP 200 counts as a failed offer fetch. The approved copy
// is kept.
func TestAnOfferRereadWithoutAnIssuerKeepsTheApprovedOne(t *testing.T) {
	w := generateTestWallet(t)

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{
		offerViaURI: true,
		secondOffer: map[string]any{"error": "offer_expired", "error_description": "already consumed"},
	})
	defer srv.Close()

	consentReq, _, err := generateTestWallet(t).prepareIssuanceConsentRequest(t.Context(), offerURI, "")
	if err != nil {
		t.Fatalf("preparing the consent request: %v", err)
	}

	result, err := w.ProcessCredentialOfferWithOptions(offerURI, OfferOptions{
		ResolvedOffer: consentReq.ResolvedOffer,
	})
	if err != nil {
		t.Fatalf("issuance failed on an offer answered with an error body: %v", err)
	}
	if result.CredentialID == "" {
		t.Error("no credential was imported")
	}

	var warned bool
	for _, entry := range w.GetLog() {
		if entry.Severity == severityWarning && strings.Contains(entry.Detail, "credential_offer_uri") {
			warned = true
		}
	}
	if !warned {
		t.Error("nothing in the activity log says the offer could not be read again")
	}
}

// Automatic and API flows have no approved copy to fall back on. A failed fetch
// fails issuance.
func TestUnattendedIssuanceCarriesNoApprovedOffer(t *testing.T) {
	w := generateTestWallet(t)
	w.AutoAccept = true

	srv, offerURI := setupMockIssuer(t, w, mockIssuerOpts{offerViaURI: true, oneShotOfferURI: true})
	defer srv.Close()

	server := NewServer(w, 0, nil)
	rec := httptest.NewRecorder()
	server.processOfferURI(t.Context(), rec, offerURI, OfferOptions{}, false, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("the first, unattended run failed: %d %s", rec.Code, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	server.processOfferURI(t.Context(), rec, offerURI, OfferOptions{}, false, true)
	if rec.Code == http.StatusOK {
		t.Fatalf("a spent offer was accepted without anyone approving it: %s", rec.Body.String())
	}
}
