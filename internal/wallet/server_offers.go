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
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/format"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"

	"github.com/dominikschlosser/eudi-dev/v3/internal/config"
)

// Keep outcomes longer than the five minute authorization callback timeout so callers
// can retrieve them after the flow ends.
const pendingOfferTTL = 10 * time.Minute

// The issuance flow continues in the background while the user signs in. Callers poll
// this record for its outcome.
type pendingOffer struct {
	ID        string
	AuthURL   string
	CreatedAt time.Time

	mu     sync.Mutex
	done   bool
	result *IssuanceResult
	err    error
}

func (p *pendingOffer) complete(result *IssuanceResult, err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.done, p.result, p.err = true, result, err
}

func (p *pendingOffer) authorizationRequiredBody() map[string]any {
	return map[string]any{
		"status":            "authorization_required",
		"authorization_url": p.AuthURL,
		"offer_id":          p.ID,
	}
}

func (p *pendingOffer) outcome() (*IssuanceResult, error, bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.result, p.err, p.done
}

func (s *Server) trackPendingOffer(p *pendingOffer) {
	s.offerMu.Lock()
	defer s.offerMu.Unlock()
	if s.pendingOffers == nil {
		s.pendingOffers = make(map[string]*pendingOffer)
	}
	cutoff := time.Now().Add(-pendingOfferTTL)
	for id, old := range s.pendingOffers {
		if old.CreatedAt.Before(cutoff) {
			delete(s.pendingOffers, id)
		}
	}
	s.pendingOffers[p.ID] = p
}

func (s *Server) lookupPendingOffer(id string) *pendingOffer {
	s.offerMu.Lock()
	defer s.offerMu.Unlock()
	return s.pendingOffers[id]
}

// When sign-in is required, return a pending offer with the authorization URL and
// continue the flow in the background. The issuer's redirect to /callback resumes
// issuance. The caller opens the URL in their browser.
func (s *Server) runOffer(uri string, logDetails map[string]any, opts OfferOptions) (*IssuanceResult, *pendingOffer, error) {
	// A subscriber lets the flow return the sign-in URL when interaction is
	// required. Other flows run at the same time, so it takes only the prompt
	// of this one.
	p := &pendingOffer{ID: newConsentID(), CreatedAt: time.Now()}
	opts.Flow = p.ID
	authCh, unsubscribe := s.wallet.SubscribeAuthorization(func(prompt AuthorizationPrompt) bool {
		return prompt.Flow == p.ID
	})
	done := make(chan struct{})

	go func() {
		defer unsubscribe()
		result, err := s.wallet.ProcessCredentialOfferWithOptions(uri, opts)
		s.applyOfferOutcome(uri, opts.Owner, result, err, logDetails)
		p.complete(result, err)
		close(done)
	}()

	select {
	case prompt := <-authCh:
		authURL := prompt.URL
		p.AuthURL = authURL
		s.trackPendingOffer(p)
		s.log("  Sign-in:       %s", authURL)
		s.wallet.AddLogDetails("issuance", "Waiting for the user to sign in at the issuer", true, map[string]any{
			"offer_uri":         uri,
			"authorization_url": authURL,
		})
		return nil, p, nil
	case <-done:
		result, err, _ := p.outcome()
		return result, nil, err
	}
}

// Record the outcome in the flow's goroutine even if the caller has stopped waiting.
func (s *Server) applyOfferOutcome(uri, owner string, result *IssuanceResult, err error, logDetails map[string]any) {
	if err != nil {
		s.log("  ERROR: %v", err)
		s.wallet.AddLog("issuance", fmt.Sprintf("Failed: %v", err), false)
		s.wallet.NotifyError(WalletError{
			Owner:   owner,
			Message: "Credential issuance failed",
			Detail:  err.Error(),
		})
		return
	}

	if result.Pending {
		s.log("  Deferred:      %s will be collected every %s", result.Issuer, result.RetryInterval)
		s.saveIssuance(result)
		return
	}

	s.log("  Received:      %s credential from %s", result.Format, result.Issuer)
	if result.VerificationDetail != "" {
		s.log("  Verification:  %s [%s]", result.VerificationDetail, result.VerificationStatus)
	}
	details := map[string]any{
		"offer_uri":           uri,
		"credential_id":       result.CredentialID,
		"format":              result.Format,
		"issuer":              result.Issuer,
		"verification_status": result.VerificationStatus,
		"verification_detail": result.VerificationDetail,
	}
	for k, v := range logDetails {
		details[k] = v
	}
	s.wallet.AddLogDetails("issuance", fmt.Sprintf("Received %s credential from %s", result.Format, result.Issuer), true, details)
	s.saveIssuance(result)
}

// Redirect browser navigations to the issuer. API callers receive the sign-in URL and
// pending offer ID.
func (s *Server) writeAuthorizationRequired(w http.ResponseWriter, p *pendingOffer, browserRedirect bool) {
	if browserRedirect {
		redirectBrowser(w, p.AuthURL)
		return
	}
	writeJSON(w, http.StatusAccepted, p.authorizationRequiredBody())
}

func (s *Server) handleOfferStatus(w http.ResponseWriter, r *http.Request) {
	p := s.lookupPendingOffer(r.PathValue("id"))
	if p == nil {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown offer"})
		return
	}
	result, err, done := p.outcome()
	switch {
	case !done:
		writeJSON(w, http.StatusOK, p.authorizationRequiredBody())
	case err != nil:
		writeJSON(w, http.StatusOK, map[string]any{
			"status":   "failed",
			"error":    err.Error(),
			"offer_id": p.ID,
		})
	case result.Pending:
		writeJSON(w, http.StatusOK, map[string]any{
			"status":   "deferred",
			"result":   result,
			"offer_id": p.ID,
		})
	default:
		writeJSON(w, http.StatusOK, map[string]any{
			"status":   "completed",
			"result":   result,
			"offer_id": p.ID,
		})
	}
}

func (s *Server) handleAuthorizationCodeCallback(w http.ResponseWriter, r *http.Request) {
	values := r.URL.Query()
	if values.Get("state") == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error": "missing state in authorization callback",
		})
		return
	}
	if !s.wallet.CompleteAuthorizationCodeCallback(values) {
		writeJSON(w, http.StatusNotFound, map[string]string{
			"error": "no pending authorization-code flow for callback state",
		})
		return
	}
	// The callback resumes issuance on the server. Send the browser back to the wallet
	// UI.
	http.Redirect(w, r, "/?focus=overview", http.StatusSeeOther)
}

func (s *Server) handleOfferAPI(w http.ResponseWriter, r *http.Request) {
	var body struct {
		URI         string `json:"uri"`
		TxCode      string `json:"tx_code,omitempty"`
		Interactive bool   `json:"interactive,omitempty"`
		// ConfigurationID picks one of the offer's credential_configuration_ids.
		ConfigurationID string `json:"credential_configuration_id,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	// Clear the previous failure when a new request starts. Otherwise the UI would
	// keep showing it until the new consent dialog appears.
	s.wallet.ClearLastError(callerOwners(r))

	if body.Interactive {
		s.noteStaleClient(r)
	}
	s.processOfferURI(w, body.URI, OfferOptions{
		TxCode:          body.TxCode,
		Owner:           requestOwner(r),
		ConfigurationID: body.ConfigurationID,
	}, false, !body.Interactive)
}

// Browser submissions return to the wallet UI after import. API submissions provide
// consent and run without a dialog.
func (s *Server) processOfferURI(w http.ResponseWriter, uri string, opts OfferOptions, browserRedirect, apiInitiated bool) {
	s.log("Received credential offer")
	uriDisplay := format.Truncate(uri, 120)
	s.log("  URI: %s", uriDisplay)
	offerDetails := map[string]any{"offer_uri": uri}
	addStringDetail(offerDetails, "tx_code", opts.TxCode)
	addStringDetail(offerDetails, "credential_configuration_id", opts.ConfigurationID)
	s.wallet.AddLogDetails("issuance", "Received credential offer", true, offerDetails)

	if !s.wallet.AutoAcceptSetting() && !apiInitiated {
		consentReq, issuerDisplay, err := s.wallet.prepareIssuanceConsentRequest(uri, opts.Owner)
		if err != nil {
			s.log("  ERROR: %v", err)
			s.wallet.AddLog("issuance", fmt.Sprintf("Failed: %v", err), false)
			s.wallet.NotifyError(WalletError{
				Owner:   opts.Owner,
				Message: "The wallet refused the credential offer",
				Detail:  err.Error(),
			})
			s.triggerUIRequest("")
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		s.log("  Mode:          interactive (waiting for consent)")
		s.wallet.CreateConsentRequest(consentReq)
		s.triggerUIRequest(consentReq.ID)
		if s.onConsentRequest != nil {
			s.onConsentRequest(consentReq)
		}

		if browserRedirect {
			// Redirect browser navigations to the wallet UI immediately. Import in the
			// background after consent.
			go s.awaitOfferConsent(noopResponseWriter{}, consentReq, issuerDisplay, false, opts)
			redirectBrowser(w, "/?request="+consentReq.ID)
			return
		}
		s.awaitOfferConsent(w, consentReq, issuerDisplay, false, opts)
		return
	}

	opts.PresentationConsented = apiInitiated
	s.processOfferDirectly(w, uri, opts, browserRedirect)
}

// The submission channel also delivers the outcome to the approve API.
func (s *Server) awaitOfferConsent(w http.ResponseWriter, consentReq *ConsentRequest, issuerDisplay string, browserRedirect bool, opts OfferOptions) {
	handle := func(consent ConsentResult) {
		if !consent.Approved {
			s.log("  Consent:       denied")
			s.wallet.AddLog("issuance", fmt.Sprintf("Denied credential offer from %s", issuerDisplay), false)
			consentReq.SubmissionCh <- SubmissionResult{Error: "user denied issuance", StatusCode: http.StatusForbidden}
			writeJSON(w, http.StatusOK, map[string]any{
				"status":      "denied",
				"error":       "user denied issuance",
				"status_code": http.StatusForbidden,
			})
			return
		}

		s.log("  Consent:       approved")
		// The offer declares whether a transaction code is required. A code entered in
		// the consent dialog replaces the code from the request.
		if consent.TxCode != "" {
			opts.TxCode = consent.TxCode
		}
		// The configuration picked in the dialog replaces the one from the
		// request.
		if consent.ConfigurationID != "" {
			opts.ConfigurationID = consent.ConfigurationID
		}
		opts.ResolvedOffer = consentReq.ResolvedOffer
		opts.Owner = approvingOwner(consentReq.Owner, consent.Owner)
		// Show consent for any presentation requested by the issuer during this
		// interactive flow.
		result, pending, err := s.runOffer(consentReq.OfferURI, map[string]any{
			"credential_requested": requestedConfigurations(consentReq.OfferConfigs, opts.ConfigurationID),
		}, opts)
		if err != nil {
			consentReq.SubmissionCh <- SubmissionResult{Error: err.Error(), StatusCode: http.StatusBadRequest}
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}

		if pending != nil {
			// The UI already received the sign-in URL through the event stream and is
			// navigating to it.
			consentReq.SubmissionCh <- SubmissionResult{StatusCode: http.StatusAccepted}
			s.writeAuthorizationRequired(w, pending, browserRedirect)
			return
		}

		if result.Pending {
			consentReq.SubmissionCh <- SubmissionResult{Pending: true, TransactionID: result.TransactionID, RetryInterval: result.RetryInterval}
			writeJSON(w, http.StatusAccepted, result)
			return
		}

		consentReq.SubmissionCh <- SubmissionResult{StatusCode: http.StatusOK}
		if browserRedirect {
			redirectBrowser(w, "")
		} else {
			writeJSON(w, http.StatusOK, result)
		}
	}

	// Wait first for offer consent, then for any presentation the issuer requests.
	s.allowSlowResponse(w, config.ConsentTimeout+interactiveAuthorizationConsentTimeout)
	consent, answered := s.wallet.awaitConsent(consentReq, config.ConsentTimeout)
	if !answered {
		s.wallet.AddLog("issuance", "Consent timeout", false)
		consentReq.SubmissionCh <- SubmissionResult{Error: "consent timeout", StatusCode: http.StatusRequestTimeout}
		writeJSON(w, http.StatusRequestTimeout, map[string]string{"error": "consent timeout"})
		return
	}
	handle(consent)
}

func (s *Server) processOfferDirectly(w http.ResponseWriter, uri string, opts OfferOptions, browserRedirect bool) {
	result, pending, err := s.runOffer(uri, nil, opts)
	if err != nil {
		if !s.wallet.AutoAcceptSetting() {
			s.triggerUIRequest("")
		}
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	if pending != nil {
		s.writeAuthorizationRequired(w, pending, browserRedirect)
		return
	}

	if result.Pending {
		if browserRedirect {
			redirectBrowser(w, "")
		} else {
			writeJSON(w, http.StatusAccepted, result)
		}
		return
	}

	if browserRedirect {
		redirectBrowser(w, "")
	} else {
		writeJSON(w, http.StatusOK, result)
	}
}

// requestedConfigurations is the configuration the issuance requests, as the
// activity log shows it. Without a choice it is the first offered one.
func requestedConfigurations(offered []string, chosen string) []string {
	if chosen != "" {
		return []string{chosen}
	}
	if len(offered) > 0 {
		return offered[:1]
	}
	return nil
}

func (w *Wallet) prepareIssuanceConsentRequest(raw, owner string) (*ConsentRequest, string, error) {
	trimmed := strings.TrimSpace(raw)
	req := &ConsentRequest{
		ID:           newConsentID(),
		Type:         "issuance",
		Owner:        owner,
		OfferURI:     trimmed,
		Status:       "pending",
		ResultCh:     make(chan ConsentResult, 1),
		SubmissionCh: make(chan SubmissionResult, 1),
		CreatedAt:    time.Now(),
	}

	// Resolve referenced offers before consent so the dialog can describe the
	// credentials. The specification permits fetching the offer again after approval.
	reqType, parsed, err := oid4vc.ParseWithOptions(trimmed, oid4vc.ParseOptions{HTTPClient: w.HTTPClient()})
	if err != nil {
		// If the offer cannot be fetched, show its host in the consent dialog.
		if offerURI := extractCredentialOfferURI(trimmed); offerURI != "" {
			req.ClientID = credentialOfferIssuerDisplay(offerURI)
			req.OfferDetails = &IssuanceOfferDetails{
				Issuer:       req.ClientID,
				OfferURI:     offerURI,
				ResolveError: err.Error(),
			}
			return req, req.ClientID, nil
		}
		return nil, "", err
	}
	if reqType != oid4vc.TypeVCI {
		return nil, "", fmt.Errorf("expected VCI credential offer, got VP")
	}
	offer, ok := parsed.(*oid4vc.CredentialOffer)
	if !ok {
		return nil, "", fmt.Errorf("unexpected credential offer type")
	}
	req.ClientID = offer.CredentialIssuer
	req.OfferConfigs = append([]string(nil), offer.CredentialConfigurationIDs...)
	req.OfferDetails = w.describeCredentialOffer(offer)
	// Strict mode refuses an issuer that fails the ARF checks before the user
	// is asked, as it refuses a verifier (RPRC_22a, ISSU_24a).
	if len(req.OfferDetails.ARFFindings) > 0 && w.Mode() == ValidationModeStrict {
		return nil, "", w.reportARFIssuanceFindings(offer.CredentialIssuer, req.OfferDetails.ARFFindings)
	}
	req.Findings = req.OfferDetails.Findings
	// Keep the resolved offer for approval because the issuer may allow it to be
	// fetched only once.
	req.ResolvedOffer = offer
	return req, offer.CredentialIssuer, nil
}
func extractCredentialOfferURI(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(u.Query().Get("credential_offer_uri"))
}
func credentialOfferIssuerDisplay(offerURI string) string {
	u, err := url.Parse(strings.TrimSpace(offerURI))
	if err != nil {
		return "credential issuer"
	}
	if issuer := strings.TrimSpace(u.Scheme + "://" + u.Host); issuer != "://" && issuer != "" {
		return issuer
	}
	if host := strings.TrimSpace(u.Host); host != "" {
		return host
	}
	return "credential issuer"
}
