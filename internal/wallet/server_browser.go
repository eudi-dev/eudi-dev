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
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v2/internal/config"
)

// Returns the result that navigator.credentials.get() would deliver to the requesting
// page.
func (s *Server) handleBrowserPresentationAPI(w http.ResponseWriter, r *http.Request) {
	var body BrowserAPIRequestEnvelope
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}

	reqServer := s

	requestOrigin := strings.TrimSpace(r.Header.Get("Origin"))
	protocol, authReq, err := ParseBrowserAPIRequest(body, reqServer.parseOpts, requestOrigin)
	if err != nil {
		reqServer.log("  ERROR: %v", err)
		reqServer.wallet.AddLog("presentation", fmt.Sprintf("Failed to parse browser request: %v", err), false)
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}

	reqServer.log("Received Browser API authorization request")
	reqServer.log("  Protocol:      %s", protocol)
	reqServer.log("  Client ID:     %s", authReq.ClientID)
	reqServer.log("  Response Mode: %s", authReq.ResponseMode)
	authReq.Source = "browser_api"
	if authReq.Nonce != "" {
		reqServer.log("  Nonce:         %s", authReq.Nonce)
	}
	if requestOrigin != "" {
		reqServer.log("  Origin:        %s", requestOrigin)
	}
	reqServer.addPresentationRequestLog(authReq, "browser_api")

	if override := reqServer.wallet.ConsumeNextError(); override != nil {
		reqServer.log("  Next-error override consumed: %s", override.Error)
		result, buildErr := reqServer.buildBrowserAuthorizationErrorResult(authReq, protocol, override.Error, override.ErrorDescription)
		if buildErr != nil {
			reqServer.log("  ERROR: Browser error response failed: %v", buildErr)
			reqServer.wallet.AddLog("presentation", fmt.Sprintf("Browser error response failed: %v", buildErr), false)
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": buildErr.Error()})
			return
		}
		errorDetails := presentationRequestLogDetails(authReq)
		errorDetails["direction"] = "outbound"
		errorDetails["source"] = "browser_api"
		errorDetails["error"] = override.Error
		addStringDetail(errorDetails, "error_description", override.ErrorDescription)
		reqServer.wallet.addProtocolLog("presentation", "presentation_error_response", fmt.Sprintf("Returned Browser API error to %s", authReq.ClientID), true, errorDetails)
		writeJSON(w, http.StatusOK, result)
		return
	}

	dcMode, dcHAIP, _ := reqServer.wallet.ConformanceSettings()
	findings, err := ValidateAuthorizationRequest(dcMode, dcHAIP, authReq)
	if err != nil {
		reqServer.log("  ERROR: %v", err)
		reqServer.wallet.AddLog("presentation", err.Error(), false)
		reqServer.wallet.NotifyError(WalletError{
			Owner:   requestOwner(r),
			Message: "Authorization request validation failed",
			Detail:  err.Error(),
		})
		// Invalid requests receive an API error. OpenID4VP 1.0 §8.5 follows RFC 6749
		// §4.1.2.1, which reports the error to the user without redirecting to an
		// invalid destination.
		reqServer.triggerUIRequest("")
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":             refusalCodeForRequest(authReq, err),
			"error_description": err.Error(),
		})
		return
	}
	for _, finding := range findings {
		reqServer.log("  WARNING: %s", finding)
	}
	reqServer.wallet.warnFindings("presentation", specCitedSummary("The request", findings), findings)
	reqServer.wallet.warnUndefinedRequestParameters("presentation", authReq)

	if authReq.DCQLQuery != nil {
		if dcqlJSON, err := json.Marshal(authReq.DCQLQuery); err == nil {
			reqServer.log("  DCQL Query:    %s", string(dcqlJSON))
		}
	}

	requiresVP := ResponseTypeRequiresVP(authReq.ResponseType)

	var matches []CredentialMatch
	var credentialOptions *ConsentCredentialOptions
	if authReq.DCQLQuery != nil && requiresVP {
		matches, credentialOptions = reqServer.wallet.EvaluateDCQLWithOptions(authReq.DCQLQuery)
	}

	reqServer.log("  Matched:       %d credential(s)", len(matches))
	for _, m := range matches {
		reqServer.log("    - %s %s (%s), disclosing %d claims", m.Format, credTypeLabel(m), m.CredentialID[:8], len(m.SelectedKeys))
	}

	if requiresVP && len(matches) == 0 {
		reqServer.log("  Result:        no matching credentials")
		reqServer.wallet.AddLog("presentation", fmt.Sprintf("No matching credentials for %s", authReq.ClientID), false)
		// §8.5 access_denied: "The Wallet did not have the requested
		// Credentials to satisfy the Authorization Request."
		errorCode, description := unsatisfiableQueryError(authReq.DCQLQuery)
		reqServer.writeBrowserAuthorizationError(w, authReq, protocol, errorCode, description, http.StatusOK)
		return
	}

	if reqServer.wallet.AutoAccept {
		reqServer.writeBrowserPresentationResult(w, authReq, protocol, matches)
		return
	}

	reqServer.log("  Mode:          interactive (waiting for consent)")
	consentReq := &ConsentRequest{
		ID:           newConsentID(),
		Type:         "presentation",
		Owner:        requestOwner(r),
		MatchedCreds: matches,
		Status:       "pending",
		ResultCh:     make(chan ConsentResult, 1),
		SubmissionCh: make(chan SubmissionResult, 1),
		CreatedAt:    time.Now(),
		ClientID:     authReq.ClientID,
		Nonce:        authReq.Nonce,
		ResponseURI:  authReq.ResponseURI,
		DCQLQuery:    authReq.DCQLQuery,
		Purposes:     reqServer.wallet.consentPurposes("presentation", authReq),

		CredentialOptions: credentialOptions,
	}
	consentReq.applyClientAuth(authReq)

	reqServer.wallet.CreateConsentRequest(consentReq)
	reqServer.triggerUIRequest(consentReq.ID)
	if reqServer.onConsentRequest != nil {
		reqServer.onConsentRequest(consentReq)
	}

	handle := func(result ConsentResult) {
		if !result.Approved {
			reqServer.log("  Consent:       denied")
			browserResult, buildErr := reqServer.buildBrowserAuthorizationErrorResult(authReq, protocol, "access_denied", "User denied presentation")
			if buildErr != nil {
				reqServer.log("  ERROR: Browser error response failed: %v", buildErr)
				reqServer.wallet.AddLog("presentation", fmt.Sprintf("Browser error response failed: %v", buildErr), false)
				consentReq.SubmissionCh <- SubmissionResult{Error: buildErr.Error()}
				writeJSON(w, http.StatusBadGateway, map[string]string{"error": buildErr.Error()})
				return
			}
			denialDetails := presentationRequestLogDetails(authReq)
			denialDetails["direction"] = "outbound"
			denialDetails["source"] = "browser_api"
			denialDetails["error"] = "access_denied"
			denialDetails["browser_api_result"] = browserResult
			reqServer.wallet.addProtocolLog("presentation", "presentation_error_response", fmt.Sprintf("Returned Browser API denial to %s", authReq.ClientID), true, denialDetails)
			consentReq.SubmissionCh <- SubmissionResult{StatusCode: http.StatusOK, Error: "access_denied"}
			writeJSON(w, http.StatusOK, browserResult)
			return
		}

		matches = ApplyConsentSelection(consentReq.CredentialOptions, matches, result)

		if result.SelectedClaims != nil {
			for i, m := range matches {
				if selectedKeys, ok := result.SelectedClaims[m.CredentialID]; ok {
					matches[i].SelectedKeys = selectedKeys
					cred, _ := reqServer.wallet.GetCredential(m.CredentialID)
					matches[i].Claims = filterClaims(cred, selectedKeys)
					reqServer.log("    - %s: disclosing %v", m.CredentialID[:8], selectedKeys)
				}
			}
		}

		submission := reqServer.writeBrowserPresentationResult(w, authReq, protocol, matches)
		consentReq.SubmissionCh <- submission
	}

	reqServer.allowSlowResponse(w, config.ConsentTimeout)
	select {
	case result := <-consentReq.ResultCh:
		handle(result)
	case <-time.After(config.ConsentTimeout):
		// The timer can race with consent. Only time out requests that are still
		// pending.
		if _, ok := reqServer.wallet.ResolveRequest(consentReq.ID, statusExpired); !ok {
			handle(<-consentReq.ResultCh)
			return
		}
		reqServer.wallet.AddLog("presentation", "Consent timeout", false)
		consentReq.SubmissionCh <- SubmissionResult{Error: "consent timeout"}
		writeJSON(w, http.StatusRequestTimeout, map[string]string{"error": "consent timeout"})
	}
}

// OpenID4VP 1.0 Appendix A.4 fulfills the DC API promise even for protocol errors.
// Building an encrypted error response can still fail if dc_api.jwt has no usable key.
func (s *Server) writeBrowserAuthorizationError(w http.ResponseWriter, authReq *AuthorizationRequestParams, protocol, errorCode, errorDescription string, fallbackStatus int) {
	result, err := s.buildBrowserAuthorizationErrorResult(authReq, protocol, errorCode, errorDescription)
	if err != nil {
		s.log("  ERROR: Browser error response failed: %v", err)
		s.wallet.AddLog("presentation", fmt.Sprintf("Browser error response failed: %v", err), false)
		writeJSON(w, fallbackStatus, map[string]any{
			"error":             errorCode,
			"error_description": errorDescription,
		})
		return
	}

	details := presentationRequestLogDetails(authReq)
	details["direction"] = "outbound"
	details["source"] = "browser_api"
	details["error"] = errorCode
	addStringDetail(details, "error_description", errorDescription)
	details["browser_api_result"] = result
	s.wallet.addProtocolLog("presentation", "presentation_error_response", fmt.Sprintf("Returned Browser API error to %s", authReq.ClientID), true, details)
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) writeBrowserPresentationResult(w http.ResponseWriter, authReq *AuthorizationRequestParams, protocol string, matches []CredentialMatch) SubmissionResult {
	result, prepared, err := s.buildBrowserPresentationResult(authReq, protocol, matches)
	if err != nil {
		s.log("  ERROR: Browser API presentation failed: %v", err)
		s.wallet.AddLog("presentation", fmt.Sprintf("Browser API presentation failed: %v", err), false)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return SubmissionResult{Error: err.Error()}
	}

	if prepared.VPResult != nil {
		s.log("  VP tokens:     %d created", prepared.VPResult.PresentationCount())
	}
	if prepared.IDToken != "" {
		s.log("  id_token:      created (SIOPv2)")
	}

	details := presentationResponseLogDetails(authReq, s.wallet, matches, prepared)
	details["status_code"] = http.StatusOK
	details["browser_api_result"] = result
	payload := PresentationLogPayload(prepared.Response)
	if payload.Encrypted {
		payload.Wire = result
	} else {
		payload.Body = result
	}
	s.wallet.addProtocolLog("presentation", "presentation_response", fmt.Sprintf("Returned Browser API presentation to %s", authReq.ClientID), true, details, payload)
	writeJSON(w, http.StatusOK, result)
	return SubmissionResult{StatusCode: http.StatusOK}
}
