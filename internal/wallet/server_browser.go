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
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/apierror"
	"github.com/eudi-dev/eudi-dev/v3/internal/config"
	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/dcextension"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
)

// Returns the result that navigator.credentials.get() would deliver to the requesting
// page.
func (s *Server) handleBrowserPresentationAPI(w http.ResponseWriter, r *http.Request) {
	var body oid4vp.BrowserAPIRequestEnvelope
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		apierror.InvalidJSON(w, err)
		return
	}

	requestOrigin, err := browserAPIOrigin(r)
	if err != nil {
		apierror.WriteErr(w, http.StatusBadRequest, apierror.InvalidRequest, err)
		return
	}
	protocol, authReq, err := oid4vp.ParseBrowserAPIRequest(body, s.parseOpts, requestOrigin)
	if err != nil {
		s.refuseUnreadableRequest(w, requestOwner(r), err)
		return
	}

	s.log("Received an authorization request through the Digital Credentials API")
	s.log("  Protocol:      %s", protocol)
	s.log("  Client ID:     %s", authReq.ClientID)
	s.log("  Response Mode: %s", authReq.ResponseMode)
	authReq.Source = "browser_api"
	if authReq.Nonce != "" {
		s.log("  Nonce:         %s", authReq.Nonce)
	}
	if requestOrigin != "" {
		s.log("  Origin:        %s", requestOrigin)
	}
	s.addPresentationRequestLog(authReq, "browser_api")

	outcome := s.wallet.evaluatePresentationRequest(authReq, presentationEntry{
		action: "presentation", subject: "The request", owner: requestOwner(r), interactive: !s.autoAccepts(authReq),
	})
	s.logPresentationOutcome(authReq, outcome)

	switch {
	case outcome.invalid != nil:
		// OpenID4VP 1.0 §8.5 follows RFC 6749 §4.1.2.1. The error goes to the
		// user, and the invalid request gets no answer.
		s.triggerUIRequest("")
		apierror.WriteErr(w, http.StatusBadRequest, outcome.invalidCode, outcome.invalid)
		return
	case outcome.refusal != nil:
		// OpenID4VP 1.0 Appendix A returns a protocol error inside the
		// fulfilled API result.
		s.triggerUIRequest("")
		s.writeBrowserAuthorizationError(w, authReq, protocol, outcome.refusal.code, outcome.refusal.description, http.StatusOK)
		return
	case s.autoAccepts(authReq):
		s.writeBrowserPresentationResult(w, authReq, protocol, outcome.matches)
		return
	}

	s.log("  Mode:          interactive (waiting for consent)")
	s.allowSlowResponse(w, config.ConsentTimeout)
	consentReq, matches, approved, answered, err := s.wallet.askPresentationConsent(consent.TypePresentation, requestOwner(r), authReq.ClientID, authReq, outcome, config.ConsentTimeout, func(req *consent.Request) {
		s.triggerUIRequest(req.ID)
		if s.onConsentRequest != nil {
			s.onConsentRequest(req)
		}
	})
	switch {
	case err != nil:
		s.refuseBusy(w, err)
	case !answered:
		s.answerConsentTimeout(w, "presentation", consentReq)
	case !approved:
		s.logDeniedPresentation(authReq)
		consentReq.SubmissionCh <- consent.SubmissionResult{StatusCode: http.StatusOK, Error: oid4vp.ErrorAccessDenied}
		s.writeBrowserAuthorizationError(w, authReq, protocol, oid4vp.ErrorAccessDenied, "User denied presentation", http.StatusBadGateway)
	default:
		consentReq.SubmissionCh <- s.writeBrowserPresentationResult(w, authReq, protocol, matches)
	}
}

// handleDCExtension serves the browser extension that forwards Digital
// Credentials API calls to this wallet.
func (s *Server) handleDCExtension(w http.ResponseWriter, r *http.Request) {
	var archive bytes.Buffer
	walletURL := jsonutil.FirstNonEmpty(s.wallet.BaseURL, s.wallet.ServingOrigin)
	if err := dcextension.WriteZip(&archive, dcextension.Options{WalletURL: walletURL, Version: s.version}); err != nil {
		apierror.WriteErr(w, http.StatusInternalServerError, apierror.ServerError, fmt.Errorf("packaging the browser extension: %w", err))
		return
	}
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+dcextension.ZipName+`"`)
	_, _ = w.Write(archive.Bytes())
}

// CallerOriginHeader carries the origin of the page that called
// navigator.credentials.get() when the eudi-dev browser extension forwards the
// call. The extension's request has the extension's own Origin. A web page
// can't send the header to another origin, because /api/dc-api answers no
// CORS preflight.
const CallerOriginHeader = "X-Eudi-Caller-Origin"

// browserAPIOrigin returns the origin of the page behind a Digital Credentials
// API request. A web page's Origin header comes from its browser and wins.
func browserAPIOrigin(r *http.Request) (string, error) {
	origin := strings.TrimSpace(r.Header.Get("Origin"))
	caller := strings.TrimSpace(r.Header.Get(CallerOriginHeader))
	if caller == "" || (origin != "" && !extensionOrigin(origin)) {
		return origin, nil
	}
	parsed, err := url.Parse(caller)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" || parsed.Scheme+"://"+parsed.Host != caller {
		return "", fmt.Errorf("%s must be a web origin such as https://verifier.example, got %q", CallerOriginHeader, caller)
	}
	return caller, nil
}

func extensionOrigin(origin string) bool {
	scheme, _, _ := strings.Cut(origin, "://")
	return scheme == "chrome-extension" || scheme == "moz-extension" || scheme == "safari-web-extension"
}

// OpenID4VP 1.0 Appendix A.4 fulfills the DC API promise even for protocol errors.
// Building an encrypted error response can still fail if dc_api.jwt has no usable key.
func (s *Server) writeBrowserAuthorizationError(w http.ResponseWriter, authReq *oid4vp.Request, protocol, errorCode, errorDescription string, fallbackStatus int) {
	result, err := s.buildBrowserAuthorizationErrorResult(authReq, protocol, errorCode, errorDescription)
	if err != nil {
		s.log("  ERROR: Browser error response failed: %v", err)
		s.wallet.addProtocolLog("presentation", "presentation_failed", fmt.Sprintf("Browser error response failed: %v", err), false, map[string]any{"error": err.Error()})
		apierror.Write(w, fallbackStatus, errorCode, errorDescription)
		return
	}

	details := presentationRequestLogDetails(authReq)
	details["direction"] = "outbound"
	details["source"] = "browser_api"
	details["error"] = errorCode
	addStringDetail(details, "error_description", errorDescription)
	details["browser_api_result"] = result
	s.wallet.addProtocolLog("presentation", "presentation_error_response", fmt.Sprintf("Returned an error to %s through the Digital Credentials API", authReq.ClientID), true, details)
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) writeBrowserPresentationResult(w http.ResponseWriter, authReq *oid4vp.Request, protocol string, matches []consent.Match) consent.SubmissionResult {
	result, prepared, err := s.buildBrowserPresentationResult(authReq, protocol, matches)
	if err != nil {
		s.log("  ERROR: Digital Credentials API presentation failed: %v", err)
		s.wallet.addProtocolLog("presentation", "presentation_failed", fmt.Sprintf("Digital Credentials API presentation failed: %v", err), false, map[string]any{"error": err.Error()})
		apierror.WriteErr(w, http.StatusInternalServerError, apierror.ServerError, err)
		return consent.SubmissionResult{Error: err.Error()}
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
		payload.Body = oid4vp.BrowserAPIResult{Protocol: result.Protocol, Data: payload.Body}
	} else {
		payload.Body = result
	}
	s.wallet.addProtocolLog("presentation", "presentation_response", fmt.Sprintf("Returned the presentation to %s through the Digital Credentials API", authReq.ClientID), true, details, payload)
	writeJSON(w, http.StatusOK, result)
	return consent.SubmissionResult{StatusCode: http.StatusOK}
}
