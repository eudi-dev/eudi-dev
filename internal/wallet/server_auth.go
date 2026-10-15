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
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/eudi-dev/eudi-dev/v3/internal/apierror"
	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"

	"github.com/eudi-dev/eudi-dev/v3/internal/config"
)

var walletPresentationFormats = map[string]bool{
	credtype.FormatSDJWT: true,
	credtype.FormatMDOC:  true,
	credtype.FormatJWTVC: true,
}

// OpenID4VP 1.0 §8.5 uses vp_formats_not_supported when every query requests an
// unsupported format. Other unmatched queries use access_denied.
func unsatisfiableQueryError(query map[string]any) (string, string) {
	credQueries, _ := query["credentials"].([]any)
	unsupported := map[string]bool{}
	for _, item := range credQueries {
		cq, ok := item.(map[string]any)
		if !ok {
			continue
		}
		requested, _ := cq["format"].(string)
		if requested == "" || walletPresentationFormats[requested] {
			return oid4vp.ErrorAccessDenied, "no stored credential satisfies the requested query"
		}
		unsupported[requested] = true
	}
	if len(unsupported) == 0 {
		return oid4vp.ErrorAccessDenied, "no stored credential satisfies the requested query"
	}
	formats := make([]string, 0, len(unsupported))
	for format := range unsupported {
		formats = append(formats, format)
	}
	sort.Strings(formats)
	return oid4vp.ErrorVPFormatsNotSupported, "unsupported credential format(s): " + strings.Join(formats, ", ")
}

func newConsentID() string {
	return uuid.New().String()
}

func isBrowserNavigation(r *http.Request) bool {
	return r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html")
}

// forgetRefusal drops the stored error of a refused request once the browser
// follows the verifier's redirect_uri. The verifier's page then shows the
// outcome. Errors stored before the request stay.
func (s *Server) forgetRefusal(authReq *oid4vp.Request, redirectURI string, started time.Time) {
	if authReq.BrowserRedirect && redirectURI != "" {
		s.wallet.Consents().ForgetError(authReq.Session, started)
	}
}

func redirectBrowser(w http.ResponseWriter, redirectURI string) {
	if redirectURI == "" {
		redirectURI = "/"
	}
	w.Header().Set("Location", redirectURI)
	w.WriteHeader(http.StatusSeeOther)
}

type preparedPresentation struct {
	ResponseURI string
	VPResult    *VPTokenMapResult
	IDToken     string
	Response    *oid4vp.AuthorizationResponseEnvelope
}

func (s *Server) handleAuthFlow(w http.ResponseWriter, authReq *oid4vp.Request) {
	started := time.Now()
	if authReq.Source == "" {
		authReq.Source = "authorize"
	}
	s.addPresentationRequestLog(authReq, authReq.Source)

	outcome := s.wallet.evaluatePresentationRequest(authReq, presentationEntry{
		action: "presentation", subject: "The request", owner: authReq.Session, interactive: !s.autoAccepts(authReq),
	})
	s.logPresentationOutcome(authReq, outcome)

	switch {
	case outcome.invalid != nil:
		s.triggerUIRequest("")
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":             outcome.invalidCode,
			"error_description": outcome.invalid.Error(),
		})
	case outcome.refusal != nil && outcome.refusal.status == "no_match":
		s.triggerUIRequest("")
		redirectURI := s.reportRefusalToVerifier(authReq, outcome.refusal.code, outcome.refusal.description)
		if authReq.BrowserRedirect {
			s.forgetRefusal(authReq, redirectURI, started)
			redirectBrowser(w, redirectURI)
			return
		}
		writeJSON(w, http.StatusOK, withRedirectURI(map[string]any{
			"status":            "no_match",
			"error":             outcome.refusal.code,
			"error_description": outcome.refusal.description,
		}, redirectURI))
	case outcome.refusal != nil:
		s.triggerUIRequest("")
		result := s.submitAuthorizationError(w, authReq, outcome.refusal.status, outcome.refusal.code, outcome.refusal.description)
		s.forgetRefusal(authReq, result.RedirectURI, started)
	case s.autoAccepts(authReq):
		s.log("  Mode:          auto-accept")
		s.autoAcceptPresentation(w, authReq, outcome.matches)
	case authReq.BrowserRedirect:
		// Browser navigations go to the wallet UI while the consent waits.
		// After approval, the UI follows the verifier's redirect_uri.
		s.log("  Mode:          interactive (waiting for consent)")
		shown := make(chan *consent.Request, 1)
		go s.awaitPresentationConsent(noopResponseWriter{}, authReq, outcome, func(req *consent.Request) { shown <- req })
		req := <-shown
		if req == nil {
			s.refuseBusy(w, consent.ErrTooManyPending)
			return
		}
		redirectBrowser(w, "/?request="+req.ID)
	default:
		s.log("  Mode:          interactive (waiting for consent)")
		s.awaitPresentationConsent(w, authReq, outcome, nil)
	}
}

// logPresentationOutcome writes the decision of the shared flow to the console.
func (s *Server) logPresentationOutcome(authReq *oid4vp.Request, outcome presentationOutcome) {
	switch {
	case outcome.invalid != nil:
		s.log("  ERROR: %v", outcome.invalid)
		return
	case outcome.refusal != nil && outcome.refusal.status == "no_match":
		s.log("  Result:        no matching credentials")
		return
	case outcome.refusal != nil:
		s.log("  REFUSED: %s %s", outcome.refusal.code, outcome.refusal.description)
		return
	}
	for _, finding := range authReq.Findings {
		s.log("  WARNING: %s", finding)
	}
	s.log("  Matched:       %d credential(s)", len(outcome.matches))
	for _, m := range outcome.matches {
		s.log("    - %s %s (%s), disclosing %d claims", m.Format, credTypeLabel(m), shortID(m.CredentialID), len(m.SelectedKeys))
	}
	if len(outcome.matches) == 0 && outcome.options != nil {
		s.log("  Result:        no matching credentials, debug mode offers the others")
	}
}

// autoAccepts reports whether the request goes without a consent dialog. An
// API submission provides the caller's consent.
func (s *Server) autoAccepts(authReq *oid4vp.Request) bool {
	return s.wallet.AutoAcceptSetting() || authReq.AutoAccept || authReq.Source == "api"
}

// awaitPresentationConsent asks the user and delivers the answer. The
// submission channel also delivers the result to the approve API. shown gets
// nil when the wallet refuses to ask.
func (s *Server) awaitPresentationConsent(w http.ResponseWriter, authReq *oid4vp.Request, outcome presentationOutcome, shown func(*consent.Request)) {
	s.allowSlowResponse(w, config.ConsentTimeout)
	consentReq, matches, approved, answered, err := s.wallet.askPresentationConsent(consent.TypePresentation, authReq.Session, authReq.ClientID, authReq, outcome, config.ConsentTimeout, func(req *consent.Request) {
		s.triggerUIRequest(req.ID)
		if s.onConsentRequest != nil {
			s.onConsentRequest(req)
		}
		if shown != nil {
			shown(req)
		}
	})
	switch {
	case err != nil:
		if shown != nil {
			shown(nil)
		}
		s.refuseBusy(w, err)
	case !answered:
		s.answerConsentTimeout(w, "presentation", consentReq)
	case !approved:
		s.logDeniedPresentation(authReq)
		consentReq.SubmissionCh <- s.submitAuthorizationError(w, authReq, "denied", oid4vp.ErrorAccessDenied, "User denied presentation")
	default:
		s.log("  Consent:       approved")
		consentReq.SubmissionCh <- s.submitPresentation(w, authReq, matches)
	}
}

// refuseBusy refuses a new flow when too many flows wait for consent.
func (s *Server) refuseBusy(w http.ResponseWriter, err error) {
	s.log("  REFUSED: %v", err)
	w.Header().Set("Retry-After", strconv.Itoa(int(config.ConsentTimeout.Seconds())))
	apierror.Write(w, http.StatusServiceUnavailable, apierror.TemporarilyUnavailable, err.Error())
}

// answerConsentTimeout ends a consent request without an answer in time. It
// answers 504, because RFC 9110 §15.5.9 lets a client repeat a request after
// a 408, and browsers do. The repeat would open a new consent request.
func (s *Server) answerConsentTimeout(w http.ResponseWriter, action string, req *consent.Request) {
	s.wallet.AddLog(action, "Consent timed out", false)
	req.SubmissionCh <- consent.SubmissionResult{Error: "consent timeout", StatusCode: http.StatusGatewayTimeout}
	apierror.Write(w, http.StatusGatewayTimeout, apierror.ConsentTimeout, "consent timeout")
}

func (s *Server) logDeniedPresentation(authReq *oid4vp.Request) {
	s.log("  Consent:       denied")
	s.wallet.AddLog("presentation", fmt.Sprintf("Denied presentation to %s", authReq.ClientID), false)
}

// Browser navigations redirect to the UI immediately. Their consent flows finish in
// the background without writing to the original HTTP response.
type noopResponseWriter struct{}

func (noopResponseWriter) Header() http.Header         { return http.Header{} }
func (noopResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (noopResponseWriter) WriteHeader(int)             {}

func (s *Server) autoAcceptPresentation(w http.ResponseWriter, authReq *oid4vp.Request, matches []consent.Match) {
	s.log("  Verifier:      %s", authReq.ClientID)
	for _, m := range matches {
		s.log("  Credential:    %s (%s), disclosing %v", m.Format, credTypeLabel(m), m.SelectedKeys)
	}
	s.submitPresentation(w, authReq, matches)
	s.log("  Auto-accepted")
}

func (s *Server) buildBrowserPresentationResult(authReq *oid4vp.Request, protocol string, matches []consent.Match) (*oid4vp.BrowserAPIResult, *preparedPresentation, error) {
	prepared, err := s.wallet.preparePresentation(authReq, matches)
	if err != nil {
		return nil, nil, err
	}
	response, err := s.wallet.buildAuthorizationResponse(prepared.VPResult, prepared.IDToken, authReq.State, authReq)
	if err != nil {
		return nil, nil, err
	}
	result, err := oid4vp.BuildBrowserAPIResult(protocol, response)
	if err != nil {
		return nil, nil, err
	}
	prepared.Response = response
	return result, prepared, nil
}

func (s *Server) buildBrowserAuthorizationErrorResult(authReq *oid4vp.Request, protocol, errorCode, errorDescription string) (*oid4vp.BrowserAPIResult, error) {
	response, err := s.wallet.buildAuthorizationErrorResponse(errorCode, errorDescription, authReq.State, authReq)
	if err != nil {
		return nil, err
	}
	return oid4vp.BuildBrowserAPIResult(protocol, response)
}

// deliverAuthorizationError logs the delivery of an error response to the
// console.
func (s *Server) deliverAuthorizationError(authReq *oid4vp.Request, errorCode, errorDescription string) (*oid4vp.DirectPostResult, error) {
	s.log("  Submitting authorization error to %s", authReq.ResponseDestination())
	if authReq.State != "" {
		s.log("  State:         %s", authReq.State)
	}
	result, err := s.wallet.deliverAuthorizationError(authReq, errorCode, errorDescription)
	if err != nil {
		s.log("  ERROR: Error submission failed: %v", err)
		return nil, err
	}
	s.log("  Response:      HTTP %d", result.StatusCode)
	if result.RedirectURI != "" {
		s.log("  Redirect:      %s", result.RedirectURI)
	}
	return result, nil
}

// reportRefusalToVerifier sends the refusal in the request's response mode
// (OpenID4VP 1.0 §5.6) and returns the redirect_uri from the verifier's answer
// (§8.2). A failed delivery is logged and doesn't change the refusal.
func (s *Server) reportRefusalToVerifier(authReq *oid4vp.Request, errorCode, errorDescription string) string {
	if !oid4vp.CanDeliverError(authReq) {
		return ""
	}
	result, err := s.deliverAuthorizationError(authReq, errorCode, errorDescription)
	if err != nil {
		return ""
	}
	return result.RedirectURI
}

// SubmittedPresentation builds the answer of POST /api/presentations after the
// verifier received the response. findings are the checks that failed in
// debug mode.
func SubmittedPresentation(result *oid4vp.DirectPostResult, vp *VPTokenMapResult, findings []string) map[string]any {
	keys := []string{}
	if vp != nil && len(vp.QueryIDs()) > 0 {
		keys = vp.QueryIDs()
	}
	body := map[string]any{"status": "submitted", "response": result, "vp_token_keys": keys}
	if len(findings) > 0 {
		body["findings"] = findings
	}
	return withRedirectURI(body, result.RedirectURI)
}

// withRedirectURI adds the verifier's redirect_uri to an API response. Without
// one the field stays out, because a missing redirect_uri means the verifier
// wants no redirect (OpenID4VP 1.0 §8.2).
func withRedirectURI(body map[string]any, redirectURI string) map[string]any {
	if redirectURI != "" {
		body["redirect_uri"] = redirectURI
	}
	return body
}

func (s *Server) submitAuthorizationError(w http.ResponseWriter, authReq *oid4vp.Request, status, errorCode, errorDescription string) consent.SubmissionResult {
	result, err := s.deliverAuthorizationError(authReq, errorCode, errorDescription)
	if err != nil {
		apierror.Write(w, http.StatusBadGateway, apierror.ServerError, err.Error())
		return consent.SubmissionResult{Error: err.Error()}
	}

	if authReq.BrowserRedirect {
		redirectBrowser(w, result.RedirectURI)
	} else {
		writeJSON(w, http.StatusOK, withRedirectURI(map[string]any{
			"status":            status,
			"error":             errorCode,
			"error_description": errorDescription,
			"response":          result,
		}, result.RedirectURI))
	}
	return submissionResult(result)
}

func submissionResult(result *oid4vp.DirectPostResult) consent.SubmissionResult {
	submission := consent.SubmissionResult{RedirectURI: result.RedirectURI, StatusCode: result.StatusCode}
	if result.StatusCode >= 400 {
		submission.Error = result.Body
	}
	return submission
}

func (s *Server) submitPresentation(w http.ResponseWriter, authReq *oid4vp.Request, matches []consent.Match) consent.SubmissionResult {
	s.log("  Submitting VP token to %s", authReq.ResponseDestination())
	if authReq.State != "" {
		s.log("  State:         %s", authReq.State)
	}

	prepared, err := s.wallet.preparePresentation(authReq, matches)
	if err != nil {
		s.log("  ERROR: Presentation preparation failed: %v", err)
		s.wallet.AddLog("presentation", fmt.Sprintf("Presentation preparation failed: %v", err), false)
		apierror.Write(w, http.StatusInternalServerError, apierror.ServerError, err.Error())
		return consent.SubmissionResult{Error: err.Error()}
	}
	if prepared.VPResult != nil {
		s.log("  VP tokens:     %d created", prepared.VPResult.PresentationCount())
	}
	if prepared.IDToken != "" {
		s.log("  id_token:      created (SIOPv2)")
	}

	result, err := s.wallet.submitPreparedPresentation(authReq, matches, prepared)
	if err != nil {
		s.log("  ERROR: Submission failed: %v", err)
		apierror.Write(w, http.StatusBadGateway, apierror.ServerError, err.Error())
		return consent.SubmissionResult{Error: err.Error()}
	}

	s.log("  Response:      HTTP %d", result.StatusCode)
	if result.RedirectURI != "" {
		s.log("  Redirect:      %s", result.RedirectURI)
	}
	if result.StatusCode >= 400 {
		s.log("  ERROR:         %s", result.Body)
	}

	if authReq.BrowserRedirect {
		redirectBrowser(w, result.RedirectURI)
	} else {
		writeJSON(w, http.StatusOK, SubmittedPresentation(result, prepared.VPResult, authReq.Findings))
	}
	return submissionResult(result)
}

// shortID shortens a credential ID for the console. An ID from a credentials
// file can have fewer than 8 characters.
func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func credTypeLabel(m consent.Match) string {
	if m.VCT != "" {
		return m.VCT
	}
	if m.DocType != "" {
		return m.DocType
	}
	return m.Format
}
