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
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"

	"github.com/dominikschlosser/eudi-dev/v3/internal/config"
)

// OpenID4VP 1.0 §8.5 uses invalid_request and access_denied from OAuth 2.0. Appendix
// E.3 registers the additional error codes.
const (
	errorCodeInvalidRequest          = "invalid_request"
	errorCodeAccessDenied            = "access_denied"
	errorCodeVPFormatsNotSupported   = "vp_formats_not_supported"
	errorCodeInvalidRequestURIMethod = "invalid_request_uri_method"
	errorCodeInvalidTransactionData  = "invalid_transaction_data"
)

// Errors without an explicit protocol code are reported as invalid_request.
type authorizationError struct {
	Code string
	Err  error
}

func (e *authorizationError) Error() string { return e.Err.Error() }
func (e *authorizationError) Unwrap() error { return e.Err }

// Default to invalid_request for requests the wallet cannot parse (OpenID4VP 1.0
// §8.5).
func authorizationErrorCode(err error) string {
	var authErr *authorizationError
	if errors.As(err, &authErr) && authErr.Code != "" {
		return authErr.Code
	}
	return errorCodeInvalidRequest
}

var walletPresentationFormats = map[string]bool{
	"dc+sd-jwt":   true,
	"mso_mdoc":    true,
	"jwt_vc_json": true,
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
			return errorCodeAccessDenied, "no stored credential satisfies the requested query"
		}
		unsupported[requested] = true
	}
	if len(unsupported) == 0 {
		return errorCodeAccessDenied, "no stored credential satisfies the requested query"
	}
	formats := make([]string, 0, len(unsupported))
	for format := range unsupported {
		formats = append(formats, format)
	}
	sort.Strings(formats)
	return errorCodeVPFormatsNotSupported, "unsupported credential format(s): " + strings.Join(formats, ", ")
}

// An explicit error code takes precedence. Otherwise inspect the request for the
// parameter errors defined by OpenID4VP 1.0 §8.5.
func refusalCodeForRequest(authReq *AuthorizationRequestParams, err error) string {
	if code := authorizationErrorCode(err); code != errorCodeInvalidRequest {
		return code
	}
	if authReq == nil {
		return errorCodeInvalidRequest
	}
	// §8.5 invalid_request_uri_method: "The value of the request_uri_method
	// request parameter is neither get nor post (case-sensitive)."
	switch authReq.RequestURIMethod {
	case "", "get", "post":
	default:
		return errorCodeInvalidRequestURIMethod
	}
	// OpenID4VP 1.0 §8.5 uses invalid_transaction_data for unsupported transaction
	// types. This wallet supports none.
	if requestHasTransactionData(authReq, authReq.RequestPayload) {
		return errorCodeInvalidTransactionData
	}
	return errorCodeInvalidRequest
}

func newConsentID() string {
	return uuid.New().String()
}

func isBrowserNavigation(r *http.Request) bool {
	return r.Method == http.MethodGet && strings.Contains(r.Header.Get("Accept"), "text/html")
}

func redirectBrowser(w http.ResponseWriter, redirectURI string) {
	if redirectURI == "" {
		redirectURI = "/"
	}
	w.Header().Set("Location", redirectURI)
	w.WriteHeader(http.StatusSeeOther)
}

type AuthorizationRequestParams struct {
	// Findings are the checks that failed in debug mode. The consent dialog
	// and the API response list them.
	Findings []string
	// AutoAccept and SessionTranscript override the wallet's settings for
	// this request (POST /api/presentations).
	AutoAccept        bool
	SessionTranscript SessionTranscriptMode
	ClientID          string
	ResponseType      string
	ResponseMode      string
	Nonce             string
	State             string
	RequestOrigin     string
	// Session identifies the browser that owns the consent request. Empty for requests
	// without a browser session.
	Session          string
	RedirectURI      string
	ResponseURI      string
	Scope            string
	RequestURIMethod string
	// Empty when the Request Object was not fetched by reference.
	RequestURI     string
	ClientMetadata map[string]any
	DCQLQuery      map[string]any
	RequestObject  *oid4vc.RequestObjectJWT
	RequestPayload map[string]any
	// Preserved to detect undefined parameters.
	FullParams map[string]string
	Source     string
	// Unsigned DC API requests use the platform's origin to identify the caller and
	// omit client_id (OpenID4VP 1.0 Appendix A.2 and A.3.1).
	UnsignedDCAPI bool
	// InteractiveAuthorizationEndpoint is the Authorization Challenge Endpoint
	// of a presentation during issuance (OpenID4VCI 1.1 §6.2.1.1).
	InteractiveAuthorizationEndpoint string
	// Browser navigations redirect to the verifier after submission. API calls receive
	// JSON.
	BrowserRedirect bool
	// StatusClient fetches the status lists of registration certificates
	// (Wallet.RegistrationStatusClient).
	StatusClient *http.Client
	// RelyingPartyCAs, RegistrarCAs and RegistrationStatusCAs anchor the --arf
	// checks of access certificates, registration certificates and their status
	// lists.
	RelyingPartyCAs       []*x509.Certificate
	RegistrarCAs          []*x509.Certificate
	RegistrationStatusCAs []*x509.Certificate
}

type preparedPresentation struct {
	ResponseURI string
	Params      PresentationParams
	VPResult    *VPTokenMapResult
	IDToken     string
	Response    *AuthorizationResponseEnvelope
}

func (s *Server) handleAuthFlow(w http.ResponseWriter, authReq *AuthorizationRequestParams) {
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
			redirectBrowser(w, redirectURI)
			return
		}
		writeJSON(w, http.StatusOK, withRedirectURI(map[string]any{
			"status":            "no_match",
			"error":             "no matching credentials found",
			"error_code":        outcome.refusal.code,
			"error_description": outcome.refusal.description,
		}, redirectURI))
	case outcome.refusal != nil:
		s.triggerUIRequest("")
		s.submitAuthorizationError(w, authReq, outcome.refusal.status, outcome.refusal.code, outcome.refusal.description)
	case s.autoAccepts(authReq):
		s.log("  Mode:          auto-accept")
		s.autoAcceptPresentation(w, authReq, outcome.matches)
	case authReq.BrowserRedirect:
		// Browser navigations go to the wallet UI while the consent waits.
		// After approval, the UI follows the verifier's redirect_uri.
		s.log("  Mode:          interactive (waiting for consent)")
		shown := make(chan *ConsentRequest, 1)
		go s.awaitPresentationConsent(noopResponseWriter{}, authReq, outcome, func(req *ConsentRequest) { shown <- req })
		redirectBrowser(w, "/?request="+(<-shown).ID)
	default:
		s.log("  Mode:          interactive (waiting for consent)")
		s.awaitPresentationConsent(w, authReq, outcome, nil)
	}
}

// logPresentationOutcome writes the decision of the shared flow to the console.
func (s *Server) logPresentationOutcome(authReq *AuthorizationRequestParams, outcome presentationOutcome) {
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
func (s *Server) autoAccepts(authReq *AuthorizationRequestParams) bool {
	return s.wallet.AutoAccept || authReq.AutoAccept || authReq.Source == "api"
}

// awaitPresentationConsent asks the user and delivers the answer. The
// submission channel also delivers the result to the approve API.
func (s *Server) awaitPresentationConsent(w http.ResponseWriter, authReq *AuthorizationRequestParams, outcome presentationOutcome, shown func(*ConsentRequest)) {
	s.allowSlowResponse(w, config.ConsentTimeout)
	consentReq, matches, approved, answered := s.wallet.askPresentationConsent("presentation", authReq.Session, authReq.ClientID, authReq, outcome, config.ConsentTimeout, func(req *ConsentRequest) {
		s.triggerUIRequest(req.ID)
		if s.onConsentRequest != nil {
			s.onConsentRequest(req)
		}
		if shown != nil {
			shown(req)
		}
	})
	switch {
	case !answered:
		s.wallet.AddLog("presentation", "Consent timeout", false)
		consentReq.SubmissionCh <- SubmissionResult{Error: "consent timeout"}
		writeJSON(w, http.StatusRequestTimeout, map[string]string{"error": "consent timeout"})
	case !approved:
		s.log("  Consent:       denied")
		s.wallet.AddLog("presentation", fmt.Sprintf("Denied presentation to %s", authReq.ClientID), false)
		consentReq.SubmissionCh <- s.submitAuthorizationError(w, authReq, "denied", errorCodeAccessDenied, "User denied presentation")
	default:
		s.log("  Consent:       approved")
		consentReq.SubmissionCh <- s.submitPresentation(w, authReq, matches)
	}
}

// Browser navigations redirect to the UI immediately. Their consent flows finish in
// the background without writing to the original HTTP response.
type noopResponseWriter struct{}

func (noopResponseWriter) Header() http.Header         { return http.Header{} }
func (noopResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (noopResponseWriter) WriteHeader(int)             {}

func (s *Server) autoAcceptPresentation(w http.ResponseWriter, authReq *AuthorizationRequestParams, matches []CredentialMatch) {
	s.log("  Verifier:      %s", authReq.ClientID)
	for _, m := range matches {
		s.log("  Credential:    %s (%s), disclosing %v", m.Format, credTypeLabel(m), m.SelectedKeys)
	}
	s.submitPresentation(w, authReq, matches)
	s.log("  Auto-accepted")
}

func (s *Server) buildBrowserPresentationResult(authReq *AuthorizationRequestParams, protocol string, matches []CredentialMatch) (*BrowserAPIResult, *preparedPresentation, error) {
	prepared, err := s.wallet.preparePresentation(authReq, matches)
	if err != nil {
		return nil, nil, err
	}
	response, err := s.wallet.BuildAuthorizationResponse(prepared.VPResult, prepared.IDToken, authReq.State, prepared.Params)
	if err != nil {
		return nil, nil, err
	}
	result, err := BuildBrowserAPIResult(protocol, response)
	if err != nil {
		return nil, nil, err
	}
	prepared.Response = response
	return result, prepared, nil
}

func (s *Server) buildBrowserAuthorizationErrorResult(authReq *AuthorizationRequestParams, protocol, errorCode, errorDescription string) (*BrowserAPIResult, error) {
	response, err := s.wallet.BuildAuthorizationErrorResponse(errorCode, errorDescription, authReq.State, authReq.presentationParams())
	if err != nil {
		return nil, err
	}
	return BuildBrowserAPIResult(protocol, response)
}

// DC API responses return through the API call (Appendix A.4). Other responses need
// response_uri or redirect_uri.
func canDeliverAuthorizationError(authReq *AuthorizationRequestParams) bool {
	if authReq == nil || isDCAPIResponseMode(authReq.ResponseMode) {
		return false
	}
	return authReq.ResponseURI != "" || authReq.RedirectURI != ""
}

// deliverAuthorizationError logs the delivery of an error response to the
// console.
func (s *Server) deliverAuthorizationError(authReq *AuthorizationRequestParams, errorCode, errorDescription string) (*DirectPostResult, error) {
	s.log("  Submitting authorization error to %s", authReq.responseDestination())
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
func (s *Server) reportRefusalToVerifier(authReq *AuthorizationRequestParams, errorCode, errorDescription string) string {
	if !canDeliverAuthorizationError(authReq) {
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
func SubmittedPresentation(result *DirectPostResult, vp *VPTokenMapResult, findings []string) map[string]any {
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

func (s *Server) submitAuthorizationError(w http.ResponseWriter, authReq *AuthorizationRequestParams, status, errorCode, errorDescription string) SubmissionResult {
	result, err := s.deliverAuthorizationError(authReq, errorCode, errorDescription)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return SubmissionResult{Error: err.Error()}
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

func submissionResult(result *DirectPostResult) SubmissionResult {
	submission := SubmissionResult{RedirectURI: result.RedirectURI, StatusCode: result.StatusCode}
	if result.StatusCode >= 400 {
		submission.Error = result.Body
	}
	return submission
}

func (s *Server) submitPresentation(w http.ResponseWriter, authReq *AuthorizationRequestParams, matches []CredentialMatch) SubmissionResult {
	s.log("  Submitting VP token to %s", authReq.responseDestination())
	if authReq.State != "" {
		s.log("  State:         %s", authReq.State)
	}

	prepared, err := s.wallet.preparePresentation(authReq, matches)
	if err != nil {
		s.log("  ERROR: Presentation preparation failed: %v", err)
		s.wallet.AddLog("presentation", fmt.Sprintf("Presentation preparation failed: %v", err), false)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return SubmissionResult{Error: err.Error()}
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
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
		return SubmissionResult{Error: err.Error()}
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

// parseAuthParams reads the parameters of an /authorize request. The shared
// validation checks them, as it does for every entry point.
func parseAuthParams(values map[string][]string, opts oid4vc.ParseOptions) (*AuthorizationRequestParams, error) {
	parsed, err := oid4vc.ParseAuthorizationParams(values, opts)
	switch {
	case err != nil && len(values["request_uri"]) > 0:
		return nil, fmt.Errorf("parsing request_uri %q: %w", values["request_uri"][0], err)
	case err != nil:
		return nil, fmt.Errorf("parsing request JWT: %w", err)
	}
	return authorizationParams(parsed), nil
}

func requestPayload(reqObj *oid4vc.RequestObjectJWT, fallback map[string]any) map[string]any {
	return RequestPayload(reqObj, fallback)
}

// authorizationParams carries a parsed authorization request into the
// wallet's flow. Callers add where the request came from.
func authorizationParams(parsed *oid4vc.AuthorizationRequest) *AuthorizationRequestParams {
	return &AuthorizationRequestParams{
		ClientID:         parsed.ClientID,
		ResponseType:     parsed.ResponseType,
		ResponseMode:     parsed.ResponseMode,
		Nonce:            parsed.Nonce,
		State:            parsed.State,
		RedirectURI:      parsed.RedirectURI,
		ResponseURI:      parsed.ResponseURI,
		Scope:            parsed.Scope,
		RequestURIMethod: parsed.RequestURIMethod,
		RequestURI:       parsed.RequestURI,
		ClientMetadata:   parsed.ClientMetadata,
		DCQLQuery:        parsed.DCQLQuery,
		RequestObject:    parsed.RequestObject,
		RequestPayload:   requestPayload(parsed.RequestObject, parsed.FullJSON),
		FullParams:       parsed.FullParams,
	}
}

// shortID shortens a credential ID for the console. An ID from a credentials
// file can have fewer than 8 characters.
func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func credTypeLabel(m CredentialMatch) string {
	if m.VCT != "" {
		return m.VCT
	}
	if m.DocType != "" {
		return m.DocType
	}
	return m.Format
}
