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
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
	"github.com/google/uuid"

	"github.com/eudi-dev/eudi-dev/v2/internal/oid4vc"

	"github.com/eudi-dev/eudi-dev/v2/internal/config"
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
	if payloadHasKey(authReq.RequestPayload, "transaction_data") {
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
	ClientID      string
	ResponseType  string
	ResponseMode  string
	Nonce         string
	State         string
	RequestOrigin string
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
	// Browser navigations redirect to the verifier after submission. API calls receive
	// JSON.
	BrowserRedirect bool
}

type preparedPresentation struct {
	ResponseURI string
	Params      PresentationParams
	VPResult    *VPTokenMapResult
	IDToken     string
	Response    *AuthorizationResponseEnvelope
}

func (s *Server) handleAuthFlow(w http.ResponseWriter, authReq *AuthorizationRequestParams) {
	source := authReq.Source
	if source == "" {
		source = "authorize"
	}
	authReq.Source = source
	s.addPresentationRequestLog(authReq, source)

	if override := s.wallet.ConsumeNextError(); override != nil {
		s.log("  Next-error override consumed: %s", override.Error)
		s.wallet.AddLog("presentation", fmt.Sprintf("Returned error override: %s", override.Error), false)
		s.submitAuthorizationError(w, authReq, "error", override.Error, override.ErrorDescription)
		return
	}

	mode, requireHAIP, _ := s.wallet.ConformanceSettings()
	findings, err := ValidateAuthorizationRequest(mode, requireHAIP, authReq)
	if err != nil {
		s.log("  ERROR: %v", err)
		s.wallet.AddLog("presentation", err.Error(), false)
		s.wallet.NotifyError(WalletError{
			Owner:   authReq.Session,
			Message: "Authorization request validation failed",
			Detail:  err.Error(),
		})
		s.triggerUIRequest("")
		// Do not send a response to a destination from an invalid request. OpenID4VP
		// 1.0 §8.5 follows RFC 6749 §4.1.2.1, which forbids automatic redirection when
		// the client identifier or redirect URI is invalid.
		errorCode := refusalCodeForRequest(authReq, err)
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"error":             errorCode,
			"error_description": err.Error(),
		})
		return
	}
	for _, finding := range findings {
		s.log("  WARNING: %s", finding)
	}
	s.wallet.warnFindings("presentation", specCitedSummary("The request", findings), findings)
	s.wallet.warnUndefinedRequestParameters("presentation", authReq)

	if authReq.DCQLQuery != nil {
		if dcqlJSON, err := json.Marshal(authReq.DCQLQuery); err == nil {
			s.log("  DCQL Query:    %s", string(dcqlJSON))
		}
	}

	requiresVP := ResponseTypeRequiresVP(authReq.ResponseType)

	var matches []CredentialMatch
	var credentialOptions *ConsentCredentialOptions
	if authReq.DCQLQuery != nil && requiresVP {
		matches, credentialOptions = s.wallet.EvaluateDCQLWithOptions(authReq.DCQLQuery)
	}

	s.log("  Matched:       %d credential(s)", len(matches))
	for _, m := range matches {
		s.log("    - %s %s (%s), disclosing %d claims", m.Format, credTypeLabel(m), m.CredentialID[:8], len(m.SelectedKeys))
	}

	if requiresVP && len(matches) == 0 {
		s.log("  Result:        no matching credentials")
		s.wallet.AddLog("presentation", fmt.Sprintf("No matching credentials for %s", authReq.ClientID), false)
		s.wallet.NotifyError(WalletError{
			Owner:   authReq.Session,
			Message: "No matching credentials",
			Detail:  fmt.Sprintf("Verifier %s requested credentials but none matched the query", authReq.ClientID),
		})
		s.triggerUIRequest("")
		// §8.5 access_denied: "The Wallet did not have the requested
		// Credentials to satisfy the Authorization Request."
		errorCode, description := unsatisfiableQueryError(authReq.DCQLQuery)
		s.reportRefusalToVerifier(authReq, errorCode, description)
		writeJSON(w, http.StatusOK, map[string]any{
			"status":            "no_match",
			"error":             "no matching credentials found",
			"error_code":        errorCode,
			"error_description": description,
		})
		return
	}

	// An API submission provides the caller's consent. Interactive URLs and scheme
	// handlers still show the consent dialog unless auto-accept is enabled.
	if s.wallet.AutoAccept || authReq.Source == "api" {
		s.log("  Mode:          auto-accept")
		s.autoAcceptPresentation(w, authReq, matches)
		return
	}

	s.log("  Mode:          interactive (waiting for consent)")
	consentReq := &ConsentRequest{
		ID:           newConsentID(),
		Type:         "presentation",
		Owner:        authReq.Session,
		MatchedCreds: matches,
		Status:       "pending",
		ResultCh:     make(chan ConsentResult, 1),
		SubmissionCh: make(chan SubmissionResult, 1),
		CreatedAt:    time.Now(),
		ClientID:     authReq.ClientID,
		Nonce:        authReq.Nonce,
		ResponseURI:  authReq.ResponseURI,
		DCQLQuery:    authReq.DCQLQuery,
		Purposes:     s.wallet.consentPurposes("presentation", authReq),

		CredentialOptions: credentialOptions,
	}
	consentReq.applyClientAuth(authReq)

	s.wallet.CreateConsentRequest(consentReq)
	s.triggerUIRequest(consentReq.ID)

	if s.onConsentRequest != nil {
		s.onConsentRequest(consentReq)
	}

	if authReq.BrowserRedirect {
		// Redirect browser navigations to the wallet UI while waiting for consent.
		// After approval, the UI follows the verifier's redirect_uri.
		go s.awaitPresentationConsent(noopResponseWriter{}, authReq, matches, consentReq)
		redirectBrowser(w, "/?request="+consentReq.ID)
		return
	}
	s.awaitPresentationConsent(w, authReq, matches, consentReq)
}

// The submission channel also delivers the result to the approve API.
func (s *Server) awaitPresentationConsent(w http.ResponseWriter, authReq *AuthorizationRequestParams, matches []CredentialMatch, consentReq *ConsentRequest) {
	handle := func(result ConsentResult) {
		if !result.Approved {
			s.log("  Consent:       denied")
			s.wallet.AddLog("presentation", fmt.Sprintf("Denied presentation to %s", authReq.ClientID), false)
			submission := s.submitAuthorizationError(w, authReq, "denied", "access_denied", "User denied presentation")
			consentReq.SubmissionCh <- submission
			return
		}

		s.log("  Consent:       approved")

		// Keep the automatic selection unless the user chose a different option or
		// credential.
		matches = ApplyConsentSelection(consentReq.CredentialOptions, matches, result)

		if result.SelectedClaims != nil {
			for i, m := range matches {
				if selectedKeys, ok := result.SelectedClaims[m.CredentialID]; ok {
					matches[i].SelectedKeys = selectedKeys
					cred, _ := s.wallet.GetCredential(m.CredentialID)
					matches[i].Claims = filterClaims(cred, selectedKeys)
					s.log("    - %s: disclosing %v", m.CredentialID[:8], selectedKeys)
				}
			}
		}

		s.submitPresentationWithNotify(w, authReq, matches, consentReq.SubmissionCh)
	}

	s.allowSlowResponse(w, config.ConsentTimeout)
	select {
	case result := <-consentReq.ResultCh:
		handle(result)
	case <-time.After(config.ConsentTimeout):
		// The timer can race with consent. Only time out requests that are still
		// pending.
		if _, ok := s.wallet.ResolveRequest(consentReq.ID, statusExpired); !ok {
			handle(<-consentReq.ResultCh)
			return
		}
		s.wallet.AddLog("presentation", "Consent timeout", false)
		consentReq.SubmissionCh <- SubmissionResult{Error: "consent timeout"}
		writeJSON(w, http.StatusRequestTimeout, map[string]string{"error": "consent timeout"})
	}
}

// Browser navigations redirect to the UI immediately. Their consent flows finish in
// the background without writing to the original HTTP response.
type noopResponseWriter struct{}

func (noopResponseWriter) Header() http.Header         { return http.Header{} }
func (noopResponseWriter) Write(b []byte) (int, error) { return len(b), nil }
func (noopResponseWriter) WriteHeader(int)             {}

func (s *Server) autoAcceptPresentation(w http.ResponseWriter, authReq *AuthorizationRequestParams, matches []CredentialMatch) {
	dim := color.New(color.Faint)
	green := color.New(color.FgGreen)
	yellow := color.New(color.FgYellow)

	dim.Println("───────────────────────────────────────")
	yellow.Printf("  Verifier: %s\n", authReq.ClientID)
	for _, m := range matches {
		fmt.Printf("  Credential: %s (%s)\n", m.Format, credTypeLabel(m))
		fmt.Printf("  Disclosing: %v\n", m.SelectedKeys)
	}

	s.submitPresentation(w, authReq, matches)
	green.Printf("  Auto-accepted\n")
	dim.Println("───────────────────────────────────────")
}

func (s *Server) submitPresentationWithNotify(w http.ResponseWriter, authReq *AuthorizationRequestParams, matches []CredentialMatch, submissionCh chan SubmissionResult) {
	result := s.submitPresentation(w, authReq, matches)
	if submissionCh != nil {
		submissionCh <- result
	}
}

func (s *Server) preparePresentation(authReq *AuthorizationRequestParams, matches []CredentialMatch) (*preparedPresentation, error) {
	responseURI := authReq.ResponseURI
	if responseURI == "" {
		responseURI = authReq.RedirectURI
	}

	params := PresentationParams{
		Nonce:          authReq.Nonce,
		ClientID:       authReq.ClientID,
		RequestOrigin:  authReq.RequestOrigin,
		ResponseURI:    responseURI,
		RedirectURI:    authReq.RedirectURI,
		ResponseMode:   authReq.ResponseMode,
		ClientMetadata: authReq.ClientMetadata,
		RequestObject:  authReq.RequestObject,
	}

	prepared := &preparedPresentation{
		ResponseURI: responseURI,
		Params:      params,
	}

	if ResponseTypeContains(authReq.ResponseType, "vp_token") || authReq.ResponseType == "" {
		vpResult, err := s.wallet.CreateVPTokenMap(matches, params)
		if err != nil {
			return nil, fmt.Errorf("creating VP token map: %w", err)
		}
		prepared.VPResult = vpResult
		// Persist the batch credential's updated use count.
		if s.wallet.takeBatchStateDirty() {
			s.persistWallet()
		}
	}

	if ResponseTypeContains(authReq.ResponseType, "id_token") {
		// DC API presentations use the platform origin as the audience, prefixed with
		// origin: (OID4VP 1.0 §5.9.3).
		idToken, err := s.wallet.CreateSelfIssuedIDToken(authReq.Nonce, presentationAudience(authReq))
		if err != nil {
			return nil, fmt.Errorf("creating id_token: %w", err)
		}
		prepared.IDToken = idToken
	}

	return prepared, nil
}

func (s *Server) buildBrowserPresentationResult(authReq *AuthorizationRequestParams, protocol string, matches []CredentialMatch) (*BrowserAPIResult, *preparedPresentation, error) {
	prepared, err := s.preparePresentation(authReq, matches)
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
	params := PresentationParams{
		Nonce:          authReq.Nonce,
		ClientID:       authReq.ClientID,
		RequestOrigin:  authReq.RequestOrigin,
		ResponseURI:    authReq.ResponseURI,
		RedirectURI:    authReq.RedirectURI,
		ResponseMode:   authReq.ResponseMode,
		ClientMetadata: authReq.ClientMetadata,
		RequestObject:  authReq.RequestObject,
	}
	response, err := s.wallet.BuildAuthorizationErrorResponse(errorCode, errorDescription, authReq.State, params)
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

// deliverAuthorizationError returns an OpenID4VP 1.0 §8.5 Authorization Error
// Response over the Response Mode of the request. §5.6: "Both successful and
// error responses SHOULD be returned using the supplied Response Mode."
func (s *Server) deliverAuthorizationError(authReq *AuthorizationRequestParams, errorCode, errorDescription string) (*DirectPostResult, error) {
	responseURI := authReq.ResponseURI
	if responseURI == "" {
		responseURI = authReq.RedirectURI
	}

	s.log("  Submitting authorization error to %s", responseURI)
	if authReq.State != "" {
		s.log("  State:         %s", authReq.State)
	}

	params := PresentationParams{
		Nonce:          authReq.Nonce,
		ClientID:       authReq.ClientID,
		RequestOrigin:  authReq.RequestOrigin,
		ResponseURI:    responseURI,
		RedirectURI:    authReq.RedirectURI,
		ResponseMode:   authReq.ResponseMode,
		ClientMetadata: authReq.ClientMetadata,
		RequestObject:  authReq.RequestObject,
	}

	errorDetails := presentationRequestLogDetails(authReq)
	addStringDetail(errorDetails, "submission_uri", responseURI)
	errorDetails["direction"] = "outbound"
	errorDetails["error"] = errorCode
	addStringDetail(errorDetails, "error_description", errorDescription)
	if authReq.Source != "" {
		errorDetails["source"] = authReq.Source
	}
	result, err := s.wallet.SubmitAuthorizationError(errorCode, errorDescription, authReq.State, responseURI, params, func(response *AuthorizationResponseEnvelope) {
		s.wallet.addProtocolLog("presentation", "presentation_error_response", fmt.Sprintf("Sending authorization error to %s", authReq.ClientID), true, errorDetails, PresentationLogPayload(response))
	})
	if err != nil {
		s.log("  ERROR: Error submission failed: %v", err)
		s.wallet.AddLogPayload("presentation", fmt.Sprintf("Error submission failed: %v", err), false, nil, VerifierResponseErrorPayload(err))
		return nil, err
	}

	s.log("  Response:      HTTP %d", result.StatusCode)
	if result.RedirectURI != "" {
		s.log("  Redirect:      %s", result.RedirectURI)
	}

	s.wallet.addProtocolLog("presentation", "verifier_response", fmt.Sprintf("Verifier result from %s: %s", authReq.ClientID, FormatDirectPostResult(result)), result.StatusCode < 400, verifierResponseLogDetails(authReq, &preparedPresentation{ResponseURI: responseURI}, result))

	return result, nil
}

// Send the refusal using the request's response mode (OID4VP 1.0 §5.6). Log delivery
// failures without changing the refusal.
func (s *Server) reportRefusalToVerifier(authReq *AuthorizationRequestParams, errorCode, errorDescription string) {
	if !canDeliverAuthorizationError(authReq) {
		return
	}
	_, _ = s.deliverAuthorizationError(authReq, errorCode, errorDescription)
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

	return SubmissionResult{
		RedirectURI: result.RedirectURI,
		StatusCode:  result.StatusCode,
		Error: func() string {
			if result.StatusCode >= 400 {
				return result.Body
			}
			return ""
		}(),
	}
}

func (s *Server) submitPresentation(w http.ResponseWriter, authReq *AuthorizationRequestParams, matches []CredentialMatch) SubmissionResult {
	responseURI := authReq.ResponseURI
	if responseURI == "" {
		responseURI = authReq.RedirectURI
	}

	s.log("  Submitting VP token to %s", responseURI)
	if authReq.State != "" {
		s.log("  State:         %s", authReq.State)
	}

	prepared, err := s.preparePresentation(authReq, matches)
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

	result, err := s.wallet.SubmitPresentation(prepared.VPResult, prepared.IDToken, authReq.State, responseURI, prepared.Params, func(response *AuthorizationResponseEnvelope) {
		s.wallet.addProtocolLog("presentation", "presentation_response", fmt.Sprintf("Sending presentation response to %s", authReq.ClientID), true, presentationResponseLogDetails(authReq, s.wallet, matches, prepared), PresentationLogPayload(response))
	})
	if err != nil {
		s.log("  ERROR: Submission failed: %v", err)
		s.wallet.AddLogPayload("presentation", fmt.Sprintf("Submission failed: %v", err), false, nil, VerifierResponseErrorPayload(err))
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

	s.wallet.addProtocolLog("presentation", "verifier_response", fmt.Sprintf("Verifier result from %s: %s", authReq.ClientID, FormatDirectPostResult(result)), result.StatusCode < 400, verifierResponseLogDetails(authReq, prepared, result))

	if authReq.BrowserRedirect {
		redirectBrowser(w, result.RedirectURI)
	} else {
		writeJSON(w, http.StatusOK, withRedirectURI(map[string]any{
			"status":   "submitted",
			"response": result,
			"vp_token_keys": func() []string {
				if prepared.VPResult == nil {
					return nil
				}
				return prepared.VPResult.QueryIDs()
			}(),
		}, result.RedirectURI))
	}

	return SubmissionResult{
		RedirectURI: result.RedirectURI,
		StatusCode:  result.StatusCode,
		Error: func() string {
			if result.StatusCode >= 400 {
				return result.Body
			}
			return ""
		}(),
	}
}

func parseAuthParams(values map[string][]string, opts oid4vc.ParseOptions, mode ValidationMode) (*AuthorizationRequestParams, error) {
	get := func(key string) string {
		if vs, ok := values[key]; ok && len(vs) > 0 {
			return vs[0]
		}
		return ""
	}

	fullParams := make(map[string]string, len(values))
	for key := range values {
		fullParams[key] = get(key)
	}

	params := &AuthorizationRequestParams{
		ClientID:         get("client_id"),
		ResponseType:     get("response_type"),
		ResponseMode:     get("response_mode"),
		Nonce:            get("nonce"),
		State:            get("state"),
		RedirectURI:      get("redirect_uri"),
		ResponseURI:      oid4vc.DeriveResponseURI(get("client_id"), get("response_mode"), get("response_uri")),
		RequestURIMethod: get("request_uri_method"),
		FullParams:       fullParams,
	}

	if cm := get("client_metadata"); cm != "" {
		var clientMetadata map[string]any
		if err := json.Unmarshal([]byte(cm), &clientMetadata); err != nil {
			return nil, fmt.Errorf("parsing client_metadata: %w", err)
		}
		params.ClientMetadata = clientMetadata
	}

	if td := get("transaction_data"); td != "" {
		if mode == ValidationModeStrict {
			// OpenID4VP 1.0 §8.5 uses invalid_transaction_data for unsupported
			// transaction types. This wallet supports none.
			return nil, &authorizationError{
				Code: errorCodeInvalidTransactionData,
				Err:  fmt.Errorf("transaction_data is not supported by this wallet"),
			}
		}
		log.Printf("[Wallet] WARNING: request contains transaction_data which is not processed (OID4VP §7.2)")
	}
	if method := get("request_uri_method"); method != "" && get("request_uri") == "" {
		return nil, fmt.Errorf("request_uri_method requires request_uri")
	}
	if method := get("request_uri_method"); method != "" && method != "get" && method != "post" {
		// §8.5 invalid_request_uri_method: "The value of the
		// request_uri_method request parameter is neither get nor post
		// (case-sensitive)."
		return nil, &authorizationError{
			Code: errorCodeInvalidRequestURIMethod,
			Err:  fmt.Errorf("unsupported request_uri_method %q", method),
		}
	}

	if dq := get("dcql_query"); dq != "" {
		var query map[string]any
		if err := json.Unmarshal([]byte(dq), &query); err != nil {
			return nil, fmt.Errorf("parsing dcql_query: %w", err)
		}
		params.DCQLQuery = query
	}

	// Pass all parameters to the parser so it can fetch request_uri using the
	// requested method.
	if requestURI := get("request_uri"); requestURI != "" {
		syntheticParams := url.Values{}
		for k, vs := range values {
			if len(vs) > 0 {
				syntheticParams.Set(k, vs[0])
			}
		}
		syntheticURI := "openid4vp://authorize?" + syntheticParams.Encode()

		parsed, err := ParseAuthorizationRequestWithOptions(syntheticURI, opts)
		if err != nil {
			return nil, fmt.Errorf("parsing request_uri %q: %w", requestURI, err)
		}
		params.ClientID = parsed.ClientID
		params.ResponseType = parsed.ResponseType
		params.Nonce = parsed.Nonce
		params.State = parsed.State
		params.ResponseURI = parsed.ResponseURI
		params.RedirectURI = parsed.RedirectURI
		params.ResponseMode = parsed.ResponseMode
		params.RequestURIMethod = parsed.RequestURIMethod
		params.RequestURI = parsed.RequestURI
		params.ClientMetadata = parsed.ClientMetadata
		params.DCQLQuery = parsed.DCQLQuery
		params.RequestObject = parsed.RequestObject
		params.RequestPayload = requestPayload(parsed.RequestObject, nil)
	}

	if requestJWT := get("request"); requestJWT != "" {
		parsed, err := ParseAuthorizationRequestWithOptions(requestJWT, opts)
		if err != nil {
			return nil, fmt.Errorf("parsing request JWT: %w", err)
		}
		params.ClientID = parsed.ClientID
		params.ResponseType = parsed.ResponseType
		params.Nonce = parsed.Nonce
		params.State = parsed.State
		params.ResponseURI = parsed.ResponseURI
		params.RedirectURI = parsed.RedirectURI
		params.ResponseMode = parsed.ResponseMode
		params.RequestURIMethod = parsed.RequestURIMethod
		params.ClientMetadata = parsed.ClientMetadata
		params.DCQLQuery = parsed.DCQLQuery
		params.RequestObject = parsed.RequestObject
		params.RequestPayload = requestPayload(parsed.RequestObject, nil)
	}

	if params.ClientID == "" {
		return nil, fmt.Errorf("missing client_id")
	}

	return params, nil
}

func requestPayload(reqObj *oid4vc.RequestObjectJWT, fallback map[string]any) map[string]any {
	return RequestPayload(reqObj, fallback)
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
