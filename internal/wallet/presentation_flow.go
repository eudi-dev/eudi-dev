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
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/consent"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vp"
)

// presentationEntry describes the entry point a request came through.
type presentationEntry struct {
	// action files the activity log entries, such as presentation or issuance.
	action string
	// subject names the request in a findings summary.
	subject string
	// owner is the browser session that sees notifications and consent.
	owner string
	// interactive is set when a person decides. Debug mode then offers
	// credentials that do not match.
	interactive bool
}

// presentationOutcome is what the shared presentation flow decided for a
// request (ADR-0012). The entry point delivers it.
type presentationOutcome struct {
	// invalid is a request the wallet answers only to its caller. OpenID4VP
	// 1.0 §8.5 applies RFC 6749 §4.1.2.1, which sends nothing to the
	// destination of an invalid request.
	invalid     error
	invalidCode string
	// refusal is the Authorization Error Response for the verifier.
	refusal *presentationRefusal
	matches []consent.Match
	options *consent.CredentialOptions
}

// presentationRefusal is an error the wallet sends to the verifier. status
// names it in an API answer: refused, error or no_match.
type presentationRefusal struct {
	status, code, description string
}

// evaluatePresentationRequest validates a parsed request, records what it
// found and decides between refusing it and presenting credentials.
func (w *Wallet) evaluatePresentationRequest(authReq *oid4vp.Request, entry presentationEntry) presentationOutcome {
	w.PrepareARFChecks(authReq)
	findings, err := oid4vp.ValidateAuthorizationRequest(w.Conformance().checks(), authReq)
	var arf *oid4vp.ARFRefusal
	if errors.As(err, &arf) {
		w.AddLog(entry.action, err.Error(), false)
		w.Consents().NotifyError(consent.Error{Owner: entry.owner, Message: "The request does not meet the ARF registration rules", Detail: err.Error()})
		// The description names the findings, so the verifier under test sees
		// which rule its request breaks.
		return presentationOutcome{refusal: &presentationRefusal{
			status: "refused", code: oid4vp.ErrorAccessDenied,
			description: "The request does not meet the ARF registration rules: " + strings.Join(arf.Findings, ", "),
		}}
	}
	if err != nil {
		w.AddLog(entry.action, err.Error(), false)
		w.Consents().NotifyError(consent.Error{Owner: entry.owner, Message: "Authorization request validation failed", Detail: err.Error()})
		return presentationOutcome{invalid: err, invalidCode: oid4vp.RefusalCode(authReq, err)}
	}
	// The override answers only a valid request.
	if override := w.Consents().ConsumeNextError(); override != nil {
		w.AddLog(entry.action, fmt.Sprintf("Returned error override: %s", override.Error), false)
		return presentationOutcome{refusal: &presentationRefusal{status: "error", code: override.Error, description: override.ErrorDescription}}
	}

	authReq.Findings = findings
	w.warnFindings(entry.action, specCitedSummary(entry.subject, findings), findings)
	w.warnUndefinedRequestParameters(entry.action, authReq)

	if !oid4vp.ResponseTypeRequiresVP(authReq.ResponseType) {
		return presentationOutcome{}
	}
	var outcome presentationOutcome
	if authReq.DCQLQuery != nil {
		outcome.matches, outcome.options, err = w.EvaluateDCQLWithOptions(authReq.DCQLQuery)
		if err != nil {
			w.AddLog(entry.action, err.Error(), false)
			w.Consents().NotifyError(consent.Error{Owner: entry.owner, Message: "The wallet refuses the credential query", Detail: err.Error()})
			code := oid4vp.ErrorCode(err)
			if code == oid4vp.ErrorInvalidRequest {
				return presentationOutcome{invalid: err, invalidCode: code}
			}
			return presentationOutcome{refusal: &presentationRefusal{status: "refused", code: code, description: err.Error()}}
		}
	}
	// Debug mode lets a person answer with a credential that does not match.
	if len(outcome.matches) == 0 && (outcome.options == nil || !entry.interactive) {
		w.AddLog(entry.action, fmt.Sprintf("No matching credentials for %s", authReq.ClientID), false)
		w.Consents().NotifyError(consent.Error{
			Owner:   entry.owner,
			Message: "No matching credentials",
			Detail:  fmt.Sprintf("Verifier %s requested credentials but none matched the query", authReq.ClientID),
		})
		// §8.5 access_denied: "The Wallet did not have the requested
		// Credentials to satisfy the Authorization Request."
		code, description := unsatisfiableQueryError(authReq.DCQLQuery)
		return presentationOutcome{refusal: &presentationRefusal{status: "no_match", code: code, description: description}}
	}
	return outcome
}

// askPresentationConsent shows the consent dialog and waits for the
// decision. answered is false after the timeout. The caller reports the
// submission on the request's SubmissionCh.
func (w *Wallet) askPresentationConsent(typ, owner, asking string, authReq *oid4vp.Request, outcome presentationOutcome, timeout time.Duration, shown func(*consent.Request)) (consentReq *consent.Request, matches []consent.Match, approved, answered bool) {
	consentReq = newPresentationConsent(typ, owner, asking, authReq, outcome.matches, outcome.options)
	w.Consents().Create(consentReq)
	if shown != nil {
		shown(consentReq)
	}
	result, answered := w.awaitConsent(consentReq, timeout)
	if !answered || !result.Approved {
		return consentReq, nil, false, answered
	}
	return consentReq, w.consentedMatches(consentReq, outcome.matches, result), true, true
}

// presentationParams are the request parameters the response depends on.
func presentationParams(r *oid4vp.Request) PresentationParams {
	return PresentationParams{
		Nonce:                            r.Nonce,
		ClientID:                         r.ClientID,
		RequestOrigin:                    r.RequestOrigin,
		ResponseURI:                      r.ResponseDestination(),
		RedirectURI:                      r.RedirectURI,
		ResponseMode:                     r.ResponseMode,
		ClientMetadata:                   r.ClientMetadata,
		RequestObject:                    r.RequestObject,
		SessionTranscript:                r.SessionTranscript,
		InteractiveAuthorizationEndpoint: r.InteractiveAuthorizationEndpoint,
	}
}

// preparePresentation creates the vp_token and the id_token the request asks
// for.
func (w *Wallet) preparePresentation(authReq *oid4vp.Request, matches []consent.Match) (*preparedPresentation, error) {
	prepared := &preparedPresentation{
		ResponseURI: authReq.ResponseDestination(),
		Params:      presentationParams(authReq),
	}

	if oid4vp.ResponseTypeContains(authReq.ResponseType, "vp_token") || authReq.ResponseType == "" {
		// A batch credential's use count changes, so it is saved under the
		// store lock.
		var err error
		w.saveChange(func() bool {
			prepared.VPResult, err = w.CreateVPTokenMap(matches, prepared.Params)
			return w.takeBatchStateDirty()
		})
		if err != nil {
			return nil, fmt.Errorf("creating VP token map: %w", err)
		}
	}

	if oid4vp.ResponseTypeContains(authReq.ResponseType, "id_token") {
		// DC API presentations use the platform origin as the audience, prefixed
		// with origin: (OID4VP 1.0 §5.9.3).
		idToken, err := w.CreateSelfIssuedIDToken(authReq.Nonce, presentationAudience(authReq))
		if err != nil {
			return nil, fmt.Errorf("creating id_token: %w", err)
		}
		prepared.IDToken = idToken
	}

	return prepared, nil
}

// saveChange runs change under the server's store lock and saves the wallet
// when change reports true. A wallet without a server runs change alone.
func (w *Wallet) saveChange(change func() bool) {
	if w.saveMutation != nil {
		w.saveMutation(change)
		return
	}
	change()
}

// submitPreparedPresentation sends a prepared presentation to the response
// destination and records both directions in the activity log.
func (w *Wallet) submitPreparedPresentation(authReq *oid4vp.Request, matches []consent.Match, prepared *preparedPresentation) (*oid4vp.DirectPostResult, error) {
	result, err := w.SubmitPresentation(prepared.VPResult, prepared.IDToken, authReq.State, prepared.ResponseURI, prepared.Params, func(response *oid4vp.AuthorizationResponseEnvelope) {
		w.addProtocolLog("presentation", "presentation_response", fmt.Sprintf("Sending presentation response to %s", authReq.ClientID), true, presentationResponseLogDetails(authReq, w, matches, prepared), PresentationLogPayload(response))
	})
	if err != nil {
		w.AddLogPayload("presentation", fmt.Sprintf("Submission failed: %v", err), false, nil, VerifierResponseErrorPayload(err))
		return nil, err
	}
	w.addProtocolLog("presentation", "verifier_response", fmt.Sprintf("Verifier result from %s: %s", authReq.ClientID, oid4vp.FormatDirectPostResult(result)), result.StatusCode < 400, verifierResponseLogDetails(authReq, prepared, result))
	return result, nil
}

// deliverAuthorizationError returns an OpenID4VP 1.0 §8.5 Authorization Error
// Response over the Response Mode of the request. §5.6: "Both successful and
// error responses SHOULD be returned using the supplied Response Mode."
func (w *Wallet) deliverAuthorizationError(authReq *oid4vp.Request, errorCode, errorDescription string) (*oid4vp.DirectPostResult, error) {
	responseURI := authReq.ResponseDestination()
	errorDetails := presentationRequestLogDetails(authReq)
	addStringDetail(errorDetails, "submission_uri", responseURI)
	errorDetails["direction"] = "outbound"
	errorDetails["error"] = errorCode
	addStringDetail(errorDetails, "error_description", errorDescription)
	if authReq.Source != "" {
		errorDetails["source"] = authReq.Source
	}
	result, err := w.SubmitAuthorizationError(errorCode, errorDescription, authReq.State, responseURI, presentationParams(authReq), func(response *oid4vp.AuthorizationResponseEnvelope) {
		w.addProtocolLog("presentation", "presentation_error_response", fmt.Sprintf("Sending authorization error to %s", authReq.ClientID), true, errorDetails, PresentationLogPayload(response))
	})
	if err != nil {
		w.AddLogPayload("presentation", fmt.Sprintf("Error submission failed: %v", err), false, nil, VerifierResponseErrorPayload(err))
		return nil, err
	}
	w.addProtocolLog("presentation", "verifier_response", fmt.Sprintf("Verifier result from %s: %s", authReq.ClientID, oid4vp.FormatDirectPostResult(result)), result.StatusCode < 400, verifierResponseLogDetails(authReq, &preparedPresentation{ResponseURI: responseURI}, result))
	return result, nil
}

func applyClientAuth(r *consent.Request, params *oid4vp.Request) {
	r.ClientAuthSigned, r.ClientAuthDetail = oid4vp.ClientAuthState(params)
	r.ClientName = oid4vp.ClientMetadataName(params)
}
