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
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/findings"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
)

// presentationEntry describes the entry point a request came through.
type presentationEntry struct {
	// action labels the activity log entries, such as presentation or issuance.
	action string
	// subject identifies the request in a findings summary.
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
	// invalid is set for an invalid request from a relying party without a
	// trusted access certificate. The wallet reports it only to its caller and
	// sends nothing to the request's destination (RFC 6749 §4.1.2.1, applied
	// by OpenID4VP 1.0 §8.5).
	invalid     error
	invalidCode string
	// refusal is the Authorization Error Response for the verifier.
	refusal *presentationRefusal
	matches []consent.Match
	options *consent.CredentialOptions
}

// presentationRefusal is an error the wallet sends to the verifier. status
// identifies it in an API answer: refused, error or no_match.
type presentationRefusal struct {
	status, code, description string
}

// requestRefused is the error title when the wallet refuses a request because
// of its findings. Every view uses the same title.
const requestRefused = "The wallet refused the request"

// evaluatePresentationRequest validates a parsed request, records what it
// found and decides between refusing it and presenting credentials.
func (w *Wallet) evaluatePresentationRequest(authReq *oid4vp.Request, entry presentationEntry) presentationOutcome {
	w.PrepareARFChecks(authReq)
	list, err := oid4vp.ValidateAuthorizationRequest(w.Conformance().checks(), authReq)
	var authenticated *oid4vp.AuthenticatedRefusal
	// The verifier gets the error only if the wallet can encrypt it for an
	// encrypted response mode. Otherwise only the caller gets the refusal.
	if errors.As(err, &authenticated) && w.responseEncryptionError(authReq) == nil {
		event, summary := "authorization_request_refused", specCitedSummary(entry.subject, authenticated.Findings)
		if authenticated.Code == oid4vp.ErrorAccessDenied {
			event, summary = "arf_refusal", "The request does not meet the ARF rules"
		}
		w.reportRefusal(entry.action, event, entry.owner, requestRefused, summary, err)
		// The description lists the findings, so the verifier under test sees
		// which rule its request breaks.
		return presentationOutcome{refusal: &presentationRefusal{
			status: "refused", code: authenticated.Code,
			description: (&findings.Error{Summary: summary, Findings: authenticated.Findings}).Error(),
		}}
	}
	if err != nil {
		w.reportRefusal(entry.action, "authorization_request_refused", entry.owner, requestRefused, specCitedSummary(entry.subject, findings.Of(err)), err)
		return presentationOutcome{invalid: err, invalidCode: oid4vp.RefusalCode(authReq)}
	}
	// OID4VP 1.0 §8.3.1 lets the wallet send an unencrypted error response
	// here ("MAY"). The wallet answers only its caller, with invalid_request.
	if err := w.responseEncryptionError(authReq); err != nil {
		w.reportRefusal(entry.action, "response_encryption_unavailable", entry.owner, "The response cannot be encrypted", "", err)
		return presentationOutcome{invalid: err, invalidCode: oid4vp.ErrorInvalidRequest}
	}
	// The override answers only a valid request.
	if override := w.Consents().ConsumeNextError(); override != nil {
		w.AddLog(entry.action, fmt.Sprintf("Returned error override: %s", override.Error), false)
		return presentationOutcome{refusal: &presentationRefusal{status: "error", code: override.Error, description: override.ErrorDescription}}
	}

	authReq.Findings = list
	w.warnFindings(entry.action, "authorization_request_finding", specCitedSummary(entry.subject, list), list, nil)
	w.warnUndefinedRequestParameters(entry.action, authReq)

	if !oid4vp.ResponseTypeRequiresVP(authReq.ResponseType) {
		return presentationOutcome{}
	}
	// OID4VP 1.0 §5.5 leaves the scope values to the Wallet, and this wallet
	// defines none. §8.5 answers an unknown one with invalid_scope.
	if authReq.DCQLQuery == nil && strings.TrimSpace(authReq.Scope) != "" {
		description := fmt.Sprintf("the wallet supports no scope %q", authReq.Scope)
		w.reportRefusal(entry.action, "unsupported_scope", entry.owner, "Unsupported scope", "", errors.New(description))
		return presentationOutcome{refusal: &presentationRefusal{status: "refused", code: oid4vp.ErrorInvalidScope, description: description}}
	}
	var outcome presentationOutcome
	if authReq.DCQLQuery != nil {
		outcome.matches, outcome.options = w.matchDCQL(authReq.DCQLQuery)
	}
	// Debug mode lets a person answer with a credential that does not match.
	if len(outcome.matches) == 0 && (outcome.options == nil || !entry.interactive) {
		w.reportRefusal(entry.action, "no_matching_credentials", entry.owner, "No matching credentials", "",
			fmt.Errorf("no credential matches the query of %s", authReq.ClientID))
		// §8.5 access_denied: "The Wallet did not have the requested
		// Credentials to satisfy the Authorization Request."
		code, description := unsatisfiableQueryError(authReq.DCQLQuery)
		return presentationOutcome{refusal: &presentationRefusal{status: "no_match", code: code, description: description}}
	}
	return outcome
}

// askPresentationConsent shows the consent dialog and waits for the
// decision. answered is false after the timeout or when ctx ends. The caller
// reports the submission on the request's SubmissionCh. An error means the
// dialog was not shown, because too many requests wait for consent.
func (w *Wallet) askPresentationConsent(ctx context.Context, typ, owner, asking string, authReq *oid4vp.Request, outcome presentationOutcome, timeout time.Duration, shown func(*consent.Request)) (consentReq *consent.Request, matches []consent.Match, approved, answered bool, err error) {
	consentReq = newPresentationConsent(typ, owner, asking, authReq, outcome.matches, outcome.options)
	if err := w.Consents().Create(consentReq); err != nil {
		return nil, nil, false, false, err
	}
	if shown != nil {
		shown(consentReq)
	}
	result, answered := w.awaitConsent(ctx, consentReq, timeout)
	if !answered || !result.Approved {
		return consentReq, nil, false, answered, nil
	}
	return consentReq, w.consentedMatches(consentReq, outcome.matches, result), true, true, nil
}

// preparePresentation creates the vp_token and the requested id_token.
func (w *Wallet) preparePresentation(authReq *oid4vp.Request, matches []consent.Match) (*preparedPresentation, error) {
	prepared := &preparedPresentation{
		ResponseURI: authReq.ResponseDestination(),
	}

	if oid4vp.ResponseTypeContains(authReq.ResponseType, "vp_token") || authReq.ResponseType == "" {
		w.renewExpiring(matches)
		// A batch credential's use count changes, so it is saved under the
		// store lock.
		var err error
		w.saveChange(func() bool {
			prepared.VPResult, err = w.createVPTokenMap(matches, authReq)
			return w.takeBatchStateDirty()
		})
		if err != nil {
			return nil, fmt.Errorf("creating VP token map: %w", err)
		}
	}

	if oid4vp.ResponseTypeContains(authReq.ResponseType, "id_token") {
		// DC API presentations use the platform origin as the audience, prefixed
		// with origin: (OID4VP 1.0 §5.9.3).
		idToken, err := w.createSelfIssuedIDToken(authReq.Nonce, presentationAudience(authReq))
		if err != nil {
			return nil, fmt.Errorf("creating id_token: %w", err)
		}
		prepared.IDToken = idToken
	}

	return prepared, nil
}

// renewExpiring renews the matched credentials that are about to expire, so
// headless CLI flows without the background poller present a fresh one. The
// renewal calls the issuer, so it runs before the store lock is taken. A
// failed renewal keeps the stored credential. The verifier may still accept
// it.
func (w *Wallet) renewExpiring(matches []consent.Match) {
	manage := &Management{wallet: w, commit: func(change func() error) error {
		var err error
		w.saveChange(func() bool {
			err = change()
			return err == nil
		})
		return err
	}}
	now := time.Now()
	for _, match := range matches {
		cred, ok := w.GetCredential(match.CredentialID)
		if !ok || !cred.CanRenew() || !w.credentialNeedsRenewal(cred, now) {
			continue
		}
		if _, err := manage.RenewCredential(cred.ID); err != nil {
			log.Printf("[VP] renewing %s before presenting it failed, sending the credential as it is: %v", cred.ID, err)
			continue
		}
		log.Printf("[VP] renewed %s before presenting it", cred.ID)
	}
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
	result, err := w.submitPresentation(prepared.VPResult, prepared.IDToken, authReq.State, prepared.ResponseURI, authReq, func(response *oid4vp.AuthorizationResponseEnvelope) {
		w.addProtocolLog("presentation", "presentation_response", fmt.Sprintf("Sending presentation response to %s", authReq.ClientID), true, presentationResponseLogDetails(authReq, w, matches, prepared), PresentationLogPayload(response))
	})
	if err != nil {
		w.addProtocolLog("presentation", "presentation_failed", fmt.Sprintf("Submission failed: %v", err), false, map[string]any{"error": err.Error()}, VerifierResponseErrorPayload(err))
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
	result, err := w.submitAuthorizationError(errorCode, errorDescription, authReq.State, responseURI, authReq, func(response *oid4vp.AuthorizationResponseEnvelope) {
		w.addProtocolLog("presentation", "presentation_error_response", fmt.Sprintf("Sending authorization error to %s", authReq.ClientID), true, errorDetails, PresentationLogPayload(response))
	})
	if err != nil {
		w.addProtocolLog("presentation", "presentation_failed", fmt.Sprintf("Error submission failed: %v", err), false, map[string]any{"error": err.Error()}, VerifierResponseErrorPayload(err))
		return nil, err
	}
	w.addProtocolLog("presentation", "verifier_response", fmt.Sprintf("Verifier result from %s: %s", authReq.ClientID, oid4vp.FormatDirectPostResult(result)), result.StatusCode < 400, verifierResponseLogDetails(authReq, &preparedPresentation{ResponseURI: responseURI}, result))
	return result, nil
}

func applyClientAuth(r *consent.Request, params *oid4vp.Request) {
	r.ClientAuthSigned, r.ClientAuthDetail = oid4vp.ClientAuthState(params)
	r.ClientName = oid4vp.ClientMetadataName(params)
}
