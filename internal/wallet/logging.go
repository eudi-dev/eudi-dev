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
	"net/url"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
)

// formLogPayload shows each field of a form body. The encoded form stays as
// the wire value.
func formLogPayload(label string, form url.Values) *LogPayload {
	if len(form) == 0 {
		return &LogPayload{Label: label, Body: ""}
	}
	fields := make(map[string]any, len(form))
	for key, values := range form {
		if len(values) == 1 {
			fields[key] = values[0]
		} else {
			fields[key] = values
		}
	}
	return &LogPayload{Label: label, Body: fields, Wire: form.Encode()}
}

func VerifierResponseErrorPayload(err error) *LogPayload {
	var responseErr *oid4vp.VerifierResponseError
	if errors.As(err, &responseErr) {
		return &LogPayload{Label: "Response", Body: responseErr.Body()}
	}
	return nil
}

func authorizationResponsePlaintext(plain map[string]any, responseMode string) map[string]any {
	if oid4vp.IsDCAPIResponseMode(responseMode) {
		out := make(map[string]any, len(plain))
		for key, value := range plain {
			if key != "state" {
				out[key] = value
			}
		}
		return out
	}
	return plain
}

func PresentationLogPayload(response *oid4vp.AuthorizationResponseEnvelope) *LogPayload {
	if response == nil {
		return nil
	}
	payload := &LogPayload{Label: "Response", Body: authorizationResponsePlaintext(response.Plain, response.ResponseMode)}
	if response.ResponseJWT != "" {
		payload.Encrypted = true
		payload.Wire = url.Values{"response": {response.ResponseJWT}}.Encode()
	} else if response.RedirectURI != "" {
		payload.Wire = response.RedirectURI
	} else if response.ResponseMode == "direct_post" {
		if form, err := oid4vp.DirectPostForm(response.Plain); err == nil {
			payload.Wire = form.Encode()
		}
	}
	return payload
}

func (s *Server) addPresentationRequestLog(authReq *oid4vp.Request, source string) {
	clientID := authReq.ClientID
	if clientID == "" {
		clientID = "unknown verifier"
	}
	details := presentationRequestLogDetails(authReq)
	details["event"] = "presentation_request"
	details["direction"] = "inbound"
	if source != "" {
		details["source"] = source
	}
	s.wallet.AddLogPayload("presentation", fmt.Sprintf("Received presentation request from %s", clientID), true, details, presentationRequestLogPayload(authReq))
}

func presentationRequestLogPayload(authReq *oid4vp.Request) *LogPayload {
	if authReq.RequestObject != nil {
		return &LogPayload{Label: "Request object", Body: authReq.RequestObject.Raw}
	}
	if authReq.RequestPayload != nil {
		return &LogPayload{Label: "Request", Body: authReq.RequestPayload}
	}
	return nil
}

func (w *Wallet) addProtocolLog(action, event, detail string, success bool, details map[string]any, payloads ...*LogPayload) {
	w.AddLogPayload(action, detail, success, protocolLogDetails(event, details), firstLogPayload(payloads))
}

func firstLogPayload(payloads []*LogPayload) *LogPayload {
	if len(payloads) == 0 {
		return nil
	}
	return payloads[0]
}

func (w *Wallet) addProtocolWarning(action, event, detail string, details map[string]any) {
	w.AddWarning(action, detail, protocolLogDetails(event, details))
}

func protocolLogDetails(event string, details map[string]any) map[string]any {
	if details == nil {
		details = map[string]any{}
	} else {
		clone := make(map[string]any, len(details)+1)
		for key, value := range details {
			clone[key] = value
		}
		details = clone
	}
	details["event"] = event
	return details
}

func presentationRequestLogDetails(authReq *oid4vp.Request) map[string]any {
	details := map[string]any{}
	addStringDetail(details, "client_id", authReq.ClientID)
	addStringDetail(details, "response_type", authReq.ResponseType)
	addStringDetail(details, "response_mode", authReq.ResponseMode)
	addStringDetail(details, "response_uri", authReq.ResponseURI)
	addStringDetail(details, "redirect_uri", authReq.RedirectURI)
	addStringDetail(details, "state", authReq.State)
	addStringDetail(details, "nonce", authReq.Nonce)
	addStringDetail(details, "request_uri_method", authReq.RequestURIMethod)
	addStringDetail(details, "request_origin", authReq.RequestOrigin)
	if authReq.ClientMetadata != nil {
		details["client_metadata"] = authReq.ClientMetadata
	}
	if authReq.DCQLQuery != nil {
		details["dcql_query"] = authReq.DCQLQuery
	}
	if authReq.RequestPayload != nil {
		details["request_object"] = authReq.RequestPayload
	}
	return details
}

func presentationSubmissionLogDetails(authReq *oid4vp.Request, w *Wallet, matches []consent.Match, vpResult *VPTokenMapResult, idToken string, result *oid4vp.DirectPostResult) map[string]any {
	details := presentationRequestLogDetails(authReq)
	if result != nil {
		details["status_code"] = result.StatusCode
		addStringDetail(details, "redirect_uri", result.RedirectURI)
		addStringDetail(details, "response_body", result.Body)
	}
	if vpResult != nil {
		details["vp_token"] = vpResult.VPToken()
	}
	if idToken != "" {
		details["id_token"] = idToken
	}
	if authReq.State != "" {
		details["state"] = authReq.State
	}
	if sent := sentCredentialLogDetails(matches); len(sent) > 0 {
		details["sent_credentials"] = sent
	}
	if presented := presentedCredentialLogDetails(w, matches, vpResult); len(presented) > 0 {
		details["presented_credentials"] = presented
	}
	return details
}

func presentationResponseLogDetails(authReq *oid4vp.Request, w *Wallet, matches []consent.Match, prepared *preparedPresentation) map[string]any {
	var vpResult *VPTokenMapResult
	var idToken string
	var submissionURI string
	if prepared != nil {
		vpResult = prepared.VPResult
		idToken = prepared.IDToken
		submissionURI = prepared.ResponseURI
	}
	return PresentationResponseLogDetails(authReq, w, matches, vpResult, idToken, submissionURI)
}

// PresentationResponseLogDetails returns the details of the wallet's outbound
// authorization response. Request material such as DCQL, request objects,
// client metadata and nonce belongs to the presentation_request entry.
func PresentationResponseLogDetails(authReq *oid4vp.Request, w *Wallet, matches []consent.Match, vpResult *VPTokenMapResult, idToken, submissionURI string) map[string]any {
	details := map[string]any{
		"direction": "outbound",
	}
	addStringDetail(details, "submission_uri", submissionURI)
	addStringDetail(details, "state", authReq.State)
	if authReq.Source != "" {
		details["source"] = authReq.Source
	}
	if vpResult != nil {
		details["vp_token"] = vpResult.VPToken()
	}
	if idToken != "" {
		details["id_token"] = idToken
	}
	if sent := sentCredentialLogDetails(matches); len(sent) > 0 {
		details["sent_credentials"] = sent
	}
	if presented := presentedCredentialLogDetails(w, matches, vpResult); len(presented) > 0 {
		details["presented_credentials"] = presented
	}
	return details
}

func verifierResponseLogDetails(authReq *oid4vp.Request, prepared *preparedPresentation, result *oid4vp.DirectPostResult) map[string]any {
	details := map[string]any{
		"direction": "inbound",
	}
	addStringDetail(details, "client_id", authReq.ClientID)
	addStringDetail(details, "response_mode", authReq.ResponseMode)
	addStringDetail(details, "state", authReq.State)
	if prepared != nil {
		addStringDetail(details, "submission_uri", prepared.ResponseURI)
	}
	if authReq.Source != "" {
		details["source"] = authReq.Source
	}
	if result != nil {
		details["status_code"] = result.StatusCode
		addStringDetail(details, "redirect_uri", result.RedirectURI)
		addStringDetail(details, "response_body", result.Body)
	}
	return details
}

func credentialImportLogDetails(cred *StoredCredential, raw string) map[string]any {
	if cred == nil {
		return map[string]any{}
	}
	details := map[string]any{
		"credential": CredentialSummary(*cred),
	}
	addStringDetail(details, "credential_id", cred.ID)
	addStringDetail(details, "format", cred.Format)
	addStringDetail(details, "vct", cred.VCT)
	addStringDetail(details, "doc_type", cred.DocType)
	addStringDetail(details, "raw_credential", raw)
	return details
}

type importedCredentialLogItem struct {
	ID  string `json:"credential_id"`
	Raw string `json:"credential"`
}

func credentialImportLogPayload(credentials []StoredCredential) *LogPayload {
	if len(credentials) == 0 {
		return nil
	}
	if len(credentials) == 1 {
		return &LogPayload{Label: "Credential", Body: credentials[0].Raw}
	}
	items := make([]importedCredentialLogItem, 0, len(credentials))
	for _, credential := range credentials {
		items = append(items, importedCredentialLogItem{ID: credential.ID, Raw: credential.Raw})
	}
	return &LogPayload{Label: "Imported credentials", Body: struct {
		Credentials []importedCredentialLogItem `json:"credentials"`
	}{Credentials: items}}
}

func sentCredentialLogDetails(matches []consent.Match) []map[string]any {
	if len(matches) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(matches))
	for _, match := range matches {
		item := map[string]any{
			"id":        match.CredentialID,
			"query_id":  match.QueryID,
			"format":    match.Format,
			"disclosed": append([]string(nil), match.SelectedKeys...),
		}
		addStringDetail(item, "vct", match.VCT)
		addStringDetail(item, "doc_type", match.DocType)
		out = append(out, item)
	}
	return out
}

func presentedCredentialLogDetails(w *Wallet, matches []consent.Match, vpResult *VPTokenMapResult) []map[string]any {
	if len(matches) == 0 {
		return nil
	}
	out := make([]map[string]any, 0, len(matches))
	// Matches of one query fill its vp_token array in order.
	tokenIndex := map[string]int{}
	for _, match := range matches {
		item := map[string]any{
			"id":        match.CredentialID,
			"query_id":  match.QueryID,
			"format":    match.Format,
			"disclosed": append([]string(nil), match.SelectedKeys...),
		}
		addStringDetail(item, "vct", match.VCT)
		addStringDetail(item, "doc_type", match.DocType)
		if len(match.Claims) > 0 {
			item["claims"] = match.Claims
		}
		if w != nil {
			if cred, ok := w.GetCredential(match.CredentialID); ok {
				item["credential"] = CredentialSummary(cred)
				addStringDetail(item, "raw_credential", cred.Raw)
			}
		}
		if vpResult != nil {
			if tokens, i := vpResult.TokenMap[match.QueryID], tokenIndex[match.QueryID]; i < len(tokens) {
				addStringDetail(item, "presentation", tokens[i])
			}
			tokenIndex[match.QueryID]++
		}
		out = append(out, item)
	}
	return out
}

func addStringDetail(details map[string]any, key string, value string) {
	if value != "" {
		details[key] = value
	}
}

func (w *Wallet) warnUndefinedRequestParameters(scope string, params *oid4vp.Request) {
	w.warnFindings(scope, "undefined_request_parameter", "The request contains parameters OID4VP 1.0 does not define", oid4vp.UndefinedRequestParameterFindings(params), nil)
}

func (w *Wallet) warnUndefinedResponseMembers(result *oid4vp.DirectPostResult) {
	members := oid4vp.UndefinedResponseMembers(result)
	if len(members) == 0 {
		return
	}
	w.AddWarning("presentation", fmt.Sprintf(
		"The verifier's response contains fields OID4VP 1.0 §8.2 does not define: %s. They are ignored.",
		strings.Join(members, ", ")), nil)
}
