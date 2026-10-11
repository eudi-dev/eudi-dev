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
	"net/url"
	"slices"
	"strings"

	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
)

// ValidateAuthorizationRequest adds profile checks when the settings require
// HAIP or ARF. The validation mode decides whether findings stop the flow or
// become warnings.
func ValidateAuthorizationRequest(settings ConformanceSettings, params *AuthorizationRequestParams) ([]string, error) {
	mode, requireHAIP, requireARF := settings.ValidationMode, settings.RequireHAIP, settings.RequireARF
	if err := validateAuthorizationRequestSyntax(params); err != nil {
		return nil, fmt.Errorf("authorization request validation failed: %w", err)
	}

	var reqPayload map[string]any
	if params != nil && params.RequestObject != nil {
		reqPayload = params.RequestObject.Payload
	}
	if reqPayload == nil && params != nil {
		reqPayload = params.RequestPayload
	}
	var outerClientMetadata map[string]any
	if params != nil {
		outerClientMetadata = params.ClientMetadata
	}
	if err := ValidateClientMetadata(ResolveClientMetadata(reqPayload, outerClientMetadata)); err != nil {
		return nil, fmt.Errorf("authorization request validation failed: %w", err)
	}

	responseURI := ""
	clientID := ""
	requestOrigin := ""
	var reqObj *oid4vc.RequestObjectJWT
	if params != nil {
		responseURI = params.ResponseURI
		if responseURI == "" {
			responseURI = params.RedirectURI
		}
		clientID = params.ClientID
		requestOrigin = params.RequestOrigin
		reqObj = params.RequestObject
	}
	return validatePresentationRequestCore(mode, requireHAIP, requireARF, clientID, reqObj, responseURI, requestOrigin, params, reqPayload)
}

// ARFRefusal is a strict refusal on ARF findings alone. The relying party
// signed the request with a trusted access certificate, so its client
// identifier is valid and the wallet answers it with access_denied (RFC 6749
// §4.1.2.1, which OpenID4VP 1.0 §8.5 applies).
type ARFRefusal struct {
	Findings []string
}

func (e *ARFRefusal) Error() string {
	return "authorization request validation failed: " + strings.Join(e.Findings, ", ")
}

func validatePresentationRequestCore(mode ValidationMode, requireHAIP, requireARF bool, clientID string, reqObj *oid4vc.RequestObjectJWT, responseURI string, requestOrigin string, params *AuthorizationRequestParams, payload map[string]any) ([]string, error) {
	var findings []string

	if finding := VerifyClientID(clientID, reqObj, responseURI, requestOrigin); finding != "" {
		findings = append(findings, finding)
	}
	if finding := ValidateRequestObject(clientID, reqObj); finding != "" {
		findings = append(findings, finding)
	}
	if finding := VerifyRequestObjectSignature(clientID, reqObj); finding != "" {
		findings = append(findings, finding)
	}
	findings = append(findings, authorizationFindings(params, payload)...)
	var advisories []string
	if requireHAIP {
		findings = append(findings, ValidateHAIPCompliance(params, reqObj)...)
		advisories = HAIPAdvisories(params)
	}
	var arfFindings []string
	if requireARF {
		arfFindings = ARFFindings(params)
	}

	if mode == ValidationModeStrict && len(findings) == 0 && len(arfFindings) > 0 && relyingPartyAuthenticated(params) {
		return nil, &ARFRefusal{Findings: arfFindings}
	}
	findings = append(findings, arfFindings...)
	if mode == ValidationModeStrict && len(findings) > 0 {
		return nil, fmt.Errorf("authorization request validation failed: %s", strings.Join(findings, ", "))
	}

	return append(findings, advisories...), nil
}

// Collect the same OID4VP 1.0 findings in every mode. The caller decides whether to
// reject or warn.
func authorizationFindings(params *AuthorizationRequestParams, payload map[string]any) []string {
	if params == nil {
		return nil
	}

	var findings []string
	if !hasKnownClientIDPrefix(params.ClientID) {
		findings = append(findings, fmt.Sprintf("OID4VP 1.0 §5.9.3: client_id uses an unsupported prefix: %q", params.ClientID))
	}
	// §5.2 marks nonce REQUIRED. It binds the presentation to this request.
	if requestRequiresNonce(params.ResponseType) && params.Nonce == "" {
		findings = append(findings, "OID4VP 1.0 §5.2: nonce is required")
	}
	// §5.2 marks response_mode REQUIRED. Debug mode answers with direct_post.
	if params.ResponseMode == "" {
		findings = append(findings, "OID4VP 1.0 §5.2: response_mode is required")
	}
	// §8.2: "When the response_uri parameter is present, the redirect_uri
	// Authorization Request parameter MUST NOT be present."
	if responseModeUsesDirectPost(params.ResponseMode) && params.RedirectURI != "" {
		findings = append(findings, fmt.Sprintf("OID4VP 1.0 §8.2: redirect_uri must not be used with response_mode %q", params.ResponseMode))
	}
	// §5.1: "Either a dcql_query or a scope parameter representing a DCQL
	// Query MUST be present in the Authorization Request, but not both."
	if ResponseTypeRequiresVP(params.ResponseType) {
		hasDCQL := params.DCQLQuery != nil
		hasScope := strings.TrimSpace(params.Scope) != ""
		switch {
		case hasDCQL && hasScope:
			findings = append(findings, "OID4VP 1.0 §5.1: dcql_query and scope must not both be present")
		case !hasDCQL && !hasScope:
			findings = append(findings, "OID4VP 1.0 §5.1: a vp_token request must carry either dcql_query or scope")
		}
	}
	// Invalid format, meta or query ID fields violate §6.1. This is a request
	// error.
	findings = append(findings, DCQLQueryFindings(params.DCQLQuery)...)
	// §5.1: "Wallets that do not support this parameter MUST reject requests
	// that contain it."
	if requestHasTransactionData(params, payload) {
		findings = append(findings, "OID4VP 1.0 §5.1: transaction_data is not supported by this wallet")
	}
	if finding := expectedOriginsFinding(params, payload); finding != "" {
		findings = append(findings, finding)
	}
	return findings
}

// expectedOriginsFinding compares expected_origins with the origin the request
// came from, using simple string comparison.
func expectedOriginsFinding(params *AuthorizationRequestParams, payload map[string]any) string {
	origin := params.RequestOrigin
	if origin == "" {
		return ""
	}
	values := stringValues(payload["expected_origins"])
	switch {
	// OpenID4VCI 1.1 §6.2.1.1: "If expected_origins is present, it MUST
	// contain only the derived Origin of the Authorization Challenge Endpoint".
	case isInteractiveAuthorizationResponseMode(params.ResponseMode):
		if !payloadHasKey(payload, "expected_origins") || slices.Equal(values, []string{origin}) {
			return ""
		}
		return fmt.Sprintf("OID4VCI 1.1 §6.2.1.1: expected_origins must contain only %q, the origin of the authorization challenge endpoint, and contains %v", origin, payload["expected_origins"])
	// OpenID4VP 1.0 Appendix A.2: for a signed Digital Credentials API request
	// expected_origins is REQUIRED, and "If the Origin does not match any of
	// the entries in expected_origins, the Wallet MUST return an error."
	case isDCAPIResponseMode(params.ResponseMode) && !params.UnsignedDCAPI:
		if slices.Contains(values, origin) {
			return ""
		}
		return fmt.Sprintf("OID4VP 1.0 Appendix A.2: expected_origins must include the caller origin %q", origin)
	}
	return ""
}

// stringValues reads a JSON array in which every entry is a string. Any other
// value gives nil.
func stringValues(raw any) []string {
	entries, ok := raw.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		text, ok := entry.(string)
		if !ok {
			return nil
		}
		out = append(out, text)
	}
	return out
}

// specCitedSummary names the specifications the findings cite. A finding
// starts with its citation, such as "OID4VP 1.0 §5.2:" or "ARF RPRC_19:".
func specCitedSummary(subject string, findings []string) string {
	var specs []string
	for _, finding := range findings {
		if spec := citedSpecification(finding); spec != "" && !slices.Contains(specs, spec) {
			specs = append(specs, spec)
		}
	}
	if len(specs) == 0 {
		return subject + " does not follow the specification"
	}
	return fmt.Sprintf("%s does not follow %s", subject, strings.Join(specs, " and "))
}

// citedSpecification is the citation before the first colon of a finding, up
// to its first section or rule reference. A citation names a version or
// standard number, or a reference, so plain prose before a colon is none.
func citedSpecification(finding string) string {
	citation, _, found := strings.Cut(finding, ":")
	if !found {
		return ""
	}
	var spec []string
	referenced, numbered := false, false
	for _, word := range strings.Fields(citation) {
		if isSectionReference(word) {
			referenced = true
			break
		}
		numbered = numbered || isVersionNumber(word)
		spec = append(spec, word)
	}
	if len(spec) == 0 || (!referenced && !numbered) {
		return ""
	}
	return strings.Join(spec, " ")
}

// isSectionReference matches §5.2, Appendix, Annex and rule identifiers such
// as RPRC_19 or GEN-5.2.4-08.
func isSectionReference(word string) bool {
	if strings.HasPrefix(word, "§") || word == "Appendix" || word == "Annex" {
		return true
	}
	letters := strings.IndexFunc(word, func(r rune) bool { return r < 'A' || r > 'Z' })
	return letters > 0 && letters+1 < len(word) && (word[letters] == '_' || word[letters] == '-') && word[letters+1] >= '0' && word[letters+1] <= '9'
}

// isVersionNumber matches 1.0, 18013-5 and similar.
func isVersionNumber(word string) bool {
	return strings.Trim(word, "0123456789.-") == "" && strings.ContainsAny(word, "0123456789")
}

func requestRequiresNonce(responseType string) bool {
	return responseType == "" || ResponseTypeRequiresVP(responseType) || ResponseTypeContains(responseType, "id_token")
}

// OpenID4VCI 1.1 §6.2.1.1 allows openid4vp_request as unsigned parameters.
func unsignedInteractiveAuthorizationRequest(params *AuthorizationRequestParams) bool {
	return isInteractiveAuthorizationResponseMode(params.ResponseMode) && params.RequestObject == nil
}

func responseModeUsesDirectPost(responseMode string) bool {
	return responseMode == "direct_post" || responseMode == "direct_post.jwt"
}

// OID4VP 1.0 §5.9.2 treats identifiers without a colon as pre-registered clients.
// Report only unknown prefixes.
func hasKnownClientIDPrefix(clientID string) bool {
	_, _, known := lookupClientIDPrefix(clientID)
	return known || !strings.Contains(clientID, ":")
}

// requestHasTransactionData finds transaction_data in a request object,
// a JSON request or the query parameters.
func requestHasTransactionData(params *AuthorizationRequestParams, payload map[string]any) bool {
	_, inQuery := params.FullParams["transaction_data"]
	return inQuery || payloadHasKey(payload, "transaction_data")
}

func payloadHasKey(payload map[string]any, key string) bool {
	if payload == nil {
		return false
	}
	_, ok := payload[key]
	return ok
}

func validateAuthorizationRequestSyntax(params *AuthorizationRequestParams) error {
	if params == nil {
		return fmt.Errorf("authorization request is missing")
	}
	// OID4VP 1.0 Appendix A.2: "The client_id parameter MUST be omitted in
	// unsigned requests defined in Appendix A.3.1." That covers the Digital
	// Credentials API and, through OpenID4VCI 1.1 §6.2.1.1, an unsigned
	// openid4vp_request.
	if params.ClientID == "" && !params.UnsignedDCAPI && !unsignedInteractiveAuthorizationRequest(params) {
		return fmt.Errorf("missing client_id")
	}
	if err := validateResponseType(params.ResponseType); err != nil {
		return err
	}
	if err := validateResponseMode(params.ResponseMode, params.ResponseURI, params.RedirectURI); err != nil {
		return err
	}
	if err := validateRequestURIMethod(params.RequestURIMethod); err != nil {
		return err
	}
	if params.RequestURIMethod != "" && params.RequestURI == "" {
		return fmt.Errorf("request_uri_method requires request_uri")
	}
	// RFC 6749 §4.1.1 carries the request in query parameters, where an
	// object such as client_metadata is a JSON string (OID4VP 1.0 §5.1).
	for _, name := range []string{"client_metadata", "dcql_query"} {
		if raw := params.FullParams[name]; raw != "" && !json.Valid([]byte(raw)) {
			return fmt.Errorf("parsing %s: not valid JSON", name)
		}
	}
	if err := validateAbsoluteURI("response_uri", params.ResponseURI); err != nil {
		return err
	}
	if err := validateAbsoluteURI("redirect_uri", params.RedirectURI); err != nil {
		return err
	}
	return nil
}

func validateRequestURIMethod(method string) error {
	switch method {
	case "", "get", "post":
		return nil
	default:
		return fmt.Errorf("unsupported request_uri_method %q", method)
	}
}

func validateResponseType(responseType string) error {
	if responseType == "" {
		return nil
	}
	seen := map[string]bool{}
	for _, part := range strings.Fields(responseType) {
		switch part {
		case "vp_token", "id_token":
			if seen[part] {
				return fmt.Errorf("response_type %q contains duplicate %q", responseType, part)
			}
			seen[part] = true
		default:
			return fmt.Errorf("unsupported response_type value %q", part)
		}
	}
	return nil
}

func validateResponseMode(responseMode, responseURI, redirectURI string) error {
	switch responseMode {
	case "", "direct_post", "direct_post.jwt":
		if responseMode != "" && responseURI == "" {
			return fmt.Errorf("response_mode %q requires response_uri", responseMode)
		}
	case "dc_api", "dc_api.jwt":
		return nil
	case "ia_post", "ia_post.jwt":
		// The response goes to the Authorization Challenge Endpoint called by the
		// wallet, so there is no response_uri to require (OpenID4VCI 1.1
		// §6.2.1.1).
		return nil
	case "fragment":
		if redirectURI == "" {
			return fmt.Errorf("response_mode %q requires redirect_uri", responseMode)
		}
	default:
		return fmt.Errorf("unsupported response_mode %q", responseMode)
	}
	return nil
}

// Only HTTP and HTTPS redirects are safe here. url.Parse also treats javascript: and
// data: URLs as absolute, and navigating to them could run script on the wallet's
// origin.
func validateAbsoluteURI(field, raw string) error {
	if raw == "" {
		return nil
	}
	u, err := url.Parse(raw)
	if err != nil || !u.IsAbs() {
		return fmt.Errorf("%s must be an absolute URI", field)
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return nil
	default:
		return fmt.Errorf("%s must use http or https, got scheme %q", field, u.Scheme)
	}
}
