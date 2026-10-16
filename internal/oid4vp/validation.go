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

package oid4vp

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/dcql"
	"github.com/eudi-dev/eudi-dev/v3/internal/findings"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
)

// Checks selects how a wallet checks a request. Strict refuses a request with
// findings. Otherwise the findings become warnings. HAIP and ARF add the
// checks of those profiles.
type Checks struct {
	Strict bool
	HAIP   bool
	ARF    bool
}

// ValidateAuthorizationRequest adds profile checks when the checks require
// HAIP or ARF.
func ValidateAuthorizationRequest(checks Checks, params *Request) ([]string, error) {
	if err := validateAuthorizationRequestSyntax(params); err != nil {
		return nil, fmt.Errorf("authorization request validation failed: %w", err)
	}

	payload := requestPayload(params.RequestObject, params.RequestPayload)
	if err := validateClientMetadata(resolveClientMetadata(payload, params.ClientMetadata)); err != nil {
		return nil, fmt.Errorf("authorization request validation failed: %w", err)
	}
	return validatePresentationRequestCore(checks, params, payload)
}

// AuthenticatedRefusal is a strict refusal of a request signed with a trusted
// access certificate. The client identifier is valid, so the wallet sends Code
// to the relying party (RFC 6749 §4.1.2.1, applied by OpenID4VP 1.0 §8.5).
// Code is access_denied when only ARF findings remain. Otherwise it is the
// §8.5 code of the request error.
type AuthenticatedRefusal struct {
	Code     string
	Findings []string
}

func (e *AuthenticatedRefusal) Error() string { return refusal(e.Findings).Error() }
func (e *AuthenticatedRefusal) Unwrap() error { return refusal(e.Findings) }

func validatePresentationRequestCore(checks Checks, params *Request, payload map[string]any) ([]string, error) {
	// clientFindings make the client identifier invalid. RFC 6749 §4.1.2.1
	// then forbids sending the error to the client.
	var clientFindings []string
	clientID, reqObj := params.ClientID, params.RequestObject
	if finding := verifyClientID(clientID, reqObj, params.ResponseDestination(), params.RequestOrigin); finding != "" {
		clientFindings = append(clientFindings, finding)
	}
	if finding := validateRequestObject(clientID, reqObj); finding != "" {
		clientFindings = append(clientFindings, finding)
	}
	if finding := verifyRequestObjectSignature(clientID, reqObj); finding != "" {
		clientFindings = append(clientFindings, finding)
	}
	findings := append([]string{}, clientFindings...)
	findings = append(findings, requestObjectClaimFindings(params)...)
	findings = append(findings, authorizationFindings(params, payload)...)
	var advisories []string
	if advisory := unsignedRequestObjectAdvisory(reqObj); advisory != "" {
		advisories = append(advisories, advisory)
	}
	if advisory := missingAudienceAdvisory(params); advisory != "" {
		advisories = append(advisories, advisory)
	}
	if checks.HAIP {
		findings = append(findings, validateHAIPCompliance(params, reqObj)...)
		advisories = append(advisories, haipAdvisories(params)...)
	}
	var arfFindings []string
	if checks.ARF {
		arfFindings = append(ARFFindings(params), responseEncryptionFindings(checks, params)...)
		advisories = append(advisories, ARFAdvisories(params)...)
	}

	code := RefusalCode(params)
	if len(findings) == 0 {
		code = ErrorAccessDenied
	}
	findings = append(findings, arfFindings...)
	if checks.Strict && len(findings) > 0 && len(clientFindings) == 0 && relyingPartyAuthenticated(params) {
		return nil, &AuthenticatedRefusal{Code: code, Findings: findings}
	}
	if checks.Strict && len(findings) > 0 {
		return nil, refusal(findings)
	}

	return append(findings, advisories...), nil
}

func refusal(list []string) *findings.Error {
	return &findings.Error{Summary: "authorization request validation failed", Findings: list}
}

// authorizationFindings collects the OID4VP 1.0 findings of a request.
// validatePresentationRequestCore refuses them in strict mode and returns them
// as warnings otherwise.
func authorizationFindings(params *Request, payload map[string]any) []string {
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
	// §5.3: the Verifier MUST include state "if at least one Presentation
	// without Holder Binding is requested and unless the Digital Credentials
	// API is used".
	if params.State == "" && !IsDCAPIResponseMode(params.ResponseMode) && dcql.RequestsUnboundPresentation(params.DCQLQuery) {
		findings = append(findings, "OID4VP 1.0 §5.3: state is required when the request accepts a presentation without holder binding")
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
	findings = append(findings, dcql.QueryFindings(params.DCQLQuery)...)
	// §5: "Wallets that do not support this parameter MUST reject requests
	// that contain it." §8.4 repeats it.
	if hasTransactionData(params, payload) {
		findings = append(findings, "OID4VP 1.0 §5: transaction_data is not supported by this wallet")
	}
	if finding := expectedOriginsFinding(params, payload); finding != "" {
		findings = append(findings, finding)
	}
	return findings
}

// expectedOriginsFinding compares expected_origins with the request's origin,
// using simple string comparison.
func expectedOriginsFinding(params *Request, payload map[string]any) string {
	origin := params.RequestOrigin
	if origin == "" {
		return ""
	}
	values := jsonutil.Strings(payload["expected_origins"])
	switch {
	// OpenID4VCI 1.1 §6.2.1.1: "If expected_origins is present, it MUST
	// contain only the derived Origin of the Authorization Challenge Endpoint".
	case IsInteractiveAuthorizationResponseMode(params.ResponseMode):
		if !payloadHasKey(payload, "expected_origins") || slices.Equal(values, []string{origin}) {
			return ""
		}
		return fmt.Sprintf("OID4VCI 1.1 §6.2.1.1: expected_origins must contain only %q, the origin of the authorization challenge endpoint, and contains %v", origin, payload["expected_origins"])
	// OpenID4VP 1.0 Appendix A.2: for a signed Digital Credentials API request
	// expected_origins is REQUIRED, and "If the Origin does not match any of
	// the entries in expected_origins, the Wallet MUST return an error."
	case IsDCAPIResponseMode(params.ResponseMode) && !params.UnsignedDCAPI:
		if slices.Contains(values, origin) {
			return ""
		}
		return fmt.Sprintf("OID4VP 1.0 Appendix A.2: expected_origins must include the caller origin %q", origin)
	}
	return ""
}

func requestRequiresNonce(responseType string) bool {
	return responseType == "" || ResponseTypeRequiresVP(responseType) || ResponseTypeContains(responseType, "id_token")
}

// OpenID4VCI 1.1 §6.2.1.1 allows openid4vp_request as unsigned parameters.
func unsignedInteractiveAuthorizationRequest(params *Request) bool {
	return IsInteractiveAuthorizationResponseMode(params.ResponseMode) && params.RequestObject == nil
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

// hasTransactionData finds transaction_data in a request object,
// a JSON request or the query parameters.
func hasTransactionData(params *Request, payload map[string]any) bool {
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

func validateAuthorizationRequestSyntax(params *Request) error {
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
	if err := format.ValidateAbsoluteURI("response_uri", params.ResponseURI); err != nil {
		return err
	}
	if err := format.ValidateAbsoluteURI("redirect_uri", params.RedirectURI); err != nil {
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

// responseEncryptionFindings applies ARF OIA_09: "For remote presentation
// flows the Wallet Unit SHALL ensure that the attributes included in the
// presented attestation are accessible only to the Relying Party Instance, by
// encrypting the presentation response." HAIP 1.0 §5.1 and §5.2 require the
// same outside Interactive Authorization, so with the HAIP checks the HAIP
// finding covers it.
func responseEncryptionFindings(checks Checks, params *Request) []string {
	if ResponseModeEncrypts(params.ResponseMode) {
		return nil
	}
	if checks.HAIP && !IsInteractiveAuthorizationResponseMode(params.ResponseMode) {
		return nil
	}
	return []string{fmt.Sprintf("ARF OIA_09: response_mode %q returns the presentation unencrypted. The wallet must encrypt it", params.ResponseMode)}
}
