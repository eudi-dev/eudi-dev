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
	"net/netip"
	"net/url"
	"strings"

	"github.com/eudi-dev/eudi-dev/v2/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v2/internal/oid4vc"
	"github.com/eudi-dev/eudi-dev/v2/internal/sdjwt"
	"github.com/eudi-dev/eudi-dev/v2/internal/validate"
)

// ValidateHAIPCompliance checks an authorization request against HAIP 1.0 and
// returns the violations. Every finding is a MUST in the profile. The
// validation mode decides what a violation does.
func ValidateHAIPCompliance(params *AuthorizationRequestParams, reqObj *oid4vc.RequestObjectJWT) []string {
	var violations []string
	if params == nil {
		return []string{"HAIP 1.0: authorization request is missing"}
	}
	// §5.2: "The Wallet MUST support unsigned, signed, and multi-signed
	// requests as defined in Appendices A.3.1 and A.3.2 of [OIDF.OID4VP]." An
	// unsigned request carries no client_id, so the platform-reported origin
	// identifies the caller instead.
	unsigned := params.UnsignedDCAPI || (reqObj == nil && isDCAPIResponseMode(params.ResponseMode))

	// OpenID4VCI 1.1 §6.2.1.1 defines response mode, delivery and binding for a
	// presentation during Interactive Authorization. The HAIP 1.0 channel rules
	// do not apply to it. The HAIP 1.0 query rules still do.
	interactive := isInteractiveAuthorizationResponseMode(params.ResponseMode)

	// §5: "The Response type MUST be vp_token."
	if params.ResponseType != "vp_token" {
		violations = append(violations, fmt.Sprintf(
			"HAIP 1.0 §5: response_type MUST be 'vp_token', got %q", params.ResponseType))
	}

	// §5.1: "Response encryption MUST be used by utilizing response mode
	// direct_post.jwt." §5.2: "The Verifier MUST use the Response Mode
	// dc_api.jwt." Those are the only two the profile permits.
	if !interactive && params.ResponseMode != "direct_post.jwt" && params.ResponseMode != "dc_api.jwt" {
		violations = append(violations, fmt.Sprintf(
			"HAIP 1.0 §5.1/§5.2: response_mode MUST be 'direct_post.jwt' or 'dc_api.jwt', got %q", params.ResponseMode))
	}

	if !unsigned && !interactive {
		// §5: "For signed requests, the Verifier MUST use, and the Wallet
		// MUST accept the Client Identifier Prefix x509_hash."
		if !strings.HasPrefix(params.ClientID, "x509_hash:") {
			violations = append(violations, fmt.Sprintf(
				"HAIP 1.0 §5: a signed request MUST use the 'x509_hash:' Client Identifier Prefix, got %q", params.ClientID))
		}
		if reqObj == nil || reqObj.Header == nil {
			violations = append(violations, "HAIP 1.0 §5.1: signed Request Object (JAR) MUST be used")
		}
		// §5.1: "Signed Authorization Requests MUST be used by utilizing
		// JWT-Secured Authorization Request (JAR) [RFC9101] with the
		// request_uri parameter." An inline request object is signed but has no
		// request_uri. The Digital Credentials API has no request_uri at all.
		if reqObj != nil && !isDCAPIResponseMode(params.ResponseMode) && params.RequestURI == "" {
			violations = append(violations, "HAIP 1.0 §5.1: the signed Request Object MUST be delivered through the request_uri parameter")
		}
		violations = append(violations, haipSignedRequestViolations(reqObj)...)
	}

	// §5: "The DCQL query and response MUST be used as defined in Section 6
	// of [OIDF.OID4VP]."
	if params.DCQLQuery == nil {
		violations = append(violations, "HAIP 1.0 §5: DCQL query MUST be used (not presentation_definition)")
	}
	violations = append(violations, haipCredentialFormatViolations(params.DCQLQuery)...)

	if !interactive {
		violations = append(violations, haipClientMetadataViolations(params.ClientMetadata)...)
		violations = append(violations, haipEncryptionKeyViolations(params.RequestObject, params.ClientMetadata)...)
	}

	return violations
}

// haipEncryptionKeyViolations checks §5's requirement that the response is
// encrypted with ECDH-ES to the Verifier's key on the P-256 curve. It checks
// the key that findEncryptionJWK picks for the response.
func haipEncryptionKeyViolations(reqObj *oid4vc.RequestObjectJWT, clientMetadata map[string]any) []string {
	jwk := findEncryptionJWK(reqObj, clientMetadata)
	if jwk == nil {
		return nil
	}
	if kty, _ := jwk["kty"].(string); kty != "" && kty != "EC" {
		return []string{fmt.Sprintf("HAIP 1.0 §5: response encryption key MUST be an EC key on P-256 (ECDH-ES), got kty %q", kty)}
	}
	if crv, ok := jwk["crv"].(string); ok && crv != "P-256" {
		return []string{fmt.Sprintf("HAIP 1.0 §5: response encryption key MUST be on the P-256 curve, got %q", crv)}
	}
	return nil
}

func isDCAPIResponseMode(mode string) bool {
	return mode == "dc_api" || mode == "dc_api.jwt"
}

func haipSignedRequestViolations(reqObj *oid4vc.RequestObjectJWT) []string {
	if reqObj == nil || reqObj.Header == nil {
		return nil
	}
	var violations []string

	// §5: "The X.509 certificate of the trust anchor MUST NOT be included in
	// the x5c JOSE header of the signed request. The X.509 certificate
	// signing the request MUST NOT be self-signed."
	//
	// The trust anchor depends on what the checking party trusts. This wallet
	// holds no trust list, so it reports what it can see: a self-signed
	// certificate.
	certs, _ := extractCertChain(reqObj)
	if len(certs) > 0 {
		leaf := certs[0]
		if validate.SelfSignedCertificate(leaf) {
			violations = append(violations, "HAIP 1.0 §5: the certificate signing the request MUST NOT be self-signed")
		}
		for i, cert := range certs[1:] {
			if validate.SelfSignedCertificate(cert) {
				violations = append(violations, fmt.Sprintf(
					"HAIP 1.0 §5: the x5c header of the signed request carries a self-signed certificate at position %d (subject %q), where the certificate of the trust anchor MUST NOT be included",
					i+2, cert.Subject.String()))
				break
			}
		}
	}

	return violations
}

// haipCredentialFormatViolations checks the credential formats a DCQL query
// asks for. §5.3.1: "The Credential Format identifier MUST be mso_mdoc."
// §5.3.2: "The Credential Format identifier MUST be dc+sd-jwt." HAIP 1.0
// profiles only these two formats.
func haipCredentialFormatViolations(query map[string]any) []string {
	credentials, _ := query["credentials"].([]any)
	var violations []string
	for _, entry := range credentials {
		credential, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		format := jsonutil.GetString(credential, "format")
		if format != "mso_mdoc" && format != "dc+sd-jwt" {
			violations = append(violations, fmt.Sprintf(
				"HAIP 1.0 §5.3.1/§5.3.2: credential format MUST be 'mso_mdoc' or 'dc+sd-jwt', got %q", format))
		}
	}
	return violations
}

// haipClientMetadataViolations reports client metadata that lists neither of
// the encryption algorithms HAIP 1.0 §5 requires.
func haipClientMetadataViolations(metadata map[string]any) []string {
	if metadata == nil {
		return nil
	}
	if listed := haipContentEncryptionAlgorithms(metadata); !listed["A128GCM"] && !listed["A256GCM"] {
		return []string{"HAIP 1.0 §5: client metadata MUST list both 'A128GCM' and 'A256GCM' in encrypted_response_enc_values_supported, and lists neither"}
	}
	return nil
}

// HAIPAdvisories reports client metadata that lists only one of A128GCM and
// A256GCM. HAIP 1.0 §5 requires both. This is a warning in every mode, and the
// wallet encrypts the response with the listed one.
func HAIPAdvisories(params *AuthorizationRequestParams) []string {
	if params == nil || params.ClientMetadata == nil || isInteractiveAuthorizationResponseMode(params.ResponseMode) {
		return nil
	}
	if listed := haipContentEncryptionAlgorithms(params.ClientMetadata); listed["A128GCM"] != listed["A256GCM"] {
		return []string{"HAIP 1.0 §5: client metadata MUST list both 'A128GCM' and 'A256GCM' in encrypted_response_enc_values_supported"}
	}
	return nil
}

func haipContentEncryptionAlgorithms(metadata map[string]any) map[string]bool {
	values, _ := metadata["encrypted_response_enc_values_supported"].([]any)
	listed := make(map[string]bool, len(values))
	for _, value := range values {
		if text, ok := value.(string); ok {
			listed[text] = true
		}
	}
	return listed
}

func originAllowedByExpectedOrigins(payload map[string]any, origin string) bool {
	if payload == nil {
		return false
	}
	values := jsonutil.GetArray(payload, "expected_origins")
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		if text, ok := value.(string); ok && text == origin {
			return true
		}
	}
	return false
}

// ValidateHAIPIssuanceCompliance checks a credential offer and the issuer's
// metadata against the HAIP 1.0 profile of OpenID4VCI.
//
// The checks depend on the flow of the offer. §4 requires an issuer to
// support the authorization code flow. It has no rule for the pre-authorized
// code flow and scopes PAR to "when using the Authorization Endpoint":
//
//   - always: the credential issuer MUST be an https origin
//   - authorization code offers: the authorization server MUST support the
//     flow, offer pushed authorization requests, support PKCE with S256,
//     and support DPoP
func ValidateHAIPIssuanceCompliance(offer *oid4vc.CredentialOffer, oauthMeta map[string]any) []string {
	var violations []string
	if offer == nil {
		return []string{"HAIP 1.0: credential offer is missing"}
	}

	// OID4VCI 1.0 §12.2.1: "The Credential Issuer Identifier MUST be a case
	// sensitive URL using the https scheme".
	if issuer := strings.TrimSpace(offer.CredentialIssuer); issuer != "" && !secureIssuerOrigin(issuer) {
		violations = append(violations, fmt.Sprintf("OID4VCI 1.0 §12.2.1: the credential issuer must be an https URL, got %q", issuer))
	}

	if !usesAuthorizationEndpoint(offer) {
		return violations
	}

	if oauthMeta == nil {
		return append(violations, "HAIP 1.0 §4: the authorization server metadata could not be read")
	}
	if !supportsAuthorizationCodeFlow(oauthMeta) {
		violations = append(violations, "HAIP 1.0 §4: the authorization server must support the authorization code flow")
	}
	// §4 scopes PAR to "when using the Authorization Endpoint". Interactive
	// Authorization sends its request to the Authorization Challenge Endpoint
	// instead, so PAR does not apply there.
	//
	// Only the endpoint is checkable. RFC 9126 makes
	// require_pushed_authorization_requests optional.
	_, hasPAR := oauthMeta["pushed_authorization_request_endpoint"].(string)
	if !hasPAR && interactiveAuthorizationEndpoint(oauthMeta) == "" {
		violations = append(violations, "HAIP 1.0 §4: the authorization server must support pushed authorization requests")
	}
	// Both metadata fields are optional, so a missing list says nothing about
	// PKCE or DPoP support. A list that is present and lacks them is a
	// violation.
	if _, declared := oauthMeta["code_challenge_methods_supported"]; declared &&
		!metadataListContains(oauthMeta, "code_challenge_methods_supported", "S256") {
		violations = append(violations, "HAIP 1.0 §4: the authorization server advertises PKCE without S256")
	}
	// §7 requires every party to support ES256 at a minimum. This wallet signs
	// DPoP proofs with it.
	if _, declared := oauthMeta["dpop_signing_alg_values_supported"]; declared &&
		!metadataListContains(oauthMeta, "dpop_signing_alg_values_supported", "ES256") {
		violations = append(violations, "HAIP 1.0 §7: the authorization server advertises DPoP without ES256")
	}
	// §4.4.1 requires the issuer to require client authentication. Advertising
	// it is only a SHOULD (§10.1 of the attestation draft), so the wallet learns
	// it by authenticating.

	return violations
}

// usesAuthorizationEndpoint reports whether redeeming this offer goes through
// the authorization endpoint. An offer carrying only a pre-authorized code
// goes straight to the token endpoint.
func usesAuthorizationEndpoint(offer *oid4vc.CredentialOffer) bool {
	if offer.Grants.AuthorizationCode != "" || offer.Grants.IssuerState != "" {
		return true
	}
	return offer.Grants.PreAuthorizedCode == ""
}

// supportsAuthorizationCodeFlow reports whether the authorization server
// advertises the flow HAIP 1.0 §4 requires it to support. Metadata that
// omits grant_types_supported defaults to authorization_code per RFC 8414,
// so an authorization endpoint alone is enough to satisfy it.
func supportsAuthorizationCodeFlow(oauthMeta map[string]any) bool {
	if _, declared := oauthMeta["grant_types_supported"]; declared {
		return metadataListContains(oauthMeta, "grant_types_supported", "authorization_code")
	}
	// The Authorization Challenge Endpoint of Interactive Authorization also
	// issues an authorization_code grant.
	if interactiveAuthorizationEndpoint(oauthMeta) != "" {
		return true
	}
	endpoint, _ := oauthMeta["authorization_endpoint"].(string)
	return strings.TrimSpace(endpoint) != ""
}

// secureIssuerOrigin reports whether an issuer URL is acceptable transport.
// https always is. Plain http is allowed only on loopback, the way OAuth
// treats a local development host.
func secureIssuerOrigin(issuer string) bool {
	parsed, err := url.Parse(issuer)
	if err != nil {
		return false
	}
	if parsed.Scheme == "https" {
		return true
	}
	if parsed.Scheme != "http" {
		return false
	}
	host := parsed.Hostname()
	if host == "localhost" {
		return true
	}
	addr, err := netip.ParseAddr(host)
	return err == nil && addr.IsLoopback()
}

func metadataListContains(meta map[string]any, key, want string) bool {
	values, ok := meta[key].([]any)
	if !ok {
		return false
	}
	for _, raw := range values {
		if s, _ := raw.(string); s == want {
			return true
		}
	}
	return false
}

// haipCredentialViolations checks a received credential against §6.1.1. That
// section profiles IETF SD-JWT VC, so other formats and credentials the wallet
// cannot parse get no findings here.
func (w *Wallet) haipCredentialViolations(raw string) []string {
	token, err := sdjwt.ParseLenient(strings.TrimSpace(raw))
	if err != nil {
		return nil
	}
	return validate.HAIPCredentialFindings(token.Header, token.Payload)
}
