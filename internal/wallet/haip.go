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
	"net/url"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/netaddr"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
	"github.com/eudi-dev/eudi-dev/v3/internal/validate"
)

// ValidateHAIPIssuanceCompliance checks a credential offer and the issuer's
// metadata against the HAIP 1.0 profile of OpenID4VCI.
//
// The checks depend on the flow of the offer. §4 requires an issuer to
// support the authorization code flow. It has no rule for the pre-authorized
// code flow and scopes PAR to "when using the Authorization Endpoint":
//
//   - always: the credential issuer MUST be an https origin
//   - authorization code offers: the authorization server MUST support the
//     flow, offer pushed authorization requests and support PKCE with S256
//
// HAIP 1.0 §7 lists what ES256 must validate, and DPoP proofs are not on the
// list. dpop_signing_alg_values_supported is not a profile check.
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
	// The metadata field is optional, so a missing list says nothing about
	// PKCE support. A list that is present and lacks S256 is a violation.
	if _, declared := oauthMeta["code_challenge_methods_supported"]; declared &&
		!metadataListContains(oauthMeta, "code_challenge_methods_supported", "S256") {
		violations = append(violations, "HAIP 1.0 §4: the authorization server advertises PKCE without S256")
	}
	// §4.4.1 requires the issuer to require client authentication. Advertising
	// it is only a SHOULD (draft-ietf-oauth-attestation-based-client-auth-07
	// §10.1, -08 §9, -10 §8), so the wallet learns it by authenticating.

	return violations
}

// haipIssuerMetadataViolations checks the issuer metadata for the requested
// configuration against HAIP 1.0 §4.1. Both grants use the same metadata.
func haipIssuerMetadataViolations(metadata map[string]any, configID string) []string {
	var violations []string
	configs, _ := metadata["credential_configurations_supported"].(map[string]any)
	config, _ := configs[configID].(map[string]any)
	// §4.1: "The Credential Issuer metadata MUST include a scope for every
	// Credential Configuration it supports."
	if scope, _ := config["scope"].(string); scope == "" {
		violations = append(violations, fmt.Sprintf("HAIP 1.0 §4.1: credential configuration %q has no scope, which the issuer metadata must include for every credential configuration", configID))
	}
	// §4.1: "If the Issuer supports Credential Configurations that require key
	// binding, as indicated by the presence of
	// cryptographic_binding_methods_supported, the nonce_endpoint MUST be
	// present in the Credential Issuer Metadata."
	if _, binds := config["cryptographic_binding_methods_supported"]; binds {
		if endpoint, _ := metadata["nonce_endpoint"].(string); endpoint == "" {
			violations = append(violations, fmt.Sprintf("HAIP 1.0 §4.1: credential configuration %q requires key binding, and the issuer metadata has no nonce_endpoint", configID))
		}
	}
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
// advertises the authorization code flow. HAIP 1.0 §4 requires it. Metadata
// without grant_types_supported defaults to authorization_code (RFC 8414), so
// an authorization endpoint is enough.
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
// https always is. Plain http is allowed only on a local development host.
func secureIssuerOrigin(issuer string) bool {
	parsed, err := url.Parse(issuer)
	if err != nil {
		return false
	}
	return parsed.Scheme == "https" || parsed.Scheme == "http" && netaddr.IsLocal(parsed.Hostname())
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
// section profiles IETF SD-JWT VC, so other formats and unparseable
// credentials get no findings here.
func (w *Wallet) haipCredentialViolations(raw string) []string {
	token, err := sdjwt.ParseLenient(strings.TrimSpace(raw))
	if err != nil {
		return nil
	}
	return validate.HAIPCredentialFindings(token.Header, token.Payload)
}
