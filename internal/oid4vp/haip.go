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
	"fmt"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/jwe"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
	"github.com/eudi-dev/eudi-dev/v3/internal/validate"
)

// validateHAIPCompliance checks an authorization request against HAIP 1.0 and
// returns the violations. Every finding is a MUST in the profile. The
// validation mode decides what a violation does.
func validateHAIPCompliance(params *Request, reqObj *oid4vc.RequestObjectJWT) []string {
	var violations []string
	if params == nil {
		return []string{"HAIP 1.0: authorization request is missing"}
	}
	// §5.2: "The Wallet MUST support unsigned, signed, and multi-signed
	// requests as defined in Appendices A.3.1 and A.3.2 of [OIDF.OID4VP]." An
	// unsigned request carries no client_id, so the platform-reported origin
	// identifies the caller instead.
	unsigned := params.UnsignedDCAPI || (reqObj == nil && IsDCAPIResponseMode(params.ResponseMode))

	// OpenID4VCI 1.1 §6.2.1.1 defines response mode, delivery and binding for a
	// presentation during Interactive Authorization. The HAIP 1.0 channel rules
	// do not apply to it. The HAIP 1.0 query rules still do.
	interactive := IsInteractiveAuthorizationResponseMode(params.ResponseMode)

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
			violations = append(violations, "HAIP 1.0 §5.1: a signed request object MUST be used")
		}
		// §5.1: "Signed Authorization Requests MUST be used by utilizing
		// JWT-Secured Authorization Request (JAR) [RFC9101] with the
		// request_uri parameter." An inline request object is signed but has no
		// request_uri. The Digital Credentials API has no request_uri at all.
		if reqObj != nil && !IsDCAPIResponseMode(params.ResponseMode) && params.RequestURI == "" {
			violations = append(violations, "HAIP 1.0 §5.1: the signed Request Object MUST be delivered through the request_uri parameter")
		}
		violations = append(violations, haipSignedRequestViolations(reqObj)...)
	}

	// §5: "The DCQL query and response MUST be used as defined in Section 6
	// of [OIDF.OID4VP]."
	if params.DCQLQuery == nil {
		violations = append(violations, "HAIP 1.0 §5: DCQL query MUST be used (not presentation_definition)")
	}

	if !interactive {
		violations = append(violations, haipClientMetadataViolations(params.ClientMetadata)...)
		violations = append(violations, haipEncryptionKeyViolations(params.RequestObject, params.ClientMetadata)...)
	}

	return violations
}

// haipEncryptionKeyViolations checks §5's requirement that the response is
// encrypted with ECDH-ES to the Verifier's key on the P-256 curve. It checks
// the key chosen by FindEncryptionJWK.
func haipEncryptionKeyViolations(reqObj *oid4vc.RequestObjectJWT, clientMetadata map[string]any) []string {
	jwk := FindEncryptionJWK(reqObj, clientMetadata)
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

func IsDCAPIResponseMode(mode string) bool {
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
	// Which certificate is the trust anchor depends on the party that checks the
	// chain. The wallet can only see whether the signer is self-signed.
	certs, _ := extractCertChain(reqObj)
	if len(certs) > 0 {
		leaf := certs[0]
		if validate.SelfSignedCertificate(leaf) {
			violations = append(violations, "HAIP 1.0 §5: the certificate signing the request MUST NOT be self-signed")
		}
		for i, cert := range certs[1:] {
			if validate.SelfSignedCertificate(cert) {
				violations = append(violations, fmt.Sprintf(
					"HAIP 1.0 §5: the x5c header of the signed request carries a self-signed certificate at position %d (subject %q). The trust anchor certificate MUST NOT be included",
					i+2, cert.Subject.String()))
				break
			}
		}
	}

	return violations
}

// haipClientMetadataViolations reports client metadata without A128GCM and
// A256GCM, the encryption algorithms required by HAIP 1.0 §5.
func haipClientMetadataViolations(metadata map[string]any) []string {
	if metadata == nil {
		return nil
	}
	if listed := haipContentEncryptionAlgorithms(metadata); !listed[jwe.EncA128GCM] && !listed[jwe.EncA256GCM] {
		return []string{"HAIP 1.0 §5: client metadata MUST list both 'A128GCM' and 'A256GCM' in encrypted_response_enc_values_supported, and lists neither"}
	}
	return nil
}

// haipAdvisories reports client metadata that lists only one of A128GCM and
// A256GCM. HAIP 1.0 §5 requires both. This is a warning in every mode, and the
// wallet encrypts the response with the listed one.
func haipAdvisories(params *Request) []string {
	if params == nil || params.ClientMetadata == nil || IsInteractiveAuthorizationResponseMode(params.ResponseMode) {
		return nil
	}
	if listed := haipContentEncryptionAlgorithms(params.ClientMetadata); listed[jwe.EncA128GCM] != listed[jwe.EncA256GCM] {
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
