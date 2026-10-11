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

package validate

import (
	"crypto/x509"
	"fmt"

	"github.com/dominikschlosser/eudi-dev/v3/internal/keys"
)

// NonStatusListFormat describes a status claim that does not use the IETF Token
// Status List (status.status_list), such as a W3C StatusList2021Entry. It
// returns "" when the status claim is absent or is a status_list. HAIP 1.0 §6.1
// requires the status_list form.
func NonStatusListFormat(claims map[string]any) string {
	status, ok := claims["status"].(map[string]any)
	if !ok {
		return ""
	}
	if _, ietf := status["status_list"].(map[string]any); ietf {
		return ""
	}
	if typ, _ := status["type"].(string); typ != "" {
		return fmt.Sprintf("the status claim uses %q, not a Token Status List (status.status_list)", typ)
	}
	return "the status claim is not a Token Status List (status.status_list)"
}

// HAIPCredentialFindings checks a credential's issuer key against HAIP 1.0
// §6.1.1. It checks the signing certificate chain and reports a DID key
// reference, which this profile cannot resolve.
func HAIPCredentialFindings(header, payload map[string]any) []string {
	var findings []string
	kid, _ := header["kid"].(string)
	iss, _ := payload["iss"].(string)
	if did := keys.DIDReference(kid, iss); did != "" {
		findings = append(findings, fmt.Sprintf(
			"HAIP 1.0 §6.1.1: the credential names its issuer key by the DID %s. The profile requires the issuer's signing certificate and its trust chain in the x5c header", did))
	}
	// HAIP 1.0 §6.1: "The status claim, if present, MUST contain status_list as
	// defined in [I-D.ietf-oauth-status-list]." The status claim is always in the
	// payload because it is never selectively disclosed.
	if nonStandard := NonStatusListFormat(payload); nonStandard != "" {
		findings = append(findings, fmt.Sprintf("HAIP 1.0 §6.1: %s", nonStandard))
	}

	chain, err := X5CCertificates(header)
	if err != nil {
		return append(findings, fmt.Sprintf("HAIP 1.0 §6.1.1: the x5c header does not hold readable certificates: %v", err))
	}
	return append(findings, HAIPCredentialChain(chain)...)
}

// HAIPCredentialChain checks what HAIP 1.0 §6.1.1 asks of an issued SD-JWT VC:
// "The SD-JWT VC MUST contain the credential issuer's signing certificate
// along with a trust chain in the x5c JOSE header parameter as described in
// section 3.5 of [I-D.ietf-oauth-sd-jwt-vc]. The X.509 certificate of the
// trust anchor MUST NOT be included in the x5c JOSE header of the SD-JWT VC.
// The X.509 certificate signing the request MUST NOT be self-signed."
//
// With x5c the issuer is the subject of the end-entity certificate, so SD-JWT
// VC makes iss optional. §6.1.1 is the IETF SD-JWT VC profile and has no
// counterpart for an mdoc.
func HAIPCredentialChain(chain []*x509.Certificate) []string {
	if len(chain) == 0 {
		return []string{"HAIP 1.0 §6.1.1: the credential has no x5c header. The profile requires the issuer's signing certificate and its trust chain there"}
	}

	var violations []string
	if SelfSignedCertificate(chain[0]) {
		violations = append(violations, "HAIP 1.0 §6.1.1: the certificate signing the credential MUST NOT be self-signed")
	}
	// The trust anchor depends on the checking party, and the wallet has no such
	// list. So every self-signed certificate in the chain is a finding.
	for i, cert := range chain[1:] {
		if SelfSignedCertificate(cert) {
			violations = append(violations, fmt.Sprintf(
				"HAIP 1.0 §6.1.1: the credential's x5c header carries a self-signed certificate at position %d (subject %q). The trust anchor certificate MUST NOT be included",
				i+2, cert.Subject.String()))
			break
		}
	}
	return violations
}

// SelfSignedCertificate checks whether a certificate verifies with its own public key.
func SelfSignedCertificate(cert *x509.Certificate) bool {
	if cert == nil {
		return false
	}
	if cert.Subject.String() != cert.Issuer.String() {
		return false
	}
	// CheckSignatureFrom rejects a non-CA certificate before it checks the signature.
	// It would miss a self-signed end-entity leaf, which HAIP §6.1.1 targets.
	return cert.CheckSignature(cert.SignatureAlgorithm, cert.RawTBSCertificate, cert.Signature) == nil
}
