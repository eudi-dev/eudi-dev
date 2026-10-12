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
	"fmt"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
)

// CheckSDJWTIntegrity reports the RFC 9901 §7.1 processing of the
// disclosures: "If any step fails, the SD-JWT is not valid, and processing
// MUST be aborted." Parsing records each failed step as a deviation, such as a
// repeated digest (step 4) or an unreferenced disclosure (step 5). It adds the SD-JWT VC rule that registered claims stay in the
// Issuer-signed JWT.
func CheckSDJWTIntegrity(token *sdjwt.Token) Check {
	findings := append(append([]string{}, token.Deviations...), DisclosedRegisteredClaims(token)...)
	if len(findings) > 0 {
		return Check{Name: CheckIntegrity, Status: Fail, Detail: strings.Join(findings, ". ")}
	}
	if len(token.Disclosures) == 0 {
		return Check{Name: CheckIntegrity, Status: Skipped, Detail: "No disclosures to verify"}
	}
	n := len(token.Disclosures)
	return Check{Name: CheckIntegrity, Status: Pass, Detail: fmt.Sprintf("%d/%d disclosure digests verified", n, n)}
}

// DisclosedRegisteredClaims returns the registered claims provided by a
// disclosure. It also returns those whose signed value holds digests of
// sub-claims.
func DisclosedRegisteredClaims(token *sdjwt.Token) []string {
	var findings []string
	for _, name := range credtype.NeverDisclosedClaims {
		signed, isSigned := token.Payload[name]
		_, resolved := token.ResolvedClaims[name]
		switch {
		case !isSigned && resolved:
			findings = append(findings, fmt.Sprintf("the claim %s is selectively disclosed, which draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 does not allow", name))
		case isSigned && len(sdjwt.ReferencedDigests(&sdjwt.Token{Payload: map[string]any{name: signed}})) > 0:
			findings = append(findings, fmt.Sprintf("the claim %s has selectively disclosable sub-claims, which draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 does not allow", name))
		}
	}
	return findings
}

// CheckSDJWTType verifies the typ header parameter of the Issuer-signed JWT.
// draft-ietf-oauth-sd-jwt-vc-19 §2.2.1: "The Issuer MUST include the typ
// header parameter in the SD-JWT. The typ value MUST use dc+sd-jwt". A
// vc+sd-jwt token decodes but fails this check.
func CheckSDJWTType(token *sdjwt.Token) Check {
	if err := sdjwt.ValidateVCType(token.Header); err != nil {
		return Check{Name: CheckType, Status: Fail, Detail: err.Error()}
	}
	typ, _ := token.Header["typ"].(string)
	if format.JOSETypeIs(typ, sdjwt.TypeSDJWTVCLegacy) {
		return Check{Name: CheckType, Status: Fail, Detail: fmt.Sprintf("the typ header is %s, draft-ietf-oauth-sd-jwt-vc-19 §2.2.1 requires %s", typ, sdjwt.TypeSDJWTVC)}
	}
	return Check{Name: CheckType, Status: Pass, Detail: typ}
}

// CheckMDOCIntegrity hashes the complete IssuerSignedItem encodings and
// compares them with the MSO valueDigests. The issuer signature covers only
// the MSO, so this check binds the element values to it. An unreadable part
// or a docType different from the signed one fails it.
func CheckMDOCIntegrity(doc *mdoc.Document) Check {
	if len(doc.Deviations) > 0 {
		return Check{Name: CheckIntegrity, Status: Fail, Detail: strings.Join(doc.Deviations, ". ")}
	}
	if doc.IssuerAuth == nil || doc.IssuerAuth.MSO == nil {
		return Check{Name: CheckIntegrity, Status: Skipped, Detail: "No MSO available for digest verification"}
	}
	total := 0
	for _, items := range doc.NameSpaces {
		total += len(items)
	}
	if total == 0 {
		return Check{Name: CheckIntegrity, Status: Skipped, Detail: "No disclosed elements to verify"}
	}
	if err := mdoc.VerifyValueDigests(doc); err != nil {
		return Check{Name: CheckIntegrity, Status: Fail, Detail: err.Error()}
	}
	return Check{Name: CheckIntegrity, Status: Pass, Detail: fmt.Sprintf("%d/%d claim digests verified", total, total)}
}
