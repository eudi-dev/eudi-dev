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
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/certchain"
	"github.com/eudi-dev/eudi-dev/v3/internal/findings"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/keys"
	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
	"github.com/eudi-dev/eudi-dev/v3/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
	"github.com/eudi-dev/eudi-dev/v3/internal/statuslist"
	"github.com/eudi-dev/eudi-dev/v3/internal/validity"
)

// jwtValidity reads exp and nbf from the issuer-signed payload. SD-JWT VC
// forbids selective disclosure of exp and nbf. iat falls back to the resolved
// claims, because a PID discloses it (CIR (EU) 2024/2977 Annex section 4.2,
// as replaced by CIR (EU) 2026/1731).
func jwtValidity(token *sdjwt.Token, now time.Time) Check {
	issued := unixClaim(token.Payload, "iat")
	if issued == nil {
		issued = unixClaim(token.ResolvedClaims, "iat")
	}
	return validityCheck(unixClaim(token.Payload, "nbf"), issued, unixClaim(token.Payload, "exp"), now, "No exp claim present")
}

// mdocValidity reads the MSO validityInfo. ISO 18013-5 §9.1.2.4 makes
// validityInfo and its validUntil mandatory.
func mdocValidity(doc *mdoc.Document, now time.Time) Check {
	var vi *mdoc.ValidityInfo
	if doc.IssuerAuth != nil && doc.IssuerAuth.MSO != nil {
		vi = doc.IssuerAuth.MSO.ValidityInfo
	}
	if vi == nil || vi.ValidUntil == nil {
		return Check{Name: CheckExpiry, Status: Fail, Detail: "the MSO has no validityInfo.validUntil, which ISO 18013-5 §9.1.2.4 requires"}
	}
	return validityCheck(vi.ValidFrom, vi.Signed, vi.ValidUntil, now, "")
}

func validityCheck(from, issued, until *time.Time, now time.Time, noUntil string) Check {
	switch {
	case validity.NotYet(from, now):
		return Check{Name: CheckExpiry, Status: Fail, Detail: fmt.Sprintf("not yet valid (valid from %s)", from.Format(time.RFC3339))}
	case validity.Expired(until, now):
		return Check{Name: CheckExpiry, Status: Fail, Detail: fmt.Sprintf("expired %s", validity.Relative(*until, now))}
	case validity.NotYet(issued, now):
		return Check{Name: CheckExpiry, Status: Warning, Detail: fmt.Sprintf("issued in the future (%s)", issued.Format(time.RFC3339))}
	case until == nil:
		return Check{Name: CheckExpiry, Status: Skipped, Detail: noUntil}
	}
	return Check{Name: CheckExpiry, Status: Pass, Detail: fmt.Sprintf("expires %s", validity.Relative(*until, now))}
}

func unixClaim(claims map[string]any, name string) *time.Time {
	seconds, ok := jsonutil.GetFloat64(claims, name)
	if !ok {
		return nil
	}
	t := time.Unix(int64(seconds), 0)
	return &t
}

// catalogueState is what the credential's catalogue entry says about it.
type catalogueState struct {
	found     bool
	anchoring CatalogueAnchoring
}

func (v run) catalogue(raw string) catalogueState {
	if v.opts.Offline || v.trust.Catalogue == nil {
		return catalogueState{}
	}
	anchoring, found := v.trust.Catalogue.CheckCatalogueAnchoring(raw)
	return catalogueState{found: found, anchoring: anchoring}
}

// catalogueAnchors returns the anchoring of the catalogue list. It counts
// only without supplied trust.
func (v run) catalogueAnchors(c catalogueState) (CatalogueAnchoring, bool) {
	return c.anchoring, !v.trust.Supplied && c.anchoring.AnchoredBy != ""
}

// trustCheck reports whether the trusted lists of the catalogue entry anchor
// the credential, as the wallet checks a received credential.
func (v run) trustCheck(c catalogueState, r *Result) Check {
	check := Check{Name: CheckTrust, Status: Skipped}
	switch {
	case v.opts.Offline:
		check.Detail = "Needs the trusted lists of the attestation catalogue"
		check.NeedsNetwork = true
		return check
	case v.trust.CatalogueErr != nil:
		check.Status = Fail
		check.Detail = fmt.Sprintf("Reading the wallet: %v", v.trust.CatalogueErr)
		return check
	case v.trust.Catalogue == nil:
		check.Detail = "No wallet with an attestation catalogue"
		return check
	case !c.found:
		check.Detail = "The attestation catalogue has no entry for this credential type"
		return check
	}
	anchoring := c.anchoring
	r.Catalogue = &anchoring
	switch {
	case anchoring.AnchoredBy != "":
		check.Status = Pass
		check.Anchor = anchoring.Anchor(ServiceIssuance)
		check.Detail = check.Anchor.String()
	case len(anchoring.Findings) > 0:
		check.Status = Warning
		if v.trust.Catalogue.RefusesTrustFindings() {
			check.Status = Fail
		}
		check.Detail = findings.Join(anchoring.Findings)
	default:
		check.Detail = findings.Join(append([]string{"The catalogue entry has no readable trusted list. ARF ISSU_10 asks to check an EAA only with access to its provider's trust anchors"}, anchoring.Warnings...))
	}
	return check
}

// emptyTrust fails the signature when the supplied trust has no key and no
// issuance service. Supplied trust is the only trust source, so the embedded
// certificate cannot stand in for it.
func (v run) emptyTrust() (Check, bool) {
	if v.trust.Supplied && !v.trust.Pending && len(v.trust.Keys) == 0 && len(v.trust.Issuance) == 0 {
		return Check{Name: CheckSignature, Status: Fail, Detail: "The supplied trust has no key and no issuance service"}, true
	}
	return Check{}, false
}

func (v run) jwtSignature(token *sdjwt.Token, c catalogueState, r *Result) Check {
	if v.trust.Err != nil {
		return Check{Name: CheckSignature, Status: Fail, Detail: v.trust.Err.Error()}
	}
	if check, empty := v.emptyTrust(); empty {
		return check
	}
	// The catalogue reports AnchoredBy only after the credential's chain and
	// signature verified with that list.
	if a, ok := v.catalogueAnchors(c); ok {
		if key, err := ExtractAndValidateX5C(token.Header, lote.CertInfos(a.IssuanceAnchors)); err == nil && key != nil {
			if res := sdjwt.Verify(token, key); res.SignatureValid {
				r.SDJWTVerify, r.SignatureSource = res, SourceX5CChain
				return Check{Name: CheckSignature, Status: Pass, Detail: "Valid, " + res.Algorithm}
			}
		}
	}

	anchors := lote.CertInfos(v.trust.Issuance)
	if v.opts.Offline {
		res, source, err := VerifyJWTSignatureOffline(token, v.trust.Keys, anchors)
		switch {
		case err != nil:
			return Check{Name: CheckSignature, Status: Fail, Detail: err.Error()}
		case res != nil && res.SignatureValid:
			r.SDJWTVerify, r.SignatureSource = res, source
			return Check{Name: CheckSignature, Status: Pass, Detail: validVia(res.Algorithm, source)}
		// Without supplied keys, the issuer metadata can provide the key.
		case (len(v.trust.Keys) == 0 && CanResolveJWTIssuerMetadata(token)) || (res == nil && v.trust.Pending):
			return Check{Name: CheckSignature, Status: Skipped, Detail: "Needs an issuer key that is only reachable over the network", NeedsNetwork: true}
		case res == nil:
			return Check{Name: CheckSignature, Status: Skipped, Detail: noKeyDetail(token)}
		}
		r.SDJWTVerify, r.SignatureSource = res, source
		return Check{Name: CheckSignature, Status: Fail, Detail: failedDetail(source, res.Errors)}
	}

	res, source, err := VerifyJWTSignature(token, v.trust.Keys, anchors, v.trust.HTTPClient)
	var metadataErr *IssuerMetadataError
	switch {
	case errors.As(err, &metadataErr) && !v.trust.Supplied:
		return Check{Name: CheckSignature, Status: Skipped, Detail: fmt.Sprintf("Issuer metadata lookup failed: %v", err)}
	case err != nil:
		return Check{Name: CheckSignature, Status: Fail, Detail: err.Error()}
	case res == nil:
		return Check{Name: CheckSignature, Status: Skipped, Detail: noKeyDetail(token)}
	}
	r.SDJWTVerify, r.SignatureSource = res, source
	if res.SignatureValid {
		return Check{Name: CheckSignature, Status: Pass, Detail: validVia(res.Algorithm, source)}
	}
	return Check{Name: CheckSignature, Status: Fail, Detail: failedDetail(source, res.Errors)}
}

// validVia is the detail of a passing signature. A chain to a trust anchor
// needs no source. The trust check reports the anchor.
func validVia(alg, source string) string {
	if source == SourceX5CChain {
		return "Valid, " + alg
	}
	return fmt.Sprintf("Valid, %s, via %s", alg, source)
}

// noKeyDetail explains a signature check without a key. A DID key reference
// gets its own reason, because this tool does not resolve DIDs.
func noKeyDetail(token *sdjwt.Token) string {
	kid, _ := token.Header["kid"].(string)
	iss, _ := token.Payload["iss"].(string)
	if did := keys.DIDReference(kid, iss); did != "" {
		return fmt.Sprintf("The issuer key is identified by the DID %s. This tool does not resolve DIDs", did)
	}
	return "No key provided"
}

func failedDetail(source string, errs []string) string {
	detail := "Signature verification failed"
	if source != "" {
		detail += " via " + source
	}
	var reasons []string
	for _, e := range errs {
		if e != sdjwt.ErrSignatureInvalid {
			reasons = append(reasons, e)
		}
	}
	if len(reasons) > 0 {
		detail += ": " + findings.Join(reasons)
	}
	return detail
}

// mdocSignature verifies the issuer signature over the MSO. The key comes
// from the x5chain when it chains to the anchors, then from the supplied
// keys. Without supplied trust, the x5chain leaf proves integrity only.
func (v run) mdocSignature(doc *mdoc.Document, c catalogueState, r *Result) Check {
	if v.trust.Err != nil {
		return Check{Name: CheckSignature, Status: Fail, Detail: v.trust.Err.Error()}
	}
	if check, empty := v.emptyTrust(); empty {
		return check
	}
	chain, err := ExtractMDOCX5ChainCertificates(doc)
	if err != nil {
		return Check{Name: CheckSignature, Status: Fail, Detail: fmt.Sprintf("Reading the x5chain: %v", err)}
	}

	anchors := v.trust.Issuance
	if a, ok := v.catalogueAnchors(c); ok {
		anchors = a.IssuanceAnchors
	}
	var reasons []string
	if len(anchors) > 0 && len(chain) > 0 {
		if leaf, err := certchain.Verify(chain, anchors); err != nil {
			reasons = append(reasons, fmt.Sprintf("certificate chain not trusted: %v", err))
		} else {
			res := mdoc.Verify(doc, leaf.PublicKey)
			r.MDOCVerify, r.SignatureSource = res, SourceX5CChain
			if res.SignatureValid {
				return Check{Name: CheckSignature, Status: Pass, Detail: validVia(res.Algorithm, SourceX5CChain)}
			}
			reasons = append(reasons, "the key of the trusted chain does not verify the signature")
		}
	}

	for _, key := range v.trust.Keys {
		res := mdoc.Verify(doc, key)
		r.MDOCVerify, r.SignatureSource = res, SourceProvidedKey
		if res.SignatureValid {
			return Check{Name: CheckSignature, Status: Pass, Detail: validVia(res.Algorithm, SourceProvidedKey)}
		}
	}

	if !v.trust.Supplied && len(chain) > 0 {
		res := mdoc.Verify(doc, chain[0].PublicKey)
		r.MDOCVerify, r.SignatureSource = res, SourceX5CLeaf
		if res.SignatureValid {
			return Check{Name: CheckSignature, Status: Pass, Detail: validVia(res.Algorithm, SourceX5CLeaf)}
		}
		return Check{Name: CheckSignature, Status: Fail, Detail: "Signature invalid (embedded x5chain leaf key)"}
	}

	if r.MDOCVerify == nil && len(reasons) == 0 {
		return Check{Name: CheckSignature, Status: Skipped, Detail: "No key provided"}
	}
	return Check{Name: CheckSignature, Status: Fail, Detail: failedDetail("", reasons)}
}

// status reads the credential's status. The credential status and the trust
// in the status list signature are separate checks. The revocation service
// of the trusted list anchors the status list (ETSI TS 119 602 V1.1.1 Table
// D.3). That list is the supplied list or the catalogue list anchoring the
// credential.
func (v run) status(claims map[string]any, prefer string, c catalogueState, r *Result) []Check {
	if nonStandard := NonStatusListFormat(claims); nonStandard != "" {
		return []Check{{Name: CheckStatus, Status: Warning, Detail: nonStandard + ". This status is not checked."}}
	}
	ref := statuslist.ExtractStatusRef(claims)
	switch {
	case ref == nil:
		return []Check{{Name: CheckStatus, Status: Skipped, Detail: "No status list reference in credential"}}
	case v.opts.Offline:
		return []Check{{Name: CheckStatus, Status: Skipped, Detail: "Needs the status list from the issuer", NeedsNetwork: true}}
	case !v.opts.Status:
		return []Check{{Name: CheckStatus, Status: Skipped, Detail: "Not requested"}}
	case v.trust.Err != nil:
		return []Check{{Name: CheckStatus, Status: Fail, Detail: v.trust.Err.Error()}}
	case ref.Invalid != "":
		return []Check{{Name: CheckStatus, Status: Fail, Detail: fmt.Sprintf("Malformed status list reference: %s", ref.Invalid)}}
	}

	checkOpts := statuslist.CheckOptions{Prefer: prefer, HTTPClient: v.trust.HTTPClient, Now: v.opts.Now}
	for _, cert := range v.trust.Revocation {
		checkOpts.TrustListCerts = append(checkOpts.TrustListCerts, statuslist.TrustCert{Raw: cert.Raw})
	}
	a, anchored := v.catalogueAnchors(c)
	if anchored {
		for _, cert := range a.StatusAnchors {
			checkOpts.CandidateAnchors = append(checkOpts.CandidateAnchors, statuslist.TrustCert{Raw: cert.Raw})
		}
	}

	result, err := statuslist.CheckWithOptions(ref, checkOpts)
	if err != nil {
		return []Check{{Name: CheckStatus, Status: Fail, Detail: fmt.Sprintf("Status check error: %v", err)}}
	}
	if len(result.HAIPFindings) > 0 && v.trust.Catalogue != nil && v.trust.Catalogue.RefusesHAIPFindings() {
		return []Check{{Name: CheckStatus, Status: Fail, Detail: findings.Join(result.HAIPFindings)}}
	}
	r.Status = result
	// draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3: "If the status claim is present
	// and using the status_list mechanism, the associated Status List Token
	// MUST be in JWT format."
	if r.Format == FormatSDJWT && result.Format == statuslist.FormatCWT {
		result.Warnings = append(result.Warnings, "the status list token is a CWT, but draft-ietf-oauth-sd-jwt-vc-19 §2.2.2.3 requires a JWT for an SD-JWT VC")
	}

	if !result.IsValid {
		return []Check{{Name: CheckStatus, Status: Fail, Detail: fmt.Sprintf("%s (index %d, status %d)", capitalize(result.StatusName), result.Index, result.Status)}}
	}
	status := Check{Name: CheckStatus, Status: Pass, Detail: fmt.Sprintf("Valid (index %d)", result.Index)}

	signature := Check{Name: CheckStatusSignature, Status: Pass, Detail: "Valid, " + result.SignatureInfo}
	notes := slices.Concat(result.Warnings, result.HAIPFindings)
	switch {
	case !result.TrustAnchored || len(result.HAIPFindings) > 0:
		signature.Status = Warning
		signature.Detail = findings.Join(append([]string{capitalize(result.SignatureInfo)}, notes...))
	case len(notes) > 0:
		signature.Detail += ". " + findings.Join(notes)
	}
	if result.TrustAnchored && anchored {
		signature.Anchor = a.Anchor(ServiceRevocation)
	}
	return []Check{status, signature}
}

func capitalize(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}
