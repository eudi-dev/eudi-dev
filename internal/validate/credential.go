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
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/certchain"
	"github.com/eudi-dev/eudi-dev/v3/internal/certinfo"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/findings"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
	"github.com/eudi-dev/eudi-dev/v3/internal/statuslist"
)

// Check is one step of a credential validation.
type Check struct {
	Name string `json:"name"`
	// Status is Pass, Fail, Warning or Skipped.
	Status string `json:"status"`
	Detail string `json:"detail"`
	// NeedsNetwork marks a check skipped because the validation ran offline.
	NeedsNetwork bool `json:"needsNetwork,omitempty"`
	// Anchor is the trusted list service behind a passing trust or status
	// list signature check.
	Anchor *Anchor `json:"anchor,omitempty"`
}

// Check states.
const (
	Pass    = "pass"
	Fail    = "fail"
	Warning = "warning"
	Skipped = "skipped"
)

// Check names, in the order Credential runs them.
const (
	CheckType            = "type"
	CheckExpiry          = "expiry"
	CheckIntegrity       = "integrity"
	CheckTrustedList     = "trusted list"
	CheckSignature       = "signature"
	CheckTrust           = "trust"
	CheckStatus          = "status"
	CheckCertificates    = "certificate revocation"
	CheckStatusSignature = "status list signature"
	CheckHAIP            = "haip"
	CheckDelegation      = "delegation"
)

// Credential formats of a Result.
const (
	FormatSDJWT = credtype.FormatSDJWT
	FormatJWT   = "jwt"
	FormatMDOC  = credtype.FormatMDOC
	FormatX509  = string(format.FormatX509)
)

// Options select the checks that run.
type Options struct {
	// Offline skips every check that needs the network and marks it
	// NeedsNetwork.
	Offline bool
	// Status fetches the status list of a credential with a status reference.
	Status bool
	// HAIP adds the HAIP 1.0 §6.1 rules for an SD-JWT VC as the haip check.
	HAIP bool
	// Now is the time of the validity checks. The zero value is the current
	// time.
	Now time.Time
}

// Result is one credential validation.
type Result struct {
	Format string
	// SDJWT is the parsed SD-JWT VC or JWT. MDOC is the parsed mdoc.
	SDJWT *sdjwt.Token
	MDOC  *mdoc.Document
	// Delegation is the chain of a Delegate SD-JWT. SDJWT is its SD-JWT.
	Delegation *sdjwt.Delegation
	// Chain is the result of each part of a Delegate SD-JWT or of a
	// KB-SD-JWT on its own. It is nil for any other credential.
	Chain *Chain
	// Certificates are pasted certificates, leaf first.
	Certificates []*x509.Certificate
	// Checks run in a fixed order: type, expiry, integrity, trusted list,
	// signature, trust, status, status list signature, haip.
	Checks []Check

	// SDJWTVerify or MDOCVerify is the signature verification behind the
	// signature check. SignatureSource identifies the verifying key.
	SDJWTVerify     *sdjwt.VerifyResult
	MDOCVerify      *mdoc.VerifyResult
	SignatureSource string
	// Catalogue is the anchoring by the credential's catalogue entry. It is
	// nil when the catalogue was not consulted or has no entry.
	Catalogue *CatalogueAnchoring
	// Status is the fetched status list entry.
	Status *statuslist.StatusResult
	// HAIPFindings are set when Options.HAIP applies to the credential.
	HAIPFindings findings.List
}

// Find returns the check with the name.
func (r *Result) Find(name string) (Check, bool) {
	for _, c := range r.Checks {
		if c.Name == name {
			return c, true
		}
	}
	return Check{}, false
}

func (r *Result) add(checks ...Check) {
	r.Checks = append(r.Checks, checks...)
}

// Credential validates a raw SD-JWT VC, JWT, mdoc or X.509 certificates. It
// fails when the input is none of these or a certificate in it doesn't parse.
// All other findings are checks of the result.
func Credential(raw string, trust Trust, opts Options) (*Result, error) {
	if jwt, ok := format.Base64URLEncodedJWT(raw); ok {
		raw = jwt
	}
	var certErr *format.CertificateError
	if certs, err := format.Certificates(raw); err == nil {
		return Certificates(certs, trust, opts), nil
	} else if errors.As(err, &certErr) {
		return nil, err
	}
	switch format.DetectEncoding(raw) {
	case format.FormatSDJWT:
		if sdjwt.IsDelegation(raw) {
			return delegation(raw, trust, opts)
		}
		token, err := sdjwt.Inspect(raw)
		if err != nil {
			return nil, fmt.Errorf("parsing SD-JWT: %w", err)
		}
		if isKBSDJWT(token) {
			return KBSDJWT(token, opts), nil
		}
		return SDJWT(token, trust, opts), nil
	case format.FormatJWT:
		// sdjwt reports a broken JWT part as "parsing JWT" already.
		token, err := sdjwt.Inspect(raw)
		if err != nil {
			return nil, err
		}
		if isKBSDJWT(token) {
			return KBSDJWT(token, opts), nil
		}
		return JWT(token, trust, opts), nil
	case format.FormatMDOC:
		doc, err := mdoc.Parse(raw)
		if err != nil {
			return nil, fmt.Errorf("parsing mdoc: %w", err)
		}
		return MDOC(doc, trust, opts), nil
	}
	return nil, fmt.Errorf("unable to auto-detect credential format (not JWT, SD-JWT, or mdoc)")
}

// delegation validates the SD-JWT of a Delegate SD-JWT and adds the delegation
// check for its KB-SD-JWTs (draft-ietf-oauth-delegate-sd-jwt-00 §6).
func delegation(raw string, trust Trust, opts Options) (*Result, error) {
	d, err := sdjwt.ParseDelegation(raw)
	if err != nil {
		return unreadableDelegation(raw, err, trust, opts)
	}
	r := SDJWT(d.Credential, trust, opts)
	r.Delegation = d
	check := Check{Name: CheckDelegation, Status: Pass, Detail: fmt.Sprintf("%s with %d KB-SD-JWT", d.Format(), len(d.Links))}
	if len(d.Links) > 1 {
		check.Detail += "s"
	}
	report := d.Inspect(sdjwt.DelegationOptions{Now: opts.Now})
	if err := report.Err(); err != nil {
		check.Status, check.Detail = Fail, err.Error()
	}
	r.add(check)
	r.Chain = delegationChain(d, report, r)
	return r, nil
}

// isKBSDJWT reports a KB-SD-JWT by its typ (draft-ietf-oauth-delegate-sd-jwt-00
// §5.1.4).
func isKBSDJWT(token *sdjwt.Token) bool {
	typ := headerTyp(token.Header)
	return format.JOSETypeIs(typ, sdjwt.TypeKBSDJWT) || format.JOSETypeIs(typ, sdjwt.TypeKBSDJWTKB)
}

// KBSDJWT validates a KB-SD-JWT on its own. The key that signs it is in the
// part before it, so only the whole chain checks the signature. The checks of
// a credential, such as the status, do not apply.
func KBSDJWT(token *sdjwt.Token, opts Options) *Result {
	v := newRun(Trust{}, opts)
	r := &Result{Format: FormatSDJWT, SDJWT: token, Chain: kbSDJWTChain(token)}
	r.add(
		Check{Name: CheckType, Status: Pass, Detail: headerTyp(token.Header)},
		kbSDJWTValidity(token, v.now),
		CheckSDJWTIntegrity(token),
		Check{Name: CheckSignature, Status: Skipped, Detail: "Checked with the whole chain"},
	)
	return r
}

// kbSDJWTValidity reads nbf and exp from the Delegate Payload.
// draft-ietf-oauth-delegate-sd-jwt-00 §6 step 3.1: "Treat the Delegate Payload
// as the JWT Payload for finding all claims other than the _sd_alg claim."
func kbSDJWTValidity(token *sdjwt.Token, now time.Time) Check {
	payload := sdjwt.NewDelegationLink(token).Payload
	return validityCheck(unixClaim(payload, "nbf"), unixClaim(token.Payload, "iat"), expiry(payload), now, "The Delegate Payload has no exp claim")
}

// unreadableDelegation validates the SD-JWT before the first empty component
// and fails the delegation check with the parse error.
func unreadableDelegation(raw string, chainErr error, trust Trust, opts Options) (*Result, error) {
	credential, _, _ := strings.Cut(strings.TrimSpace(raw), "~~")
	token, err := sdjwt.ParseLenient(credential + "~")
	if err != nil {
		return nil, fmt.Errorf("parsing Delegate SD-JWT: %w", err)
	}
	r := SDJWT(token, trust, opts)
	r.add(Check{Name: CheckDelegation, Status: Fail, Detail: chainErr.Error()})
	return r, nil
}

// SDJWT validates a parsed SD-JWT VC.
func SDJWT(token *sdjwt.Token, trust Trust, opts Options) *Result {
	v := newRun(trust, opts)
	r := &Result{Format: FormatSDJWT, SDJWT: token}
	r.add(CheckSDJWTType(token), jwtValidity(token, v.now), CheckSDJWTIntegrity(token))
	r.add(v.trustedListCheck()...)
	cat := v.catalogue(token.Raw)
	r.add(v.jwtSignature(token, cat, r), v.trustCheck(cat, r))
	r.add(v.status(token.ResolvedClaims, statuslist.FormatJWT, cat, r)...)
	chain, _ := X5CCertificates(token.Header)
	r.add(v.certificateRevocation(chain, r)...)
	if opts.HAIP {
		r.add(haipCheck(token, r))
	}
	return r
}

// JWT validates a parsed JWT. The attestation catalogue lists SD-JWT VC and
// mdoc types only. A wallet still anchors a registration certificate in its
// lists of registration certificate providers. Any other JWT gets no trust
// check.
func JWT(token *sdjwt.Token, trust Trust, opts Options) *Result {
	v := newRun(trust, opts)
	r := &Result{Format: FormatJWT, SDJWT: token}
	r.add(jwtValidity(token, v.now), Check{Name: CheckIntegrity, Status: Skipped, Detail: "Not applicable for plain JWT"})
	r.add(v.trustedListCheck()...)
	cat := v.catalogue(token.Raw)
	r.add(v.jwtSignature(token, cat, r))
	if cat.found {
		r.add(v.trustCheck(cat, r))
	}
	r.add(v.status(token.ResolvedClaims, statuslist.FormatJWT, cat, r)...)
	return r
}

// MDOC validates a parsed mdoc. HAIP 1.0 §6.1.1 profiles the SD-JWT VC only,
// so an mdoc gets no haip check.
func MDOC(doc *mdoc.Document, trust Trust, opts Options) *Result {
	v := newRun(trust, opts)
	r := &Result{Format: FormatMDOC, MDOC: doc}
	r.add(mdocValidity(doc, v.now), CheckMDOCIntegrity(doc))
	r.add(v.trustedListCheck()...)
	cat := v.catalogue(format.EncodeBase64URL(doc.Raw))
	r.add(v.mdocSignature(doc, cat, r), v.trustCheck(cat, r))
	r.add(v.status(doc.StatusClaims(), statuslist.FormatCWT, cat, r)...)
	chain, _ := ExtractMDOCX5ChainCertificates(doc)
	r.add(v.certificateRevocation(chain, r)...)
	return r
}

type run struct {
	trust Trust
	opts  Options
	now   time.Time
}

func newRun(trust Trust, opts Options) run {
	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}
	return run{trust: trust, opts: opts, now: now}
}

// MaxRevocationChain limits the CRLs read for one credential.
const MaxRevocationChain = 5

// CRLReader reads the CRLs of a chain with the client.
func CRLReader(client *http.Client) func([]*x509.Certificate) []certchain.RevocationProblem {
	return func(chain []*x509.Certificate) []certchain.RevocationProblem {
		return certchain.CheckRevocation(chain, client, time.Now())
	}
}

// certificateRevocation fails for a revoked certificate. RFC 5280 §6.1.3
// (a)(3): "At the current time, the certificate is not revoked." A CRL that
// can't be read is a warning. It reads CRLs only for a chain with a valid
// signature, because anyone can present a long x5c with slow CRL URLs.
func (v run) certificateRevocation(chain []*x509.Certificate, r *Result) []Check {
	if v.trust.CertificateProblems == nil || len(chain) == 0 {
		return nil
	}
	if len(chain) > MaxRevocationChain {
		return []Check{{Name: CheckCertificates, Status: Warning, Detail: fmt.Sprintf("The chain has %d certificates, so the CRLs were not read", len(chain))}}
	}
	signed := slices.ContainsFunc(r.Checks, func(c Check) bool { return c.Name == CheckSignature && c.Status == Pass })
	if !signed {
		return nil
	}
	// The last certificate needs its issuer for a CRL check, and an x5c often
	// ends below the anchor.
	last := chain[len(chain)-1]
	if i := slices.IndexFunc(v.trust.Issuance, func(a *x509.Certificate) bool { return !a.Equal(last) && last.CheckSignatureFrom(a) == nil }); i >= 0 {
		chain = append(slices.Clone(chain), v.trust.Issuance[i])
	}
	if v.trust.CompleteChain != nil {
		chain = v.trust.CompleteChain(chain)
	}
	check := Check{Name: CheckCertificates, Status: Skipped}
	// An offline run has no wallet to complete the chain, so a CRL of the last
	// certificate may still be read online.
	if v.opts.Offline && slices.ContainsFunc(chain, namesCRL) {
		check.Detail = "Needs the CRLs of the certificates"
		check.NeedsNetwork = true
		return []Check{check}
	}
	if !slices.ContainsFunc(chain[:len(chain)-1], namesCRL) {
		check.Detail = "No certificate with a known issuer names a CRL"
		return []Check{check}
	}
	check.Status, check.Detail = Pass, "No certificate is revoked"
	if last := chain[len(chain)-1]; namesCRL(last) && !certinfo.SelfSigned(last) {
		check.Status, check.Detail = Warning, fmt.Sprintf("The CRL of %q needs its issuer certificate", last.Subject.String())
	}
	for _, problem := range v.trust.CertificateProblems(chain) {
		if problem.Revoked {
			check.Status, check.Detail = Fail, problem.Error()
			break
		}
		check.Status, check.Detail = Warning, problem.Error()
	}
	return []Check{check}
}

// namesCRL tells whether cert names a CRL over http or https.
// certchain.CheckRevocation reads only such CRLs, and only for a certificate
// whose issuer follows it in the chain.
func namesCRL(cert *x509.Certificate) bool {
	return slices.ContainsFunc(cert.CRLDistributionPoints, func(point string) bool {
		return strings.HasPrefix(point, "http://") || strings.HasPrefix(point, "https://")
	})
}

func (v run) trustedListCheck() []Check {
	if len(v.trust.Findings) == 0 {
		return nil
	}
	return []Check{{Name: CheckTrustedList, Status: Warning, Detail: findings.Join(v.trust.Findings)}}
}

func haipCheck(token *sdjwt.Token, r *Result) Check {
	r.HAIPFindings = append(findings.List{}, HAIPCredentialFindings(token.Header, token.Payload)...)
	if len(r.HAIPFindings) == 0 {
		return Check{Name: CheckHAIP, Status: Pass, Detail: "No findings"}
	}
	return Check{Name: CheckHAIP, Status: Warning, Detail: findings.Join(r.HAIPFindings.Texts())}
}
