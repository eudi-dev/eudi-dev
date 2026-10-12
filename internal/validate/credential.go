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
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
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
	// NeedsNetwork marks a skipped check that an offline validation could not
	// run.
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
	CheckStatusSignature = "status list signature"
	CheckHAIP            = "haip"
)

// Credential formats of a Result.
const (
	FormatSDJWT = credtype.FormatSDJWT
	FormatJWT   = "jwt"
	FormatMDOC  = credtype.FormatMDOC
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
	// Checks run in a fixed order: type, expiry, integrity, trusted list,
	// signature, trust, status, status list signature, haip.
	Checks []Check

	// SDJWTVerify or MDOCVerify is the signature verification behind the
	// signature check, and SignatureSource names the key that verified it.
	SDJWTVerify     *sdjwt.VerifyResult
	MDOCVerify      *mdoc.VerifyResult
	SignatureSource string
	// Catalogue is the anchoring by the credential's catalogue entry. It is
	// nil when the catalogue was not consulted or has no entry.
	Catalogue *CatalogueAnchoring
	// Status is the fetched status list entry.
	Status *statuslist.StatusResult
	// HAIPFindings are set when Options.HAIP applies to the credential.
	HAIPFindings []string
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

// Credential validates a raw SD-JWT VC, JWT or mdoc. It fails only when the
// input is none of these. Every finding is a check of the result.
func Credential(raw string, trust Trust, opts Options) (*Result, error) {
	switch format.DetectEncoding(raw) {
	case format.FormatSDJWT:
		token, err := sdjwt.Inspect(raw)
		if err != nil {
			return nil, fmt.Errorf("parsing SD-JWT: %w", err)
		}
		return SDJWT(token, trust, opts), nil
	case format.FormatJWT:
		// sdjwt reports a broken JWT part as "parsing JWT" already.
		token, err := sdjwt.Inspect(raw)
		if err != nil {
			return nil, err
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

// SDJWT validates a parsed SD-JWT VC.
func SDJWT(token *sdjwt.Token, trust Trust, opts Options) *Result {
	v := newRun(trust, opts)
	r := &Result{Format: FormatSDJWT, SDJWT: token}
	r.add(CheckSDJWTType(token), jwtValidity(token.Payload, v.now), CheckSDJWTIntegrity(token))
	r.add(v.trustedListCheck()...)
	cat := v.catalogue(token.Raw)
	r.add(v.jwtSignature(token, cat, r), v.trustCheck(cat, r))
	r.add(v.status(token.ResolvedClaims, statuslist.FormatJWT, cat, r)...)
	if opts.HAIP {
		r.add(haipCheck(token, r))
	}
	return r
}

// JWT validates a parsed JWT. The attestation catalogue lists SD-JWT VC and
// mdoc types only, so a JWT gets no trust check.
func JWT(token *sdjwt.Token, trust Trust, opts Options) *Result {
	v := newRun(trust, opts)
	r := &Result{Format: FormatJWT, SDJWT: token}
	r.add(jwtValidity(token.Payload, v.now), Check{Name: CheckIntegrity, Status: Skipped, Detail: "Not applicable for plain JWT"})
	r.add(v.trustedListCheck()...)
	r.add(v.jwtSignature(token, catalogueState{}, r))
	r.add(v.status(token.ResolvedClaims, statuslist.FormatJWT, catalogueState{}, r)...)
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

func (v run) trustedListCheck() []Check {
	if len(v.trust.Findings) == 0 {
		return nil
	}
	return []Check{{Name: CheckTrustedList, Status: Warning, Detail: strings.Join(v.trust.Findings, ". ")}}
}

func haipCheck(token *sdjwt.Token, r *Result) Check {
	r.HAIPFindings = append([]string{}, HAIPCredentialFindings(token.Header, token.Payload)...)
	if len(r.HAIPFindings) == 0 {
		return Check{Name: CheckHAIP, Status: Pass, Detail: "No findings"}
	}
	return Check{Name: CheckHAIP, Status: Warning, Detail: strings.Join(r.HAIPFindings, ". ")}
}
