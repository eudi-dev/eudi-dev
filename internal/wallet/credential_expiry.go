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
	"sort"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
)

// renewalMargin is how long before expiry a credential is renewed. It only
// has to cover the round trip to the issuer.
const renewalMargin = time.Minute

// CredentialValidity reads nbf and exp from a JWT payload, or validFrom and
// validUntil from an mdoc MSO. A missing bound is the zero time.
func CredentialValidity(cred StoredCredential) (notBefore, expiry time.Time) {
	switch cred.Format {
	case credtype.FormatMDOC:
		doc, err := mdoc.Parse(cred.Raw)
		if err != nil || doc.IssuerAuth == nil || doc.IssuerAuth.MSO == nil || doc.IssuerAuth.MSO.ValidityInfo == nil {
			return time.Time{}, time.Time{}
		}
		validity := doc.IssuerAuth.MSO.ValidityInfo
		if validity.ValidFrom != nil {
			notBefore = *validity.ValidFrom
		}
		if validity.ValidUntil != nil {
			expiry = *validity.ValidUntil
		}
		return notBefore, expiry
	default:
		token, err := sdjwt.ParseLenient(cred.Raw)
		if err != nil || token == nil {
			return time.Time{}, time.Time{}
		}
		return unixClaim(token.Payload, "nbf"), unixClaim(token.Payload, "exp")
	}
}

func unixClaim(payload map[string]any, name string) time.Time {
	value, ok := payload[name].(float64)
	if !ok || value <= 0 {
		return time.Time{}
	}
	return time.Unix(int64(value), 0)
}

// CredentialNeedsRenewal is false for a credential without an expiry, since
// there is nothing to schedule against.
func CredentialNeedsRenewal(cred StoredCredential, now time.Time) bool {
	_, expiry := CredentialValidity(cred)
	if expiry.IsZero() {
		return false
	}
	return now.Add(renewalMargin).After(expiry)
}

// credentialNeedsRenewal adds the triggers of the issuer's reuse policy to
// CredentialNeedsRenewal (ETSI TS 119 472-3 V1.1.1 clause 4.2.4.2). ARF ISSU_45:
// under once_only the wallet "SHALL request the issuance of a new batch when
// this limit is reached", where reissue_trigger_unused is "the lower limit for
// the number of unused PIDs/EAAs" (-10). Under the other methods
// reissue_trigger_lifetime_left is "the number of seconds before the
// expiration of the PID/EAA" (-13) at which the wallet renews.
func (w *Wallet) credentialNeedsRenewal(cred StoredCredential, now time.Time) bool {
	if CredentialNeedsRenewal(cred, now) {
		return true
	}
	if cred.Renewal == nil || cred.Renewal.ReusePolicy == nil {
		return false
	}
	reuse := cred.Renewal.ReusePolicy
	if reuse.Method == reuseOnceOnly {
		// A batch at or below the limit means the issuer issued fewer copies
		// than requested. A renewal would return the same number.
		return w.batchSize(cred) > reuse.ReissueTriggerUnused && w.unusedCopies(cred) <= reuse.ReissueTriggerUnused
	}
	_, expiry := CredentialValidity(cred)
	if expiry.IsZero() || reuse.ReissueTriggerLifetimeLeft <= 0 {
		return false
	}
	return !now.Add(time.Duration(reuse.ReissueTriggerLifetimeLeft) * time.Second).Before(expiry)
}

// CredentialIssuedAt reads iat from a JWT payload or signed from an mdoc MSO.
// It returns the zero time when the credential has neither.
func CredentialIssuedAt(cred StoredCredential) time.Time {
	if !cred.issuedAt.IsZero() {
		return cred.issuedAt
	}
	switch cred.Format {
	case credtype.FormatMDOC:
		doc, err := mdoc.Parse(cred.Raw)
		if err != nil {
			return time.Time{}
		}
		return mdocSignedAt(doc)
	default:
		token, err := sdjwt.ParseLenient(cred.Raw)
		if err != nil || token == nil {
			return time.Time{}
		}
		return jwtIssuedAt(token.ResolvedClaims)
	}
}

// SortCredentialsNewestFirst sorts credentials without an issuance time
// last. Ties keep arrival order because IDs are random.
func SortCredentialsNewestFirst(creds []StoredCredential) {
	issued := make(map[string]time.Time, len(creds))
	for _, c := range creds {
		issued[c.ID] = CredentialIssuedAt(c)
	}
	sort.SliceStable(creds, func(i, j int) bool {
		a, b := issued[creds[i].ID], issued[creds[j].ID]
		if a.Equal(b) {
			return false
		}
		if a.IsZero() {
			return false
		}
		if b.IsZero() {
			return true
		}
		return a.After(b)
	})
}
