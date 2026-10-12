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

	"github.com/eudi-dev/eudi-dev/v2/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v2/internal/sdjwt"
)

// renewalMargin is how long before expiry a credential is renewed. It only
// has to cover the round trip to the issuer.
const renewalMargin = time.Minute

// CredentialExpiry reads exp from a JWT payload or validUntil from an mdoc
// MSO. It returns the zero time when the credential has no expiry.
func CredentialExpiry(cred StoredCredential) time.Time {
	switch cred.Format {
	case "mso_mdoc":
		doc, err := mdoc.Parse(cred.Raw)
		if err != nil || doc.IssuerAuth == nil || doc.IssuerAuth.MSO == nil {
			return time.Time{}
		}
		validity := doc.IssuerAuth.MSO.ValidityInfo
		if validity == nil || validity.ValidUntil == nil {
			return time.Time{}
		}
		return *validity.ValidUntil
	default:
		token, err := sdjwt.ParseLenient(cred.Raw)
		if err != nil || token == nil {
			return time.Time{}
		}
		exp, ok := token.Payload["exp"].(float64)
		if !ok || exp <= 0 {
			return time.Time{}
		}
		return time.Unix(int64(exp), 0)
	}
}

// CredentialNeedsRenewal is false for a credential without an expiry, since
// there is nothing to schedule against.
func CredentialNeedsRenewal(cred StoredCredential, now time.Time) bool {
	expiry := CredentialExpiry(cred)
	if expiry.IsZero() {
		return false
	}
	return now.Add(renewalMargin).After(expiry)
}

// CredentialIssuedAt reads iat from a JWT payload or signed from an mdoc MSO.
// It returns the zero time when the credential has neither.
func CredentialIssuedAt(cred StoredCredential) time.Time {
	if !cred.issuedAt.IsZero() {
		return cred.issuedAt
	}
	switch cred.Format {
	case "mso_mdoc":
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
		return jwtIssuedAt(token.Payload)
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
