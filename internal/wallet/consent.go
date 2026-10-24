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
	"context"
	"log"
	"slices"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/dcql"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
)

// applySelectedClaims discloses the user's selected claims for each credential.
// Always disclosed claims stay in the selection, because the presentation
// sends them anyway.
func (w *Wallet) applySelectedClaims(matches []consent.Match, selected map[string][]string) []consent.Match {
	if selected == nil {
		return matches
	}
	for i := range matches {
		m := &matches[i]
		keys, ok := selected[m.CredentialID]
		if !ok {
			continue
		}
		cred, ok := w.GetCredential(m.CredentialID)
		if !ok {
			continue
		}
		keys = slices.Clone(keys)
		for _, key := range m.AlwaysDisclosed {
			if !slices.Contains(keys, key) {
				keys = append(keys, key)
			}
		}
		m.SelectedKeys = keys
		m.Claims = dcql.FilterClaims(dcqlCredential(cred), keys)
		log.Printf("[VP]   %s: disclosing %v", shortID(m.CredentialID), keys)
	}
	return matches
}

// newPresentationConsent is the consent request for a presentation. typ tells a
// verifier's request apart from an issuer's request during issuance.
func newPresentationConsent(typ, owner, clientID string, authReq *oid4vp.Request, matches []consent.Match, options *consent.CredentialOptions) *consent.Request {
	req := consent.NewRequest(typ, owner)
	req.MatchedCreds = matches
	req.ClientID = clientID
	req.Nonce = authReq.Nonce
	req.ResponseURI = authReq.ResponseURI
	req.DCQLQuery = authReq.DCQLQuery
	req.Findings = authReq.Findings
	req.CredentialOptions = options
	req.Purposes, req.PrivacyPolicies = oid4vp.ConsentRegistration(authReq)
	req.RegisteredName = oid4vp.RegisteredName(authReq)
	applyClientAuth(req, authReq)
	return req
}

// consentedMatches applies the user's chosen credentials and claims.
func (w *Wallet) consentedMatches(req *consent.Request, matches []consent.Match, result consent.Result) []consent.Match {
	return w.applySelectedClaims(consent.ApplySelection(req.CredentialOptions, matches, result), result.SelectedClaims)
}

// awaitConsent waits for the decision on req. After timeout a request that is
// still pending expires, and when ctx ends it is cancelled. Both report false.
// A decision that arrives at the same time wins.
func (w *Wallet) awaitConsent(ctx context.Context, req *consent.Request, timeout time.Duration) (consent.Result, bool) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	status := consent.StatusExpired
	select {
	case result := <-req.ResultCh:
		return result, true
	case <-timer.C:
	case <-ctx.Done():
		status = consent.StatusCancelled
	}
	if _, ok := w.Consents().Resolve(req.ID, status); !ok {
		return <-req.ResultCh, true
	}
	return consent.Result{}, false
}
