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
	"log"
	"slices"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/consent"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vp"
)

// applySelectedClaims discloses the claims the user selected per credential.
// Strict mode discloses only claims the request asked for, so a selection can
// withhold a claim but not add one. Debug mode sends the selection as it is.
func (w *Wallet) applySelectedClaims(matches []consent.Match, selected map[string][]string) []consent.Match {
	if selected == nil {
		return matches
	}
	strict := w.Mode() == ValidationModeStrict
	for i, m := range matches {
		keys, ok := selected[m.CredentialID]
		if !ok {
			continue
		}
		if strict {
			requested := m.SelectedKeys
			keys = slices.DeleteFunc(slices.Clone(keys), func(k string) bool { return !slices.Contains(requested, k) })
		}
		cred, ok := w.GetCredential(m.CredentialID)
		if !ok {
			continue
		}
		matches[i].SelectedKeys = keys
		matches[i].Claims = filterClaims(cred, keys)
		log.Printf("[VP]   %s: disclosing %v", shortID(m.CredentialID), keys)
	}
	return matches
}

// newPresentationConsent is the consent request for a presentation. typ tells a
// verifier's request from one an issuer makes during issuance.
func newPresentationConsent(typ, owner, clientID string, authReq *oid4vp.Request, matches []consent.Match, options *consent.CredentialOptions) *consent.Request {
	req := &consent.Request{
		ID:                newConsentID(),
		Type:              typ,
		Owner:             owner,
		MatchedCreds:      matches,
		Status:            "pending",
		ResultCh:          make(chan consent.Result, 1),
		SubmissionCh:      make(chan consent.SubmissionResult, 1),
		CreatedAt:         time.Now(),
		ClientID:          clientID,
		Nonce:             authReq.Nonce,
		ResponseURI:       authReq.ResponseURI,
		DCQLQuery:         authReq.DCQLQuery,
		Findings:          authReq.Findings,
		CredentialOptions: options,
	}
	req.Purposes, req.PrivacyPolicies = oid4vp.ConsentRegistration(authReq)
	req.RegisteredName = oid4vp.RegisteredName(authReq)
	applyClientAuth(req, authReq)
	return req
}

// consentedMatches applies the credentials and claims the user chose.
func (w *Wallet) consentedMatches(req *consent.Request, matches []consent.Match, result consent.Result) []consent.Match {
	return w.applySelectedClaims(consent.ApplySelection(req.CredentialOptions, matches, result), result.SelectedClaims)
}

// awaitConsent waits for the decision on req. After timeout a request that is
// still pending expires and awaitConsent reports false. A decision that
// arrives together with the timeout wins.
func (w *Wallet) awaitConsent(req *consent.Request, timeout time.Duration) (consent.Result, bool) {
	select {
	case result := <-req.ResultCh:
		return result, true
	case <-time.After(timeout):
		if _, ok := w.Consents().Resolve(req.ID, consent.StatusExpired); !ok {
			return <-req.ResultCh, true
		}
		return consent.Result{}, false
	}
}
