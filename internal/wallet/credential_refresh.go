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
	"fmt"
	"slices"
	"strings"
	"time"
)

// RefreshCredential renews a credential with its refresh token. The renewed
// credential keeps the ID, so queries, UI selections and logs still match.
func (w *Wallet) RefreshCredential(id string) (*StoredCredential, error) {
	cred, ok := w.GetCredential(id)
	if !ok {
		return nil, fmt.Errorf("credential %s not found", id)
	}
	if !cred.CanRenew() {
		return nil, fmt.Errorf("credential %s cannot be renewed: its issuer handed over no refresh token", id)
	}
	renewal := *cred.Renewal

	// A renewal requests a credential too, so the issuer checks apply. They
	// run before the token request, so a refusal keeps the refresh token.
	metadata, err := w.loadIssuerMetadata(renewal.Issuer, []string{renewal.ConfigurationID}, ignoreFindings)
	if err != nil {
		return nil, err
	}

	grant, err := w.refreshAccessToken(renewal)
	// The issuer may rotate the refresh token and retire the old one, so the
	// wallet keeps the new one even when a later step fails.
	if grant != nil && grant.refreshToken != "" {
		renewal.RefreshToken = grant.refreshToken
		w.rememberRenewal(cred.ID, renewal)
	}
	if err != nil {
		return nil, fmt.Errorf("renewing the access token: %w", err)
	}

	nonce := ""
	// A batch is renewed as a whole, each copy bound to a fresh key, so no
	// expired copy stays in the presentation rotation.
	proofKeys, err := batchProofKeys(w.HolderKeyPair(), metadata, w.batchSize(cred))
	if err != nil {
		return nil, err
	}
	credResp, err := w.requestCredential(credentialRequest{
		renewal:   renewal,
		metadata:  metadata,
		grant:     grant,
		proofKeys: proofKeys,
		nonce:     &nonce,
	})
	if err != nil {
		return nil, err
	}
	renewed, _, err := w.storeIssuedCredential(credResp, credentialDelivery{
		metadata:  metadata,
		renewal:   renewal,
		proofKeys: proofKeys,
		replaceID: id,
		access: resourceAccess{
			accessToken: grant.accessToken,
			authScheme:  grant.authScheme,
			dpopKey:     w.dpopKeyForRenewal(renewal),
			nonce:       &nonce,
		},
		logSummary: "Renewed credential",
		report:     ignoreFindings,
	})
	if err != nil {
		return nil, err
	}
	return renewed, nil
}

func (s *Server) RefreshCredential(id string) (*StoredCredential, error) {
	renewed, err := s.wallet.RefreshCredential(id)
	if err != nil {
		// A failed renewal can still have rotated the refresh token.
		if cred, ok := s.wallet.GetCredential(id); ok {
			s.saveCredential(&cred, false)
		}
		return nil, err
	}
	s.log("  Renewed:       %s credential %s", renewed.Format, renewed.ID)
	s.saveCredential(renewed, true)
	return renewed, nil
}

// ReplaceCredential puts a renewed credential in place of the one with id.
// The renewal replaces the credential's content. The wallet's bookkeeping of
// it (protection, display, batch, use count) stays, and so does its place.
func (w *Wallet) ReplaceCredential(id, raw string, renewal *CredentialRenewal) (*StoredCredential, error) {
	fresh, err := w.parseDetectedFormat(strings.TrimSpace(raw), "", "")
	if err != nil {
		return nil, fmt.Errorf("parsing the renewed credential: %w", err)
	}

	w.mu.Lock()
	i := slices.IndexFunc(w.Credentials, func(c StoredCredential) bool { return c.ID == id })
	if i < 0 {
		w.mu.Unlock()
		return nil, fmt.Errorf("credential %s not found", id)
	}
	old := w.Credentials[i]
	fresh.ID = id
	fresh.Protected = old.Protected
	fresh.Renewal = renewal
	fresh.Display = old.Display
	// Batch membership stays, so listing, presentation, deletion and
	// revocation still see one credential. The renewal is bound to the
	// wallet holder key, so no per-copy key carries over.
	fresh.BatchGroup = old.BatchGroup
	fresh.Uses = old.Uses
	fresh.LastPresentedAt = old.LastPresentedAt
	w.Credentials[i] = fresh
	renewed := w.Credentials[i]
	w.mu.Unlock()

	// The renewed credential's entry on the wallet's own list replaces the
	// old one.
	if ref := w.ownStatusRef(renewed); ref != nil {
		w.registerStatusEntry(id, ref.Idx)
	}
	return &renewed, nil
}

// renewalCheckInterval has to be shorter than renewalMargin, so a credential
// is noticed while there is still time to renew it.
const renewalCheckInterval = 30 * time.Second

// renewalRetryAfter keeps a failed renewal from being retried on every sweep.
const renewalRetryAfter = 10 * time.Minute

// renewExpiringCredentials renews credentials inside renewalMargin. One
// failure does not stop the sweep.
func (s *Server) renewExpiringCredentials(now time.Time) error {
	for _, cred := range s.wallet.GetCredentials() {
		if !cred.CanRenew() || !CredentialNeedsRenewal(cred, now) {
			continue
		}
		if !s.renewalDue(cred.ID, now) {
			continue
		}
		if _, err := s.RefreshCredential(cred.ID); err != nil {
			s.noteRenewalFailure(cred.ID, now)
			s.log("  ERROR: renewing credential %s: %v", cred.ID, err)
		}
	}
	return nil
}

func (s *Server) renewalDue(credentialID string, now time.Time) bool {
	s.renewalMu.Lock()
	defer s.renewalMu.Unlock()
	next, seen := s.renewalBackoff[credentialID]
	return !seen || now.After(next)
}

func (s *Server) noteRenewalFailure(credentialID string, now time.Time) {
	s.renewalMu.Lock()
	defer s.renewalMu.Unlock()
	if s.renewalBackoff == nil {
		s.renewalBackoff = make(map[string]time.Time)
	}
	s.renewalBackoff[credentialID] = now.Add(renewalRetryAfter)
}
