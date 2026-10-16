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
	"time"
)

// RenewCredential renews a credential with its refresh token. The renewed
// credential keeps the ID, so queries, UI selections and logs still match.
// A failed renewal is logged like a failed issuance.
func (w *Wallet) RenewCredential(id string) (renewed *StoredCredential, err error) {
	cred, ok := w.GetCredential(id)
	if !ok {
		return nil, fmt.Errorf("%w: %s", ErrCredentialNotFound, id)
	}
	defer func() {
		if err != nil {
			w.addProtocolLog("issuance", "renewal_failed", fmt.Sprintf("Renewing credential %s failed: %v", credentialLabel(cred), err), false, map[string]any{
				"credential_id": id,
				"error":         err.Error(),
			})
		}
	}()
	if !cred.CanRenew() {
		return nil, fmt.Errorf("credential %s cannot be renewed: its issuer handed over no refresh token", id)
	}
	renewal := *cred.Renewal

	// A renewal requests a credential too, so the issuer checks apply. They
	// run before the token request, so a refusal keeps the refresh token.
	metadata, findings, err := w.loadIssuerMetadata(renewal.Issuer, []string{renewal.ConfigurationID})
	if err != nil {
		return nil, err
	}
	w.logIssuerFindings(renewal.Issuer, findings)
	renewal.ReusePolicy = w.reuseOption(metadata, renewal.ConfigurationID)

	grant, err := w.refreshAccessToken(renewal)
	// The issuer may rotate the refresh token and retire the old one, so the
	// wallet keeps the new one even when a later step fails.
	if grant != nil && grant.refreshToken != "" {
		renewal.RefreshToken = grant.refreshToken
		w.saveChange(func() bool {
			w.rememberRenewal(cred.ID, renewal)
			return true
		})
	}
	if err != nil {
		return nil, fmt.Errorf("renewing the access token: %w", err)
	}

	nonce := ""
	// A batch is renewed as a whole, each copy bound to a fresh key, so no
	// expired copy stays in the presentation rotation. Under a reuse policy
	// the renewal is a new batch of the policy's size (ARF ISSU_45).
	wanted := w.batchSize(cred)
	if renewal.ReusePolicy != nil {
		wanted = MaxBatchSize
	}
	proofKeys, err := batchProofKeys(metadata, renewal.ReusePolicy, wanted)
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
	renewed, _, err = w.storeIssuedCredential(credResp, credentialDelivery{
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

func (s *Server) RenewCredential(id string) (*StoredCredential, error) {
	renewed, err := s.management().RenewCredential(id)
	if err != nil {
		return nil, err
	}
	s.log("  Renewed:       %s credential %s", renewed.Format, renewed.ID)
	return renewed, nil
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
		if !cred.CanRenew() || !s.wallet.credentialNeedsRenewal(cred, now) {
			continue
		}
		if !s.renewalDue(cred.ID, now) {
			continue
		}
		if _, err := s.RenewCredential(cred.ID); err != nil {
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
