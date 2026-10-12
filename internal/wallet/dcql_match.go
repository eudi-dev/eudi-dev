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
	"crypto/x509"
	"fmt"
	"maps"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/dcql"
	"github.com/eudi-dev/eudi-dev/v3/internal/lote"
)

// matchDCQL matches the stored credentials against a DCQL query with the
// wallet's settings (dcql.Evaluate).
func (w *Wallet) matchDCQL(query map[string]any) ([]consent.Match, *consent.CredentialOptions) {
	credentials := w.GetCredentials()
	creds := make([]dcql.Credential, len(credentials))
	for i, cred := range credentials {
		creds[i] = dcqlCredential(cred)
	}
	// The conformance API can change these settings while a query runs.
	return dcql.Evaluate(query, creds, dcql.Options{
		Strict:          w.Mode() == ValidationModeStrict,
		PreferredFormat: w.PreferredFormatSetting(),
		Anchors:         w.trustedAuthorityAnchors(query),
		// Keep one unused batch copy so consent and presentation treat the
		// batch as one credential.
		Collapse: func(matches []consent.Match) []consent.Match {
			return w.collapseBatchMatches(matches, credentials)
		},
	})
}

// dcqlCredential is a stored credential as the DCQL matcher sees it.
func dcqlCredential(cred StoredCredential) dcql.Credential {
	return dcql.Credential{
		ID: cred.ID, Format: cred.Format, VCT: cred.VCT, DocType: cred.DocType, Raw: cred.Raw,
		Claims:      cred.Claims,
		Disclosures: cred.Disclosures,
		Bound:       (cred.Format == credtype.FormatSDJWT || cred.Format == credtype.FormatMDOC) && credentialHolderBinding(cred.Raw).Bound,
		IssuedAt:    CredentialIssuedAt(cred),
	}
}

// PreferredFormatSetting takes the lock because PUT
// /api/config/preferred-format changes the setting at runtime.
func (w *Wallet) PreferredFormatSetting() string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.PreferredFormat
}

// trustedAuthorityAnchors reads the trusted lists referenced by the credential
// queries. §6.1.1: a credential matches "one of the provided values in one of
// the provided types". An unusable list matches nothing.
func (w *Wallet) trustedAuthorityAnchors(query map[string]any) map[string][]*x509.Certificate {
	anchors := map[string][]*x509.Certificate{}
	credQueries, _ := query["credentials"].([]any)
	for _, cq := range credQueries {
		cqMap, _ := cq.(map[string]any)
		taList, _ := cqMap["trusted_authorities"].([]any)
		queryID, _ := cqMap["id"].(string)
		listAnchors, listFindings := w.etsiTrustedListAnchors(taList)
		w.warnFindings("presentation", fmt.Sprintf("The trusted lists of credential query %s", queryID), listFindings)
		maps.Copy(anchors, listAnchors)
	}
	return anchors
}

// etsiTrustedListAnchors reads the lists referenced by the etsi_tl entries of
// trusted_authorities. It reads them like the wallet's own trusted lists:
// cached, signed by a trusted list operator and current. The issuance services
// anchor credentials (ETSI TS 119 602 V1.1.1 Table D.3). Each list that gives
// no anchors is a finding.
func (w *Wallet) etsiTrustedListAnchors(taList []any) (map[string][]*x509.Certificate, []string) {
	anchors := map[string][]*x509.Certificate{}
	var findings []string
	for _, entry := range taList {
		entryMap, _ := entry.(map[string]any)
		if t, _ := entryMap["type"].(string); t != "etsi_tl" {
			continue
		}
		values, _ := entryMap["values"].([]any)
		for _, v := range values {
			listURL, _ := v.(string)
			if listURL == "" {
				continue
			}
			if _, read := anchors[listURL]; read {
				continue
			}
			certs, err := w.issuanceAnchors(listURL)
			if err != nil {
				findings = append(findings, fmt.Sprintf("the trusted list %s of trusted_authorities cannot be used: %v", listURL, err))
			}
			anchors[listURL] = certs
		}
	}
	return anchors, findings
}

func (w *Wallet) issuanceAnchors(listURL string) ([]*x509.Certificate, error) {
	list, err := w.TrustedLists().ReadList(listURL)
	if err != nil {
		return nil, err
	}
	certs, err := lote.Anchors(list, lote.IssuanceServices, time.Now())
	if err != nil {
		return nil, err
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("the list names no issuance service")
	}
	return certs, nil
}
