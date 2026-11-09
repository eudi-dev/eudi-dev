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
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/findings"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
	"github.com/eudi-dev/eudi-dev/v3/internal/typemetadata"
)

// transactionDataRefusal is a strict-mode refusal of transaction data after
// consent. The verifier gets it as invalid_transaction_data (OpenID4VP 1.0
// §8.5).
type transactionDataRefusal struct{ err error }

func (r *transactionDataRefusal) Error() string { return r.err.Error() }
func (r *transactionDataRefusal) Unwrap() error { return r.err }

func refuseTransactionData(err error) error {
	if err == nil {
		return nil
	}
	return &transactionDataRefusal{err: err}
}

// asTransactionDataRefusal finds a transaction data refusal in err.
func asTransactionDataRefusal(err error) (*transactionDataRefusal, bool) {
	var refusal *transactionDataRefusal
	return refusal, errors.As(err, &refusal)
}

// ParseTransactionDataTypes trims the registered transaction data types and
// drops duplicates.
func ParseTransactionDataTypes(raw []string) ([]string, error) {
	var types []string
	for _, typ := range raw {
		typ = strings.TrimSpace(typ)
		if typ == "" {
			return nil, fmt.Errorf("a transaction data type must not be empty")
		}
		if !slices.Contains(types, typ) {
			types = append(types, typ)
		}
	}
	return types, nil
}

// transactionData is the request's transaction data when the wallet supports
// it. Without support, validation reported the parameter and the wallet
// ignores it.
func (w *Wallet) transactionData(params *oid4vp.Request) []oid4vp.TransactionData {
	if !w.Conformance().TransactionData {
		return nil
	}
	return oid4vp.ParseTransactionData(params)
}

// bindTransactionData binds each entry to one presentation, chosen by
// transactionDataMatch. OpenID4VP 1.0 §5.1: "If there is more than one
// element in the array, the Wallet MUST use only one of the referenced
// Credentials for transaction authorization." The result maps a match index
// to its entries.
func (w *Wallet) bindTransactionData(params *oid4vp.Request, matches []consent.Match) (map[int][]oid4vp.TransactionData, error) {
	bound := map[int][]oid4vp.TransactionData{}
	var unbound findings.List
	for _, entry := range w.transactionData(params) {
		index := w.transactionDataMatch(entry, matches)
		if index < 0 {
			// §8.5 invalid_transaction_data: "the referenced Credential(s)
			// are not available in the Wallet."
			unbound = append(unbound, findings.OID4VP.Protocol("§8.5").Newf("%s references %s, but the response presents none of them", entry.Label(), strings.Join(entry.CredentialIDs, ", ")))
			continue
		}
		bound[index] = append(bound[index], entry)
	}
	if len(unbound) > 0 {
		err := w.reportDeviation(deviation{action: "presentation", event: "transaction_data_unbound", subject: subjectPresentation,
			summary: "The presentation cannot authorize the transaction data", findings: unbound})
		if err != nil {
			return nil, refuseTransactionData(err)
		}
	}
	return bound, nil
}

// transactionDataMatch picks the presentation for entry: the first query in
// its credential_ids answered with a credential that has a Key Binding JWT,
// else the first answered query.
func (w *Wallet) transactionDataMatch(entry oid4vp.TransactionData, matches []consent.Match) int {
	first := -1
	for _, id := range entry.CredentialIDs {
		index := slices.IndexFunc(matches, func(m consent.Match) bool { return m.QueryID == id })
		if index < 0 {
			continue
		}
		if cred, ok := w.GetCredential(matches[index].CredentialID); ok && hasKeyBindingJWT(cred) {
			return index
		}
		if first < 0 {
			first = index
		}
	}
	return first
}

func hasKeyBindingJWT(cred StoredCredential) bool {
	return cred.Format == credtype.FormatSDJWT && credentialHolderBinding(cred.Raw).Bound
}

// transactionDataClaims are the Key Binding JWT claims for the entries bound
// to cred. Only an SD-JWT VC with holder binding has a Key Binding JWT
// (Appendix B.3.3).
func (w *Wallet) transactionDataClaims(cred StoredCredential, entries []oid4vp.TransactionData, responseMode string) (map[string]any, error) {
	if len(entries) == 0 {
		return nil, nil
	}
	if !hasKeyBindingJWT(cred) {
		finding := findings.OID4VP.Protocol("Appendix B.3.3").Newf("credential %s has no Key Binding JWT, so the presentation carries no transaction data", credentialLabel(cred))
		return nil, refuseTransactionData(w.reportDeviation(deviation{action: "presentation", event: "transaction_data_no_key_binding", subject: subjectPresentation, finding: finding,
			details: map[string]any{"credential_id": cred.ID, "format": cred.Format}}))
	}
	w.warnFindings("presentation", "transaction_data_sca", subjectPresentation, "The credential's Type Metadata does not permit the transaction data",
		scaFindings(cred, entries), map[string]any{"credential_id": cred.ID})
	claims, err := oid4vp.TransactionDataClaims(entries, responseMode)
	if list := findings.Of(err); len(list) > 0 {
		if err := w.reportDeviation(deviation{action: "presentation", event: "transaction_data_hash_alg", subject: subjectPresentation, findings: list,
			summary: "The transaction data accepts no common hash algorithm"}); err != nil {
			return nil, refuseTransactionData(err)
		}
		return claims, nil
	}
	return claims, err
}

// scaFindings are the failures of EUDI TS12 v1.0.1 §3.2 steps 1 and 2 for the
// entries bound to cred. TS12 requires the wallet to cease processing. Both
// steps are warnings (ADR 0031).
// Step 1 applies to the TS12 types only, because OpenID4VP lets any credential
// carry other transaction data types.
func scaFindings(cred StoredCredential, entries []oid4vp.TransactionData) findings.List {
	var list findings.List
	metadata := cred.TypeMetadata
	for _, entry := range entries {
		if !metadata.IsSCA() {
			if slices.Contains(oid4vp.TS12TransactionDataTypes, entry.Type) {
				list = append(list, findings.TS12.Protocol("§3.2").Newf("%s is bound to %s, whose Type Metadata does not have the category %s", entry.Label(), credentialLabel(cred), typemetadata.SCACategory))
			}
			continue
		}
		if _, ok := metadata.TransactionDataTypes[entry.Type]; !ok {
			list = append(list, findings.TS12.Protocol("§3.2").Newf("%s is bound to %s, whose Type Metadata does not list %s in transaction_data_types", entry.Label(), credentialLabel(cred), entry.Type))
		}
	}
	return list
}
