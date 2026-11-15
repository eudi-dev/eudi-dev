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
	"github.com/eudi-dev/eudi-dev/v3/pkg/sdjwt/delegate"
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

// ParseTransactionDataTypes trims the --transaction-data-type types and drops
// duplicates.
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

// acceptedTransactionDataTypes are the --transaction-data-type types, with
// delegate when the wallet delegates.
func (c ConformanceSettings) acceptedTransactionDataTypes() []string {
	if !c.Delegates() || slices.Contains(c.TransactionDataTypes, oid4vp.DelegateTransactionDataType) {
		return c.TransactionDataTypes
	}
	return append(slices.Clone(c.TransactionDataTypes), oid4vp.DelegateTransactionDataType)
}

// delegation is the KB-SD-JWT for the delegate entries among entries
// (draft-ietf-oauth-delegate-sd-jwt-00 §7.1). claims are the Key Binding JWT
// claims of the same presentation. The result is nil when the presentation
// has no Key Binding JWT, when no entry has a delegate payload disclosure, or
// when Delegate SD-JWT is off.
//
// §7.1: "Multiple delegate transaction_data MAY be included in the same
// request. In that case, each MUST have their digest included in the
// delegate_payload."
func (w *Wallet) delegation(entries []oid4vp.TransactionData, claims map[string]any) (*delegate.KBSDJWT, error) {
	if claims == nil || !w.Conformance().Delegates() {
		return nil, nil
	}
	// §7.1: "_sd_alg may use any hash algorithm specified for hashing the
	// transaction_data."
	sdAlg := oid4vp.TransactionDataHashAlg(entries)
	kb := &delegate.KBSDJWT{Type: delegate.TypeKBSDJWT, SDAlg: sdAlg}
	var delegates []oid4vp.TransactionData
	for _, entry := range entries {
		delegation, ok := entry.Delegation()
		if !ok {
			continue
		}
		if delegation.Format == delegate.FormatDSDJWTKB {
			kb.Type = delegate.TypeKBSDJWTKB
		}
		kb.Payloads = append(kb.Payloads, delegate.PayloadDisclosure{Disclosure: delegation.PayloadDisclosure, Disclosures: delegation.Disclosures})
		delegates = append(delegates, entry)
	}
	if len(delegates) == 0 {
		return nil, nil
	}
	var list findings.List
	for _, entry := range delegates {
		// The request validation checked the entry under its preferred
		// algorithm.
		if sdAlg != entry.PreferredHashAlg() {
			list = append(list, entry.DelegateFindings(sdAlg)...)
		}
		// One KB-SD-JWT signs every delegate payload. Its typ applies to each
		// of them. §5.1.4: "If the typ is KB-SD-JWT+KB then the Delegate
		// Payload MUST include a cnf claim."
		if delegation, _ := entry.Delegation(); kb.Type == delegate.TypeKBSDJWTKB && delegation.Format != delegate.FormatDSDJWTKB && entry.DelegatePayload()["cnf"] == nil {
			list = append(list, findings.DelegateSDJWT.Protocol("§5.1.4").Newf("%s shares a KB-SD-JWT of typ %s with another entry, but its Delegate Payload has no cnf claim", entry.Label(), delegate.TypeKBSDJWTKB))
		}
	}
	if len(list) > 0 {
		err := w.reportDeviation(deviation{action: "presentation", event: "transaction_data_delegate", subject: subjectPresentation,
			summary: "These delegate transaction data entries can't share one KB-SD-JWT", findings: list})
		if err != nil {
			return nil, refuseTransactionData(err)
		}
	}
	return kb, nil
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

// TransactionDataType is a transaction data type the wallet accepts. A TS12
// type lists the members of its payload.
type TransactionDataType struct {
	Type   string                `json:"type"`
	TS12   bool                  `json:"ts12,omitempty"`
	Fields []oid4vp.PayloadField `json:"fields,omitempty"`
}

// TransactionDataTypes are the accepted transaction data types and hash
// algorithms.
type TransactionDataTypes struct {
	Types    []TransactionDataType `json:"types"`
	HashAlgs []string              `json:"hash_algs"`
}

// AcceptedTransactionDataTypes lists the TS12 types, the types from
// --transaction-data-type and delegate when Delegate SD-JWT is on.
func (w *Wallet) AcceptedTransactionDataTypes() (TransactionDataTypes, error) {
	list := TransactionDataTypes{HashAlgs: oid4vp.TransactionDataHashAlgs}
	for _, typ := range oid4vp.TS12TransactionDataTypes {
		fields, err := oid4vp.TS12PayloadFields(typ)
		if err != nil {
			return TransactionDataTypes{}, err
		}
		list.Types = append(list.Types, TransactionDataType{Type: typ, TS12: true, Fields: fields})
	}
	for _, typ := range w.Conformance().acceptedTransactionDataTypes() {
		if !slices.Contains(oid4vp.TS12TransactionDataTypes, typ) {
			list.Types = append(list.Types, TransactionDataType{Type: typ})
		}
	}
	return list, nil
}

// canDelegate reports whether entry is a delegate entry and its matched
// credential can delegate. Only an SD-JWT with a holder key (cnf) can sign a
// KB-SD-JWT. Another credential answers with a plain presentation.
func (w *Wallet) canDelegate(entry oid4vp.TransactionData, matches []consent.Match) bool {
	if _, ok := entry.Delegation(); !ok {
		return false
	}
	for _, match := range matches {
		if match.Format != credtype.FormatSDJWT || !slices.Contains(entry.CredentialIDs, match.QueryID) {
			continue
		}
		if cred, ok := w.GetCredential(match.CredentialID); ok && credentialHolderBinding(cred.Raw).Bound {
			return true
		}
	}
	return false
}
