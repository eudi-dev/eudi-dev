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

package oid4vp

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/dcql"
	"github.com/eudi-dev/eudi-dev/v3/internal/findings"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
)

// TS12TransactionDataTypes are the basic transaction types of EUDI TS12
// v1.0.1 §4.3. "Wallet Units SHALL support the processing and rendering" of
// them.
var TS12TransactionDataTypes = []string{
	"urn:eudi:sca:payment:1",
	"urn:eudi:sca:login_risk_transaction:1",
	"urn:eudi:sca:account_access:1",
	"urn:eudi:sca:emandate:1",
}

// TransactionDataHashAlgs are the supported hash algorithms for
// transaction_data_hashes, in order of preference.
var TransactionDataHashAlgs = []string{"sha-256", "sha-384", "sha-512"}

// defaultTransactionDataHashAlg applies when an entry has no
// transaction_data_hashes_alg (Appendix B.3.3.1).
const defaultTransactionDataHashAlg = "sha-256"

// TransactionData is one entry of the transaction_data request parameter
// (OpenID4VP 1.0 §5.1).
type TransactionData struct {
	// Raw is the base64url string as received. Appendix B.3.3.1 hashes it
	// without decoding it.
	Raw string `json:"-"`
	// Index is the position in the request, even when an earlier malformed
	// entry was left out.
	Index int    `json:"-"`
	Type  string `json:"type"`
	// CredentialIDs are the ids of the credential queries that can authorize
	// the transaction.
	CredentialIDs []string `json:"credential_ids"`
	// HashAlgs is transaction_data_hashes_alg. It is nil when the entry has
	// none, and empty when the member is not an array of strings.
	HashAlgs []string `json:"transaction_data_hashes_alg,omitempty"`
	// Data is the whole decoded object, for the consent dialog.
	Data map[string]any `json:"data"`
}

// ParseTransactionData decodes the transaction_data parameter. An entry that
// is not a base64url JSON object is left out. The validation reports it.
func ParseTransactionData(params *Request) []TransactionData {
	entries, _ := parseTransactionData(params, requestPayload(params.RequestObject, params.RequestPayload))
	return entries
}

func parseTransactionData(params *Request, payload map[string]any) ([]TransactionData, findings.List) {
	raw, ok := payload["transaction_data"]
	if !ok {
		query, inQuery := queryTransactionData(params)
		if !inQuery {
			return nil, nil
		}
		if err := json.Unmarshal([]byte(query), &raw); err != nil {
			return nil, findings.List{findings.OID4VP.Protocol("§5.1").Newf("transaction_data is not a JSON array: %v", err)}
		}
	}
	values, ok := raw.([]any)
	if !ok || len(values) == 0 {
		return nil, findings.List{findings.OID4VP.Protocol("§5.1").New("transaction_data must be a non-empty array of strings")}
	}
	var entries []TransactionData
	var list findings.List
	for i, value := range values {
		label := fmt.Sprintf("transaction_data[%d]", i)
		encoded, ok := value.(string)
		if !ok {
			list = append(list, findings.OID4VP.Protocol("§5.1").Newf("%s is not a string", label))
			continue
		}
		decoded, err := format.DecodeBase64URL(encoded)
		var object map[string]any
		if err == nil {
			err = json.Unmarshal(decoded, &object)
		}
		if err != nil || object == nil {
			list = append(list, findings.OID4VP.Protocol("§5.1").Newf("%s is not a base64url-encoded JSON object", label))
			continue
		}
		entry := NewTransactionData(encoded, object)
		entry.Index = i
		if entry.HashAlgs != nil && len(entry.HashAlgs) == 0 {
			list = append(list, findings.OID4VP.Protocol("Appendix B.3.3.1").Newf("transaction_data_hashes_alg of %s must be a non-empty array of strings", label))
		}
		entries = append(entries, entry)
	}
	return entries, list
}

// NewTransactionData reads the members of a decoded entry. raw is the string
// as sent.
func NewTransactionData(raw string, object map[string]any) TransactionData {
	entry := TransactionData{Raw: raw, Data: object}
	entry.Type, _ = object["type"].(string)
	entry.CredentialIDs = jsonutil.Strings(object["credential_ids"])
	if algs, present := object["transaction_data_hashes_alg"]; present {
		entry.HashAlgs = jsonutil.Strings(algs)
		if entry.HashAlgs == nil {
			entry.HashAlgs = []string{}
		}
	}
	return entry
}

// Label identifies the entry in findings.
func (e TransactionData) Label() string {
	return fmt.Sprintf("transaction_data[%d]", e.Index)
}

// queryTransactionData is the transaction_data query parameter of an unsigned
// request. A signed request uses only the parameters of its Request Object,
// even when the query repeats one (RFC 9101 §6.3).
func queryTransactionData(params *Request) (string, bool) {
	if params.RequestObject != nil {
		return "", false
	}
	query, ok := params.FullParams["transaction_data"]
	return query, ok
}

// transactionDataFindings checks transaction_data against OpenID4VP 1.0 §5.1,
// §8.5 and Appendix B.3.3. §5.1: "The Wallet MUST return an error if a
// request contains even one unrecognized transaction data type or transaction
// data not conforming to the respective type definition."
func transactionDataFindings(checks Checks, params *Request, payload map[string]any) findings.List {
	if !hasTransactionData(params, payload) {
		return nil
	}
	// §5: "Wallets that do not support this parameter MUST reject requests
	// that contain it." §8.4 repeats it.
	if !checks.TransactionData {
		return findings.List{findings.OID4VP.Protocol("§5").New("transaction_data is not supported by this wallet")}
	}
	entries, list := parseTransactionData(params, payload)
	for _, entry := range entries {
		label := entry.Label()
		switch {
		case entry.Type == "":
			list = append(list, findings.OID4VP.Protocol("§5.1").Newf("%s has no type", label))
		case !checks.acceptsTransactionDataType(entry.Type):
			list = append(list, findings.OID4VP.Protocol("§8.5").Newf("%s has the unsupported type %q", label, entry.Type))
		}
		if len(entry.CredentialIDs) == 0 {
			list = append(list, findings.OID4VP.Protocol("§5.1").Newf("%s must have credential_ids, a non-empty array of credential query ids", label))
		}
		for _, id := range entry.CredentialIDs {
			list = append(list, transactionCredentialFindings(label, id, params.DCQLQuery)...)
		}
		if len(entry.HashAlgs) > 0 && !slices.ContainsFunc(entry.HashAlgs, func(alg string) bool { return slices.Contains(TransactionDataHashAlgs, alg) }) {
			list = append(list, findings.OID4VP.Protocol("Appendix B.3.3.1").Newf("%s accepts only the hash algorithms %s. This wallet supports %s", label, strings.Join(entry.HashAlgs, ", "), strings.Join(TransactionDataHashAlgs, ", ")))
		}
		if slices.Contains(TS12TransactionDataTypes, entry.Type) {
			list = append(list, ts12Findings(label, entry)...)
		}
	}
	return list
}

func transactionCredentialFindings(label, id string, query map[string]any) findings.List {
	cq := dcql.QueryByID(query, id)
	if cq == nil {
		return findings.List{findings.OID4VP.Protocol("§5.1").Newf("credential_ids of %s contains %q, but dcql_query has no credential query with that id", label, id)}
	}
	var list findings.List
	switch queryFormat, _ := cq["format"].(string); queryFormat {
	case credtype.FormatSDJWT:
	case credtype.FormatMDOC:
		// Appendix B.2.1: the document type specifications say which
		// transaction data types they support. This wallet knows of none.
		list = append(list, findings.OID4VP.Protocol("Appendix B.2.1").Newf("%s references the mdoc query %q. This wallet knows no mdoc document type with transaction data support", label, id))
	default:
		list = append(list, findings.OID4VP.Protocol("§8.4").Newf("%s references the query %q of format %q. This wallet adds transaction data only to SD-JWT VC presentations", label, id, queryFormat))
	}
	// Appendix B.3.3: "Wallets MUST reject requests with transaction data
	// types that have the require_cryptographic_holder_binding parameter set
	// to false."
	if !dcql.RequiresHolderBinding(cq) {
		list = append(list, findings.OID4VP.Protocol("Appendix B.3.3").Newf("%s references the query %q, which sets require_cryptographic_holder_binding to false", label, id))
	}
	return list
}

func (c Checks) acceptsTransactionDataType(typ string) bool {
	return slices.Contains(TS12TransactionDataTypes, typ) || slices.Contains(c.TransactionDataTypes, typ)
}

// TransactionDataClaims are the Key Binding JWT claims that bind entries to
// one presentation (Appendix B.3.3.1). They use the first algorithm of
// TransactionDataHashAlgs accepted by every entry. Without such an algorithm
// the claims use sha-256 and come back together with an error. An entry of a
// TS12 type adds the claims of TS12 §3.6. responseMode is the response mode of
// the answer.
func TransactionDataClaims(entries []TransactionData, responseMode string) (map[string]any, error) {
	alg := ""
	for _, candidate := range TransactionDataHashAlgs {
		if !slices.ContainsFunc(entries, func(e TransactionData) bool { return !e.acceptsHashAlg(candidate) }) {
			alg = candidate
			break
		}
	}
	var algErr error
	if alg == "" {
		alg = defaultTransactionDataHashAlg
		algErr = &findings.Error{Summary: "no common hash algorithm for transaction data", Findings: findings.List{
			findings.OID4VP.Protocol("Appendix B.3.3.1").New("the transaction data entries of one presentation have no common hash algorithm supported by this wallet"),
		}}
	}
	hashes := make([]string, 0, len(entries))
	sendAlg := false
	for _, entry := range entries {
		hash, err := sdjwt.SDHash(entry.Raw, alg)
		if err != nil {
			return nil, err
		}
		hashes = append(hashes, hash)
		sendAlg = sendAlg || entry.HashAlgs != nil
	}
	claims := map[string]any{"transaction_data_hashes": hashes}
	// Appendix B.3.3.1: transaction_data_hashes_alg is "REQUIRED when this
	// parameter was present in the transaction_data request parameter".
	if sendAlg {
		claims["transaction_data_hashes_alg"] = alg
	}
	if slices.ContainsFunc(entries, func(e TransactionData) bool { return slices.Contains(TS12TransactionDataTypes, e.Type) }) {
		addTS12Claims(claims, responseMode)
	}
	return claims, algErr
}

func (e TransactionData) acceptsHashAlg(alg string) bool {
	if e.HashAlgs == nil {
		return alg == defaultTransactionDataHashAlg
	}
	return slices.Contains(e.HashAlgs, alg)
}
