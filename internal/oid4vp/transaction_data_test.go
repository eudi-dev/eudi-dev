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
	"crypto/sha256"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/findings"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
)

// ts12Payment is a TS12 v1.0.1 §4.2 entry with every REQUIRED member.
var ts12Payment = map[string]any{
	"type":                        "urn:eudi:sca:payment:1",
	"credential_ids":              []any{"pid"},
	"transaction_data_hashes_alg": []any{"sha-256"},
	"payload": map[string]any{
		"transaction_id": "8D8AC610-566D-4EF0-9C22-186B2A5ED793",
		"payee":          map[string]any{"name": "Merchant", "id": "DE89370400440532013000"},
		"currency":       "EUR",
		"amount":         12.5,
	},
}

var transactionDataQuery = map[string]any{"credentials": []any{
	map[string]any{"id": "pid", "format": "dc+sd-jwt"},
	map[string]any{"id": "mdl", "format": "mso_mdoc"},
	map[string]any{"id": "unbound", "format": "dc+sd-jwt", "require_cryptographic_holder_binding": false},
}}

func transactionDataEntry(t *testing.T, entry map[string]any) string {
	t.Helper()
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	return format.EncodeBase64URL(data)
}

func with(entry map[string]any, key string, value any) map[string]any {
	out := map[string]any{}
	for k, v := range entry {
		out[k] = v
	}
	if value == nil {
		delete(out, key)
	} else {
		out[key] = value
	}
	return out
}

func transactionDataRequest(entries ...any) *Request {
	payload := map[string]any{"transaction_data": entries}
	return &Request{
		AuthorizationRequest: oid4vc.AuthorizationRequest{ClientID: "x509_san_dns:verifier.example", DCQLQuery: transactionDataQuery},
		RequestPayload:       payload,
	}
}

func TestTransactionDataFindings(t *testing.T) {
	supported := Checks{TransactionData: true, TransactionDataTypes: []string{"urn:example:sign"}}
	sign := map[string]any{"type": "urn:example:sign", "credential_ids": []any{"pid"}}
	for _, tt := range []struct {
		name   string
		checks Checks
		entry  any
		want   string
	}{
		{"a TS12 entry", supported, ts12Payment, ""},
		{"a registered type", supported, sign, ""},
		// §5: "Wallets that do not support this parameter MUST reject
		// requests that contain it."
		{"a wallet without support", Checks{}, ts12Payment, "OID4VP 1.0 §5: transaction_data is not supported by this wallet"},
		// §5.1: "The Wallet MUST return an error if a request contains even
		// one unrecognized transaction data type".
		{"an unknown type", supported, with(sign, "type", "urn:example:other"), `OID4VP 1.0 §8.5: transaction_data[0] has the unsupported type "urn:example:other"`},
		{"no type", supported, with(sign, "type", nil), "OID4VP 1.0 §5.1: transaction_data[0] has no type"},
		{"no credential_ids", supported, with(sign, "credential_ids", nil), "OID4VP 1.0 §5.1: transaction_data[0] must have credential_ids"},
		// §8.5: "the credential_ids does not match".
		{"an unknown credential query", supported, with(sign, "credential_ids", []any{"ticket"}), `OID4VP 1.0 §5.1: credential_ids of transaction_data[0] contains "ticket", but dcql_query has no credential query with that id`},
		{"an mdoc query", supported, with(sign, "credential_ids", []any{"mdl"}), `OID4VP 1.0 Appendix B.2.1: transaction_data[0] references the mdoc query "mdl"`},
		// Appendix B.3.3: "Wallets MUST reject requests with transaction
		// data types that have the require_cryptographic_holder_binding
		// parameter set to false."
		{"a query without holder binding", supported, with(sign, "credential_ids", []any{"unbound"}), `OID4VP 1.0 Appendix B.3.3: transaction_data[0] references the query "unbound", which sets require_cryptographic_holder_binding to false`},
		{"an unsupported hash algorithm", supported, with(sign, "transaction_data_hashes_alg", []any{"md5"}), "OID4VP 1.0 Appendix B.3.3.1: transaction_data[0] accepts only the hash algorithms md5"},
		{"an empty hash algorithm list", supported, with(sign, "transaction_data_hashes_alg", []any{}), "OID4VP 1.0 Appendix B.3.3.1: transaction_data_hashes_alg of transaction_data[0] must be a non-empty array of strings"},
		// TS12 v1.0.1 §4.2 makes transaction_data_hashes_alg and payload
		// REQUIRED.
		{"a TS12 entry without payload", supported, with(ts12Payment, "payload", nil), `EUDI TS12 v1.0.1 §4.2: transaction_data[0] of type "urn:eudi:sca:payment:1" has no payload object`},
		{"a TS12 entry without hash algorithms", supported, with(ts12Payment, "transaction_data_hashes_alg", nil), `EUDI TS12 v1.0.1 §4.2: transaction_data[0] of type "urn:eudi:sca:payment:1" has no transaction_data_hashes_alg`},
		// TS12 v1.0.1 §3.2 step 4 validates the payload against the JSON
		// Schema of its type (§4.3).
		{"a payment without amount", supported, with(ts12Payment, "payload", with(ts12Payment["payload"].(map[string]any), "amount", nil)), `EUDI TS12 v1.0.1 §3.2: payload of transaction_data[0] does not match the schema of "urn:eudi:sca:payment:1": at /: missing property 'amount'`},
		{"a payment with a lowercase currency", supported, with(ts12Payment, "payload", with(ts12Payment["payload"].(map[string]any), "currency", "eur")), `EUDI TS12 v1.0.1 §3.2: payload of transaction_data[0] does not match the schema of "urn:eudi:sca:payment:1": at /currency:`},
		// §8.5 invalid_transaction_data: "contains unknown fields".
		{"a TS12 entry with an unknown member", supported, with(ts12Payment, "note", "x"), `OID4VP 1.0 §8.5: transaction_data[0] of type "urn:eudi:sca:payment:1" has the unknown member note`},
		{"an entry that is no string", supported, map[string]any{"type": "urn:example:sign"}, "OID4VP 1.0 §5.1: transaction_data[0] is not a string"},
		{"an entry that is no JSON object", supported, "bm90IGpzb24", "OID4VP 1.0 §5.1: transaction_data[0] is not a base64url-encoded JSON object"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			entry := tt.entry
			if object, ok := entry.(map[string]any); ok && tt.name != "an entry that is no string" {
				entry = transactionDataEntry(t, object)
			}
			req := transactionDataRequest(entry)
			got := transactionDataFindings(tt.checks, req, req.RequestPayload).Texts()
			if tt.want == "" {
				if len(got) > 0 {
					t.Errorf("findings = %q, want none", got)
				}
				return
			}
			if !slices.ContainsFunc(got, func(text string) bool { return strings.HasPrefix(text, tt.want) }) {
				t.Errorf("findings = %q, want one starting with %q", got, tt.want)
			}
		})
	}
}

func TestTransactionDataInTheQuery(t *testing.T) {
	req := &Request{AuthorizationRequest: oid4vc.AuthorizationRequest{
		ClientID:   "redirect_uri:https://verifier.example/response",
		DCQLQuery:  transactionDataQuery,
		FullParams: map[string]string{"transaction_data": `["` + transactionDataEntry(t, ts12Payment) + `"]`},
	}}
	entries := ParseTransactionData(req)
	if len(entries) != 1 || entries[0].Type != "urn:eudi:sca:payment:1" || !slices.Equal(entries[0].CredentialIDs, []string{"pid"}) {
		t.Fatalf("entries = %+v, want the payment entry", entries)
	}
	if got := transactionDataFindings(Checks{TransactionData: true}, req, nil); len(got) > 0 {
		t.Errorf("findings = %q, want none", got.Texts())
	}
}

func TestStrictModeRefusesUnsupportedTransactionData(t *testing.T) {
	req := transactionDataRequest(transactionDataEntry(t, with(ts12Payment, "type", "urn:example:other")))
	req.ResponseType, req.ResponseMode, req.ResponseURI, req.Nonce = "vp_token", "direct_post", "https://verifier.example/response", "n"
	req.ClientID = "redirect_uri:https://verifier.example/response"
	_, err := ValidateAuthorizationRequest(Checks{Strict: true, TransactionData: true}, req)
	if err == nil || !strings.Contains(err.Error(), `type "urn:example:other"`) {
		t.Fatalf("err = %v, want the unknown type refused", err)
	}
}

// Appendix B.3.3.1: each hash is "calculated using a hash function over the
// string received in the transaction_data request parameter (base64url
// decoding is not performed before hashing)".
func TestTransactionDataClaimsHashTheReceivedString(t *testing.T) {
	raw := transactionDataEntry(t, map[string]any{"type": "urn:example:sign", "credential_ids": []any{"pid"}})
	claims, err := TransactionDataClaims([]TransactionData{{Raw: raw}}, "direct_post")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(raw))
	if got := claims["transaction_data_hashes"]; !slices.Equal(got.([]string), []string{format.EncodeBase64URL(sum[:])}) {
		t.Errorf("transaction_data_hashes = %v, want the SHA-256 of the received string", got)
	}
	// transaction_data_hashes_alg is "REQUIRED when this parameter was
	// present in the transaction_data request parameter".
	if _, ok := claims["transaction_data_hashes_alg"]; ok {
		t.Errorf("claims = %v, want no transaction_data_hashes_alg for a request without one", claims)
	}
}

func TestTransactionDataClaimsUseACommonAlgorithm(t *testing.T) {
	claims, err := TransactionDataClaims([]TransactionData{
		{Raw: "a", HashAlgs: []string{"sha-512", "sha-384"}},
		{Raw: "b", HashAlgs: []string{"sha-384"}},
	}, "direct_post")
	if err != nil {
		t.Fatal(err)
	}
	if claims["transaction_data_hashes_alg"] != "sha-384" || len(claims["transaction_data_hashes"].([]string)) != 2 {
		t.Errorf("claims = %v, want two sha-384 hashes", claims)
	}
}

func TestTransactionDataClaimsWithoutACommonAlgorithm(t *testing.T) {
	claims, err := TransactionDataClaims([]TransactionData{
		{Raw: "a", HashAlgs: []string{"sha-512"}},
		{Raw: "b"},
	}, "direct_post")
	if err == nil || !strings.Contains(err.Error(), "no common hash algorithm") {
		t.Errorf("err = %v, want the missing common algorithm reported", err)
	}
	if claims["transaction_data_hashes_alg"] != "sha-256" {
		t.Errorf("claims = %v, want the sha-256 claims for debug mode", claims)
	}
}

// TS12 v1.0.1 §4.3 defines the payload schemas. The e-mandate schema refers
// to the payment schema.
func TestTheTS12SchemasCompile(t *testing.T) {
	schemas, err := ts12Schemas()
	if err != nil {
		t.Fatal(err)
	}
	for _, typ := range TS12TransactionDataTypes {
		if schemas[typ] == nil {
			t.Errorf("no schema for %s", typ)
		}
	}
}

// TS12 v1.0.1 §3.6: jti "SHALL be unique for each presentation".
func TestTS12ClaimsHaveAFreshJTI(t *testing.T) {
	entries := []TransactionData{{Raw: "a", Type: "urn:eudi:sca:payment:1"}}
	first, err := TransactionDataClaims(entries, "dc_api.jwt")
	if err != nil {
		t.Fatal(err)
	}
	second, _ := TransactionDataClaims(entries, "dc_api.jwt")
	if first["jti"] == "" || first["jti"] == second["jti"] {
		t.Errorf("jti = %v and %v, want two fresh values", first["jti"], second["jti"])
	}
	if first["response_mode"] != "dc_api.jwt" {
		t.Errorf("response_mode = %v, want the request's dc_api.jwt", first["response_mode"])
	}
}

// RFC 9101 §6.3: a signed request uses only the parameters of its Request
// Object.
func TestASignedRequestIgnoresTransactionDataInTheQuery(t *testing.T) {
	req := &Request{AuthorizationRequest: oid4vc.AuthorizationRequest{
		DCQLQuery:     transactionDataQuery,
		RequestObject: &oid4vc.RequestObjectJWT{Payload: map[string]any{"dcql_query": transactionDataQuery}},
		FullParams:    map[string]string{"transaction_data": `["` + transactionDataEntry(t, ts12Payment) + `"]`},
	}}
	if entries := ParseTransactionData(req); len(entries) > 0 {
		t.Errorf("entries = %+v, want none from the query", entries)
	}
}

// Appendix B.3.3.1: transaction_data_hashes_alg is "REQUIRED when this
// parameter was present in the transaction_data request parameter", even when
// its value is malformed.
func TestAMalformedHashAlgorithmListKeepsTheAlgorithmClaim(t *testing.T) {
	req := transactionDataRequest(transactionDataEntry(t, with(ts12Payment, "transaction_data_hashes_alg", []any{"sha-256", 5})))
	claims, err := TransactionDataClaims(ParseTransactionData(req), "direct_post")
	if err == nil {
		t.Error("err = nil, want no common algorithm")
	}
	if claims["transaction_data_hashes_alg"] != "sha-256" {
		t.Errorf("claims = %v, want transaction_data_hashes_alg", claims)
	}
}

// A finding identifies the entry by its position in the request, even after a
// malformed entry was left out.
func TestTransactionDataFindingsUseTheRequestIndex(t *testing.T) {
	entry, _ := json.Marshal(map[string]any{"credential_ids": []any{"pid"}})
	req := &Request{
		AuthorizationRequest: oid4vc.AuthorizationRequest{DCQLQuery: map[string]any{"credentials": []any{
			map[string]any{"id": "pid", "format": "dc+sd-jwt"},
		}}},
		RequestPayload: map[string]any{"transaction_data": []any{"not base64 json", format.EncodeBase64URL(entry)}},
	}
	list := transactionDataFindings(Checks{TransactionData: true}, req, req.RequestPayload)
	if !slices.ContainsFunc(list, func(f findings.Finding) bool { return strings.Contains(f.Text, "transaction_data[1] has no type") }) {
		t.Errorf("findings %v, want transaction_data[1] has no type", list)
	}
}

func TestTS12FindingsChecksThePayloadOfATS12Type(t *testing.T) {
	payment := map[string]any{
		"type":                        "urn:eudi:sca:payment:1",
		"transaction_data_hashes_alg": []any{"sha-256"},
		"payload":                     map[string]any{"transaction_id": "1", "currency": "EUR", "amount": 1.0},
	}
	if list := TS12Findings(payment); len(list) != 1 || !strings.Contains(list[0].Text, "payee") {
		t.Errorf("TS12Findings(payment without payee) = %v", list.Texts())
	}
	if list := TS12Findings(map[string]any{"type": "urn:example:refund"}); len(list) != 0 {
		t.Errorf("TS12Findings(other type) = %v", list.Texts())
	}
}
