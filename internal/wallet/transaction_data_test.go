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
	"crypto/sha256"
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
	"github.com/eudi-dev/eudi-dev/v3/internal/typemetadata"
)

func encodedTransactionData(t *testing.T, entry map[string]any) string {
	t.Helper()
	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	return format.EncodeBase64URL(data)
}

// transactionDataWallet has a PID and accepts transaction data in the given
// validation mode.
func transactionDataWallet(t *testing.T, mode string) (*Wallet, StoredCredential) {
	t.Helper()
	w := generateTestWalletWithPID(t)
	enabled := true
	if err := w.UpdateConformance(ConformancePatch{ValidationMode: &mode, TransactionData: &enabled}); err != nil {
		t.Fatal(err)
	}
	i := slices.IndexFunc(w.GetCredentials(), func(c StoredCredential) bool { return c.Format == "dc+sd-jwt" })
	if i < 0 {
		t.Fatal("no SD-JWT credential")
	}
	return w, w.GetCredentials()[i]
}

func transactionDataPresentationRequest(entries ...string) *oid4vp.Request {
	values := make([]any, 0, len(entries))
	for _, entry := range entries {
		values = append(values, entry)
	}
	return &oid4vp.Request{
		AuthorizationRequest: oid4vc.AuthorizationRequest{
			Nonce: "n", ClientID: "https://verifier.example", ResponseMode: "direct_post", ResponseURI: "https://verifier.example/response",
			DCQLQuery: map[string]any{"credentials": []any{
				map[string]any{"id": "pid", "format": "dc+sd-jwt"},
				map[string]any{"id": "other", "format": "dc+sd-jwt"},
			}},
		},
		RequestPayload: map[string]any{"transaction_data": values},
	}
}

func keyBindingPayload(t *testing.T, presentation string) map[string]any {
	t.Helper()
	token, err := sdjwt.Parse(presentation)
	if err != nil || token.KeyBindingJWT == nil {
		t.Fatalf("presentation has no key binding JWT: %v", err)
	}
	return token.KeyBindingJWT.Payload
}

// OpenID4VP 1.0 Appendix B.3.3.1: the Key Binding JWT carries a hash of each
// transaction_data string as received, and transaction_data_hashes_alg when
// the request lists algorithms.
func TestTransactionDataHashesAreInTheKeyBindingJWT(t *testing.T) {
	w, cred := transactionDataWallet(t, "debug")
	entry := encodedTransactionData(t, map[string]any{
		"type": "urn:eudi:sca:payment:1", "credential_ids": []any{"pid"}, "transaction_data_hashes_alg": []any{"sha-256"},
		"payload": map[string]any{"transaction_id": "t1", "payee": map[string]any{"name": "Shop", "id": "DE89370400440532013000"}, "currency": "EUR", "amount": 12.5},
	})
	result, err := w.createVPTokenMap([]consent.Match{{QueryID: "pid", CredentialID: cred.ID, Format: cred.Format}}, transactionDataPresentationRequest(entry))
	if err != nil {
		t.Fatal(err)
	}
	payload := keyBindingPayload(t, result.TokenMap["pid"][0])
	sum := sha256.Sum256([]byte(entry))
	if got, _ := json.Marshal(payload["transaction_data_hashes"]); string(got) != `["`+format.EncodeBase64URL(sum[:])+`"]` {
		t.Errorf("transaction_data_hashes = %s, want the SHA-256 of the received string", got)
	}
	if payload["transaction_data_hashes_alg"] != "sha-256" {
		t.Errorf("transaction_data_hashes_alg = %v, want sha-256", payload["transaction_data_hashes_alg"])
	}
	// EUDI TS12 v1.0.1 §3.6 adds jti, response_mode and amr.
	if jti, _ := payload["jti"].(string); jti == "" || payload["response_mode"] != "direct_post" {
		t.Errorf("jti = %v, response_mode = %v, want a jti and direct_post", payload["jti"], payload["response_mode"])
	}
	if got, _ := json.Marshal(payload["amr"]); string(got) != `[{"knowledge":"pin_6_or_more_digits"},{"possession":"key_in_local_native_wscd"}]` {
		t.Errorf("amr = %s, want a PIN and a native key", got)
	}
}

// TS12 §3.6: response_mode is the mode of the answer. The wallet answers a
// request without one with direct_post.
func TestTS12ResponseModeIsTheModeOfTheAnswer(t *testing.T) {
	w, cred := transactionDataWallet(t, "debug")
	entry := encodedTransactionData(t, map[string]any{
		"type": "urn:eudi:sca:payment:1", "credential_ids": []any{"pid"}, "transaction_data_hashes_alg": []any{"sha-256"},
		"payload": map[string]any{"transaction_id": "t1", "payee": map[string]any{"name": "Shop", "id": "DE89370400440532013000"}, "currency": "EUR", "amount": 12.5},
	})
	req := transactionDataPresentationRequest(entry)
	req.ResponseMode = ""
	result, err := w.createVPTokenMap([]consent.Match{{QueryID: "pid", CredentialID: cred.ID, Format: cred.Format}}, req)
	if err != nil {
		t.Fatal(err)
	}
	if got := keyBindingPayload(t, result.TokenMap["pid"][0])["response_mode"]; got != "direct_post" {
		t.Errorf("response_mode = %v, want direct_post", got)
	}
}

func TestOtherTransactionDataHasNoTS12Claims(t *testing.T) {
	w, cred := transactionDataWallet(t, "debug")
	entry := encodedTransactionData(t, map[string]any{"type": "urn:example:sign", "credential_ids": []any{"pid"}})
	result, err := w.createVPTokenMap([]consent.Match{{QueryID: "pid", CredentialID: cred.ID, Format: cred.Format}}, transactionDataPresentationRequest(entry))
	if err != nil {
		t.Fatal(err)
	}
	payload := keyBindingPayload(t, result.TokenMap["pid"][0])
	if _, ok := payload["transaction_data_hashes"]; !ok {
		t.Error("debug mode did not bind the entry of an unknown type")
	}
	for _, claim := range []string{"jti", "response_mode", "amr"} {
		if _, ok := payload[claim]; ok {
			t.Errorf("the key binding JWT has %s, want it only for TS12 types", claim)
		}
	}
}

// OpenID4VP 1.0 §5.1: "If there is more than one element in the array, the
// Wallet MUST use only one of the referenced Credentials for transaction
// authorization."
func TestTransactionDataIsBoundToOnePresentation(t *testing.T) {
	w, cred := transactionDataWallet(t, "debug")
	entry := encodedTransactionData(t, map[string]any{"type": "urn:example:sign", "credential_ids": []any{"other", "pid"}})
	matches := []consent.Match{
		{QueryID: "pid", CredentialID: cred.ID, Format: cred.Format},
		{QueryID: "other", CredentialID: cred.ID, Format: cred.Format},
	}
	result, err := w.createVPTokenMap(matches, transactionDataPresentationRequest(entry))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := keyBindingPayload(t, result.TokenMap["other"][0])["transaction_data_hashes"]; !ok {
		t.Error("the presentation for the first referenced query has no transaction_data_hashes")
	}
	if _, ok := keyBindingPayload(t, result.TokenMap["pid"][0])["transaction_data_hashes"]; ok {
		t.Error("the presentation for the second referenced query also has transaction_data_hashes")
	}
}

// OpenID4VP 1.0 Appendix B.3.3: only an SD-JWT VC with holder binding carries
// transaction data. The wallet binds the entry to the query whose credential
// can carry it.
func TestTransactionDataPrefersACredentialWithKeyBinding(t *testing.T) {
	w, cred := transactionDataWallet(t, "strict")
	mdoc := transactionDataMDoc(t, w)
	entry := encodedTransactionData(t, map[string]any{"type": "urn:example:sign", "credential_ids": []any{"other", "pid"}})
	matches := []consent.Match{
		{QueryID: "pid", CredentialID: cred.ID, Format: cred.Format},
		{QueryID: "other", CredentialID: mdoc.ID, Format: mdoc.Format},
	}
	result, err := w.createVPTokenMap(matches, transactionDataPresentationRequest(entry))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := keyBindingPayload(t, result.TokenMap["pid"][0])["transaction_data_hashes"]; !ok {
		t.Error("the SD-JWT VC presentation has no transaction_data_hashes")
	}
}

func TestStrictModeRefusesTransactionDataForAnMDoc(t *testing.T) {
	w, _ := transactionDataWallet(t, "strict")
	mdoc := transactionDataMDoc(t, w)
	entry := encodedTransactionData(t, map[string]any{"type": "urn:example:sign", "credential_ids": []any{"other"}})
	_, err := w.createVPTokenMap([]consent.Match{{QueryID: "other", CredentialID: mdoc.ID, Format: mdoc.Format}}, transactionDataPresentationRequest(entry))
	if err == nil || !strings.Contains(err.Error(), "has no Key Binding JWT, so the presentation carries no transaction data") {
		t.Fatalf("err = %v, want the mdoc refused", err)
	}
}

// Appendix B.3.3.1: the wallet hashes with an algorithm accepted by the entry.
// Strict mode refuses entries without a common one. Debug mode sends sha-256
// hashes.
func TestTransactionDataWithoutACommonHashAlgorithm(t *testing.T) {
	for _, mode := range []string{"strict", "debug"} {
		t.Run(mode, func(t *testing.T) {
			w, cred := transactionDataWallet(t, mode)
			request := transactionDataPresentationRequest(
				encodedTransactionData(t, map[string]any{"type": "urn:example:sign", "credential_ids": []any{"pid"}, "transaction_data_hashes_alg": []any{"sha-512"}}),
				encodedTransactionData(t, map[string]any{"type": "urn:example:sign", "credential_ids": []any{"pid"}}),
			)
			result, err := w.createVPTokenMap([]consent.Match{{QueryID: "pid", CredentialID: cred.ID, Format: cred.Format}}, request)
			if mode == "strict" {
				if err == nil || !strings.Contains(err.Error(), "have no common hash algorithm") {
					t.Fatalf("err = %v, want no common algorithm refused", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if alg := keyBindingPayload(t, result.TokenMap["pid"][0])["transaction_data_hashes_alg"]; alg != "sha-256" {
				t.Errorf("transaction_data_hashes_alg = %v, want sha-256", alg)
			}
		})
	}
}

func transactionDataMDoc(t *testing.T, w *Wallet) StoredCredential {
	t.Helper()
	i := slices.IndexFunc(w.GetCredentials(), func(c StoredCredential) bool { return c.Format == "mso_mdoc" })
	if i < 0 {
		t.Fatal("no mdoc credential")
	}
	return w.GetCredentials()[i]
}

// OpenID4VP 1.0 §8.5 invalid_transaction_data: "the referenced Credential(s)
// are not available in the Wallet."
func TestStrictModeRefusesTransactionDataWithoutAPresentation(t *testing.T) {
	w, cred := transactionDataWallet(t, "strict")
	entry := encodedTransactionData(t, map[string]any{"type": "urn:example:sign", "credential_ids": []any{"other"}})
	_, err := w.createVPTokenMap([]consent.Match{{QueryID: "pid", CredentialID: cred.ID, Format: cred.Format}}, transactionDataPresentationRequest(entry))
	if err == nil || !strings.Contains(err.Error(), "transaction_data[0] references other, but the response presents none of them") {
		t.Fatalf("err = %v, want the unbound transaction data refused", err)
	}
}

func TestWithoutSupportTheKeyBindingJWTHasNoTransactionData(t *testing.T) {
	w := generateTestWalletWithPID(t)
	i := slices.IndexFunc(w.GetCredentials(), func(c StoredCredential) bool { return c.Format == "dc+sd-jwt" })
	cred := w.GetCredentials()[i]
	entry := encodedTransactionData(t, map[string]any{"type": "urn:example:sign", "credential_ids": []any{"pid"}})
	result, err := w.createVPTokenMap([]consent.Match{{QueryID: "pid", CredentialID: cred.ID, Format: cred.Format}}, transactionDataPresentationRequest(entry))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := keyBindingPayload(t, result.TokenMap["pid"][0])["transaction_data_hashes"]; ok {
		t.Error("a wallet without transaction data support sent transaction_data_hashes")
	}
}

func TestTransactionDataTypesAreTrimmedAndUnique(t *testing.T) {
	got, err := ParseTransactionDataTypes([]string{" urn:example:sign ", "urn:example:sign", "urn:example:pay"})
	if err != nil || !slices.Equal(got, []string{"urn:example:sign", "urn:example:pay"}) {
		t.Errorf("types = %v, %v", got, err)
	}
	if _, err := ParseTransactionDataTypes([]string{" "}); err == nil {
		t.Error("an empty type was accepted")
	}
}

// EUDI TS12 v1.0.1 §3.2 steps 1 and 2 are warnings in both modes (ADR 0031).
// The PID has no Type Metadata, so a payment bound to it is not authorized by
// an SCA Attestation.
func TestStrictModeWarnsWhenAPaymentIsBoundToANonSCACredential(t *testing.T) {
	w, cred := transactionDataWallet(t, "strict")
	entry := encodedTransactionData(t, map[string]any{
		"type": "urn:eudi:sca:payment:1", "credential_ids": []any{"pid"}, "transaction_data_hashes_alg": []any{"sha-256"},
		"payload": map[string]any{"transaction_id": "t1", "payee": map[string]any{"name": "Shop", "id": "DE89370400440532013000"}, "currency": "EUR", "amount": 12.5},
	})
	result, err := w.createVPTokenMap([]consent.Match{{QueryID: "pid", CredentialID: cred.ID, Format: cred.Format}}, transactionDataPresentationRequest(entry))
	if err != nil {
		t.Fatalf("createVPTokenMap: %v, want a presentation", err)
	}
	if keyBindingPayload(t, result.TokenMap["pid"][0])["transaction_data_hashes"] == nil {
		t.Error("the Key Binding JWT has no transaction_data_hashes")
	}
	warning := findLogEntry(w.GetLog(), "transaction_data_sca")
	if warning == nil || warning.Severity != severityWarning || !strings.Contains(warning.Detail, "category urn:eu:europa:ec:eudi:sua:sca") {
		t.Fatalf("log entry = %+v, want a category warning", warning)
	}
}

func TestSCAFindings(t *testing.T) {
	sca := &typemetadata.Metadata{Category: typemetadata.SCACategory, TransactionDataTypes: map[string]typemetadata.TransactionDataType{
		"urn:eudi:sca:payment:1": {Schema: json.RawMessage(`"urn:eudi:sca:payment:1"`)},
	}}
	payment := oid4vp.NewTransactionData("", map[string]any{"type": "urn:eudi:sca:payment:1"})
	login := oid4vp.NewTransactionData("", map[string]any{"type": "urn:eudi:sca:login_risk_transaction:1"})
	custom := oid4vp.NewTransactionData("", map[string]any{"type": "urn:example:sign"})
	for name, tc := range map[string]struct {
		metadata *typemetadata.Metadata
		entry    oid4vp.TransactionData
		want     string
	}{
		"listed type":                           {sca, payment, ""},
		"type the SCA Attestation omits":        {sca, login, "does not list urn:eudi:sca:login_risk_transaction:1"},
		"custom type the SCA Attestation omits": {sca, custom, "does not list urn:example:sign"},
		"TS12 type without Type Metadata":       {nil, payment, "does not have the category"},
		"TS12 type on another category":         {&typemetadata.Metadata{Category: "urn:example:other"}, payment, "does not have the category"},
		"custom type without Type Metadata":     {nil, custom, ""},
	} {
		t.Run(name, func(t *testing.T) {
			list := scaFindings(StoredCredential{VCT: "https://issuer.example/types/card", TypeMetadata: tc.metadata}, []oid4vp.TransactionData{tc.entry})
			if tc.want == "" {
				if len(list) != 0 {
					t.Fatalf("findings = %v, want none", list.Texts())
				}
				return
			}
			if len(list) != 1 || !strings.Contains(list[0].String(), tc.want) || !strings.Contains(list[0].String(), "TS12") {
				t.Fatalf("findings = %v, want one TS12 finding with %q", list.Texts(), tc.want)
			}
		})
	}
}
