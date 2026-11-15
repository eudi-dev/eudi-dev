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
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/pkg/sdjwt"
)

var delegateJWK = map[string]any{
	"kty": "EC", "crv": "P-256",
	"x": "TCAER19Zvu3OHF4j4W4vfSVoHIP1ILilDls7vCeGemc",
	"y": "ZxjiWWbZMQGHVWKVQ4hbSIirsVfuecCE6t4jT9F2HZQ",
}

func delegateDisclosure(t *testing.T, parts ...any) string {
	t.Helper()
	encoded, err := json.Marshal(parts)
	if err != nil {
		t.Fatal(err)
	}
	return format.EncodeBase64URL(encoded)
}

// delegateEntry is a §7.1 entry for a dSD-JWT+KB. Its delegate payload has a
// cnf key and one selectively disclosable audience hashed with sdAlg.
func delegateEntry(t *testing.T, sdAlg string) map[string]any {
	t.Helper()
	audience := delegateDisclosure(t, "salt-a", "https://verifier.example")
	digest, err := sdjwt.SDHash(audience, sdAlg)
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{
		"vct": "urn:example:mandate:1", "exp": 1794574800, "cnf": map[string]any{"jwk": delegateJWK},
		"audiences": []any{map[string]any{"...": digest}},
	}
	return map[string]any{
		"type": "delegate", "credential_ids": []any{"pid"}, "format": "dSD-JWT+KB",
		"delegate_payload_disclosure": delegateDisclosure(t, "salt-p", payload),
		"delegate_disclosures":        []any{audience},
	}
}

func TestDelegateFindings(t *testing.T) {
	supported := Checks{TransactionData: true, TransactionDataTypes: []string{DelegateTransactionDataType}, DelegateSDJWT: true}
	valid := delegateEntry(t, "sha-256")
	withoutCnf := delegateDisclosure(t, "salt-p", map[string]any{"vct": "urn:example:mandate:1"})
	for _, tt := range []struct {
		name  string
		entry map[string]any
		want  string
	}{
		{"a complete entry", valid, ""},
		{"a dSD-JWT entry without cnf", with(with(with(valid, "format", "dSD-JWT"), "delegate_payload_disclosure", withoutCnf), "delegate_disclosures", nil), ""},
		{"digests under the algorithm of the entry", with(delegateEntry(t, "sha-384"), "transaction_data_hashes_alg", []any{"sha-384"}), ""},
		// §7.1: "format": REQUIRED string containing either dSD-JWT or dSD-JWT+KB.
		{"no format", with(valid, "format", nil), "draft-ietf-oauth-delegate-sd-jwt-00 §7.1: format of transaction_data[0] must be dSD-JWT or dSD-JWT+KB"},
		{"an unknown format", with(valid, "format", "dc+sd-jwt"), "draft-ietf-oauth-delegate-sd-jwt-00 §7.1: format of transaction_data[0] must be dSD-JWT or dSD-JWT+KB"},
		{"no delegate_payload_disclosure", with(valid, "delegate_payload_disclosure", nil), "draft-ietf-oauth-delegate-sd-jwt-00 §7.1: transaction_data[0] has no delegate_payload_disclosure string"},
		// §5.1.3: the base64url encoding of [salt, JSON Object Payload].
		{"a payload disclosure that is not base64url JSON", with(valid, "delegate_payload_disclosure", "*"), "draft-ietf-oauth-delegate-sd-jwt-00 §5.1.3: transaction_data[0]: delegate_payload_disclosure does not decode"},
		{"a payload disclosure with a claim name", with(valid, "delegate_payload_disclosure", delegateDisclosure(t, "s", "mandate", map[string]any{})), "draft-ietf-oauth-delegate-sd-jwt-00 §5.1.3: transaction_data[0]: delegate_payload_disclosure must decode to [salt, JSON object]"},
		{"a payload that is not an object", with(valid, "delegate_payload_disclosure", delegateDisclosure(t, "s", "mandate")), "draft-ietf-oauth-delegate-sd-jwt-00 §5.1.3: transaction_data[0]: delegate_payload_disclosure must decode to [salt, JSON object]"},
		{"delegate_disclosures that is not an array of strings", with(valid, "delegate_disclosures", []any{1}), "draft-ietf-oauth-delegate-sd-jwt-00 §7.1: delegate_disclosures of transaction_data[0] must be an array of strings"},
		// §7.1: "The delegate payload MUST NOT contain any disclosures not
		// provided in delegate_disclosures."
		{"a digest without its disclosure", with(valid, "delegate_disclosures", nil), "draft-ietf-oauth-delegate-sd-jwt-00 §7.1: the Delegate Payload of transaction_data[0] contains the sha-256 digest"},
		{"digests under another algorithm", delegateEntry(t, "sha-384"), "draft-ietf-oauth-delegate-sd-jwt-00 §7.1: the Delegate Payload of transaction_data[0] contains the sha-256 digest"},
		{"a disclosure without a digest", with(valid, "delegate_disclosures", []any{valid["delegate_disclosures"].([]any)[0], delegateDisclosure(t, "s", "extra")}), "RFC 9901 §7.1: delegate_disclosures[1] of transaction_data[0] does not match any sha-256 digest in the Delegate Payload"},
		// §5.1.4: "If the typ is KB-SD-JWT+KB then the Delegate Payload MUST
		// include a cnf claim."
		{"a dSD-JWT+KB entry without cnf", with(with(valid, "delegate_payload_disclosure", withoutCnf), "delegate_disclosures", nil), "draft-ietf-oauth-delegate-sd-jwt-00 §5.1.4: transaction_data[0] asks for a dSD-JWT+KB, but its Delegate Payload has no cnf claim"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req := transactionDataRequest(transactionDataEntry(t, tt.entry))
			got := transactionDataFindings(supported, req, req.RequestPayload).Texts()
			if tt.want == "" {
				if len(got) > 0 {
					t.Errorf("findings = %q, want none", got)
				}
				return
			}
			if !slices.ContainsFunc(got, func(text string) bool { return strings.HasPrefix(text, tt.want) }) {
				t.Errorf("findings = %q, want one starting with %q", got, tt.want)
			}
			// OpenID4VP 1.0 §8.5: transaction data "not conforming to the
			// respective type definition" is invalid_transaction_data.
			if code := RefusalCode(supported, req); code != ErrorInvalidTransactionData {
				t.Errorf("RefusalCode = %q, want %q", code, ErrorInvalidTransactionData)
			}
		})
	}
}

// Without --delegate-sd-jwt, delegate is an ordinary transaction data type
// (ADR-0033). The wallet accepts it only from --transaction-data-type and
// skips the §7.1 checks.
func TestDelegateIsAnOrdinaryTypeWithoutDelegateSDJWT(t *testing.T) {
	req := transactionDataRequest(transactionDataEntry(t, with(delegateEntry(t, "sha-256"), "format", nil)))
	got := transactionDataFindings(Checks{TransactionData: true}, req, req.RequestPayload).Texts()
	want := []string{`OID4VP 1.0 §8.5: transaction_data[0] has the unsupported type "delegate"`}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("findings = %q, want %q", got, want)
	}
	listed := Checks{TransactionData: true, TransactionDataTypes: []string{DelegateTransactionDataType}}
	if got := transactionDataFindings(listed, req, req.RequestPayload).Texts(); len(got) > 0 {
		t.Errorf("findings = %q, want none for a listed type", got)
	}
}

func TestDelegatePayloadAndSummary(t *testing.T) {
	entry := NewTransactionData("", delegateEntry(t, "sha-256"))
	payload := entry.DelegatePayload()
	if want := []any{"https://verifier.example"}; !reflect.DeepEqual(payload["audiences"], want) {
		t.Errorf("audiences = %v, want %v", payload["audiences"], want)
	}
	// RFC 7638 thumbprint of delegateJWK.
	want := "Delegate this credential to the key aISfTcr9M_Zd09AXGAAeFxnLbFY6lBa87UN515wm5d4 until 2026-11-13 13:00 UTC"
	if got := DelegateSummary(payload); got != want {
		t.Errorf("DelegateSummary = %q, want %q", got, want)
	}
	if got := DelegateSummary(map[string]any{"vct": "urn:example:mandate:1"}); got != "Delegate this credential" {
		t.Errorf("DelegateSummary without cnf and exp = %q", got)
	}
	payment := NewTransactionData("", ts12Payment)
	if payment.DelegatePayload() != nil || DelegateSummary(payment.DelegatePayload()) != "" {
		t.Error("an entry of another type has a delegate payload or summary")
	}
}

func TestInspectDelegatePayload(t *testing.T) {
	digest := func(disclosure string) string {
		t.Helper()
		digest, err := sdjwt.SDHash(disclosure, "sha-384")
		if err != nil {
			t.Fatal(err)
		}
		return digest
	}
	first := delegateDisclosure(t, "salt-1", "https://one.example")
	second := delegateDisclosure(t, "salt-2", "https://two.example")
	payload := delegateDisclosure(t, "salt-p", map[string]any{"vct": "urn:example:mandate:1", "audiences": []any{
		map[string]any{"...": digest(first)}, map[string]any{"...": digest(second)},
	}})

	t.Run("complete", func(t *testing.T) {
		got, err := inspectDelegatePayload(payload, []string{first, second}, "sha-384")
		if err != nil {
			t.Fatal(err)
		}
		if len(got.MissingDigests) != 0 || len(got.Unreferenced) != 0 {
			t.Errorf("missing %v, unreferenced %v, want none", got.MissingDigests, got.Unreferenced)
		}
		if want := []any{"https://one.example", "https://two.example"}; !reflect.DeepEqual(got.Claims["audiences"], want) {
			t.Errorf("audiences = %v, want %v", got.Claims["audiences"], want)
		}
	})
	t.Run("digest without Disclosure", func(t *testing.T) {
		got, err := inspectDelegatePayload(payload, []string{first}, "sha-384")
		if err != nil {
			t.Fatal(err)
		}
		if want := []string{digest(second)}; !reflect.DeepEqual(got.MissingDigests, want) {
			t.Errorf("MissingDigests = %v, want %v", got.MissingDigests, want)
		}
		if want := []any{"https://one.example"}; !reflect.DeepEqual(got.Claims["audiences"], want) {
			t.Errorf("audiences = %v, want %v", got.Claims["audiences"], want)
		}
	})
	t.Run("Disclosure without digest", func(t *testing.T) {
		got, err := inspectDelegatePayload(payload, []string{first, second, delegateDisclosure(t, "salt-3", "extra")}, "sha-384")
		if err != nil {
			t.Fatal(err)
		}
		if want := []int{2}; !reflect.DeepEqual(got.Unreferenced, want) {
			t.Errorf("Unreferenced = %v, want %v", got.Unreferenced, want)
		}
	})
	for name, disclosure := range map[string]string{
		"not base64url":         "*",
		"object claim":          delegateDisclosure(t, "salt", "mandate", map[string]any{}),
		"array element of text": delegateDisclosure(t, "salt", "mandate"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := inspectDelegatePayload(disclosure, nil, "sha-256"); err == nil {
				t.Fatal("inspectDelegatePayload succeeded")
			}
		})
	}
}
