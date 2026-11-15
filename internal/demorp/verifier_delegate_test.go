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

package demorp

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/experimental"
	"github.com/eudi-dev/eudi-dev/v3/internal/format"
	"github.com/eudi-dev/eudi-dev/v3/internal/keys"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
	"github.com/eudi-dev/eudi-dev/v3/pkg/sdjwt/delegate"
)

const delegationRequest = `{"type":"custom",` +
	`"credentials":[{"format":"dc+sd-jwt","vct":"` + PIDVCT + `","claims":[["given_name"]]}],` +
	`"transaction_data":[{"type":"delegate","credential_ids":["cred_0"],"format":"dSD-JWT+KB",` +
	`"delegate_payload":{"purpose":"Order office supplies","max_amount":250}}]}`

func delegatingWallet(t *testing.T) *wallet.Wallet {
	t.Helper()
	w := customTestWallet(t)
	on := true
	if err := w.UpdateConformance(wallet.ConformancePatch{Patch: experimental.Patch{TransactionData: &on, DelegateSDJWT: &on}}); err != nil {
		t.Fatal(err)
	}
	return w
}

// draft-ietf-oauth-delegate-sd-jwt-00 §7.1: the wallet answers a delegate
// entry with a dSD-JWT, and §6 tells the verifier how to check the chain.
func TestTheVerifierChecksADelegateSDJWT(t *testing.T) {
	d, ts := serveDemoStack(t, delegatingWallet(t))

	id := createCustom(t, ts, delegationRequest)
	status := getJSONFrom(t, ts.URL+"/verifier/api/requests/"+id)
	if status["status"] != "verified" {
		t.Fatalf("status = %v, want verified (error %v, checks %v)", status["status"], status["error"], status["checks"])
	}
	names := strings.Join(checkNames(status), "\n")
	for _, want := range []string{
		"Delegate SD-JWT chain verifies (draft-ietf-oauth-delegate-sd-jwt-00 §6)",
		"the KB-SD-JWT carries each requested Delegate Payload",
		"transaction_data_hashes match the request",
		"every transaction is authorized by a presentation",
	} {
		if !strings.Contains(names, want) {
			t.Errorf("checks %s, want %q", names, want)
		}
	}
	if presentation, _ := status["presentation"].(string); !delegate.IsChain(presentation) {
		t.Errorf("presentation = %q, want a Delegate SD-JWT", presentation)
	}

	delegations, _ := status["delegations"].(map[string]any)
	delegation, _ := delegations["cred_0"].(map[string]any)
	own, _ := keys.PublicJWK(&d.delegateKey.PublicKey)
	thumbprint, _ := keys.Thumbprint(own)
	if delegation["format"] != delegate.FormatDSDJWT || delegation["format for the Delegate Holder"] != delegate.FormatDSDJWTKB || delegation["delegate key"] != format.EncodeBase64URL(thumbprint) || delegation["key holder"] != "this verifier" {
		t.Errorf("delegation = %v, want a dSD-JWT for the key of the verifier", delegation)
	}
	payload, _ := delegation["payload"].(map[string]any)
	if payload["purpose"] != "Order office supplies" || payload["max_amount"] != 250.0 {
		t.Errorf("payload = %v, want the claims of the request", payload)
	}
	exp, _ := payload["exp"].(float64)
	if left := time.Until(time.Unix(int64(exp), 0)); left < delegateLifetime-time.Minute || left > delegateLifetime {
		t.Errorf("exp is %s away, want %s", left, delegateLifetime)
	}
}

// The claims of a multiple query are a list under the query ID, so each
// delegation gets the key of its presentation.
func TestTheVerifierKeysTheDelegationOfEachPresentation(t *testing.T) {
	_, ts := serveDemoStack(t, delegatingWallet(t))

	request := strings.Replace(delegationRequest, `"claims":[["given_name"]]`, `"claims":[["given_name"]],"multiple":true`, 1)
	status := getJSONFrom(t, ts.URL+"/verifier/api/requests/"+createCustom(t, ts, request))
	if status["status"] != "verified" {
		t.Fatalf("status = %v, want verified (error %v, checks %v)", status["status"], status["error"], status["checks"])
	}
	delegations, _ := status["delegations"].(map[string]any)
	if len(delegations) != 1 || delegations["cred_0[0]"] == nil {
		t.Errorf("delegations = %v, want the delegation of cred_0[0]", delegations)
	}
}

// A disclosed claim named delegation stays a claim. The result of a Delegate
// SD-JWT goes into its own member, so it never replaces the claim.
func TestTheVerifierKeepsAClaimNamedDelegation(t *testing.T) {
	claim := map[string]any{"role": "deputy"}
	const request = `{"type":"custom",` +
		`"credentials":[{"format":"dc+sd-jwt","vct":"` + PIDVCT + `","claims":[["given_name"],["delegation"]]}]`
	for _, tc := range []struct {
		name     string
		features bool
		body     string
	}{
		{"features off", false, request + `}`},
		{"Delegate SD-JWT", true, request + `,"transaction_data":[{"type":"delegate","credential_ids":["cred_0"],"format":"dSD-JWT+KB","delegate_payload":{"purpose":"Order office supplies"}}]}`},
	} {
		w := customTestWallet(t)
		if err := w.GenerateDefaultCredentials(map[string]any{"delegation": claim}, ""); err != nil {
			t.Fatal(err)
		}
		if tc.features {
			if err := w.UpdateConformance(wallet.ConformancePatch{Patch: experimental.Patch{TransactionData: &tc.features, DelegateSDJWT: &tc.features}}); err != nil {
				t.Fatal(err)
			}
		}
		_, ts := serveDemoStack(t, w)

		status := getJSONFrom(t, ts.URL+"/verifier/api/requests/"+createCustom(t, ts, tc.body))
		if status["status"] != "verified" {
			t.Fatalf("%s: status = %v, want verified (error %v)", tc.name, status["status"], status["error"])
		}
		claims, _ := status["claims"].(map[string]any)
		answer, _ := claims["cred_0"].(map[string]any)
		if got, _ := json.Marshal(answer["delegation"]); string(got) != `{"role":"deputy"}` {
			t.Errorf("%s: claim delegation = %s, want the disclosed value", tc.name, got)
		}
		delegations, hasDelegations := status["delegations"].(map[string]any)
		if hasDelegations != tc.features {
			t.Errorf("%s: delegations = %v, want them only for a Delegate SD-JWT", tc.name, status["delegations"])
		}
		if tc.features && delegations["cred_0"] == nil {
			t.Errorf("%s: delegations = %v, want the delegation of cred_0", tc.name, delegations)
		}
	}
}

// The verifier warns when the request asked a query for a delegation and the
// wallet answered with an SD-JWT+KB.
func TestTheVerifierWarnsWhenTheWalletDelegatesNothing(t *testing.T) {
	entry := oid4vp.TransactionData{Type: oid4vp.DelegateTransactionDataType, CredentialIDs: []string{"cred_0"},
		Data: map[string]any{"delegate_payload_disclosure": "WyJzYWx0Iix7fV0"}}
	req := &requestState{transactionData: []oid4vp.TransactionData{entry}}
	for _, tc := range []struct {
		query string
		want  int
	}{{"cred_0", 1}, {"cred_1", 0}} {
		log := &checklist{}
		warnWithoutDelegation(req, credentialQuery{id: tc.query}, "", log)
		if len(log.entries) != tc.want {
			t.Fatalf("%s: checks = %v, want %d", tc.query, log.entries, tc.want)
		}
		if tc.want == 1 && log.entries[0]["warning"] != "the wallet answered with an SD-JWT+KB and did not delegate the credential" {
			t.Errorf("%s: check = %v, want a warning about the missing delegation", tc.query, log.entries[0])
		}
	}
}

// Delegate SD-JWT has an effect only with transaction data on. Otherwise the
// verifier sends a delegate entry as given and checks the answer like any
// other SD-JWT+KB.
func TestTheVerifierSendsADelegateEntryAsGivenWhileDelegateSDJWTHasNoEffect(t *testing.T) {
	on, off := true, false
	for _, patch := range []experimental.Patch{
		{TransactionData: &on, DelegateSDJWT: &off},
		{TransactionData: &off, DelegateSDJWT: &on},
	} {
		w := customTestWallet(t)
		if err := w.UpdateConformance(wallet.ConformancePatch{Patch: patch}); err != nil {
			t.Fatal(err)
		}
		d, ts := serveDemoStack(t, w)
		settings := w.Conformance().Settings

		id := createCustom(t, ts, delegationRequest)
		status := getJSONFrom(t, ts.URL+"/verifier/api/requests/"+id)
		if !slices.Contains(checkNames(status), "cred_0: presentation parses as SD-JWT") {
			t.Errorf("%+v: checks = %v, want the SD-JWT+KB parsed", settings, checkNames(status))
		}
		encoded, _ := json.Marshal(status["checks"])
		if strings.Contains(string(encoded), "delegat") {
			t.Errorf("%+v: checks = %s, want no delegation checks", settings, encoded)
		}
		var entries []oid4vp.TransactionData
		d.mu.Lock()
		for _, req := range d.requests {
			if req.transactionID == id {
				entries = req.transactionData
			}
		}
		d.mu.Unlock()
		if len(entries) != 1 {
			t.Fatalf("%+v: transaction data = %v, want one entry", settings, entries)
		}
		sent := entries[0].Data
		if _, encodedPayload := sent["delegate_payload_disclosure"]; encodedPayload || sent["delegate_payload"] == nil {
			t.Errorf("%+v: entry = %v, want the delegate_payload as given", settings, sent)
		}
	}
}

func TestADelegatePayloadKeepsItsOwnKeyAndExpiry(t *testing.T) {
	d, _, _ := newDemoRP(t)
	jwk := map[string]any{"kty": "EC", "crv": "P-256", "x": "x", "y": "y"}
	entries := []map[string]any{
		{"type": "delegate", "delegate_payload": map[string]any{"cnf": map[string]any{"jwk": jwk}, "exp": 4102444800.0}},
		{"type": "delegate", "delegate_payload_disclosure": "given", "delegate_payload": map[string]any{"a": 1.0}},
		{"type": "urn:example:sign", "delegate_payload": map[string]any{"a": 1.0}},
	}
	if err := d.encodeDelegatePayloads(entries); err != nil {
		t.Fatal(err)
	}
	disclosure, _ := entries[0]["delegate_payload_disclosure"].(string)
	decoded, err := format.DecodeBase64URL(disclosure)
	if err != nil {
		t.Fatal(err)
	}
	var elements []any
	if err := json.Unmarshal(decoded, &elements); err != nil || len(elements) != 2 {
		t.Fatalf("disclosure = %s, want [salt, payload] (%v)", decoded, err)
	}
	payload, _ := elements[1].(map[string]any)
	if cnf, _ := payload["cnf"].(map[string]any); cnf["jwk"].(map[string]any)["x"] != "x" || payload["exp"] != 4102444800.0 {
		t.Errorf("payload = %v, want the cnf and exp of the entry", payload)
	}
	if _, kept := entries[0]["delegate_payload"]; kept {
		t.Error("the encoded entry still has delegate_payload")
	}
	if entries[1]["delegate_payload_disclosure"] != "given" || entries[1]["delegate_payload"] == nil {
		t.Errorf("entry with a disclosure = %v, want it unchanged", entries[1])
	}
	if _, encoded := entries[2]["delegate_payload_disclosure"]; encoded {
		t.Error("an entry of another type got a delegate_payload_disclosure")
	}
}
