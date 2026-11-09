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
	"maps"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
)

const paymentRequest = `{"type":"custom",` +
	`"credentials":[{"format":"dc+sd-jwt","vct":"` + PIDVCT + `","claims":[["given_name"]]}],` +
	`"transaction_data":[{"type":"urn:eudi:sca:payment:1","credential_ids":["cred_0"],"transaction_data_hashes_alg":["sha-256"],` +
	`"payload":{"transaction_id":"T-1","payee":{"name":"Shop","id":"DE89370400440532013000"},"currency":"EUR","amount":12.5}}]}`

func acceptTransactionData(t *testing.T, w *wallet.Wallet) {
	t.Helper()
	enabled := true
	if err := w.UpdateConformance(wallet.ConformancePatch{TransactionData: &enabled}); err != nil {
		t.Fatal(err)
	}
}

// OpenID4VP 1.0 Appendix B.3.3.1: the wallet signs the hash of each
// transaction_data string into the key binding JWT, and the verifier checks it.
func TestTheVerifierChecksTransactionDataHashes(t *testing.T) {
	w := customTestWallet(t)
	acceptTransactionData(t, w)
	_, ts := serveDemoStack(t, w)

	id := createCustom(t, ts, paymentRequest)
	status := getJSONFrom(t, ts.URL+"/verifier/api/requests/"+id)
	if status["status"] != "verified" {
		t.Fatalf("status = %v, want verified (error %v, checks %v)", status["status"], status["error"], status["checks"])
	}
	names := strings.Join(checkNames(status), "\n")
	for _, want := range []string{"transaction_data_hashes match the request", "the key binding JWT carries the claims of EUDI TS12 §3.6", "every transaction is authorized by a presentation"} {
		if !strings.Contains(names, want) {
			t.Errorf("checks %s, want %q", names, want)
		}
	}
}

// §8.4: "The Wallet that received the transaction_data parameter in the
// request MUST include a representation or reference to the data in the
// respective Credential presentation." A debug wallet without support
// presents without it, and the verifier refuses the response.
func TestTheVerifierRefusesAPresentationWithoutTransactionData(t *testing.T) {
	w := customTestWallet(t)
	_, ts := serveDemoStack(t, w)

	id := createCustom(t, ts, paymentRequest)
	status := getJSONFrom(t, ts.URL+"/verifier/api/requests/"+id)
	if status["status"] != "failed" || !strings.Contains(status["error"].(string), "no key binding JWT carries the hash of transaction_data[0]") {
		t.Fatalf("status = %v, error %v, want the missing hash refused", status["status"], status["error"])
	}
}

func TestTransactionDataHashChecks(t *testing.T) {
	entries, err := encodeTransactionData([]map[string]any{
		{"type": "urn:example:sign", "credential_ids": []any{"pid"}, "transaction_data_hashes_alg": []any{"sha-384"}},
		{"type": "urn:example:sign", "credential_ids": []any{"pid"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	hash := func(i int, alg string) string {
		h, _ := sdjwt.SDHash(entries[i].Raw, alg)
		return h
	}
	for _, tt := range []struct {
		name string
		kb   map[string]any
		want string
	}{
		{"the requested algorithm", map[string]any{"transaction_data_hashes": []any{hash(0, "sha-384")}, "transaction_data_hashes_alg": "sha-384"}, ""},
		{"the default algorithm", map[string]any{"transaction_data_hashes": []any{hash(1, "sha-256")}}, ""},
		// Appendix B.3.3.1: transaction_data_hashes_alg is "REQUIRED when
		// this parameter was present in the transaction_data request
		// parameter".
		{"no algorithm claim", map[string]any{"transaction_data_hashes": []any{hash(0, "sha-256")}}, "the key binding JWT has none"},
		{"an algorithm the entry does not accept", map[string]any{"transaction_data_hashes": []any{hash(1, "sha-384")}, "transaction_data_hashes_alg": "sha-384"}, "the hash must use sha-256"},
		{"a hash of another string", map[string]any{"transaction_data_hashes": []any{"AAAA"}}, "matches no transaction_data entry"},
		{"an algorithm that is not a string", map[string]any{"transaction_data_hashes": []any{hash(0, "sha-256")}, "transaction_data_hashes_alg": 256}, "must be a string"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := checkTransactionDataHashes(entries, "pid", tt.kb, make([]bool, len(entries)))
			switch {
			case tt.want == "" && err != nil:
				t.Errorf("err = %v, want none", err)
			case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
	if _, err := encodeTransactionData([]map[string]any{nil}); err == nil {
		t.Error("a null entry was accepted")
	}
}

// EUDI TS12 v1.0.1 §3.6 makes jti, response_mode and amr REQUIRED in the key
// binding JWT.
func TestTS12ClaimChecks(t *testing.T) {
	amr := []any{map[string]any{"knowledge": "pin_6_or_more_digits"}, map[string]any{"possession": "key_in_local_native_wscd"}}
	valid := map[string]any{"jti": "j", "response_mode": "direct_post.jwt", "amr": amr}
	without := func(claim string) map[string]any {
		out := maps.Clone(valid)
		delete(out, claim)
		return out
	}
	for _, tt := range []struct {
		name string
		kb   map[string]any
		want string
	}{
		{"all claims", valid, ""},
		{"no jti", without("jti"), "has no jti"},
		{"no response_mode", without("response_mode"), "the response_mode <nil>"},
		{"one amr category", map[string]any{"jti": "j", "response_mode": "direct_post.jwt", "amr": amr[:1]}, "needs at least 2 authentication categories, and it has 1"},
		{"an unknown amr category", map[string]any{"jti": "j", "response_mode": "direct_post.jwt", "amr": []any{map[string]any{"foo": "x"}, amr[1]}}, "has foo: x"},
		{"an unknown amr method", map[string]any{"jti": "j", "response_mode": "direct_post.jwt", "amr": []any{map[string]any{"knowledge": "pin"}, amr[1]}}, "has knowledge: pin"},
		{"an amr object with two categories", map[string]any{"jti": "j", "response_mode": "direct_post.jwt", "amr": []any{map[string]any{"knowledge": "pattern", "inherence": "face_device"}}}, "with one authentication category"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := checkTS12Claims(tt.kb, "direct_post.jwt")
			switch {
			case tt.want == "" && err != nil:
				t.Errorf("err = %v, want none", err)
			case tt.want != "" && (err == nil || !strings.Contains(err.Error(), tt.want)):
				t.Errorf("err = %v, want %q", err, tt.want)
			}
		})
	}
}

// OpenID4VP 1.0 §5.1: "the Wallet MUST use only one of the referenced
// Credentials for transaction authorization." Only the entries covered by a
// key binding JWT decide whether it needs the TS12 claims.
func TestTransactionDataHashesPerPresentation(t *testing.T) {
	entries, err := encodeTransactionData([]map[string]any{
		{"type": "urn:eudi:sca:payment:1", "credential_ids": []any{"a", "b"}},
		{"type": "urn:example:sign", "credential_ids": []any{"b"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	hash := func(i int) string {
		h, _ := sdjwt.SDHash(entries[i].Raw, "sha-256")
		return h
	}
	bound := make([]bool, len(entries))
	covered, err := checkTransactionDataHashes(entries, "b", map[string]any{"transaction_data_hashes": []any{hash(1)}}, bound)
	if err != nil || hasTS12Type(covered) {
		t.Errorf("covered = %v, %v, want only the custom entry", covered, err)
	}
	if _, err := checkTransactionDataHashes(entries, "a", map[string]any{"transaction_data_hashes": []any{hash(0)}}, bound); err != nil {
		t.Fatal(err)
	}
	if _, err := checkTransactionDataHashes(entries, "b", map[string]any{"transaction_data_hashes": []any{hash(0)}}, bound); err == nil || !strings.Contains(err.Error(), "already authorized by another presentation") {
		t.Errorf("err = %v, want the second authorization refused", err)
	}
}

// With multiple: true one query gets several presentations (OpenID4VP 1.0
// §6.1). Only one of them may carry the hash of an entry (§5.1).
func TestTransactionDataHashesAcrossPresentationsOfOneQuery(t *testing.T) {
	entries, err := encodeTransactionData([]map[string]any{
		{"type": "urn:example:sign", "credential_ids": []any{"pid"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	hash, _ := sdjwt.SDHash(entries[0].Raw, "sha-256")
	kb := map[string]any{"transaction_data_hashes": []any{hash}}
	bound := make([]bool, len(entries))
	if _, err := checkTransactionDataHashes(entries, "pid", kb, bound); err != nil {
		t.Fatal(err)
	}
	if _, err := checkTransactionDataHashes(entries, "pid", kb, bound); err == nil || !strings.Contains(err.Error(), "already authorized by another presentation") {
		t.Errorf("err = %v, want the second presentation refused", err)
	}
}
