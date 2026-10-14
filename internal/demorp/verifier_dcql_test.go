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
	"strings"
	"testing"
)

func checkNames(status map[string]any) []string {
	var names []string
	checks, _ := status["checks"].([]any)
	for _, c := range checks {
		entry, _ := c.(map[string]any)
		name, _ := entry["name"].(string)
		names = append(names, name)
	}
	return names
}

// OpenID4VP 1.0 §6.4.1: the wallet returns the first claim set it can
// satisfy, and the verifier accepts it.
func TestAWrittenQueryWithClaimSetsIsVerified(t *testing.T) {
	w := customTestWallet(t)
	_, ts := serveDemoStack(t, w)

	query := `{"credentials":[{"id":"pid","format":"dc+sd-jwt","meta":{"vct_values":["` + PIDVCT + `"]},` +
		`"claims":[{"id":"a","path":["given_name"]},{"id":"b","path":["family_name"]},{"id":"c","path":["birthdate"]}],` +
		`"claim_sets":[["a","b"],["a","c"]]}]}`
	id := createCustom(t, ts, `{"type":"custom","dcql_query":`+query+`}`)
	status := getJSONFrom(t, ts.URL+"/verifier/api/requests/"+id)
	if status["status"] != "verified" {
		t.Fatalf("status = %v, want verified (error %v, checks %v)", status["status"], status["error"], status["checks"])
	}
	if names := strings.Join(checkNames(status), "\n"); !strings.Contains(names, "claim set 1 of 2 was disclosed (a, b)") {
		t.Errorf("checks %s, want the first claim set", names)
	}
}

// OpenID4VP 1.0 §6.4.2: a required credential set is satisfied by one of its
// options.
func TestAWrittenQueryWithCredentialSetsIsVerified(t *testing.T) {
	w := customTestWallet(t)
	_, ts := serveDemoStack(t, w)

	query := `{"credentials":[` +
		`{"id":"sdjwt","format":"dc+sd-jwt","meta":{"vct_values":["` + PIDVCT + `"]},"claims":[{"path":["given_name"]}]},` +
		`{"id":"mdoc","format":"mso_mdoc","meta":{"doctype_value":"` + PIDDocType + `"},"claims":[{"path":["` + PIDDocType + `","given_name"]}]}],` +
		`"credential_sets":[{"options":[["sdjwt"],["mdoc"]]}]}`
	id := createCustom(t, ts, `{"type":"custom","dcql_query":`+query+`}`)
	status := getJSONFrom(t, ts.URL+"/verifier/api/requests/"+id)
	if status["status"] != "verified" {
		t.Fatalf("status = %v, want verified (error %v, checks %v)", status["status"], status["error"], status["checks"])
	}
}

func TestAnInvalidWrittenQueryIsRefused(t *testing.T) {
	w := customTestWallet(t)
	_, ts := serveDemoStack(t, w)

	created := postJSONTo(t, ts.URL+"/verifier/api/requests", `{"type":"custom","dcql_query":{"credentials":[]}}`)
	if msg, _ := created["error"].(string); !strings.Contains(msg, "the DCQL query is invalid") {
		t.Fatalf("response %v, want the invalid query refused", created)
	}
}

func TestClaimSetsAndValuesDecideWhetherClaimsMatch(t *testing.T) {
	presented := map[string]any{"given_name": "Erika", "birthdate": "1964-08-12", "age": float64(61)}
	q := credentialQuery{
		claims: []claimQuery{
			{id: "a", path: []any{"given_name"}},
			{id: "b", path: []any{"family_name"}},
			{id: "c", path: []any{"birthdate"}},
		},
		claimSets: [][]string{{"a", "b"}, {"a", "c"}},
	}
	if name, err := q.checkClaims(presented, ""); err != nil || name != "claim set 2 of 2 was disclosed (a, c)" {
		t.Errorf("checkClaims = %q, %v, want the second claim set", name, err)
	}
	q.claimSets = [][]string{{"a", "b"}}
	if _, err := q.checkClaims(presented, ""); err == nil || !strings.Contains(err.Error(), "[a, b]") {
		t.Errorf("checkClaims error %v, want the incomplete claim set named", err)
	}

	// OpenID4VP 1.0 §6.3: a claim with values matches only one of them.
	age := credentialQuery{claims: []claimQuery{{path: []any{"age"}, values: []any{float64(61), float64(62)}}}}
	if _, err := age.checkClaims(presented, ""); err != nil {
		t.Errorf("a listed value: %v", err)
	}
	age.claims[0].values = []any{float64(18)}
	if _, err := age.checkClaims(presented, ""); err == nil {
		t.Error("a value outside the list matched")
	}
}
