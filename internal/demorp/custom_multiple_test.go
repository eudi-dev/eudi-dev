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
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/wallet"
)

// The EUDI PID and the German PID that extends it both answer a base PID query, in
// both formats.
func twoPIDWallet(t *testing.T) *wallet.Wallet {
	t.Helper()
	holderKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	issuerKey, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	w := wallet.New(holderKey, issuerKey, true)
	if err := w.GenerateProtectedDefaults(); err != nil {
		t.Fatalf("generating the PID baseline: %v", err)
	}
	return w
}

func customAnswers(t *testing.T, status map[string]any) []any {
	t.Helper()
	if status["status"] != "verified" {
		t.Fatalf("status = %v, want verified (error %v, checks %v)", status["status"], status["error"], status["checks"])
	}
	claims, _ := status["claims"].(map[string]any)
	answers, ok := claims["cred_0"].([]any)
	if !ok {
		t.Fatalf("cred_0 = %v, want an array of claim sets", claims["cred_0"])
	}
	return answers
}

func TestVerifierCustomRequestMultipleSDJWT(t *testing.T) {
	_, ts := serveDemoStack(t, twoPIDWallet(t))

	id := createCustom(t, ts, `{"type":"custom","credentials":[{"format":"dc+sd-jwt","vct":"`+PIDVCT+`","claims":[["given_name"]],"multiple":true}]}`)
	answers := customAnswers(t, getJSONFrom(t, ts.URL+"/verifier/api/requests/"+id))
	if len(answers) != 2 {
		t.Fatalf("verified %d presentations, want 2", len(answers))
	}
	for i, a := range answers {
		if claims, _ := a.(map[string]any); claims["given_name"] == nil {
			t.Errorf("presentation %d discloses %v, want given_name", i, a)
		}
	}
}

func TestVerifierCustomRequestMultipleMDoc(t *testing.T) {
	_, ts := serveDemoStack(t, twoPIDWallet(t))

	id := createCustom(t, ts, `{"type":"custom","credentials":[{"format":"mso_mdoc","doctype":"`+PIDDocType+`","claims":[["`+PIDDocType+`","given_name"]],"multiple":true}]}`)
	if answers := customAnswers(t, getJSONFrom(t, ts.URL+"/verifier/api/requests/"+id)); len(answers) != 2 {
		t.Fatalf("verified %d DeviceResponses, want 2", len(answers))
	}
}

// requestDCQL decodes the dcql_query of a request's signed request object.
func requestDCQL(t *testing.T, d *DemoRP, id string) map[string]any {
	t.Helper()
	d.mu.Lock()
	jar := d.requests[id].requestObject
	d.mu.Unlock()
	parts := strings.Split(jar, ".")
	if len(parts) != 3 {
		t.Fatalf("request object %q is not a compact JWS", jar)
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	var claims struct {
		DCQL map[string]any `json:"dcql_query"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	return claims.DCQL
}

func queryByID(t *testing.T, dcql map[string]any, id string) map[string]any {
	t.Helper()
	for _, q := range dcql["credentials"].([]any) {
		if q := q.(map[string]any); q["id"] == id {
			return q
		}
	}
	t.Fatalf("no credential query %q in %v", id, dcql)
	return nil
}

// The signed request object carries the flag, so the wallet sees it.
func TestVerifierCustomRequestMultipleReachesTheQuery(t *testing.T) {
	d, ts := serveDemoStack(t, twoPIDWallet(t))

	created := postJSONTo(t, ts.URL+"/verifier/api/requests", `{"type":"custom","credentials":[{"format":"dc+sd-jwt","vct":"`+PIDVCT+`","multiple":true},{"format":"dc+sd-jwt","vct":"`+PIDVCT+`"}]}`)
	dcql := requestDCQL(t, d, created["id"].(string))
	if queryByID(t, dcql, "cred_0")["multiple"] != true {
		t.Errorf("cred_0 = %v, want multiple true", queryByID(t, dcql, "cred_0"))
	}
	if m, present := queryByID(t, dcql, "cred_1")["multiple"]; present {
		t.Errorf("cred_1 carries multiple %v, want it absent", m)
	}
}

// verifiedAnswers returns the verified claim sets of a multiple query.
func verifiedAnswers(t *testing.T, status map[string]any, queryID string) []any {
	t.Helper()
	if status["status"] != "verified" {
		t.Fatalf("status = %v, want verified (error %v, checks %v)", status["status"], status["error"], status["checks"])
	}
	claims, _ := status["claims"].(map[string]any)
	answers, ok := claims[queryID].([]any)
	if !ok {
		t.Fatalf("claims = %v, want a list under %s", claims, queryID)
	}
	return answers
}

func TestVerifierPIDRequestMultiple(t *testing.T) {
	_, ts := serveDemoStack(t, twoPIDWallet(t))

	id := createCustom(t, ts, `{"type":"pid","format":"sd-jwt","multiple":true}`)
	pids := verifiedAnswers(t, getJSONFrom(t, ts.URL+"/verifier/api/requests/"+id), "pid")
	if len(pids) != 2 {
		t.Fatalf("verified %d PIDs, want 2", len(pids))
	}
	names := map[any]bool{}
	for _, p := range pids {
		names[p.(map[string]any)["given_name"]] = true
	}
	if len(names) != 2 {
		t.Errorf("both PIDs disclose the same given_name: %v", pids)
	}
}

func TestVerifierTicketRequestMultiple(t *testing.T) {
	w := twoPIDWallet(t)
	_, ts := serveDemoStack(t, w)
	redeemDemoTicket(t, w, ts, "")
	redeemDemoTicket(t, w, ts, "")

	id := createCustom(t, ts, `{"type":"ticket","multiple":true}`)
	if tickets := verifiedAnswers(t, getJSONFrom(t, ts.URL+"/verifier/api/requests/"+id), "ticket"); len(tickets) != 2 {
		t.Fatalf("verified %d tickets, want 2", len(tickets))
	}
}

// Every query carries multiple inside the credential sets, and the wallet answers
// the PID and the ticket with every matching credential.
func TestVerifierPIDAndTicketRequestMultiple(t *testing.T) {
	w := twoPIDWallet(t)
	d, ts := serveDemoStack(t, w)
	redeemDemoTicket(t, w, ts, "")
	redeemDemoTicket(t, w, ts, "")

	for _, mode := range []string{"combined", "optional"} {
		created := postJSONTo(t, ts.URL+"/verifier/api/requests", `{"type":"pid","format":"sd-jwt","ticket":"`+mode+`","multiple":true}`)
		dcql := requestDCQL(t, d, created["id"].(string))
		if _, ok := dcql["credential_sets"]; !ok {
			t.Fatalf("%s: no credential_sets in %v", mode, dcql)
		}
		for _, id := range []string{"pid", "ticket"} {
			if queryByID(t, dcql, id)["multiple"] != true {
				t.Errorf("%s: query %s = %v, want multiple true", mode, id, queryByID(t, dcql, id))
			}
		}

		driveWallet(t, ts, created["wallet_url"].(string))
		status := getJSONFrom(t, ts.URL+"/verifier/api/requests/"+created["transaction_id"].(string))
		if pids := verifiedAnswers(t, status, "pid"); len(pids) != 2 {
			t.Errorf("%s: verified %d PIDs, want 2", mode, len(pids))
		}
		if tickets := verifiedAnswers(t, status, "ticket"); len(tickets) != 2 {
			t.Errorf("%s: verified %d tickets, want 2", mode, len(tickets))
		}
	}
}

// OpenID4VP 1.0 §8.1: without multiple the array holds one presentation.
func TestVerifierCustomRequestRefusesSeveralPresentationsWithoutMultiple(t *testing.T) {
	d := New(twoPIDWallet(t), func() string { return "https://verifier.example" })
	req := &requestState{queries: []credentialQuery{{id: "cred_0", format: "dc+sd-jwt", vct: PIDVCT, resultKey: "cred_0"}}}

	_, checks, err := d.verifyPresentation(req, `{"cred_0":["a~","b~"]}`)
	if err == nil || !strings.Contains(err.Error(), "expected 1 presentation, got 2") {
		t.Fatalf("error = %v, checks %v", err, checks)
	}
}
