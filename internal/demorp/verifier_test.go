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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/jwe"
)

// transactionOf is the transaction_id that the page creating the request got.
func transactionOf(t *testing.T, d *DemoRP, requestID string) string {
	t.Helper()
	d.mu.Lock()
	defer d.mu.Unlock()
	req, ok := d.requests[requestID]
	if !ok {
		t.Fatalf("no request %s", requestID)
	}
	return req.transactionID
}

// requestStatus reads the result as the page that created the request does.
func requestStatus(t *testing.T, d *DemoRP, requestID string) (int, map[string]any) {
	t.Helper()
	return doJSON(t, d.VerifierHandler(), "GET", "/api/requests/"+transactionOf(t, d, requestID), "", nil)
}

// postResponseForm posts form fields to the response URI of the request.
func postResponseForm(t *testing.T, d *DemoRP, requestID string, form url.Values) (int, map[string]any) {
	t.Helper()
	return doJSON(t, d.VerifierHandler(), "POST", "/response/"+requestID, form.Encode(),
		map[string]string{"Content-Type": "application/x-www-form-urlencoded"})
}

// OpenID4VP 1.0 §8.2 requires "a fresh, cryptographically random value" in
// the redirect_uri, which "is used to ensure only the receiver of the
// redirect can fetch and process the Authorization Response". The request id
// is in the QR code, so it reads no result. The transaction_id of the
// creating page and the response_code of the redirect do (§13.3).
func TestOnlyTheTransactionIDAndTheResponseCodeReadTheResult(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	h := d.VerifierHandler()
	id, params := startVerification(t, h, "ticket")

	if code, doc := doJSON(t, h, "GET", "/api/requests/"+id, "", nil); code != http.StatusNotFound {
		t.Errorf("reading the result with the request id: %d %v, want 404", code, doc)
	}
	if code, doc := requestStatus(t, d, id); code != http.StatusOK || doc["status"] != "pending" {
		t.Errorf("reading the result with the transaction_id: %d %v, want 200 pending", code, doc)
	}

	presentation := presentTicket(t, d, holderKey, params.Get("client_id"), params.Get("nonce"))
	code, answer := postPresentationResponse(t, h, id, id, "ticket", presentation)
	if code != http.StatusOK {
		t.Fatalf("posting a response: %d %v", code, answer)
	}
	redirect, err := url.Parse(answer["redirect_uri"].(string))
	if err != nil {
		t.Fatal(err)
	}
	responseCode := redirect.Query().Get("response_code")
	if len(responseCode) < 32 || responseCode == id || responseCode == transactionOf(t, d, id) {
		t.Fatalf("redirect_uri %s carries no fresh response_code", redirect)
	}
	if code, doc := doJSON(t, h, "GET", "/api/requests/"+responseCode, "", nil); code != http.StatusOK || doc["status"] != "verified" {
		t.Errorf("reading the result with the response_code: %d %v, want 200 verified", code, doc)
	}
}

// The wallet redirects to a fresh page. The result names the page's choice,
// so the page shows the controls of the request it answers.
func TestTheResultNamesThePagesChoice(t *testing.T) {
	d, _, _ := newDemoRP(t)
	id, _ := startVerificationWith(t, d.VerifierHandler(), `{"type":"pid","format":"sd-jwt","vct":"urn:eudi:pid:de:1","multiple":true}`)

	_, doc := requestStatus(t, d, id)
	want := map[string]any{"type": "pid", "format": "sd-jwt", "vct": "urn:eudi:pid:de:1", "multiple": true}
	if got, _ := doc["request"].(map[string]any); !reflect.DeepEqual(got, want) {
		t.Errorf("request = %v, want %v", doc["request"], want)
	}
}

// OpenID4VP 1.0 §8.3.1 lets a wallet that cannot encrypt "send an error
// response without encryption as per Section 8.2", and §8.2 answers 200 after
// "the Authorization Response or Authorization Error Response" is processed.
func TestVerifierProcessesAnUnencryptedErrorResponse(t *testing.T) {
	d, _, _ := newDemoRP(t)
	id, _ := startVerification(t, d.VerifierHandler(), "ticket")

	if code, doc := postResponseForm(t, d, id, url.Values{"error": {"access_denied"}, "state": {"another-request"}}); code != http.StatusBadRequest {
		t.Errorf("an error response for another request: %d %v, want 400", code, doc)
	}

	id, _ = startVerification(t, d.VerifierHandler(), "ticket")
	form := url.Values{"error": {"access_denied"}, "error_description": {"the user declined"}, "state": {id}}
	if code, doc := postResponseForm(t, d, id, form); code != http.StatusOK {
		t.Fatalf("an error response: %d %v, want 200", code, doc)
	}
	_, status := requestStatus(t, d, id)
	if status["status"] != "failed" || !strings.Contains(status["error"].(string), "access_denied the user declined") {
		t.Errorf("result = %v, want the failure with the wallet's error", status)
	}
}

// postVPToken posts an encrypted response with the vp_token for the request.
func postVPToken(t *testing.T, d *DemoRP, requestID string, vpToken any) (int, map[string]any) {
	t.Helper()
	pub, kid := responseEncryptionKey(t, fetchRequestObject(t, d.VerifierHandler(), "/request/"+requestID))
	body, err := json.Marshal(map[string]any{"vp_token": vpToken, "state": requestID})
	if err != nil {
		t.Fatal(err)
	}
	encrypted, _, err := jwe.EncryptECDHES(body, pub, kid, "A128GCM", "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return postResponseForm(t, d, requestID, url.Values{"response": {encrypted}})
}

// The request id is in the QR code, so anyone who sees it can post to the
// response URI. A response that does not verify leaves the request open for
// the visitor's wallet.
func TestAResponseThatDoesNotVerifyLeavesTheRequestOpen(t *testing.T) {
	d, _, holderKey := newDemoRP(t)
	h := d.VerifierHandler()
	id, params := startVerification(t, h, "ticket")

	if code, doc := postResponseForm(t, d, id, url.Values{}); code != http.StatusBadRequest {
		t.Errorf("an empty response: %d %v, want 400", code, doc)
	}
	if _, status := requestStatus(t, d, id); status["status"] != "pending" {
		t.Errorf("after an empty response the request is %v, want pending", status["status"])
	}
	if code, _ := postVPToken(t, d, id, map[string][]string{"ticket": {"not a credential"}}); code != http.StatusOK {
		t.Errorf("a response that does not verify: %d, want 200 with the failure", code)
	}
	if _, status := requestStatus(t, d, id); status["status"] != "failed" || status["open"] != true {
		t.Errorf("after a response that does not verify: %v, want failed and open", status)
	}
	presentation := presentTicket(t, d, holderKey, params.Get("client_id"), params.Get("nonce"))
	if code := postPresentation(t, h, id, "ticket", presentation); code != http.StatusOK {
		t.Fatalf("the wallet's response: %d, want 200", code)
	}
	if _, status := requestStatus(t, d, id); status["status"] != "verified" || status["open"] == true {
		t.Errorf("after the wallet's response: %v, want verified and closed", status)
	}
}

// OpenID4VP 1.0 §8.1: each vp_token entry is "an array of one or more
// Presentations".
func TestAnEmptyPresentationArrayFails(t *testing.T) {
	d, _, _ := newDemoRP(t)
	id, _ := startVerification(t, d.VerifierHandler(), "ticket")
	postVPToken(t, d, id, map[string][]string{"ticket": {}})
	if _, status := requestStatus(t, d, id); status["status"] != "failed" || !strings.Contains(fmt.Sprint(status["error"]), "one or more") {
		t.Errorf("result %v, want the §8.1 failure", status)
	}
}

// The request carries state, so a response must return the same value.
func TestAuthorizationResponseRequiresTheRequestState(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	req := &requestState{id: "req-1", encKey: key}
	respond := func(payload map[string]any) (map[string]any, error) {
		body, _ := json.Marshal(payload)
		jwe, _, err := jwe.EncryptECDHES(body, &key.PublicKey, "", "A128GCM", "", nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		return authorizationResponse(req, url.Values{"response": {jwe}})
	}

	if _, err := respond(map[string]any{"vp_token": map[string]any{"q": []string{"x"}}, "state": "req-1"}); err != nil {
		t.Fatalf("a response with the request state: %v", err)
	}
	for _, state := range []any{nil, "req-2"} {
		payload := map[string]any{"vp_token": map[string]any{"q": []string{"x"}}}
		if state != nil {
			payload["state"] = state
		}
		if _, err := respond(payload); err == nil {
			t.Errorf("a response with state %v was accepted", state)
		}
	}
}

// Without credential_sets every query is required. With them, each required
// set needs one option that is answered in full.
func TestUnsatisfiedFollowsTheCredentialSets(t *testing.T) {
	queries := []credentialQuery{{id: "a"}, {id: "b"}, {id: "t"}}
	cases := []struct {
		name     string
		sets     []credentialSet
		answered []string
		ok       bool
	}{
		{"all queries answered", nil, []string{"a", "b", "t"}, true},
		{"one query missing", nil, []string{"a", "b"}, false},
		{"one option answered", []credentialSet{{options: [][]string{{"a"}, {"b"}}}, {options: [][]string{{"t"}}, optional: true}}, []string{"b"}, true},
		{"an option answered in part", []credentialSet{{options: [][]string{{"a", "t"}}}}, []string{"a"}, false},
		{"no option answered", []credentialSet{{options: [][]string{{"a"}, {"b"}}}}, []string{"t"}, false},
	}
	for _, tc := range cases {
		answered := map[string]bool{}
		for _, id := range tc.answered {
			answered[id] = true
		}
		req := &requestState{queries: queries, sets: tc.sets}
		if err := req.unsatisfied(answered); (err == nil) != tc.ok {
			t.Errorf("%s: unsatisfied = %v", tc.name, err)
		}
	}
}

// A vp_token answers only the queries of the request.
func TestVerifyPresentationRefusesUnknownQueryIDs(t *testing.T) {
	d := New(twoPIDWallet(t), func() string { return "https://verifier.example" })
	req := &requestState{queries: []credentialQuery{{id: "cred_0", format: "dc+sd-jwt", vct: PIDVCT}}}

	_, _, err := d.verifyPresentation(req, `{"cred_0":["a~"],"other":["b~"]}`)
	if err == nil || !strings.Contains(err.Error(), `no credential query "other"`) {
		t.Fatalf("error = %v", err)
	}
}
