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
	"encoding/json"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/consent"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
)

func nobodyQuery() map[string]any {
	return map[string]any{"credentials": []any{map[string]any{
		"id":     "pid",
		"format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": []any{"urn:nobody:holds:this"}},
		"claims": []any{map[string]any{"path": []any{"given_name"}}},
	}}}
}

func TestDebugModeOffersNonMatchingCredentialsWithTheirReasons(t *testing.T) {
	w := generateTestWalletWithPID(t)
	w.ValidationMode = ValidationModeDebug
	query := map[string]any{"credentials": []any{consentPIDQuery("pid", "dc+sd-jwt")}}

	matches, options := evaluateDCQLWithOptions(t, w, query)

	if len(matches) != 1 || matches[0].Format != "dc+sd-jwt" {
		t.Fatalf("matches %+v, want the SD-JWT PID as the automatic selection", matches)
	}
	others := options.Queries[0].NonMatching
	if len(others) != 1 || others[0].Format != "mso_mdoc" {
		t.Fatalf("non-matching %+v, want the mdoc PID", others)
	}
	want := []string{
		"format mso_mdoc, the query asks for dc+sd-jwt",
		"type " + mock.PIDNamespace + ", the query asks for " + mock.DefaultPIDVCT,
	}
	if !slices.Equal(others[0].Mismatches, want) {
		t.Errorf("mismatches %q, want %q", others[0].Mismatches, want)
	}
}

func TestStrictModeOffersNoNonMatchingCredentials(t *testing.T) {
	w := generateTestWalletWithPID(t)
	w.ValidationMode = ValidationModeStrict
	query := map[string]any{"credentials": []any{consentPIDQuery("pid", "dc+sd-jwt")}}

	_, options := evaluateDCQLWithOptions(t, w, query)
	if len(options.Queries[0].NonMatching) != 0 {
		t.Fatalf("strict mode offers %+v", options.Queries[0].NonMatching)
	}
	if matches, options := evaluateDCQLWithOptions(t, w, nobodyQuery()); matches != nil || options != nil {
		t.Fatalf("strict mode returns matches %+v and options %+v for a query nothing matches", matches, options)
	}
}

func TestANonMatchingCredentialIsSentOnlyWhenPicked(t *testing.T) {
	w := generateTestWalletWithPID(t)
	w.ValidationMode = ValidationModeDebug

	matches, options := evaluateDCQLWithOptions(t, w, nobodyQuery())
	if matches != nil {
		t.Fatalf("matches %+v, want none", matches)
	}
	if err := consent.ValidateSelection(options, nil, nil, nil); err == nil || !strings.Contains(err.Error(), "Pick one to send") {
		t.Fatalf("approving without a pick: error %v, want one asking for a pick", err)
	}

	sdjwt := ""
	for _, c := range options.Queries[0].NonMatching {
		if c.Format == "dc+sd-jwt" {
			sdjwt = c.CredentialID
		}
	}
	picks := map[string][]string{"pid": {sdjwt}}
	if err := consent.ValidateSelection(options, picks, nil, nil); err != nil {
		t.Fatalf("consent.ValidateSelection: %v", err)
	}
	got := consent.ApplySelection(options, matches, consent.Result{Approved: true, Picks: picks})
	if len(got) != 1 || got[0].CredentialID != sdjwt || !slices.Equal(got[0].SelectedKeys, []string{"given_name"}) {
		t.Fatalf("selection %+v, want the picked SD-JWT PID with its requested claim", got)
	}
}

func TestSetOptionsOnlyNonMatchingCredentialsAnswerFollowTheOthers(t *testing.T) {
	w := generateTestWalletWithPID(t)
	w.ValidationMode = ValidationModeDebug
	query := map[string]any{
		"credentials": []any{consentPIDQuery("pid_sdjwt", "dc+sd-jwt"), nobodyQuery()["credentials"].([]any)[0]},
		"credential_sets": []any{
			map[string]any{"options": []any{[]any{"pid"}, []any{"pid_sdjwt"}}},
		},
	}

	matches, options := evaluateDCQLWithOptions(t, w, query)

	if len(matches) != 1 || matches[0].QueryID != "pid_sdjwt" {
		t.Fatalf("matches %+v, want the satisfiable option", matches)
	}
	set := options.Sets[0]
	if len(set.Options) != 2 || set.Options[0][0] != "pid_sdjwt" || set.Options[1][0] != "pid" {
		t.Fatalf("options %v, want the satisfiable option first", set.Options)
	}
	if !slices.Equal(set.Unmatched, []int{1}) {
		t.Errorf("unmatched %v, want option 1", set.Unmatched)
	}
}

// In debug mode the consent dialog opens for an interactive request that no
// credential matches, so the user can answer with a credential that does not
// match.
func TestDebugModeAsksWhenNothingMatches(t *testing.T) {
	srv := newTestServer(t, false)
	srv.wallet.ValidationMode = ValidationModeDebug
	verifier := newCaptureVerifier(t)
	params := unsatisfiableRequest(t, verifier.URL)
	body, err := json.Marshal(map[string]any{"uri": "openid4vp://authorize?" + params.Encode(), "interactive": true})
	if err != nil {
		t.Fatalf("marshaling body: %v", err)
	}
	done := make(chan struct{})
	go func() {
		serverRequest(t, srv, "POST", "/api/presentations", string(body))
		close(done)
	}()

	pending := waitForPendingRequest(t, srv.wallet)
	var pick string
	for _, c := range pending.CredentialOptions.Queries[0].NonMatching {
		if c.Format == "dc+sd-jwt" {
			pick = c.CredentialID
		}
	}
	approve := serverRequest(t, srv, "POST", "/api/requests/"+pending.ID+"/approve", `{"picks":{"nothing":"`+pick+`"}}`)
	if approve.Code != 200 {
		t.Fatalf("approve: %d %s", approve.Code, approve.Body.String())
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the presentation request did not finish")
	}
	form := verifier.received(t)
	var tokens map[string][]string
	if err := json.Unmarshal([]byte(form.Get("vp_token")), &tokens); err != nil || len(tokens["nothing"]) != 1 {
		t.Fatalf("vp_token %q, want one presentation for the query", form.Get("vp_token"))
	}
}

func TestStrictModeRefusesWhenNothingMatches(t *testing.T) {
	srv := newTestServer(t, false)
	srv.wallet.ValidationMode = ValidationModeStrict
	verifier := newCaptureVerifier(t)
	params := unsatisfiableRequest(t, verifier.URL)
	params.Set("client_id", "redirect_uri:"+verifier.URL)
	body, err := json.Marshal(map[string]any{"uri": "openid4vp://authorize?" + params.Encode(), "interactive": true})
	if err != nil {
		t.Fatalf("marshaling body: %v", err)
	}

	rec := serverRequest(t, srv, "POST", "/api/presentations", string(body))

	if got := decodeJSON(t, rec)["status"]; got != "no_match" {
		t.Fatalf("status %v, want no_match: %s", got, rec.Body.String())
	}
	if got := verifier.received(t).Get("error"); got != "access_denied" {
		t.Fatalf("verifier received error %q, want access_denied", got)
	}
}

// If the user changes nothing, the consent sends what auto-accept sends. So an
// optional set without a matching credential starts skipped.
func TestAnUnchangedConsentSkipsAnOptionalSetNothingMatches(t *testing.T) {
	w := generateTestWalletWithPID(t)
	w.ValidationMode = ValidationModeDebug
	other := nobodyQuery()["credentials"].([]any)[0].(map[string]any)
	other["id"] = "other"
	query := map[string]any{
		"credentials": []any{consentPIDQuery("pid", "dc+sd-jwt"), other},
		"credential_sets": []any{
			map[string]any{"options": []any{[]any{"pid"}}},
			map[string]any{"options": []any{[]any{"other"}}, "required": false},
		},
	}

	matches, options := evaluateDCQLWithOptions(t, w, query)
	if len(options.Sets) != 2 || options.Sets[1].DefaultChoice() != -1 {
		t.Fatalf("sets %+v, want the optional set skipped by default", options.Sets)
	}
	if err := consent.ValidateSelection(options, nil, nil, nil); err != nil {
		t.Fatalf("an unchanged consent is refused: %v", err)
	}
	got := consent.ApplySelection(options, matches, consent.Result{Approved: true})
	if len(got) != 1 || got[0].QueryID != "pid" {
		t.Fatalf("selection %+v, want only the PID", got)
	}
}

// A dialog opened in debug mode offers non-matching credentials. After a
// switch to strict mode the wallet refuses to send one.
func TestStrictModeRefusesANonMatchingPickFromAnEarlierDialog(t *testing.T) {
	srv := newTestServer(t, false)
	srv.wallet.ValidationMode = ValidationModeDebug
	verifier := newCaptureVerifier(t)
	params := unsatisfiableRequest(t, verifier.URL)
	body, err := json.Marshal(map[string]any{"uri": "openid4vp://authorize?" + params.Encode(), "interactive": true})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		serverRequest(t, srv, "POST", "/api/presentations", string(body))
		close(done)
	}()
	pending := waitForPendingRequest(t, srv.wallet)
	pick := pending.CredentialOptions.Queries[0].NonMatching[0].CredentialID

	srv.wallet.mu.Lock()
	srv.wallet.ValidationMode = ValidationModeStrict
	srv.wallet.mu.Unlock()
	if approve := serverRequest(t, srv, "POST", "/api/requests/"+pending.ID+"/approve", `{"picks":{"nothing":"`+pick+`"}}`); approve.Code != 400 {
		t.Errorf("approve: %d %s, want 400", approve.Code, approve.Body.String())
	}
	serverRequest(t, srv, "POST", "/api/requests/"+pending.ID+"/deny", "")
	<-done
}
