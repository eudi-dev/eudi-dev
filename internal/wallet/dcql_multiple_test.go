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
	"crypto/ecdsa"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/dcql"
	"github.com/eudi-dev/eudi-dev/v3/internal/jws"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
)

// The PID baseline holds two SD-JWT PIDs that answer urn:eudi:pid:1: the EUDI PID
// and the German PID that extends it.
func multiplePIDQuery(id string) map[string]any {
	q := consentPIDQuery(id, "dc+sd-jwt")
	q["multiple"] = true
	return q
}

func TestDCQLMultiplePresentsEveryMatch(t *testing.T) {
	w := pidBaselineWallet(t)

	matches, options := evaluateDCQLWithOptions(t, w, map[string]any{"credentials": []any{multiplePIDQuery("pid")}})
	if len(matches) != 2 {
		t.Fatalf("matches = %d, want both SD-JWT PIDs", len(matches))
	}
	if matches[0].CredentialID == matches[1].CredentialID {
		t.Fatalf("both matches present credential %s", matches[0].CredentialID)
	}
	for _, m := range matches {
		if m.QueryID != "pid" {
			t.Errorf("match answers query %q, want pid", m.QueryID)
		}
	}
	if options == nil || len(options.Queries) != 1 || !options.Queries[0].Multiple {
		t.Fatalf("options = %+v, want one query marked multiple", options)
	}
	if len(options.Queries[0].Candidates) != 2 {
		t.Errorf("candidates = %d, want 2", len(options.Queries[0].Candidates))
	}

	single, singleOptions := evaluateDCQLWithOptions(t, w, map[string]any{"credentials": []any{consentPIDQuery("pid", "dc+sd-jwt")}})
	if len(single) != 1 {
		t.Errorf("a query without multiple presents %d credentials, want 1", len(single))
	}
	if singleOptions.Queries[0].Multiple {
		t.Error("a query without multiple is marked multiple")
	}
}

func TestDCQLMultipleThroughCredentialSets(t *testing.T) {
	w := pidBaselineWallet(t)
	query := map[string]any{
		"credentials": []any{multiplePIDQuery("pid_sdjwt"), consentPIDQuery("pid_mdoc", "mso_mdoc")},
		"credential_sets": []any{
			map[string]any{"options": []any{[]any{"pid_sdjwt"}, []any{"pid_mdoc"}}},
		},
	}

	matches := evaluateDCQL(t, w, query)
	if len(matches) != 2 {
		t.Fatalf("matches = %d, want both SD-JWT PIDs for the chosen option", len(matches))
	}
	for _, m := range matches {
		if m.QueryID != "pid_sdjwt" {
			t.Errorf("match answers %q, want only the first option's query", m.QueryID)
		}
	}
}

func TestDCQLMultipleMustBeBoolean(t *testing.T) {
	query := map[string]any{"credentials": []any{consentPIDQuery("pid", "dc+sd-jwt")}}
	query["credentials"].([]any)[0].(map[string]any)["multiple"] = "true"

	findings := dcql.QueryFindings(query)
	if len(findings) != 1 || !strings.Contains(findings[0], `"pid" has a multiple that is not a boolean`) {
		t.Fatalf("findings = %v", findings)
	}

	w := pidBaselineWallet(t)
	if matches := evaluateDCQL(t, w, query); len(matches) != 1 {
		t.Errorf("debug mode presents %d credentials for a non-boolean multiple, want 1", len(matches))
	}
	w.ValidationMode = ValidationModeStrict
	if outcome := w.evaluatePresentationRequest(queryRequest(query), presentationEntry{action: "presentation", subject: "The request"}); outcome.invalidCode != oid4vp.ErrorInvalidRequest {
		t.Errorf("strict mode answered a malformed query with %v, want invalid_request", outcome.invalid)
	}
}

// Copies of one batch stay unlinkable, so a multiple query presents one copy per
// batch next to the other matching credentials.
func TestDCQLMultiplePresentsOneCopyPerBatch(t *testing.T) {
	w := generateTestWallet(t)
	keys := []*ecdsa.PrivateKey{w.HolderKey, testKey(t), testKey(t)}
	storeTestBatch(t, w, keys)
	single, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer:    "https://other-issuer.example",
		VCT:       testBatchVCT,
		Claims:    map[string]any{"family_name": "Roe"},
		Key:       testKey(t),
		HolderKey: &w.HolderKey.PublicKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	standalone, err := w.ImportCredential(single)
	if err != nil {
		t.Fatal(err)
	}

	query := batchTestQuery()
	query["credentials"].([]any)[0].(map[string]any)["multiple"] = true
	matches := evaluateDCQL(t, w, query)
	if len(matches) != 2 {
		t.Fatalf("matches = %d, want one batch copy and the standalone credential", len(matches))
	}
	var sawStandalone, sawBatch bool
	for _, m := range matches {
		cred, _ := w.GetCredential(m.CredentialID)
		switch {
		case m.CredentialID == standalone.ID:
			sawStandalone = true
		case cred.BatchGroup != "":
			sawBatch = true
		}
	}
	if !sawStandalone || !sawBatch {
		t.Errorf("matches = %+v, want one batch copy and the standalone credential", matches)
	}

	result, err := w.createVPTokenMap(matches, &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "n", ClientID: "https://verifier.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := len(result.TokenMap["pid"]); got != 2 {
		t.Fatalf("vp_token holds %d presentations for pid, want 2", got)
	}
}

func TestApplyConsentSelectionMultiple(t *testing.T) {
	w := pidBaselineWallet(t)
	matches, options := evaluateDCQLWithOptions(t, w, map[string]any{"credentials": []any{multiplePIDQuery("pid")}})
	candidates := options.Queries[0].Candidates

	t.Run("no picks presents every candidate", func(t *testing.T) {
		got := consent.ApplySelection(options, matches, consent.Result{Approved: true, SetChoices: []int{}})
		if len(got) != 2 {
			t.Errorf("got %d credentials, want 2", len(got))
		}
	})

	t.Run("a set choice without picks keeps every candidate", func(t *testing.T) {
		sets := map[string]any{
			"credentials":     []any{multiplePIDQuery("pid")},
			"credential_sets": []any{map[string]any{"options": []any{[]any{"pid"}}}},
		}
		setMatches, setOptions := evaluateDCQLWithOptions(t, w, sets)
		got := consent.ApplySelection(setOptions, setMatches, consent.Result{Approved: true, SetChoices: []int{0}})
		if len(got) != 2 {
			t.Errorf("got %d credentials, want 2", len(got))
		}
	})

	t.Run("a pick withholds the other candidates", func(t *testing.T) {
		got := consent.ApplySelection(options, matches, consent.Result{
			Approved: true,
			Picks:    map[string][]string{"pid": {candidates[1].CredentialID}},
		})
		if len(got) != 1 || got[0].CredentialID != candidates[1].CredentialID {
			t.Errorf("got %+v, want only the picked credential", got)
		}
	})

	t.Run("picks keep the candidate order", func(t *testing.T) {
		got := consent.ApplySelection(options, matches, consent.Result{
			Approved: true,
			Picks:    map[string][]string{"pid": {candidates[1].CredentialID, candidates[0].CredentialID}},
		})
		if len(got) != 2 || got[0].CredentialID != candidates[0].CredentialID || got[1].CredentialID != candidates[1].CredentialID {
			t.Errorf("got %+v, want both candidates in candidate order", got)
		}
	})

	t.Run("validation accepts several credentials and refuses duplicates", func(t *testing.T) {
		both := []string{candidates[0].CredentialID, candidates[1].CredentialID}
		if err := consent.ValidateSelection(options, map[string][]string{"pid": both}, nil, nil); err != nil {
			t.Errorf("two candidates refused: %v", err)
		}
		twice := []string{candidates[0].CredentialID, candidates[0].CredentialID}
		if err := consent.ValidateSelection(options, map[string][]string{"pid": twice}, nil, nil); err == nil || !strings.Contains(err.Error(), "picked twice") {
			t.Errorf("a duplicate pick: error = %v", err)
		}
	})
}

func TestCreateVPTokenMapMultiple(t *testing.T) {
	w := pidBaselineWallet(t)
	matches := evaluateDCQL(t, w, map[string]any{"credentials": []any{multiplePIDQuery("pid")}})
	params := &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "nonce-1", ClientID: "https://verifier.example", ResponseURI: "https://verifier.example/response"}}

	result, err := w.createVPTokenMap(matches, params)
	if err != nil {
		t.Fatal(err)
	}
	tokens := result.TokenMap["pid"]
	if len(tokens) != 2 || tokens[0] == tokens[1] {
		t.Fatalf("pid presentations = %v, want two different ones", tokens)
	}
	if result.PresentationCount() != 2 {
		t.Errorf("PresentationCount = %d, want 2", result.PresentationCount())
	}
	// Each presentation carries its own key binding JWT for this request.
	for i, token := range tokens {
		payload, err := jws.Verify(token[strings.LastIndex(token, "~")+1:], &w.HolderKey.PublicKey)
		if err != nil {
			t.Fatalf("presentation %d: key binding JWT: %v", i, err)
		}
		var kb map[string]any
		if err := json.Unmarshal(payload, &kb); err != nil {
			t.Fatal(err)
		}
		if kb["nonce"] != "nonce-1" {
			t.Errorf("presentation %d: nonce = %v", i, kb["nonce"])
		}
	}

	envelope, err := w.buildAuthorizationResponse(result, "", "state", params)
	if err != nil {
		t.Fatal(err)
	}
	vpToken, _ := envelope.Plain["vp_token"].(map[string][]string)
	if len(vpToken["pid"]) != 2 {
		t.Errorf("authorization response vp_token = %v, want two pid presentations", envelope.Plain["vp_token"])
	}

	logged := presentedCredentialLogDetails(w, matches, result)
	if len(logged) != 2 || logged[0]["presentation"] != tokens[0] || logged[1]["presentation"] != tokens[1] {
		t.Errorf("activity log pairs credentials and presentations wrongly: %v", logged)
	}
}

// presentMultiple runs an interactive presentation of a multiple query, approves it
// with body and returns the vp_token received by the verifier.
func presentMultiple(t *testing.T, body string) (int, map[string][]string) {
	t.Helper()
	w := pidBaselineWallet(t)
	srv := NewServer(w, 0, nil)

	received := make(chan string, 1)
	verifier := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		form, _ := url.ParseQuery(string(raw))
		received <- form.Get("vp_token")
		rw.Header().Set("Content-Type", "application/json")
		rw.Write([]byte(`{}`))
	}))
	defer verifier.Close()

	dcqlJSON, _ := json.Marshal(map[string]any{"credentials": []any{multiplePIDQuery("pid")}})
	params := url.Values{
		"client_id":     {"redirect_uri:" + verifier.URL},
		"response_type": {"vp_token"},
		"response_mode": {"direct_post"},
		"nonce":         {"nonce"},
		"state":         {"state"},
		"response_uri":  {verifier.URL},
		"dcql_query":    {string(dcqlJSON)},
	}
	go func() {
		srv.mux.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/authorize?"+params.Encode(), nil))
	}()

	reqID := waitForPendingRequest(t, w).ID
	pending, _ := w.Consents().Get(reqID)
	ids := make([]string, 0, 2)
	for _, c := range pending.CredentialOptions.Queries[0].Candidates {
		ids = append(ids, c.CredentialID)
	}
	body = strings.NewReplacer("$0", ids[0], "$1", ids[1]).Replace(body)

	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, httptest.NewRequest("POST", "/api/requests/"+reqID+"/approve", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		return rec.Code, nil
	}
	select {
	case raw := <-received:
		var vpToken map[string][]string
		if err := json.Unmarshal([]byte(raw), &vpToken); err != nil {
			t.Fatalf("vp_token %q: %v", raw, err)
		}
		return rec.Code, vpToken
	case <-time.After(10 * time.Second):
		t.Fatal("the verifier received no presentation")
		return 0, nil
	}
}

func TestApproveMultipleQuery(t *testing.T) {
	cases := []struct {
		name string
		body string
		want int
	}{
		{name: "no picks presents every credential", body: `{}`, want: 2},
		{name: "an array pick presents those credentials", body: `{"picks":{"pid":["$0","$1"]}}`, want: 2},
		{name: "a single pick presents that credential", body: `{"picks":{"pid":"$1"}}`, want: 1},
		{name: "a null pick keeps the default", body: `{"picks":{"pid":null}}`, want: 2},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, vpToken := presentMultiple(t, tc.body)
			if code != http.StatusOK {
				t.Fatalf("approve status = %d", code)
			}
			if got := len(vpToken["pid"]); got != tc.want {
				t.Errorf("vp_token holds %d pid presentations, want %d", got, tc.want)
			}
		})
	}

	for name, body := range map[string]string{
		"an empty array":    `{"picks":{"pid":[]}}`,
		"a non-string pick": `{"picks":{"pid":7}}`,
		"invalid JSON":      `{"picks":`,
	} {
		t.Run(name+" is refused", func(t *testing.T) {
			if code, _ := presentMultiple(t, body); code != http.StatusBadRequest {
				t.Errorf("approve status = %d, want 400", code)
			}
		})
	}
}

// One set option combines a multiple query with a query for another credential.
func TestDCQLMultipleCombinedWithAnotherQueryInOneOption(t *testing.T) {
	w := pidBaselineWallet(t)
	query := map[string]any{
		"credentials": []any{multiplePIDQuery("pid_sdjwt"), consentPIDQuery("pid_mdoc", "mso_mdoc")},
		"credential_sets": []any{
			map[string]any{"options": []any{[]any{"pid_sdjwt", "pid_mdoc"}}},
		},
	}

	matches, options := evaluateDCQLWithOptions(t, w, query)
	byQuery := map[string]int{}
	for _, m := range matches {
		byQuery[m.QueryID]++
	}
	if byQuery["pid_sdjwt"] != 2 || byQuery["pid_mdoc"] != 1 {
		t.Fatalf("matches per query = %v, want both SD-JWT PIDs and one mdoc", byQuery)
	}

	sdjwt := options.Queries[0]
	if sdjwt.ID != "pid_sdjwt" || !sdjwt.Multiple {
		t.Fatalf("first query = %+v, want pid_sdjwt marked multiple", sdjwt)
	}
	got := consent.ApplySelection(options, matches, consent.Result{
		Approved:   true,
		SetChoices: []int{0},
		Picks:      map[string][]string{"pid_sdjwt": {sdjwt.Candidates[1].CredentialID}},
	})
	if len(got) != 2 || got[0].CredentialID != sdjwt.Candidates[1].CredentialID || got[1].QueryID != "pid_mdoc" {
		t.Errorf("got %+v, want the picked SD-JWT PID and the mdoc", got)
	}
}

// A required set holds a multiple query, and an optional set asks for another
// credential.
func TestDCQLMultipleWithAnOptionalSet(t *testing.T) {
	w := pidBaselineWallet(t)
	query := map[string]any{
		"credentials": []any{multiplePIDQuery("pid_sdjwt"), consentPIDQuery("pid_mdoc", "mso_mdoc")},
		"credential_sets": []any{
			map[string]any{"options": []any{[]any{"pid_sdjwt"}}},
			map[string]any{"options": []any{[]any{"pid_mdoc"}}, "required": false},
		},
	}

	matches, options := evaluateDCQLWithOptions(t, w, query)
	if len(matches) != 3 {
		t.Fatalf("matches = %d, want both SD-JWT PIDs and the optional mdoc", len(matches))
	}

	skipped := consent.ApplySelection(options, matches, consent.Result{Approved: true, SetChoices: []int{0, -1}})
	if len(skipped) != 2 || skipped[0].QueryID != "pid_sdjwt" || skipped[1].QueryID != "pid_sdjwt" {
		t.Errorf("skipping the optional set: got %+v, want both SD-JWT PIDs only", skipped)
	}

	result, err := w.createVPTokenMap(matches, &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "n", ClientID: "https://verifier.example"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.TokenMap["pid_sdjwt"]) != 2 || len(result.TokenMap["pid_mdoc"]) != 1 {
		t.Errorf("vp_token = %d SD-JWT and %d mdoc presentations, want 2 and 1", len(result.TokenMap["pid_sdjwt"]), len(result.TokenMap["pid_mdoc"]))
	}
}
