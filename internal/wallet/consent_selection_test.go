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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v2/internal/mock"
)

func TestApplyConsentSelection(t *testing.T) {
	w := pidBaselineWallet(t)
	matches, options := w.EvaluateDCQLWithOptions(setsQuery())
	alternate := options.Queries[0].Candidates[0]
	for _, candidate := range options.Queries[0].Candidates {
		if candidate.VCT == mock.GermanPIDVCT {
			alternate = candidate
			break
		}
	}
	if alternate.VCT != mock.GermanPIDVCT {
		t.Fatal("German PID candidate is missing")
	}

	t.Run("no overrides keeps the auto selection", func(t *testing.T) {
		got := ApplyConsentSelection(options, matches, ConsentResult{Approved: true})
		if len(got) != 1 || got[0].CredentialID != matches[0].CredentialID {
			t.Errorf("got %+v, want the unchanged auto selection", got)
		}
	})

	t.Run("a pick swaps the credential of its query", func(t *testing.T) {
		got := ApplyConsentSelection(options, matches, ConsentResult{
			Approved: true,
			Picks:    map[string][]string{"pid_sdjwt": {alternate.CredentialID}},
		})
		if len(got) != 1 || got[0].CredentialID != alternate.CredentialID {
			t.Fatalf("got %+v, want the picked credential", got)
		}
		if got[0].VCT != mock.GermanPIDVCT {
			t.Errorf("picked vct = %q, want the German PID", got[0].VCT)
		}
	})

	t.Run("a set choice swaps the answered option", func(t *testing.T) {
		got := ApplyConsentSelection(options, matches, ConsentResult{Approved: true, SetChoices: []int{1}})
		if len(got) != 1 || got[0].QueryID != "pid_mdoc" {
			t.Fatalf("got %+v, want the mdoc option's credential", got)
		}
	})

	t.Run("an unknown pick falls back to the wallet's choice", func(t *testing.T) {
		got := ApplyConsentSelection(options, matches, ConsentResult{
			Approved: true,
			Picks:    map[string][]string{"pid_sdjwt": {"not-a-candidate"}},
		})
		if len(got) != 1 || got[0].CredentialID != matches[0].CredentialID {
			t.Errorf("got %+v, want the auto selection", got)
		}
	})

	t.Run("skipping an optional set drops its credentials", func(t *testing.T) {
		optQuery := map[string]any{
			"credentials": []any{consentPIDQuery("pid_sdjwt", "dc+sd-jwt"), consentPIDQuery("pid_mdoc", "mso_mdoc")},
			"credential_sets": []any{
				map[string]any{"options": []any{[]any{"pid_sdjwt"}}},
				map[string]any{"options": []any{[]any{"pid_mdoc"}}, "required": false},
			},
		}
		optMatches, optOptions := w.EvaluateDCQLWithOptions(optQuery)
		got := ApplyConsentSelection(optOptions, optMatches, ConsentResult{Approved: true, SetChoices: []int{0, -1}})
		if len(got) != 1 || got[0].QueryID != "pid_sdjwt" {
			t.Errorf("got %+v, want only the required set answered", got)
		}
	})
}

func TestValidateConsentSelection(t *testing.T) {
	w := pidBaselineWallet(t)
	_, options := w.EvaluateDCQLWithOptions(setsQuery())
	first := options.Queries[0].Candidates[0].CredentialID
	valid := options.Queries[0].Candidates[1].CredentialID

	cases := []struct {
		name       string
		picks      map[string][]string
		setChoices []int
		wantErr    string
	}{
		{name: "empty selection"},
		{name: "valid pick", picks: map[string][]string{"pid_sdjwt": {valid}}},
		{name: "valid set choice", setChoices: []int{1}},
		{name: "unknown query", picks: map[string][]string{"nope": {valid}}, wantErr: "unknown credential query"},
		{name: "foreign credential", picks: map[string][]string{"pid_sdjwt": {"someone-else"}}, wantErr: "does not match query"},
		{name: "empty pick", picks: map[string][]string{"pid_sdjwt": {}}, wantErr: "needs at least one credential"},
		{name: "two credentials without multiple", picks: map[string][]string{"pid_sdjwt": {first, valid}}, wantErr: "does not set multiple"},
		{name: "option out of range", setChoices: []int{7}, wantErr: "has no option"},
		{name: "skipping a required set", setChoices: []int{-1}, wantErr: "cannot be skipped"},
		{name: "more choices than sets", setChoices: []int{0, 0}, wantErr: "set choices for"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateConsentSelection(options, tc.picks, tc.setChoices)
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error = %v, want %q", err, tc.wantErr)
			}
		})
	}

	t.Run("overrides without options are refused", func(t *testing.T) {
		if err := ValidateConsentSelection(nil, map[string][]string{"pid": {"x"}}, nil); err == nil {
			t.Fatal("expected an error")
		}
	})

	// A presentation carries at least one credential (OpenID4VP 1.0 §8.1).
	// Validation refuses a selection that skips every set. Applying such a
	// selection keeps the wallet's choice.
	t.Run("skipping every set", func(t *testing.T) {
		w := pidBaselineWallet(t)
		query := map[string]any{
			"credentials": []any{consentPIDQuery("pid_sdjwt", "dc+sd-jwt"), consentPIDQuery("pid_mdoc", "mso_mdoc")},
			"credential_sets": []any{
				map[string]any{"options": []any{[]any{"pid_sdjwt"}}, "required": false},
				map[string]any{"options": []any{[]any{"pid_mdoc"}}, "required": false},
			},
		}
		matches, allOptional := w.EvaluateDCQLWithOptions(query)
		if err := ValidateConsentSelection(allOptional, nil, []int{-1, -1}); err == nil || !strings.Contains(err.Error(), "at least one") {
			t.Fatalf("error = %v, want the all-skipped selection refused", err)
		}
		got := ApplyConsentSelection(allOptional, matches, ConsentResult{Approved: true, SetChoices: []int{-1, -1}})
		if len(got) != len(matches) {
			t.Errorf("got %d matches, want the wallet's choice kept", len(got))
		}
	})
}

// A bad selection is rejected before the consent resolves. The dialog can then
// correct it and approve again.
func TestApproveRejectsAnInvalidSelectionAndKeepsTheRequestPending(t *testing.T) {
	w := pidBaselineWallet(t)
	matches, options := w.EvaluateDCQLWithOptions(setsQuery())
	s := NewServer(w, 0, nil)

	consentReq := &ConsentRequest{
		ID:                newConsentID(),
		Type:              "presentation",
		MatchedCreds:      matches,
		Status:            "pending",
		ResultCh:          make(chan ConsentResult, 1),
		SubmissionCh:      make(chan SubmissionResult, 1),
		CredentialOptions: options,
	}
	w.CreateConsentRequest(consentReq)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest("POST", "/api/requests/"+consentReq.ID+"/approve",
		strings.NewReader(`{"picks":{"pid_sdjwt":"not-a-candidate"}}`))
	s.mux.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", rr.Code, rr.Body.String())
	}
	if pending, _ := w.GetRequest(consentReq.ID); pending.Status != "pending" {
		t.Errorf("request status = %q, want it still pending", pending.Status)
	}
}
