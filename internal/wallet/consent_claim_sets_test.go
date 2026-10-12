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
	"slices"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

// The PID satisfies the first two claim sets but not the third.
func claimSetsQuery() map[string]any {
	return map[string]any{
		"credentials": []any{map[string]any{
			"id":     "pid",
			"format": "dc+sd-jwt",
			"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
			"claims": []any{
				map[string]any{"id": "a", "path": []any{"given_name"}},
				map[string]any{"id": "b", "path": []any{"family_name"}},
				map[string]any{"id": "c", "path": []any{"birthdate"}},
				map[string]any{"id": "x", "path": []any{"no_such_claim"}},
			},
			"claim_sets": []any{
				[]any{"a", "b"},
				[]any{"x"},
				[]any{"a", "c"},
			},
		}},
	}
}

func TestDebugModeOffersEverySatisfiableClaimSet(t *testing.T) {
	w := generateTestWalletWithPID(t)
	w.ValidationMode = ValidationModeDebug

	matches, options := evaluateDCQLWithOptions(t, w, claimSetsQuery())

	if len(matches) != 1 || !slices.Equal(matches[0].SelectedKeys, []string{"given_name", "family_name"}) {
		t.Fatalf("matches %+v, want the first claim set as the automatic selection", matches)
	}
	var indexes []int
	for _, set := range matches[0].ClaimSets {
		indexes = append(indexes, set.Index)
	}
	if !slices.Equal(indexes, []int{0, 2}) {
		t.Errorf("claim set indexes %v, want 0 and 2 (the PID cannot answer set 1)", indexes)
	}
	if !slices.Equal(options.Queries[0].Candidates[0].ClaimSets[1].Keys, []string{"given_name", "birthdate"}) {
		t.Errorf("claim sets %+v, want given_name and birthdate in the second", options.Queries[0].Candidates[0].ClaimSets)
	}
}

// OpenID4VP 1.0 §6.4.1: "the Wallet SHOULD return the first option that it can
// satisfy".
func TestStrictModeOffersNoClaimSetChoice(t *testing.T) {
	w := generateTestWalletWithPID(t)
	w.ValidationMode = ValidationModeStrict

	matches, options := evaluateDCQLWithOptions(t, w, claimSetsQuery())

	if len(matches) != 1 || len(matches[0].ClaimSets) != 0 || len(options.Queries[0].Candidates[0].ClaimSets) != 0 {
		t.Fatalf("strict mode offers claim sets: matches %+v, options %+v", matches, options.Queries[0])
	}
}

func TestAChosenClaimSetIsDisclosed(t *testing.T) {
	w := generateTestWalletWithPID(t)
	w.ValidationMode = ValidationModeDebug
	matches, options := evaluateDCQLWithOptions(t, w, claimSetsQuery())

	choice := map[string]int{"pid": 2}
	if err := consent.ValidateSelection(options, nil, nil, choice); err != nil {
		t.Fatalf("consent.ValidateSelection: %v", err)
	}
	got := consent.ApplySelection(options, matches, consent.Result{Approved: true, ClaimSetChoices: choice})

	if len(got) != 1 || !slices.Equal(got[0].SelectedKeys, []string{"given_name", "birthdate"}) {
		t.Fatalf("selection %+v, want given_name and birthdate", got)
	}
	if _, ok := got[0].Claims["birthdate"]; !ok {
		t.Errorf("claims %v lack birthdate", got[0].Claims)
	}
	if !slices.Equal(matches[0].SelectedKeys, []string{"given_name", "family_name"}) {
		t.Error("applying the choice changed the automatic selection")
	}
}

func TestAClaimSetTheCredentialCannotSatisfyIsRefused(t *testing.T) {
	w := generateTestWalletWithPID(t)
	w.ValidationMode = ValidationModeDebug
	_, options := evaluateDCQLWithOptions(t, w, claimSetsQuery())

	for _, tc := range []struct {
		name   string
		choice map[string]int
		want   string
	}{
		{"unsatisfiable set", map[string]int{"pid": 1}, "does not satisfy claim set 1"},
		{"unknown query", map[string]int{"other": 0}, "unknown credential query"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := consent.ValidateSelection(options, nil, nil, tc.choice)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want one containing %q", err, tc.want)
			}
		})
	}
}
