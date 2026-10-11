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

package consent

import (
	"fmt"
	"slices"
)

// ValidateSelection checks the choices made in the consent dialog: one
// option per credential set and the credentials of each query. A query with
// multiple can take several credentials.
func ValidateSelection(options *CredentialOptions, picks map[string][]string, setChoices []int, claimSets map[string]int) error {
	if options == nil {
		if len(picks) == 0 && len(setChoices) == 0 && len(claimSets) == 0 {
			return nil
		}
		return fmt.Errorf("this request offers no credential selection")
	}
	if len(setChoices) > len(options.Sets) {
		return fmt.Errorf("%d set choices for %d sets", len(setChoices), len(options.Sets))
	}
	answered := len(options.Sets) == 0
	for i, set := range options.Sets {
		choice := chosenOption(set, i, setChoices)
		if choice == -1 {
			if !set.Optional {
				return fmt.Errorf("set %d is required and cannot be skipped", i)
			}
			continue
		}
		if choice < 0 || choice >= len(set.Options) {
			return fmt.Errorf("set %d has no option %d", i, choice)
		}
		answered = true
	}
	// A presentation carries at least one credential (OpenID4VP 1.0 §8.1),
	// so a selection must answer at least one set.
	if !answered {
		return fmt.Errorf("the selection must answer at least one credential set")
	}
	for qid, credIDs := range picks {
		query := findConsentQuery(options, qid)
		if query == nil {
			return fmt.Errorf("unknown credential query %q", qid)
		}
		if len(credIDs) == 0 {
			return fmt.Errorf("query %q needs at least one credential", qid)
		}
		// OpenID4VP 1.0 §8.1: "When multiple is omitted, or set to false, the
		// array MUST contain only one Presentation."
		if len(credIDs) > 1 && !query.Multiple {
			return fmt.Errorf("query %q does not set multiple, so it takes one credential, got %d", qid, len(credIDs))
		}
		seen := make(map[string]bool, len(credIDs))
		for _, credID := range credIDs {
			if seen[credID] {
				return fmt.Errorf("credential %s is picked twice for query %q", credID, qid)
			}
			seen[credID] = true
			if findConsentCandidate(query, credID) == nil {
				return fmt.Errorf("credential %s does not match query %q", credID, qid)
			}
		}
	}
	// In debug mode a query can have only non-matching credentials. The user
	// must pick one of them.
	for _, qid := range activeQueries(options, setChoices) {
		if query := findConsentQuery(options, qid); query != nil && len(pickedCandidates(query, picks[qid])) == 0 {
			return fmt.Errorf("no credential matches query %q. Pick one to send", qid)
		}
	}
	return validateClaimSetChoices(options, picks, claimSets)
}

// DebugOnlySelection reports a pick of a non-matching credential or a chosen
// claim set. Only debug mode offers them, and the wallet may have switched to
// strict mode while the consent dialog was open.
func DebugOnlySelection(options *CredentialOptions, picks map[string][]string, claimSets map[string]int) bool {
	if options == nil {
		return false
	}
	for qid, credIDs := range picks {
		query := findConsentQuery(options, qid)
		if query == nil {
			continue
		}
		for _, credID := range credIDs {
			if slices.ContainsFunc(query.NonMatching, func(m Match) bool { return m.CredentialID == credID }) {
				return true
			}
		}
	}
	return len(claimSets) > 0
}

// validateClaimSetChoices checks that every credential answering a query
// satisfies the claim set chosen for it.
func validateClaimSetChoices(options *CredentialOptions, picks map[string][]string, claimSets map[string]int) error {
	for qid, index := range claimSets {
		query := findConsentQuery(options, qid)
		if query == nil {
			return fmt.Errorf("unknown credential query %q", qid)
		}
		for _, c := range pickedCandidates(query, picks[qid]) {
			if findClaimSet(c, index) == nil {
				return fmt.Errorf("credential %s does not satisfy claim set %d of query %q", c.CredentialID, index, qid)
			}
		}
	}
	return nil
}

func findClaimSet(c Match, index int) *ClaimSet {
	for i := range c.ClaimSets {
		if c.ClaimSets[i].Index == index {
			return &c.ClaimSets[i]
		}
	}
	return nil
}

// ApplySelection returns the matches for the user's choices. Without
// overrides it returns the automatic selection, so an unchanged consent gives
// the same result as auto-accept.
func ApplySelection(options *CredentialOptions, matches []Match, result Result) []Match {
	if options == nil {
		return append([]Match(nil), matches...)
	}
	return applyClaimSetChoices(selectCredentials(options, matches, result), result.ClaimSetChoices)
}

// applyClaimSetChoices discloses the chosen claim set instead of the first one.
func applyClaimSetChoices(selected []Match, choices map[string]int) []Match {
	for i, m := range selected {
		index, ok := choices[m.QueryID]
		if !ok {
			continue
		}
		if set := findClaimSet(m, index); set != nil {
			selected[i].SelectedKeys = set.Keys
			selected[i].Claims = set.Claims
		}
	}
	return selected
}

func selectCredentials(options *CredentialOptions, matches []Match, result Result) []Match {
	if len(result.Picks) == 0 && len(result.SetChoices) == 0 {
		// Return a copy. Claims are filtered later while the Request can
		// still be marshalled concurrently.
		return append([]Match(nil), matches...)
	}

	// ValidateSelection has checked the choices.
	needed := activeQueries(options, result.SetChoices)
	out := make([]Match, 0, len(needed))
	for _, qid := range needed {
		query := findConsentQuery(options, qid)
		if query == nil {
			continue
		}
		out = append(out, pickedCandidates(query, result.Picks[qid])...)
	}
	// A presentation carries at least one credential (OpenID4VP 1.0 §8.1),
	// so a selection that answers nothing keeps the wallet's choice.
	if len(out) == 0 {
		return append([]Match(nil), matches...)
	}
	return out
}

// activeQueries lists the queries in the chosen credential_sets options.
// Without credential_sets every query is active.
func activeQueries(options *CredentialOptions, setChoices []int) []string {
	var ids []string
	if len(options.Sets) == 0 {
		for _, query := range options.Queries {
			ids = append(ids, query.ID)
		}
		return ids
	}
	for i, set := range options.Sets {
		choice := chosenOption(set, i, setChoices)
		if choice < 0 || choice >= len(set.Options) {
			continue
		}
		for _, qid := range set.Options[choice] {
			if !slices.Contains(ids, qid) {
				ids = append(ids, qid)
			}
		}
	}
	return ids
}

// chosenOption is the option the user chose for set i, or its default.
func chosenOption(set SetOptions, i int, setChoices []int) int {
	if i < len(setChoices) {
		return setChoices[i]
	}
	return set.DefaultChoice()
}

// pickedCandidates returns the picked credentials, matching ones first. Without a
// valid pick it returns every candidate of a query with multiple: true, and the
// first candidate of any other query.
func pickedCandidates(query *QueryOptions, credIDs []string) []Match {
	var picked []Match
	for _, list := range [][]Match{query.Candidates, query.NonMatching} {
		for _, c := range list {
			if slices.Contains(credIDs, c.CredentialID) {
				picked = append(picked, c)
			}
		}
	}
	switch {
	case len(picked) > 0:
		return picked
	case len(query.Candidates) == 0:
		return nil
	case query.Multiple:
		return query.Candidates
	default:
		return query.Candidates[:1]
	}
}

func findConsentQuery(options *CredentialOptions, id string) *QueryOptions {
	for i := range options.Queries {
		if options.Queries[i].ID == id {
			return &options.Queries[i]
		}
	}
	return nil
}

func findConsentCandidate(query *QueryOptions, credentialID string) *Match {
	for i := range query.Candidates {
		if query.Candidates[i].CredentialID == credentialID {
			return &query.Candidates[i]
		}
	}
	for i := range query.NonMatching {
		if query.NonMatching[i].CredentialID == credentialID {
			return &query.NonMatching[i]
		}
	}
	return nil
}

// DefaultChoice returns the option sent when the user changes nothing. That is
// the first option, or none (-1) for an optional set where only non-matching
// credentials fit.
func (s SetOptions) DefaultChoice() int {
	if s.Optional && len(s.Unmatched) == len(s.Options) {
		return -1
	}
	return 0
}
