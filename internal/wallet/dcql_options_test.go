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
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

func pidBaselineWallet(t *testing.T) *Wallet {
	t.Helper()
	w := generateTestWallet(t)
	if err := w.GenerateProtectedDefaults(); err != nil {
		t.Fatalf("generating the PID baseline: %v", err)
	}
	return w
}

func consentPIDQuery(id, format string) map[string]any {
	if format == "mso_mdoc" {
		return map[string]any{
			"id": id, "format": "mso_mdoc",
			"meta":   map[string]any{"doctype_value": mock.PIDNamespace},
			"claims": []any{map[string]any{"path": []any{mock.PIDNamespace, "given_name"}}},
		}
	}
	return map[string]any{
		"id": id, "format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
		"claims": []any{map[string]any{"path": []any{"given_name"}}},
	}
}

// The first offered candidate must match the automatic selection.
func TestEvaluateDCQLWithOptions_CandidatesLeadWithTheWalletsChoice(t *testing.T) {
	w := pidBaselineWallet(t)
	query := map[string]any{"credentials": []any{consentPIDQuery("pid", "dc+sd-jwt")}}

	matches, options := evaluateDCQLWithOptions(t, w, query)
	if len(matches) != 1 {
		t.Fatalf("got %d matches, want 1", len(matches))
	}
	if options == nil || len(options.Queries) != 1 {
		t.Fatalf("got options %+v, want one query entry", options)
	}
	q := options.Queries[0]
	if q.ID != "pid" {
		t.Errorf("query id = %q", q.ID)
	}
	if len(q.Candidates) != 2 {
		t.Fatalf("got %d candidates, want the EU and the German PID", len(q.Candidates))
	}
	if q.Candidates[0].CredentialID != matches[0].CredentialID {
		t.Errorf("first candidate %s is not the auto-selected match %s", q.Candidates[0].CredentialID, matches[0].CredentialID)
	}
	if len(options.Sets) != 0 {
		t.Errorf("a query without credential_sets reports no sets, got %+v", options.Sets)
	}
}

func setsQuery() map[string]any {
	return map[string]any{
		"credentials": []any{consentPIDQuery("pid_sdjwt", "dc+sd-jwt"), consentPIDQuery("pid_mdoc", "mso_mdoc")},
		"credential_sets": []any{
			map[string]any{"options": []any{[]any{"pid_sdjwt"}, []any{"pid_mdoc"}}},
		},
	}
}

// Offer only sets whose queries all have matches, with the automatic choice first.
func TestEvaluateDCQLWithOptions_SetOptions(t *testing.T) {
	w := pidBaselineWallet(t)
	query := setsQuery()
	query["credential_sets"] = []any{
		map[string]any{"options": []any{
			[]any{"pid_sdjwt"},
			[]any{"pid_mdoc"},
			[]any{"pid_sdjwt", "unmatched_query"},
		}},
	}

	matches, options := evaluateDCQLWithOptions(t, w, query)
	if len(matches) != 1 || matches[0].QueryID != "pid_sdjwt" {
		t.Fatalf("auto selection = %+v, want the first option's query", matches)
	}
	if len(options.Sets) != 1 {
		t.Fatalf("got %d sets, want 1", len(options.Sets))
	}
	set := options.Sets[0]
	if len(set.Options) != 2 {
		t.Fatalf("got options %v, want the two satisfiable ones", set.Options)
	}
	if set.Options[0][0] != "pid_sdjwt" || set.Options[1][0] != "pid_mdoc" {
		t.Errorf("options %v are not in the wallet's preference order", set.Options)
	}
	if set.Optional {
		t.Error("a set without required:false is not optional")
	}
	if len(options.Queries) != 2 {
		t.Errorf("both matched queries stay available for the edit view, got %d", len(options.Queries))
	}
}

// A combined option must offer all its required credentials together.
func TestEvaluateDCQLWithOptions_MultiCredentialOption(t *testing.T) {
	w := pidBaselineWallet(t)
	query := map[string]any{
		"credentials": []any{consentPIDQuery("pid_sdjwt", "dc+sd-jwt"), consentPIDQuery("pid_mdoc", "mso_mdoc")},
		"credential_sets": []any{
			map[string]any{"options": []any{[]any{"pid_sdjwt", "pid_mdoc"}, []any{"pid_sdjwt"}}},
		},
	}

	matches, options := evaluateDCQLWithOptions(t, w, query)
	if len(matches) != 2 {
		t.Fatalf("got %d matches, want both credentials of the first option", len(matches))
	}
	if got := options.Sets[0].Options[0]; len(got) != 2 {
		t.Fatalf("first option = %v, want pid_sdjwt+pid_mdoc", got)
	}
}

func TestEvaluateDCQLWithOptions_OptionalSet(t *testing.T) {
	w := pidBaselineWallet(t)
	query := map[string]any{
		"credentials": []any{consentPIDQuery("pid_sdjwt", "dc+sd-jwt"), consentPIDQuery("pid_mdoc", "mso_mdoc")},
		"credential_sets": []any{
			map[string]any{"options": []any{[]any{"pid_sdjwt"}}},
			map[string]any{"options": []any{[]any{"pid_mdoc"}}, "required": false},
		},
	}

	matches, options := evaluateDCQLWithOptions(t, w, query)
	if len(matches) != 2 {
		t.Fatalf("got %d matches, want the required and the optional set answered", len(matches))
	}
	if len(options.Sets) != 2 {
		t.Fatalf("got %d sets, want 2", len(options.Sets))
	}
	if options.Sets[0].Optional || !options.Sets[1].Optional {
		t.Errorf("optional flags = %v/%v, want false/true", options.Sets[0].Optional, options.Sets[1].Optional)
	}
}
