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

	"github.com/dominikschlosser/eudi-dev/v3/internal/dcql"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vp"
)

func sdjwtQuery(id, vct string, claims ...any) map[string]any {
	q := map[string]any{
		"id":     id,
		"format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": []any{vct}},
	}
	if len(claims) > 0 {
		q["claims"] = claims
	}
	return q
}

func mdocQuery(id, docType string, claims ...any) map[string]any {
	q := map[string]any{
		"id":     id,
		"format": "mso_mdoc",
		"meta":   map[string]any{"doctype_value": docType},
	}
	if len(claims) > 0 {
		q["claims"] = claims
	}
	return q
}

// §6.4.2: "If credential_sets is not provided, the Verifier requests
// presentations for all Credentials in credentials to be returned", and "If
// the Wallet cannot deliver all non-optional Credentials requested by the
// Verifier according to these rules, it MUST NOT return any Credential(s)."
func TestEvaluateDCQL_PartialFulfilmentReturnsNoCredential(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			sdjwtQuery("pid", mock.DefaultPIDVCT, map[string]any{"path": []any{"given_name"}}),
			sdjwtQuery("mdl", "urn:eudi:mdl:1", map[string]any{"path": []any{"given_name"}}),
		},
	}

	matches := evaluateDCQL(t, w, query)
	if len(matches) != 0 {
		t.Fatalf("expected no credentials when only one of two required credential queries can be answered, got %d: %+v", len(matches), matches)
	}
}

// The satisfiable part of the query succeeds when requested alone.
func TestEvaluateDCQL_FullFulfilmentStillReturnsCredentials(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			sdjwtQuery("pid", mock.DefaultPIDVCT, map[string]any{"path": []any{"given_name"}}),
			mdocQuery("pid_mdoc", "eu.europa.ec.eudi.pid.1", map[string]any{"path": []any{"eu.europa.ec.eudi.pid.1", "given_name"}}),
		},
	}

	matches := evaluateDCQL(t, w, query)
	if len(matches) != 2 {
		t.Fatalf("expected both credential queries answered, got %d: %+v", len(matches), matches)
	}
}

// The wallet returns nothing when no credential_sets option can be satisfied,
// even for a credential query it can answer. §6.4.2: "To satisfy a
// Credential Set Query, the Wallet MUST return presentations of a set of
// Credentials that match to one of the options inside the Credential Set
// Query."
func TestEvaluateDCQL_OptionalCredentialSetsWithNoSatisfiableOptionReturnNothing(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			sdjwtQuery("pid", mock.DefaultPIDVCT, map[string]any{"path": []any{"given_name"}}),
			sdjwtQuery("mdl", "urn:eudi:mdl:1", map[string]any{"path": []any{"given_name"}}),
		},
		"credential_sets": []any{
			map[string]any{
				"required": false,
				"options":  []any{[]any{"mdl"}},
			},
		},
	}

	matches := evaluateDCQL(t, w, query)
	if len(matches) != 0 {
		t.Fatalf("expected no credentials when no option of any credential set is satisfiable, got %d: %+v", len(matches), matches)
	}
}

func TestEvaluateDCQL_OptionalCredentialSetSelectsSatisfiableOption(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			sdjwtQuery("pid", mock.DefaultPIDVCT, map[string]any{"path": []any{"given_name"}}),
			sdjwtQuery("mdl", "urn:eudi:mdl:1", map[string]any{"path": []any{"given_name"}}),
		},
		"credential_sets": []any{
			map[string]any{
				"required": false,
				"options":  []any{[]any{"mdl"}, []any{"pid"}},
			},
		},
	}

	matches := evaluateDCQL(t, w, query)
	if len(matches) != 1 || matches[0].QueryID != "pid" {
		t.Fatalf("expected only the pid credential query answered, got %+v", matches)
	}
}

// §6.3: "If the values property is present, the Wallet SHOULD return the claim
// only if the type and value of the claim both match exactly for at least one
// of the elements in the array." By §6.4.1 a claim whose value does not match
// "should be treated the same as if it did not exist in the Credential".
func TestEvaluateDCQL_ValuesFilterClaims(t *testing.T) {
	tests := []struct {
		name      string
		claim     map[string]any
		german    bool
		wantMatch bool
	}{
		{
			name:      "string value matches",
			claim:     map[string]any{"path": []any{"given_name"}, "values": []any{"Jan Wijnand"}},
			wantMatch: true,
		},
		{
			name:      "string value differs",
			claim:     map[string]any{"path": []any{"given_name"}, "values": []any{"MAX"}},
			wantMatch: false,
		},
		{
			name:      "one of several values matches",
			claim:     map[string]any{"path": []any{"given_name"}, "values": []any{"MAX", "Jan Wijnand"}},
			wantMatch: true,
		},
		{
			name:      "boolean value matches",
			claim:     map[string]any{"path": []any{"age_equal_or_over", "18"}, "values": []any{true}},
			german:    true,
			wantMatch: true,
		},
		{
			name:      "boolean value differs",
			claim:     map[string]any{"path": []any{"age_equal_or_over", "18"}, "values": []any{false}},
			german:    true,
			wantMatch: false,
		},
		{
			name:      "string does not answer a boolean claim",
			claim:     map[string]any{"path": []any{"age_equal_or_over", "18"}, "values": []any{"true"}},
			german:    true,
			wantMatch: false,
		},
		{
			name:      "number does not answer a string claim",
			claim:     map[string]any{"path": []any{"given_name"}, "values": []any{float64(1)}},
			wantMatch: false,
		},
		{
			name:      "array element matches through a wildcard",
			claim:     map[string]any{"path": []any{"nationalities", nil}, "values": []any{"NL"}},
			wantMatch: true,
		},
		{
			name:      "array element differs through a wildcard",
			claim:     map[string]any{"path": []any{"nationalities", nil}, "values": []any{"FR"}},
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The nested booleans are the age thresholds of the German PID
			// Rulebook.
			vct := mock.DefaultPIDVCT
			if tt.german {
				vct = germanPIDVCT
			}
			w := generateTestWallet(t)
			if err := w.GenerateDefaultCredentials(nil, vct); err != nil {
				t.Fatalf("generating the PID: %v", err)
			}
			query := map[string]any{
				"credentials": []any{sdjwtQuery("pid", vct, tt.claim)},
			}

			matches := evaluateDCQL(t, w, query)
			if tt.wantMatch && len(matches) != 1 {
				t.Fatalf("expected the credential to answer the values restriction, got %d matches", len(matches))
			}
			if !tt.wantMatch && len(matches) != 0 {
				t.Fatalf("expected no match for a claim whose value does not match, got %d: %+v", len(matches), matches)
			}
		})
	}
}

// The same restriction applies to mdoc data elements. The German PID Rulebook
// defines the age thresholds.
func TestEvaluateDCQL_ValuesFilterMDocElements(t *testing.T) {
	w := generateTestWallet(t)
	if err := w.GenerateDefaultCredentials(nil, germanPIDVCT); err != nil {
		t.Fatalf("generating the German PID: %v", err)
	}
	ageNamespace := germanPIDNamespace

	matching := map[string]any{
		"credentials": []any{mdocQuery("pid_mdoc", "eu.europa.ec.eudi.pid.1",
			map[string]any{"path": []any{ageNamespace, "age_over_18"}, "values": []any{true}})},
	}
	if got := evaluateDCQL(t, w, matching); len(got) != 1 {
		t.Fatalf("expected the mdoc to answer age_over_18 = true, got %d matches", len(got))
	}

	differing := map[string]any{
		"credentials": []any{mdocQuery("pid_mdoc", "eu.europa.ec.eudi.pid.1",
			map[string]any{"path": []any{ageNamespace, "age_over_65"}, "values": []any{true}})},
	}
	if got := evaluateDCQL(t, w, differing); len(got) != 0 {
		t.Fatalf("expected no match for age_over_65 = true, got %d: %+v", len(got), got)
	}
}

// §6.3 defines id, path and values for a Claims Query. None of them makes a
// claim optional. §6.4.1: "If the Wallet cannot deliver
// all claims requested by the Verifier according to these rules, it MUST NOT
// return the respective Credential."
func TestEvaluateDCQL_ClaimsQueryHasNoRequiredMember(t *testing.T) {
	w := generateTestWalletWithPID(t)
	w.ValidationMode = ValidationModeStrict

	query := map[string]any{
		"credentials": []any{
			sdjwtQuery("pid", mock.DefaultPIDVCT,
				map[string]any{"path": []any{"given_name"}},
				map[string]any{"path": []any{"nonexistent_claim"}, "required": false},
			),
		},
	}

	matches := evaluateDCQL(t, w, query)
	if len(matches) != 0 {
		t.Fatalf("expected no match: a claim a Verifier asks for is required, got %d: %+v", len(matches), matches)
	}
}

// §7.2.1: "Select the data element referenced by the second component. If the
// data element does not exist in the Credential then abort processing and
// return an error."
//
// birth_place is the encoding-independent identifier in the PID Rulebook. The
// mdoc element is place_of_birth. Treating the two as equal would disclose an
// element outside the request.
func TestEvaluateDCQL_MDocDataElementIsNotAliased(t *testing.T) {
	w := generateTestWalletWithPID(t)

	query := map[string]any{
		"credentials": []any{
			mdocQuery("pid_mdoc", "eu.europa.ec.eudi.pid.1",
				map[string]any{"path": []any{"eu.europa.ec.eudi.pid.1", "birth_place"}}),
		},
	}

	matches := evaluateDCQL(t, w, query)
	if len(matches) != 0 {
		t.Fatalf("expected no match for a data element the credential does not carry, got %d: %+v", len(matches), matches)
	}
}

func TestDCQLQueryFindings(t *testing.T) {
	tests := []struct {
		name  string
		query map[string]any
		want  string
	}{
		{
			name:  "credentials missing",
			query: map[string]any{},
			want:  "credentials is required",
		},
		{
			name:  "credentials empty",
			query: map[string]any{"credentials": []any{}},
			want:  "credentials is required",
		},
		{
			name: "format missing",
			query: map[string]any{"credentials": []any{
				map[string]any{"id": "pid", "meta": map[string]any{}},
			}},
			want: "missing the required format",
		},
		{
			name: "meta missing",
			query: map[string]any{"credentials": []any{
				map[string]any{"id": "pid", "format": "dc+sd-jwt"},
			}},
			want: "missing the required meta",
		},
		{
			name: "meta not an object",
			query: map[string]any{"credentials": []any{
				map[string]any{"id": "pid", "format": "dc+sd-jwt", "meta": "none"},
			}},
			want: "meta that is not an object",
		},
		{
			name: "id empty",
			query: map[string]any{"credentials": []any{
				map[string]any{"id": "", "format": "dc+sd-jwt", "meta": map[string]any{}},
			}},
			want: "must be a non-empty string",
		},
		{
			name: "id has an illegal character",
			query: map[string]any{"credentials": []any{
				map[string]any{"id": "pid.1", "format": "dc+sd-jwt", "meta": map[string]any{}},
			}},
			want: "must be a non-empty string",
		},
		{
			name: "id repeated",
			query: map[string]any{"credentials": []any{
				map[string]any{"id": "pid", "format": "dc+sd-jwt", "meta": map[string]any{}},
				map[string]any{"id": "pid", "format": "mso_mdoc", "meta": map[string]any{}},
			}},
			want: "present more than once",
		},
		{
			name:  "credential query not an object",
			query: map[string]any{"credentials": []any{"pid"}},
			want:  "must be an object",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings := dcql.QueryFindings(tt.query)
			if len(findings) == 0 {
				t.Fatalf("expected a finding mentioning %q, got none", tt.want)
			}
			if !strings.Contains(strings.Join(findings, "; "), tt.want) {
				t.Errorf("expected a finding mentioning %q, got %v", tt.want, findings)
			}
		})
	}
}

func TestDCQLQueryFindings_WellFormedQueryHasNone(t *testing.T) {
	query := map[string]any{
		"credentials": []any{
			sdjwtQuery("pid", mock.DefaultPIDVCT, map[string]any{"path": []any{"given_name"}}),
			mdocQuery("pid-mdoc_1", "eu.europa.ec.eudi.pid.1", map[string]any{"path": []any{"eu.europa.ec.eudi.pid.1", "given_name"}}),
		},
	}

	if findings := dcql.QueryFindings(query); len(findings) > 0 {
		t.Errorf("expected no findings for a well-formed query, got %v", findings)
	}
}

// queryRequest is a valid request for query, so only the query decides the
// outcome.
func queryRequest(query map[string]any) *oid4vp.Request {
	return &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{
		ClientID:     "redirect_uri:https://verifier.example/cb",
		ResponseType: "vp_token",
		ResponseMode: "direct_post",
		ResponseURI:  "https://verifier.example/cb",
		Nonce:        "n",
		DCQLQuery:    query,
	}}
}

func queryWithoutMeta() map[string]any {
	return map[string]any{
		"credentials": []any{
			map[string]any{
				"id":     "pid",
				"format": "dc+sd-jwt",
				"claims": []any{map[string]any{"path": []any{"given_name"}}},
			},
		},
	}
}

// In strict mode the findings are errors. A query without a member that §6.1
// marks REQUIRED is an invalid_request.
func TestStrictRefusesAQueryWithoutMeta(t *testing.T) {
	w := generateTestWalletWithPID(t)
	w.ValidationMode = ValidationModeStrict

	outcome := w.evaluatePresentationRequest(queryRequest(queryWithoutMeta()), presentationEntry{action: "presentation", subject: "The request"})
	if outcome.invalid == nil || outcome.invalidCode != oid4vp.ErrorInvalidRequest || !strings.Contains(outcome.invalid.Error(), "missing the required meta") {
		t.Fatalf("want an invalid_request naming the missing meta, got %v (%s)", outcome.invalid, outcome.invalidCode)
	}
}

// Debug mode reports the same findings as warnings and continues, so a
// developer can watch the rest of the exchange.
func TestDebugWarnsAboutAQueryWithoutMeta(t *testing.T) {
	w := generateTestWalletWithPID(t)
	w.ValidationMode = ValidationModeDebug

	authReq := queryRequest(queryWithoutMeta())
	outcome := w.evaluatePresentationRequest(authReq, presentationEntry{action: "presentation", subject: "The request"})
	if len(outcome.matches) != 1 {
		t.Fatalf("expected debug mode to keep evaluating, got %d matches", len(outcome.matches))
	}
	if !slices.ContainsFunc(authReq.Findings, func(f string) bool { return strings.Contains(f, "missing the required meta") }) {
		t.Errorf("findings = %v, want the missing meta", authReq.Findings)
	}
}
