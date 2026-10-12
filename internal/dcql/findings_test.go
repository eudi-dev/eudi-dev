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

package dcql

import (
	"strings"
	"testing"
)

// credentialQuery is a well-formed credential query with the given members
// added. A nil value removes a member.
func credentialQuery(id string, members map[string]any) map[string]any {
	cq := map[string]any{
		"id":     id,
		"format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
		"claims": []any{
			map[string]any{"id": "given", "path": []any{"given_name"}},
			map[string]any{"id": "family", "path": []any{"family_name"}},
		},
	}
	for k, v := range members {
		if v == nil {
			delete(cq, k)
		} else {
			cq[k] = v
		}
	}
	return cq
}

// OID4VP 1.0 §6, §6.1, §6.1.1, §6.2 and §6.3 define the shape of claims,
// claim_sets, trusted_authorities and credential_sets.
func TestQueryFindingsChecksTheNestedQueries(t *testing.T) {
	for _, tt := range []struct {
		name  string
		query map[string]any
		want  string
	}{
		{"well formed", map[string]any{
			"credentials": []any{credentialQuery("pid", map[string]any{
				"claim_sets":          []any{[]any{"given", "family"}, []any{"given"}},
				"trusted_authorities": []any{map[string]any{"type": "aki", "values": []any{"s9tIpPmhxdiuNkHMEWNpYim8S8Y"}}},
			})},
			"credential_sets": []any{map[string]any{"options": []any{[]any{"pid"}}, "required": true}},
		}, ""},
		{"claim without path", map[string]any{"credentials": []any{credentialQuery("pid", map[string]any{
			"claims": []any{map[string]any{"id": "given"}},
		})}}, "has no path"},
		{"claim with an empty path", map[string]any{"credentials": []any{credentialQuery("pid", map[string]any{
			"claims": []any{map[string]any{"path": []any{}}},
		})}}, "has no path"},
		{"duplicate claim id", map[string]any{"credentials": []any{credentialQuery("pid", map[string]any{
			"claims": []any{map[string]any{"id": "x", "path": []any{"a"}}, map[string]any{"id": "x", "path": []any{"b"}}},
		})}}, `claim id "x" is present more than once`},
		{"claim id with a space", map[string]any{"credentials": []any{credentialQuery("pid", map[string]any{
			"claims": []any{map[string]any{"id": "given name", "path": []any{"a"}}},
		})}}, "alphanumeric"},
		{"empty claims", map[string]any{"credentials": []any{credentialQuery("pid", map[string]any{
			"claims": []any{},
		})}}, "claims that are not a non-empty array"},
		{"claim_sets without claims", map[string]any{"credentials": []any{credentialQuery("pid", map[string]any{
			"claims": nil, "claim_sets": []any{[]any{"given"}},
		})}}, "claim_sets without claims"},
		{"claim without id under claim_sets", map[string]any{"credentials": []any{credentialQuery("pid", map[string]any{
			"claims":     []any{map[string]any{"path": []any{"given_name"}}},
			"claim_sets": []any{[]any{"given"}},
		})}}, "needs an id"},
		{"claim_sets with an unknown id", map[string]any{"credentials": []any{credentialQuery("pid", map[string]any{
			"claim_sets": []any{[]any{"given", "nickname"}},
		})}}, "references nickname"},
		{"empty claim set", map[string]any{"credentials": []any{credentialQuery("pid", map[string]any{
			"claim_sets": []any{[]any{}},
		})}}, "claim_sets[0]"},
		{"trusted authority without values", map[string]any{"credentials": []any{credentialQuery("pid", map[string]any{
			"trusted_authorities": []any{map[string]any{"type": "aki"}},
		})}}, "needs values"},
		{"trusted authority without type", map[string]any{"credentials": []any{credentialQuery("pid", map[string]any{
			"trusted_authorities": []any{map[string]any{"values": []any{"abc"}}},
		})}}, "has no type"},
		{"empty trusted_authorities", map[string]any{"credentials": []any{credentialQuery("pid", map[string]any{
			"trusted_authorities": []any{},
		})}}, "trusted_authorities that are not a non-empty array"},
		{"credential set with an unknown id", map[string]any{
			"credentials":     []any{credentialQuery("pid", nil)},
			"credential_sets": []any{map[string]any{"options": []any{[]any{"pid", "mdl"}}}},
		}, "references mdl"},
		{"credential set without options", map[string]any{
			"credentials":     []any{credentialQuery("pid", nil)},
			"credential_sets": []any{map[string]any{"options": []any{}}},
		}, "needs options"},
		{"empty credential set option", map[string]any{
			"credentials":     []any{credentialQuery("pid", nil)},
			"credential_sets": []any{map[string]any{"options": []any{[]any{}}}},
		}, "options[0] is not a non-empty array"},
		{"empty credential_sets", map[string]any{
			"credentials":     []any{credentialQuery("pid", nil)},
			"credential_sets": []any{},
		}, "credential_sets must be a non-empty array"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := strings.Join(QueryFindings(tt.query), "\n")
			if tt.want == "" {
				if got != "" {
					t.Fatalf("findings %q, want none", got)
				}
				return
			}
			if !strings.Contains(got, tt.want) {
				t.Fatalf("findings %q, want %q", got, tt.want)
			}
		})
	}
}

// A well-formed trusted authority of a type this wallet does not implement,
// such as openid_federation, is no finding.
func TestQueryFindingsAcceptsAnUnknownTrustedAuthorityType(t *testing.T) {
	query := map[string]any{"credentials": []any{credentialQuery("pid", map[string]any{
		"trusted_authorities": []any{map[string]any{"type": "openid_federation", "values": []any{"https://trust.example"}}},
	})}}
	if findings := QueryFindings(query); len(findings) != 0 {
		t.Errorf("findings %v, want none", findings)
	}
}
