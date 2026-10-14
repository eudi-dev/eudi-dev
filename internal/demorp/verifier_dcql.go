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
	"encoding/json"
	"fmt"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/dcql"
)

// claimQuery is one DCQL claims query (OpenID4VP 1.0 §6.3).
type claimQuery struct {
	id     string
	path   []any
	values []any
}

// parseDCQLQuery reads the DCQL query from the verifier page. The request
// sends it unchanged, and the response is checked against it.
func parseDCQLQuery(raw map[string]any) ([]credentialQuery, []credentialSet, error) {
	if findings := dcql.QueryFindings(raw); len(findings) > 0 {
		return nil, nil, fmt.Errorf("the DCQL query is invalid: %s", strings.Join(findings, ". "))
	}
	var queries []credentialQuery
	for _, entry := range raw["credentials"].([]any) {
		cq, _ := entry.(map[string]any)
		q := credentialQuery{}
		q.id, _ = cq["id"].(string)
		q.resultKey = q.id
		q.format, _ = cq["format"].(string)
		q.multiple, _ = cq["multiple"].(bool)
		meta, _ := cq["meta"].(map[string]any)
		switch q.format {
		case credtype.FormatSDJWT:
			for _, v := range asSlice(meta["vct_values"]) {
				if s, ok := v.(string); ok && s != "" {
					q.vcts = append(q.vcts, s)
				}
			}
			if len(q.vcts) == 0 {
				return nil, nil, fmt.Errorf("the credential query %q needs meta.vct_values", q.id)
			}
		case credtype.FormatMDOC:
			q.docType, _ = meta["doctype_value"].(string)
			if q.docType == "" {
				return nil, nil, fmt.Errorf("the credential query %q needs meta.doctype_value", q.id)
			}
		default:
			return nil, nil, fmt.Errorf("the demo verifier checks dc+sd-jwt and mso_mdoc credentials. The credential query %q asks for %q", q.id, q.format)
		}
		q.claims = []claimQuery{}
		for _, c := range asSlice(cq["claims"]) {
			cm, _ := c.(map[string]any)
			claim := claimQuery{path: asSlice(cm["path"]), values: asSlice(cm["values"])}
			claim.id, _ = cm["id"].(string)
			q.claims = append(q.claims, claim)
		}
		for _, set := range asSlice(cq["claim_sets"]) {
			var ids []string
			for _, id := range asSlice(set) {
				if s, ok := id.(string); ok {
					ids = append(ids, s)
				}
			}
			q.claimSets = append(q.claimSets, ids)
		}
		for _, ta := range asSlice(cq["trusted_authorities"]) {
			if m, ok := ta.(map[string]any); ok {
				q.trustedAuthorities = append(q.trustedAuthorities, m)
			}
		}
		queries = append(queries, q)
	}

	var sets []credentialSet
	for _, entry := range asSlice(raw["credential_sets"]) {
		cs, _ := entry.(map[string]any)
		set := credentialSet{}
		// §6.2: required defaults to true.
		if required, ok := cs["required"].(bool); ok && !required {
			set.optional = true
		}
		for _, option := range asSlice(cs["options"]) {
			var ids []string
			for _, id := range asSlice(option) {
				if s, ok := id.(string); ok {
					ids = append(ids, s)
				}
			}
			set.options = append(set.options, ids)
		}
		sets = append(sets, set)
	}
	return queries, sets, nil
}

func asSlice(v any) []any {
	s, _ := v.([]any)
	return s
}

// typeValues lists the credential types an SD-JWT VC query accepts.
func (q credentialQuery) typeValues() []string {
	if len(q.vcts) > 0 {
		return q.vcts
	}
	return []string{q.vct}
}

// claimQueries lists the claims of the query. The ticket and PID requests
// have paths only.
func (q credentialQuery) claimQueries() []claimQuery {
	if q.claims != nil {
		return q.claims
	}
	claims := make([]claimQuery, len(q.paths))
	for i, path := range q.paths {
		claims[i] = claimQuery{path: path}
	}
	return claims
}

// checkClaims checks the presented claims against the query and names the
// check. Without claim_sets every claim is required. With them, one claim set
// must be complete (OpenID4VP 1.0 §6.4.1).
func (q credentialQuery) checkClaims(presented map[string]any, plain string) (string, error) {
	claims := q.claimQueries()
	if len(q.claimSets) == 0 {
		var missing []string
		for _, c := range claims {
			if !claimPresent(presented, c) {
				missing = append(missing, c.String())
			}
		}
		return plain, errIf(len(missing) > 0, "missing: %s", strings.Join(missing, ", "))
	}
	byID := make(map[string]claimQuery, len(claims))
	for _, c := range claims {
		byID[c.id] = c
	}
	var described []string
	for i, set := range q.claimSets {
		complete := true
		for _, id := range set {
			if !claimPresent(presented, byID[id]) {
				complete = false
				break
			}
		}
		if complete {
			return fmt.Sprintf("claim set %d of %d was disclosed (%s)", i+1, len(q.claimSets), strings.Join(set, ", ")), nil
		}
		described = append(described, "["+strings.Join(set, ", ")+"]")
	}
	return "a requested claim set was disclosed", fmt.Errorf("no claim set is complete: %s", strings.Join(described, " or "))
}

// String names the claim by its path and, if given, its allowed values.
func (c claimQuery) String() string {
	name := dcql.ClaimPathString(c.path)
	if len(c.values) == 0 {
		return name
	}
	values := make([]string, len(c.values))
	for i, v := range c.values {
		values[i] = fmt.Sprint(v)
	}
	return name + " (one of " + strings.Join(values, ", ") + ")"
}

// claimPresent reports whether the claim was presented. A claim with values
// must have one of them (OpenID4VP 1.0 §6.3).
func claimPresent(presented map[string]any, c claimQuery) bool {
	if len(c.path) == 0 {
		return false
	}
	selected, ok := dcql.SelectClaims(presented, c.path)
	if !ok {
		return false
	}
	if len(c.values) == 0 {
		return true
	}
	for _, got := range selected {
		for _, want := range c.values {
			if sameJSON(got, want) {
				return true
			}
		}
	}
	return false
}

// sameJSON compares two values in their JSON form, so an mdoc integer equals
// the same number from the query.
func sameJSON(a, b any) bool {
	ja, errA := json.Marshal(a)
	jb, errB := json.Marshal(b)
	return errA == nil && errB == nil && string(ja) == string(jb)
}
