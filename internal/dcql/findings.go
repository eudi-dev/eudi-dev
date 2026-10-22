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
	"fmt"

	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
)

// QueryFindings reports where a DCQL query departs from OID4VP 1.0 §6.
// Strict mode refuses the query. Debug mode logs the findings and evaluates
// the query as far as it can.
func QueryFindings(query map[string]any) []string {
	if query == nil {
		return nil
	}

	// §6: "credentials: REQUIRED. A non-empty array of Credential Queries as
	// defined in Section 6.1 that specify the requested Credentials."
	credQueries, ok := query["credentials"].([]any)
	if !ok || len(credQueries) == 0 {
		return []string{"OID4VP 1.0 §6: dcql_query.credentials is required and must be a non-empty array"}
	}

	var findings []string
	seen := make(map[string]bool, len(credQueries))
	for i, cq := range credQueries {
		cqMap, ok := cq.(map[string]any)
		if !ok {
			findings = append(findings, fmt.Sprintf("OID4VP 1.0 §6: dcql_query.credentials[%d] must be an object", i))
			continue
		}

		// §6.1: "id: REQUIRED. [...] The value MUST be a non-empty string
		// consisting of alphanumeric, underscore (_), or hyphen (-)
		// characters. Within the Authorization Request, the same id MUST NOT
		// be present more than once."
		id, _ := cqMap["id"].(string)
		switch {
		case !isIdentifier(id):
			findings = append(findings, fmt.Sprintf(
				"OID4VP 1.0 §6.1: dcql_query.credentials[%d].id must be a non-empty string of alphanumeric, underscore or hyphen characters, got %q", i, id))
		case seen[id]:
			findings = append(findings, fmt.Sprintf("OID4VP 1.0 §6.1: the credential query id %q is present more than once", id))
		default:
			seen[id] = true
		}

		label := id
		if label == "" {
			label = fmt.Sprintf("credentials[%d]", i)
		}

		// §6.1: "format: REQUIRED. A string that specifies the format of the
		// requested Credential."
		if f, _ := cqMap["format"].(string); f == "" {
			findings = append(findings, fmt.Sprintf("OID4VP 1.0 §6.1: the credential query %q is missing the required format", label))
		}

		// §6.1: "multiple: OPTIONAL. A boolean".
		if m, present := cqMap["multiple"]; present {
			if _, ok := m.(bool); !ok {
				findings = append(findings, fmt.Sprintf("OID4VP 1.0 §6.1: the credential query %q has a multiple that is not a boolean", label))
			}
		}

		// §6.1: "require_cryptographic_holder_binding: OPTIONAL. A boolean".
		if b, present := cqMap["require_cryptographic_holder_binding"]; present {
			if _, ok := b.(bool); !ok {
				findings = append(findings, fmt.Sprintf("OID4VP 1.0 §6.1: the credential query %q has a require_cryptographic_holder_binding that is not a boolean", label))
			}
		}

		// §6.1 makes meta REQUIRED. An empty object places no constraints.
		meta, present := cqMap["meta"]
		if !present {
			findings = append(findings, fmt.Sprintf("OID4VP 1.0 §6.1: the credential query %q is missing the required meta (use an empty object to place no constraints)", label))
		} else if _, ok := meta.(map[string]any); !ok {
			findings = append(findings, fmt.Sprintf("OID4VP 1.0 §6.1: the credential query %q has a meta that is not an object", label))
		}

		findings = append(findings, claimFindings(label, cqMap)...)
		findings = append(findings, trustedAuthorityFindings(label, cqMap)...)
	}
	return append(findings, credentialSetFindings(query, seen)...)
}

// claimFindings checks claims (§6.3) and claim_sets (§6.1) of one credential
// query.
func claimFindings(label string, cqMap map[string]any) []string {
	rawClaims, hasClaims := cqMap["claims"]
	rawSets, hasSets := cqMap["claim_sets"]
	if !hasClaims {
		if hasSets {
			return []string{fmt.Sprintf("OID4VP 1.0 §6.4.1: the credential query %q has claim_sets without claims", label)}
		}
		return nil
	}
	// §6.1: "claims: OPTIONAL. A non-empty array of objects".
	claims, ok := rawClaims.([]any)
	if !ok || len(claims) == 0 {
		return []string{fmt.Sprintf("OID4VP 1.0 §6.1: the credential query %q has claims that are not a non-empty array", label)}
	}

	var findings []string
	ids := make(map[string]bool, len(claims))
	for i, raw := range claims {
		claim, ok := raw.(map[string]any)
		if !ok {
			findings = append(findings, fmt.Sprintf("OID4VP 1.0 §6.3: claim %d of the credential query %q is not an object", i, label))
			continue
		}
		// §6.3: path is REQUIRED and "MUST be a non-empty array".
		if path, ok := claim["path"].([]any); !ok || len(path) == 0 {
			findings = append(findings, fmt.Sprintf("OID4VP 1.0 §6.3: claim %d of the credential query %q needs a path as a non-empty array", i, label))
		}
		// §6.3: id is "REQUIRED if claim_sets is present in the Credential
		// Query". "Within the particular claims array, the same id MUST NOT be
		// present more than once."
		rawID, hasID := claim["id"]
		id, _ := rawID.(string)
		switch {
		case !hasID && hasSets:
			findings = append(findings, fmt.Sprintf("OID4VP 1.0 §6.3: claim %d of the credential query %q needs an id, because the query has claim_sets", i, label))
		case !hasID:
		case !isIdentifier(id):
			findings = append(findings, fmt.Sprintf("OID4VP 1.0 §6.3: claim %d of the credential query %q has the id %v. A claim id must be a non-empty string of letters, digits, underscores or hyphens", i, label, rawID))
		case ids[id]:
			findings = append(findings, fmt.Sprintf("OID4VP 1.0 §6.3: the claim id %q is present more than once in the credential query %q", id, label))
		default:
			ids[id] = true
		}
	}

	if !hasSets {
		return findings
	}
	// §6.1: claim_sets is "A non-empty array containing arrays of identifiers
	// for elements in claims".
	sets, ok := rawSets.([]any)
	if !ok || len(sets) == 0 {
		return append(findings, fmt.Sprintf("OID4VP 1.0 §6.1: the credential query %q has claim_sets that are not a non-empty array", label))
	}
	for i, raw := range sets {
		set, ok := raw.([]any)
		if !ok || len(set) == 0 {
			findings = append(findings, fmt.Sprintf("OID4VP 1.0 §6.1: claim_sets[%d] of the credential query %q is not a non-empty array of claim ids", i, label))
			continue
		}
		for _, ref := range set {
			if id, _ := ref.(string); !ids[id] {
				findings = append(findings, fmt.Sprintf("OID4VP 1.0 §6.1: claim_sets[%d] of the credential query %q references %v, but that query has no such claim id", i, label, ref))
			}
		}
	}
	return findings
}

// trustedAuthorityFindings checks trusted_authorities of one credential query
// against §6.1 and §6.1.1. Other specifications may define more types, so an
// unimplemented type is no finding.
func trustedAuthorityFindings(label string, cqMap map[string]any) []string {
	raw, present := cqMap["trusted_authorities"]
	if !present {
		return nil
	}
	// §6.1: "A non-empty array of objects as defined in Section 6.1.1".
	authorities, ok := raw.([]any)
	if !ok || len(authorities) == 0 {
		return []string{fmt.Sprintf("OID4VP 1.0 §6.1: the credential query %q has trusted_authorities that are not a non-empty array", label)}
	}
	var findings []string
	for i, entry := range authorities {
		authority, ok := entry.(map[string]any)
		if !ok {
			findings = append(findings, fmt.Sprintf("OID4VP 1.0 §6.1.1: trusted_authorities[%d] of the credential query %q is not an object", i, label))
			continue
		}
		// §6.1.1: type is "REQUIRED. A string". values is "REQUIRED. A
		// non-empty array of strings".
		if typ, _ := authority["type"].(string); typ == "" {
			findings = append(findings, fmt.Sprintf("OID4VP 1.0 §6.1.1: trusted_authorities[%d] of the credential query %q has no type", i, label))
		}
		values, ok := authority["values"].([]any)
		if !ok || len(values) == 0 || !allNonEmptyStrings(values) {
			findings = append(findings, fmt.Sprintf("OID4VP 1.0 §6.1.1: trusted_authorities[%d] of the credential query %q needs values as a non-empty array of strings", i, label))
		}
	}
	return findings
}

// credentialSetFindings checks credential_sets against §6 and §6.2. ids are
// the credential query ids of the query.
func credentialSetFindings(query map[string]any, ids map[string]bool) []string {
	raw, present := query["credential_sets"]
	if !present {
		return nil
	}
	// §6: "credential_sets: OPTIONAL. A non-empty array of Credential Set
	// Queries".
	sets, ok := raw.([]any)
	if !ok || len(sets) == 0 {
		return []string{"OID4VP 1.0 §6: dcql_query.credential_sets must be a non-empty array"}
	}
	var findings []string
	for i, entry := range sets {
		set, ok := entry.(map[string]any)
		if !ok {
			findings = append(findings, fmt.Sprintf("OID4VP 1.0 §6.2: credential_sets[%d] is not an object", i))
			continue
		}
		// §6.2: options is "REQUIRED A non-empty array, where each value in the
		// array is a list of Credential Query identifiers".
		options, ok := set["options"].([]any)
		if !ok || len(options) == 0 {
			findings = append(findings, fmt.Sprintf("OID4VP 1.0 §6.2: credential_sets[%d] needs options as a non-empty array", i))
			continue
		}
		for j, rawOption := range options {
			option, ok := rawOption.([]any)
			if !ok || len(option) == 0 {
				findings = append(findings, fmt.Sprintf("OID4VP 1.0 §6.2: credential_sets[%d].options[%d] is not a non-empty array of credential query ids", i, j))
				continue
			}
			for _, ref := range option {
				if id, _ := ref.(string); !ids[id] {
					findings = append(findings, fmt.Sprintf("OID4VP 1.0 §6.2: credential_sets[%d].options[%d] references %v, but there is no credential query with that id", i, j, ref))
				}
			}
		}
		// §6.2: "required: OPTIONAL A boolean".
		if required, present := set["required"]; present {
			if _, ok := required.(bool); !ok {
				findings = append(findings, fmt.Sprintf("OID4VP 1.0 §6.2: credential_sets[%d] has a required that is not a boolean", i))
			}
		}
	}
	return findings
}

// DomesticPIDAdvisories warns about an SD-JWT VC query that requests
// urn:eudi:pid:1 without any domestic PID type. ARF Annex 2 PID_14 makes a
// domestic PID extend the base type, but OpenID4VP 1.0 Appendix B.3.5 only
// says "The Wallet MAY return Credentials that inherit from any of the
// specified types".
func DomesticPIDAdvisories(query map[string]any) []string {
	credQueries, _ := query["credentials"].([]any)
	var advisories []string
	for _, cq := range credQueries {
		cqMap, _ := cq.(map[string]any)
		meta, _ := cqMap["meta"].(map[string]any)
		vctValues, _ := meta["vct_values"].([]any)
		base, domestic := false, false
		for _, v := range vctValues {
			vct, _ := v.(string)
			_, extends := credtype.Extends(vct)
			base = base || vct == credtype.PIDVCT
			domestic = domestic || extends
		}
		if base && !domestic {
			id, _ := cqMap["id"].(string)
			advisories = append(advisories, fmt.Sprintf("OID4VP 1.0 Appendix B.3.5: the credential query %q requests %s without a domestic PID type. Other wallets may not answer it with a domestic PID such as urn:eudi:pid:de:1. List the accepted domestic types in vct_values", id, credtype.PIDVCT))
		}
	}
	return advisories
}

func allNonEmptyStrings(values []any) bool {
	for _, value := range values {
		if text, _ := value.(string); text == "" {
			return false
		}
	}
	return true
}

// isIdentifier checks the id syntax of OID4VP 1.0 §6.1: "a non-empty
// string consisting of alphanumeric, underscore (_), or hyphen (-)
// characters".
func isIdentifier(id string) bool {
	if id == "" {
		return false
	}
	for _, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}
