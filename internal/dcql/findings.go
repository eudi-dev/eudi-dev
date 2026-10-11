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

import "fmt"

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
	}
	return findings
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
