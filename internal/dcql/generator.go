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
	"sort"
	"strings"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtype"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mdoc"
	"github.com/dominikschlosser/eudi-dev/v3/internal/sdjwt"
)

func FromSDJWT(token *sdjwt.Token) *Query {
	return fromJWTToken(token, credtype.FormatSDJWT)
}

func FromJWT(token *sdjwt.Token) *Query {
	return fromJWTToken(token, credtype.FormatJWTVC)
}

func fromJWTToken(token *sdjwt.Token, credFormat string) *Query {
	vct := ""
	if v, ok := token.ResolvedClaims["vct"].(string); ok {
		vct = v
	}

	id := sanitizeID(vct)
	if id == "" {
		id = "credential_0"
	}

	claims := extractSDJWTClaims(token.ResolvedClaims)

	cq := CredentialQuery{
		ID:     id,
		Format: credFormat,
		Claims: claims,
	}

	if vct != "" {
		cq.Meta.VCTValues = []string{vct}
	}

	return &Query{Credentials: []CredentialQuery{cq}}
}

func FromMDOC(doc *mdoc.Document) *Query {
	id := sanitizeID(doc.DocType)
	if id == "" {
		id = "credential_0"
	}

	var claims []ClaimQuery
	namespaces := sortedKeys(doc.NameSpaces)
	for _, ns := range namespaces {
		// Sorting doc.NameSpaces[ns] in place reorders the caller's document.
		items := append([]mdoc.IssuerSignedItem(nil), doc.NameSpaces[ns]...)
		sort.Slice(items, func(i, j int) bool {
			return items[i].ElementIdentifier < items[j].ElementIdentifier
		})
		for _, item := range items {
			claims = append(claims, ClaimQuery{
				Path: []any{ns, item.ElementIdentifier},
			})
		}
	}

	cq := CredentialQuery{
		ID:     id,
		Format: credtype.FormatMDOC,
		Claims: claims,
	}

	if doc.DocType != "" {
		cq.Meta.DoctypeValue = doc.DocType
	}

	return &Query{Credentials: []CredentialQuery{cq}}
}

func extractSDJWTClaims(claims map[string]any) []ClaimQuery {
	var result []ClaimQuery

	keys := sortedKeys(claims)
	for _, k := range keys {
		if sdjwt.IsProtocolClaim(k) {
			continue
		}
		prefix := []any{k}
		result = append(result, extractPaths(prefix, claims[k])...)
	}

	return result
}

func extractPaths(prefix []any, v any) []ClaimQuery {
	switch val := v.(type) {
	case map[string]any:
		var result []ClaimQuery
		keys := sortedKeys(val)
		for _, k := range keys {
			if k == "_sd" || k == "_sd_alg" {
				continue
			}
			path := append(append([]any{}, prefix...), k)
			result = append(result, extractPaths(path, val[k])...)
		}
		if len(result) == 0 {
			// An object with only _sd entries has no visible sub-claims, so the query requests the object.
			return []ClaimQuery{{Path: prefix}}
		}
		return result
	case []any:
		path := append(append([]any{}, prefix...), nil)
		return []ClaimQuery{{Path: path}}
	default:
		return []ClaimQuery{{Path: prefix}}
	}
}

// sanitizeID turns a credential type into a Credential Query id.
//
// OID4VP 1.0 Section 6.1: the id "MUST be a non-empty string consisting of
// alphanumeric, underscore (_), or hyphen (-) characters". Every other
// character becomes an underscore.
func sanitizeID(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := strings.TrimLeft(b.String(), "_")
	if len(out) > 50 {
		out = out[:50]
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
