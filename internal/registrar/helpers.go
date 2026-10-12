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

package registrar

import (
	"slices"
	"strings"
)

// CredentialTypes reads the types of a DCQL meta object. SD-JWT VC uses
// vct_values and mdoc doctype_value. A W3C credential lists alternative type
// sets in type_values (OpenID4VP 1.0 §B.1.1). Each set becomes one type: its
// sorted members joined by spaces. An IRI cannot contain a space.
func CredentialTypes(meta any) []string {
	m, ok := meta.(map[string]any)
	if !ok {
		return nil
	}
	types := stringList(m["vct_values"])
	if s, ok := m["doctype_value"].(string); ok && s != "" {
		types = append(types, s)
	}
	if sets, ok := m["type_values"].([]any); ok {
		for _, set := range sets {
			if members := stringList(set); len(members) > 0 {
				slices.Sort(members)
				types = append(types, strings.Join(members, " "))
			}
		}
	}
	return types
}

func stringList(value any) []string {
	switch values := value.(type) {
	case []string:
		return slices.Clone(values)
	case []any:
		var out []string
		for _, v := range values {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

func dedupeStrings(values []string) []string {
	out := make([]string, 0, len(values))
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" && !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	slices.Sort(out)
	return out
}
