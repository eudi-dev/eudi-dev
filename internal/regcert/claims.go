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

package regcert

import (
	"encoding/json"
	"strings"

	"github.com/eudi-dev/eudi-dev/v3/internal/jsonutil"
)

func numberClaim(v any) (float64, bool) {
	f, ok := v.(float64)
	return f, ok
}

func nonEmptyList(v any) bool {
	list, ok := v.([]any)
	return ok && len(list) > 0
}

// ETSI TS 119 475 permits one or more contact addresses.
func hasContact(v any) bool {
	if jsonutil.Text(v) != "" {
		return true
	}
	return nonEmptyList(v)
}

func hasSupervisoryAuthority(v any) bool {
	m, ok := v.(map[string]any)
	if !ok {
		return false
	}
	return jsonutil.Text(m["email"]) != "" || jsonutil.Text(m["phone"]) != "" || jsonutil.Text(m["uri"]) != ""
}

// InfoEntries reads a verifier_info or issuer_info array. Plain request
// parameters carry verifier_info as a JSON string. issuer_info has the
// structure of verifier_info (ETSI TS 119 472-3 V1.1.1 ISS-MDATA-REG_CERT-4.2.3-03).
func InfoEntries(payload map[string]any, name string) []map[string]any {
	if payload == nil {
		return nil
	}
	raw := payload[name]
	if encoded, ok := raw.(string); ok && encoded != "" {
		var decoded any
		if err := json.Unmarshal([]byte(encoded), &decoded); err == nil {
			raw = decoded
		}
	}
	list, _ := raw.([]any)
	entries := make([]map[string]any, 0, len(list))
	for _, item := range list {
		if entry, ok := item.(map[string]any); ok {
			entries = append(entries, entry)
		}
	}
	return entries
}

// Prefer English, then the first available translation. Certificate entries use value.
// The TS5 data model uses content. Plain strings pass through unchanged.
func purposeStrings(raw any) []string {
	switch value := raw.(type) {
	case string:
		if v := strings.TrimSpace(value); v != "" {
			return []string{v}
		}
	case []any:
		var plain []string
		var first, english string
		for _, item := range value {
			switch entry := item.(type) {
			case string:
				if v := strings.TrimSpace(entry); v != "" {
					plain = append(plain, v)
				}
			case []any:
				// srv_description nests each description in its own array
				// (ETSI TS 119 475 V1.2.1 Annex C).
				plain = append(plain, purposeStrings(entry)...)
			case map[string]any:
				text, _ := entry["value"].(string)
				if text == "" {
					text, _ = entry["content"].(string)
				}
				text = strings.TrimSpace(text)
				if text == "" {
					continue
				}
				if first == "" {
					first = text
				}
				if lang, _ := entry["lang"].(string); strings.HasPrefix(strings.ToLower(lang), "en") && english == "" {
					english = text
				}
			}
		}
		if english != "" {
			return append(plain, english)
		}
		if first != "" {
			return append(plain, first)
		}
		return plain
	}
	return nil
}

func containsPurpose(purposes []string, purpose string) bool {
	for _, p := range purposes {
		if p == purpose {
			return true
		}
	}
	return false
}
