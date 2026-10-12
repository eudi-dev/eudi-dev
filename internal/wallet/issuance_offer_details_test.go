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
	"reflect"
	"testing"
)

// The consent dialog shows each offered claim by its display name from the
// issuer metadata, in the OpenID4VCI 1.0 claims array and in the nested object
// of earlier drafts.
func TestConfigurationClaimsDisplayNames(t *testing.T) {
	for _, tc := range []struct {
		name      string
		raw       any
		wantPaths []string
		wantNames map[string]string
	}{
		{
			name: "claims array",
			raw: []any{
				map[string]any{"path": []any{"given_name"}, "display": []any{
					map[string]any{"name": "Given name", "locale": "en-US"},
					map[string]any{"name": "Vorname", "locale": "de-DE"},
				}},
				map[string]any{"path": []any{"address", "street_address"}, "display": []any{map[string]any{"name": "Street"}}},
				map[string]any{"path": []any{"tier"}},
				map[string]any{"path": []any{"seat"}, "display": []any{map[string]any{"name": "  "}}},
			},
			wantPaths: []string{"given_name", "address.street_address", "tier", "seat"},
			wantNames: map[string]string{"given_name": "Given name", "address.street_address": "Street"},
		},
		{
			name: "nested object",
			raw: map[string]any{
				"tier":       map[string]any{},
				"given_name": map[string]any{"display": []any{map[string]any{"name": "Given name"}}},
			},
			wantPaths: []string{"given_name", "tier"},
			wantNames: map[string]string{"given_name": "Given name"},
		},
		{
			name:      "no display names",
			raw:       []any{map[string]any{"path": []any{"tier"}}},
			wantPaths: []string{"tier"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			paths, names := configurationClaims(tc.raw)
			if !reflect.DeepEqual(paths, tc.wantPaths) {
				t.Errorf("paths = %v, want %v", paths, tc.wantPaths)
			}
			if !reflect.DeepEqual(names, tc.wantNames) {
				t.Errorf("display names = %v, want %v", names, tc.wantNames)
			}
		})
	}
}
