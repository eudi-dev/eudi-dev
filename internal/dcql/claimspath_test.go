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
	"reflect"
	"testing"
)

// OID4VP 1.0 §7.1.1 defines the processing of a claims path pointer. The
// wallet's matching, value matching and disclosure and the verifier's check of
// a presentation all use it.
func TestSelectClaimsFollowsTheProcessingRules(t *testing.T) {
	root := map[string]any{
		"address": map[string]any{"locality": "Berlin", "postal_code": "10115"},
		"degrees": []any{
			map[string]any{"type": "BA", "year": float64(2019)},
			map[string]any{"type": "MA"},
		},
		"nicknames": []any{"Ada", "Addy"},
		"empty":     []any{},
		"nothing":   nil,
		"mixed":     []any{map[string]any{"type": "BA"}, "scalar"},
	}

	tests := []struct {
		name string
		path []any
		want []any
	}{
		{"a nested object", []any{"address", "locality"}, []any{"Berlin"}},
		{"an array element", []any{"degrees", float64(0), "type"}, []any{"BA"}},
		{"an int index", []any{"degrees", 1, "type"}, []any{"MA"}},
		{"every element", []any{"nicknames", nil}, []any{"Ada", "Addy"}},
		{"a member of every element", []any{"degrees", nil, "year"}, []any{float64(2019)}},
		{"a claim whose value is null", []any{"nothing"}, []any{nil}},

		{"an empty path", nil, nil},
		{"a key that is not there", []any{"address", "country"}, nil},
		{"descending into a scalar", []any{"address", "locality", "deeper"}, nil},
		{"an index past the end", []any{"degrees", float64(9)}, nil},
		{"a negative index", []any{"degrees", float64(-1)}, nil},
		{"a fractional index", []any{"degrees", 0.5}, nil},
		{"an index into an object", []any{"address", float64(0)}, nil},
		{"null over an object", []any{"address", nil}, nil},
		{"null over an empty array", []any{"empty", nil}, nil},
		{"a key under a non-object element", []any{"mixed", nil, "type"}, nil},
		{"a component of another type", []any{true}, nil},
		{"null over null", []any{"nothing", nil}, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := SelectClaims(root, tt.path)
			if ok != (tt.want != nil) {
				t.Fatalf("ok = %v, selection %#v, want %#v", ok, got, tt.want)
			}
			if ok && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("selection = %#v, want %#v", got, tt.want)
			}
		})
	}
}
