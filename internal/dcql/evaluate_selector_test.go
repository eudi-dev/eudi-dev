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

// Incorrect path parsing can disclose an unrequested claim or hide a valid match.
func TestParseSDJWTSelector(t *testing.T) {
	tests := []struct {
		selector string
		want     []any
		wantOK   bool
	}{
		{selector: "given_name", want: []any{"given_name"}, wantOK: true},
		{selector: "address.locality", want: []any{"address", "locality"}, wantOK: true},
		{selector: "a.b.c", want: []any{"a", "b", "c"}, wantOK: true},
		{selector: "degrees[0]", want: []any{"degrees", 0}, wantOK: true},
		{selector: "degrees[0].type", want: []any{"degrees", 0, "type"}, wantOK: true},
		{selector: "degrees[*]", want: []any{"degrees", nil}, wantOK: true},
		{selector: "degrees[*].type", want: []any{"degrees", nil, "type"}, wantOK: true},
		{selector: "a[0][1]", want: []any{"a", 0, 1}, wantOK: true},

		{selector: "", wantOK: false},
		{selector: ".", wantOK: false},
		{selector: ".leading", wantOK: false},
		{selector: "a[]", wantOK: false},
		{selector: "a[x]", wantOK: false},
		{selector: "a[0", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.selector, func(t *testing.T) {
			got, ok := ParseSDJWTSelector(tt.selector)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (got %#v)", ok, tt.wantOK, got)
			}
			if tt.wantOK && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("path = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestClaimValueBySelector(t *testing.T) {
	sdjwt := Credential{
		Format: "dc+sd-jwt",
		Claims: map[string]any{
			"given_name": "Ada",
			"address":    map[string]any{"locality": "Berlin"},
		},
	}
	// Stored mdoc claims are already split from their namespace, so the
	// selector is the bare element identifier.
	mdocCred := Credential{
		Format: "mso_mdoc",
		Claims: map[string]any{"given_name": "Ada"},
	}

	tests := []struct {
		name     string
		cred     Credential
		selector string
		want     any
		wantOK   bool
	}{
		{name: "a top level claim", cred: sdjwt, selector: "given_name", want: "Ada", wantOK: true},
		{name: "a nested claim", cred: sdjwt, selector: "address.locality", want: "Berlin", wantOK: true},
		{name: "a claim that is absent", cred: sdjwt, selector: "family_name", wantOK: false},
		{name: "an unparseable selector", cred: sdjwt, selector: "", wantOK: false},
		{name: "a selector that starts with an index", cred: sdjwt, selector: "[0]", wantOK: false},
		{name: "an mdoc element", cred: mdocCred, selector: "given_name", want: "Ada", wantOK: true},
		{name: "an mdoc element that is absent", cred: mdocCred, selector: "family_name", wantOK: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := claimValueBySelector(tt.cred, tt.selector)
			if ok != tt.wantOK {
				t.Fatalf("ok = %v, want %v (got %#v)", ok, tt.wantOK, got)
			}
			if tt.wantOK && !reflect.DeepEqual(got, tt.want) {
				t.Errorf("value = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestClaimPathString(t *testing.T) {
	tests := []struct {
		name string
		path []any
		want string
	}{
		{name: "empty", path: nil, want: "<empty>"},
		{name: "one name", path: []any{"given_name"}, want: "given_name"},
		{name: "nested names", path: []any{"address", "locality"}, want: "address.locality"},
		{name: "an index", path: []any{"degrees", float64(0)}, want: "degrees[0]"},
		{name: "a wildcard", path: []any{"degrees", nil}, want: "degrees[*]"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClaimPathString(tt.path); got != tt.want {
				t.Errorf("ClaimPathString(%#v) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}
