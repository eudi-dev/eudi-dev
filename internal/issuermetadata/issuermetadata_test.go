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

package issuermetadata

import "testing"

// SD-JWT VC §4 forms the metadata location "by inserting the well-known
// string /.well-known/jwt-vc-issuer between the host component and the path
// component (if any) of the iss claim value in the JWT", and §4.1 removes any
// terminating slash from the path first.
func TestURL(t *testing.T) {
	tests := []struct {
		iss     string
		want    string
		wantErr bool
	}{
		{iss: "https://example.com", want: "https://example.com/.well-known/jwt-vc-issuer"},
		{iss: "https://example.com/", want: "https://example.com/.well-known/jwt-vc-issuer"},
		{iss: "https://example.com/tenant/1234", want: "https://example.com/.well-known/jwt-vc-issuer/tenant/1234"},
		{iss: "https://example.com/tenant/1234/", want: "https://example.com/.well-known/jwt-vc-issuer/tenant/1234"},
		{iss: "https://example.com:8443/tenant", want: "https://example.com:8443/.well-known/jwt-vc-issuer/tenant"},
		{iss: "http://example.com", wantErr: true},
		{iss: "https://example.com/tenant?x=1", wantErr: true},
		{iss: "https://example.com/tenant#frag", wantErr: true},
		{iss: "not-a-url", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.iss, func(t *testing.T) {
			got, err := URL(tt.iss)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("URL(%q) = %q, want an error", tt.iss, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("URL(%q): %v", tt.iss, err)
			}
			if got != tt.want {
				t.Errorf("URL(%q) = %q, want %q", tt.iss, got, tt.want)
			}
		})
	}
}

func TestFindJWKs(t *testing.T) {
	doc := func(keys ...any) map[string]any {
		return map[string]any{"jwks": map[string]any{"keys": keys}}
	}
	kids := func(jwks []map[string]any) []any {
		var out []any
		for _, jwk := range jwks {
			out = append(out, jwk["kid"])
		}
		return out
	}

	t.Run("matches on kid", func(t *testing.T) {
		got, err := findJWKs(doc(
			map[string]any{"kid": "one", "kty": "EC"},
			map[string]any{"kid": "two", "kty": "EC"},
		), "two")
		if err != nil {
			t.Fatalf("findJWKs: %v", err)
		}
		if k := kids(got); len(k) != 1 || k[0] != "two" {
			t.Errorf("kids = %v, want [two]", k)
		}
	})

	t.Run("an empty kid takes every key", func(t *testing.T) {
		got, err := findJWKs(doc(map[string]any{"kid": "one"}, map[string]any{"kid": "two"}), "")
		if err != nil {
			t.Fatalf("findJWKs: %v", err)
		}
		if k := kids(got); len(k) != 2 {
			t.Errorf("kids = %v, want both keys", k)
		}
	})

	t.Run("a kid nothing matches", func(t *testing.T) {
		if _, err := findJWKs(doc(map[string]any{"kid": "one"}), "other"); err == nil {
			t.Error("an unmatched kid was accepted")
		}
	})

	t.Run("entries that are not objects are skipped", func(t *testing.T) {
		got, err := findJWKs(doc("not an object", map[string]any{"kid": "one"}), "one")
		if err != nil {
			t.Fatalf("findJWKs: %v", err)
		}
		if k := kids(got); len(k) != 1 || k[0] != "one" {
			t.Errorf("kids = %v", k)
		}
	})

	t.Run("no jwks", func(t *testing.T) {
		if _, err := findJWKs(map[string]any{}, "one"); err == nil {
			t.Error("a document without jwks was accepted")
		}
	})

	t.Run("jwks without keys", func(t *testing.T) {
		if _, err := findJWKs(map[string]any{"jwks": map[string]any{}}, "one"); err == nil {
			t.Error("a jwks without keys was accepted")
		}
	})

	t.Run("an empty key set", func(t *testing.T) {
		if _, err := findJWKs(doc(), "one"); err == nil {
			t.Error("an empty key set was accepted")
		}
	})
}
