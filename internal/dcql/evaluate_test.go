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
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/consent"
)

// §6.3: "the CBOR value used for matching MUST first be converted to JSON,
// following the advice given in Section 6.1 of [RFC8949]". That turns a CBOR
// integer into a JSON number and a byte string into base64url text.
func TestClaimSelectorFor_MDocValueMatchingUsesJSONConversion(t *testing.T) {
	cred := Credential{
		Format: "mso_mdoc",
		Claims: map[string]any{
			"ns:issue_count":   uint64(3),
			"ns:balance":       int64(-7),
			"ns:portrait":      []byte{0xfb, 0xfb, 0xfb},
			"ns:document_code": "D",
		},
	}

	tests := []struct {
		name  string
		claim map[string]any
		want  string
	}{
		{"unsigned integer", map[string]any{"path": []any{"ns", "issue_count"}, "values": []any{float64(3)}}, "ns:issue_count"},
		{"unsigned integer differs", map[string]any{"path": []any{"ns", "issue_count"}, "values": []any{float64(4)}}, ""},
		{"negative integer", map[string]any{"path": []any{"ns", "balance"}, "values": []any{float64(-7)}}, "ns:balance"},
		{"integer is not its decimal string", map[string]any{"path": []any{"ns", "issue_count"}, "values": []any{"3"}}, ""},
		// 0xfbfbfb is "+/v7" in standard base64 and "-_v7" in base64url.
		// RFC 8949 Section 6.1 asks for base64url.
		{"byte string as base64url", map[string]any{"path": []any{"ns", "portrait"}, "values": []any{"-_v7"}}, "ns:portrait"},
		{"byte string not as standard base64", map[string]any{"path": []any{"ns", "portrait"}, "values": []any{"+/v7"}}, ""},
		{"text string", map[string]any{"path": []any{"ns", "document_code"}, "values": []any{"D"}}, "ns:document_code"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := claimSelectorFor(cred, tt.claim); got != tt.want {
				t.Errorf("claimSelectorFor() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMatchesFormat(t *testing.T) {
	tests := []struct {
		name   string
		format string
		query  string
		want   bool
	}{
		{"exact match", "dc+sd-jwt", "dc+sd-jwt", true},
		{"mismatch", "dc+sd-jwt", "mso_mdoc", false},
		{"empty query", "dc+sd-jwt", "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cred := Credential{Format: tt.format}
			got := matchesFormat(cred, tt.query)
			if got != tt.want {
				t.Errorf("matchesFormat(%s, %s) = %v, want %v", tt.format, tt.query, got, tt.want)
			}
		})
	}
}

func TestClaimKeyFromPath(t *testing.T) {
	sdCred := Credential{
		Format: "dc+sd-jwt",
		Claims: map[string]any{
			"given_name": "Max",
			"address": map[string]any{
				"street_address": "123 Main St",
				"city":           "Berlin",
			},
			"place_of_birth": map[string]any{
				"locality": "Berlin",
			},
			"nationalities": []any{"DE", "FR"},
		},
	}
	mdocCred := Credential{
		Format: "mso_mdoc",
		Claims: map[string]any{
			"eu.europa.ec.eudi.pid.1:given_name":     "Max",
			"eu.europa.ec.eudi.pid.1:place_of_birth": "Berlin",
		},
	}

	tests := []struct {
		name string
		cred Credential
		path []any
		want string
	}{
		{"empty path", sdCred, []any{}, ""},
		{"sd-jwt simple", sdCred, []any{"given_name"}, "given_name"},
		{"sd-jwt missing", sdCred, []any{"missing"}, ""},
		{"sd-jwt nested object", sdCred, []any{"address", "street_address"}, "address"},
		{"sd-jwt nested missing key", sdCred, []any{"address", "zipcode"}, ""},
		{"sd-jwt nested non-map", sdCred, []any{"given_name", "sub"}, ""},
		{"sd-jwt nested place_of_birth", sdCred, []any{"place_of_birth", "locality"}, "place_of_birth"},
		{"sd-jwt array index", sdCred, []any{"nationalities", float64(0)}, "nationalities"},
		{"sd-jwt array oob", sdCred, []any{"nationalities", float64(5)}, ""},
		{"sd-jwt array negative", sdCred, []any{"nationalities", float64(-1)}, ""},
		{"sd-jwt array non-array", sdCred, []any{"given_name", float64(0)}, ""},
		{"sd-jwt array wildcard", sdCred, []any{"nationalities", nil}, "nationalities"},
		{"sd-jwt wildcard non-array", sdCred, []any{"given_name", nil}, ""},
		{"sd-jwt non-string first", sdCred, []any{42}, ""},
		{"sd-jwt unknown second type", sdCred, []any{"given_name", true}, ""},
		{"mdoc valid", mdocCred, []any{"eu.europa.ec.eudi.pid.1", "given_name"}, "eu.europa.ec.eudi.pid.1:given_name"},
		{"mdoc missing", mdocCred, []any{"eu.europa.ec.eudi.pid.1", "missing"}, ""},
		// §7.2.1 selects the data element in the second component and fails
		// when it does not exist. The rulebook identifier birth_place does not
		// match the mdoc element place_of_birth.
		{"mdoc no aliasing", mdocCred, []any{"eu.europa.ec.eudi.pid.1", "birth_place"}, ""},
		{"mdoc native", mdocCred, []any{"eu.europa.ec.eudi.pid.1", "place_of_birth"}, "eu.europa.ec.eudi.pid.1:place_of_birth"},
		{"mdoc nested alias unsupported", mdocCred, []any{"eu.europa.ec.eudi.pid.1", "birth_place", "locality"}, ""},
		{"mdoc nested native unsupported", mdocCred, []any{"eu.europa.ec.eudi.pid.1", "place_of_birth", "locality"}, ""},
		{"mdoc element-first unsupported", mdocCred, []any{"place_of_birth"}, ""},
		{"mdoc short path", mdocCred, []any{"eu.europa.ec.eudi.pid.1"}, ""},
		{"mdoc non-string ns", mdocCred, []any{42, "given_name"}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := claimKeyFromPath(tt.cred, tt.path)
			if got != tt.want {
				t.Errorf("claimKeyFromPath() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Sorting by preferred format keeps the order of equally preferred
// credentials. A comparator that checks only the left item breaks this.
func TestPreferredFormatSortIsStable(t *testing.T) {
	matches := []consent.Match{
		{QueryID: "q", Format: "mso_mdoc", CredentialID: "m1"},
		{QueryID: "q", Format: "dc+sd-jwt", CredentialID: "s1"},
		{QueryID: "q", Format: "mso_mdoc", CredentialID: "m2"},
		{QueryID: "q", Format: "dc+sd-jwt", CredentialID: "s2"},
	}
	sortMatchesByPreferredFormat(matches, "dc+sd-jwt")

	var order []string
	for _, m := range matches {
		order = append(order, m.CredentialID)
	}
	want := []string{"s1", "s2", "m1", "m2"}
	for i := range want {
		if order[i] != want[i] {
			t.Fatalf("order = %v, want %v (preferred first, input order kept within each group)", order, want)
		}
	}
}

func TestSortMatchesCompleteFirst(t *testing.T) {
	matches := []consent.Match{
		{QueryID: "q", CredentialID: "partial", MissingClaims: []string{"x"}},
		{QueryID: "q", CredentialID: "complete"},
	}
	sortMatchesCompleteFirst(matches)
	if matches[0].CredentialID != "complete" {
		t.Errorf("want the complete match first, got %q", matches[0].CredentialID)
	}
}

// Use the same selector format for missing and disclosed claims: namespace:element for
// mdoc and dotted paths with array brackets for SD-JWT.
func TestMissingClaimLabel(t *testing.T) {
	mdoc := Credential{Format: "mso_mdoc"}
	if got := missingClaimLabel(mdoc, []any{"eu.europa.ec.eudi.pid.1", "given_name"}); got != "eu.europa.ec.eudi.pid.1:given_name" {
		t.Errorf("mdoc label = %q, want the namespace:element form", got)
	}
	sdjwt := Credential{Format: "dc+sd-jwt"}
	if got := missingClaimLabel(sdjwt, []any{"nationalities", float64(1)}); got != "nationalities[1]" {
		t.Errorf("sd-jwt label = %q, want nationalities[1]", got)
	}
}

func TestFilterClaims(t *testing.T) {
	cred := Credential{
		Format: "dc+sd-jwt",
		Claims: map[string]any{
			"given_name":  "Erika",
			"family_name": "Mustermann",
			"birth_date":  "1984-08-12",
			"address": map[string]any{
				"postal_code": "10115",
			},
		},
	}

	filtered := FilterClaims(cred, []string{"given_name", "birth_date", "address.postal_code"})
	if len(filtered) != 3 {
		t.Fatalf("expected 3 filtered claims, got %d", len(filtered))
	}
	if filtered["given_name"] != "Erika" {
		t.Errorf("expected given_name Erika, got %v", filtered["given_name"])
	}
	if filtered["address.postal_code"] != "10115" {
		t.Errorf("expected address.postal_code 10115, got %v", filtered["address.postal_code"])
	}
	if _, ok := filtered["family_name"]; ok {
		t.Error("family_name should not be in filtered claims")
	}
}
