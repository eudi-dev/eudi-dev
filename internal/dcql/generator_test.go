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
	"encoding/json"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/mdoc"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
)

func TestFromSDJWT(t *testing.T) {
	token := &sdjwt.Token{
		ResolvedClaims: map[string]any{
			"iss":           "https://issuer.example",
			"vct":           "urn:eudi:pid:1",
			"exp":           float64(999999999),
			"iat":           float64(100000000),
			"cnf":           map[string]any{"jwk": map[string]any{}},
			"vct#integrity": "sha256-abc",
			"aka_vcts":      []any{"urn:example:other"},
			"given_name":    "Erika",
			"family_name":   "Mustermann",
			"birthdate":     "1984-01-26",
		},
	}

	q := FromSDJWT(token)

	if len(q.Credentials) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(q.Credentials))
	}

	cq := q.Credentials[0]
	if cq.Format != "dc+sd-jwt" {
		t.Errorf("format = %q, want dc+sd-jwt", cq.Format)
	}
	if len(cq.Meta.VCTValues) != 1 || cq.Meta.VCTValues[0] != "urn:eudi:pid:1" {
		t.Errorf("meta.vct_values = %v, want [urn:eudi:pid:1]", cq.Meta)
	}

	for _, c := range cq.Claims {
		name, _ := c.Path[0].(string)
		if sdjwt.IsProtocolClaim(name) {
			t.Errorf("DCQL query should not include standard claim %q", name)
		}
	}

	claimNames := make(map[string]bool)
	for _, c := range cq.Claims {
		name, _ := c.Path[0].(string)
		claimNames[name] = true
	}
	for _, expected := range []string{"given_name", "family_name", "birthdate"} {
		if !claimNames[expected] {
			t.Errorf("expected claim %q in DCQL query", expected)
		}
	}
}

func TestFromSDJWT_NestedObject(t *testing.T) {
	token := &sdjwt.Token{
		ResolvedClaims: map[string]any{
			"vct": "urn:eudi:pid:1",
			"address": map[string]any{
				"locality":       "KÖLN",
				"street_address": "HEIDESTRAẞE 17",
			},
		},
	}

	q := FromSDJWT(token)
	cq := q.Credentials[0]

	paths := make(map[string]bool)
	for _, c := range cq.Claims {
		if len(c.Path) == 2 {
			first, _ := c.Path[0].(string)
			second, _ := c.Path[1].(string)
			paths[first+"."+second] = true
		}
	}

	for _, expected := range []string{"address.locality", "address.street_address"} {
		if !paths[expected] {
			t.Errorf("expected path %q in DCQL query, got claims: %v", expected, cq.Claims)
		}
	}
}

func TestFromSDJWT_Array(t *testing.T) {
	token := &sdjwt.Token{
		ResolvedClaims: map[string]any{
			"vct":           "urn:eudi:pid:1",
			"nationalities": []any{"DE", "FR"},
		},
	}

	q := FromSDJWT(token)
	cq := q.Credentials[0]

	if len(cq.Claims) != 1 {
		t.Fatalf("expected 1 claim, got %d", len(cq.Claims))
	}

	c := cq.Claims[0]
	if len(c.Path) != 2 {
		t.Fatalf("expected path length 2, got %d: %v", len(c.Path), c.Path)
	}
	if name, _ := c.Path[0].(string); name != "nationalities" {
		t.Errorf("path[0] = %q, want nationalities", name)
	}
	if c.Path[1] != nil {
		t.Errorf("path[1] = %v, want nil (null wildcard)", c.Path[1])
	}
}

func TestFromSDJWT_NoVCT(t *testing.T) {
	token := &sdjwt.Token{
		ResolvedClaims: map[string]any{
			"iss":        "test",
			"given_name": "Test",
		},
	}

	q := FromSDJWT(token)
	cq := q.Credentials[0]

	if cq.ID != "credential_0" {
		t.Errorf("ID = %q, want credential_0", cq.ID)
	}
	// OID4VP 1.0 Section 6.1 makes meta REQUIRED. An empty object places no
	// constraints on the metadata.
	if len(cq.Meta.VCTValues) != 0 || cq.Meta.DoctypeValue != "" {
		t.Errorf("meta should be empty when no VCT, got %v", cq.Meta)
	}
	encoded, err := json.Marshal(q)
	if err != nil {
		t.Fatalf("marshalling query: %v", err)
	}
	if !strings.Contains(string(encoded), `"meta":{}`) {
		t.Errorf("expected the required meta member in %s", encoded)
	}
}

func TestFromJWT(t *testing.T) {
	token := &sdjwt.Token{
		ResolvedClaims: map[string]any{
			"iss":         "https://issuer.example",
			"vct":         "urn:eudi:pid:1",
			"exp":         float64(999999999),
			"iat":         float64(100000000),
			"given_name":  "Erika",
			"family_name": "Mustermann",
		},
	}

	q := FromJWT(token)

	if len(q.Credentials) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(q.Credentials))
	}

	cq := q.Credentials[0]
	if cq.Format != "jwt_vc_json" {
		t.Errorf("format = %q, want jwt_vc_json", cq.Format)
	}
	if len(cq.Meta.VCTValues) != 1 || cq.Meta.VCTValues[0] != "urn:eudi:pid:1" {
		t.Errorf("meta.vct_values = %v, want [urn:eudi:pid:1]", cq.Meta)
	}

	claimNames := make(map[string]bool)
	for _, c := range cq.Claims {
		name, _ := c.Path[0].(string)
		claimNames[name] = true
	}
	for _, expected := range []string{"given_name", "family_name"} {
		if !claimNames[expected] {
			t.Errorf("expected claim %q in DCQL query", expected)
		}
	}

	for _, c := range cq.Claims {
		name, _ := c.Path[0].(string)
		if sdjwt.IsProtocolClaim(name) {
			t.Errorf("DCQL query should not include standard claim %q", name)
		}
	}
}

func TestFromMDOC(t *testing.T) {
	doc := &mdoc.Document{
		DocType: "org.iso.18013.5.1.mDL",
		NameSpaces: map[string][]mdoc.IssuerSignedItem{
			"org.iso.18013.5.1": {
				{ElementIdentifier: "family_name", ElementValue: "Mustermann"},
				{ElementIdentifier: "given_name", ElementValue: "Erika"},
			},
		},
	}

	q := FromMDOC(doc)

	if len(q.Credentials) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(q.Credentials))
	}

	cq := q.Credentials[0]
	if cq.Format != "mso_mdoc" {
		t.Errorf("format = %q, want mso_mdoc", cq.Format)
	}
	if cq.Meta.DoctypeValue != "org.iso.18013.5.1.mDL" {
		t.Errorf("meta.doctype_value = %v, want org.iso.18013.5.1.mDL", cq.Meta)
	}

	if len(cq.Claims) != 2 {
		t.Fatalf("expected 2 claims, got %d", len(cq.Claims))
	}

	for _, c := range cq.Claims {
		if len(c.Path) != 2 {
			t.Errorf("claim path should have 2 elements, got %v", c.Path)
		}
		ns, _ := c.Path[0].(string)
		if ns != "org.iso.18013.5.1" {
			t.Errorf("claim namespace = %q, want org.iso.18013.5.1", ns)
		}
	}
}

func TestSanitizeID(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"urn:eudi:pid:1", "urn_eudi_pid_1"},
		{"org.iso.18013.5.1.mDL", "org_iso_18013_5_1_mDL"},
		{"", ""},
		// OID4VP 1.0 Section 6.1 allows only alphanumeric, underscore and hyphen in an id.
		{"https://issuer.example/pid#1", "https___issuer_example_pid_1"},
		{"vct with spaces", "vct_with_spaces"},
		{"keep-hyphens_and_1", "keep-hyphens_and_1"},
		{"grüße", "gr__e"},
	}
	for _, tt := range tests {
		got := sanitizeID(tt.input)
		if got != tt.want {
			t.Errorf("sanitizeID(%q) = %q, want %q", tt.input, got, tt.want)
		}
		for _, r := range got {
			switch {
			case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			default:
				t.Errorf("sanitizeID(%q) = %q contains %q, which Section 6.1 does not allow in an id", tt.input, got, r)
			}
		}
	}
}
