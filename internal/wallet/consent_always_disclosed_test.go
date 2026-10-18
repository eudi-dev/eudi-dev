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
	"slices"
	"testing"
)

func alwaysDisclosedQuery(format, typeKey, typeValue string, paths ...[]any) map[string]any {
	claims := make([]any, len(paths))
	for i, path := range paths {
		claims[i] = map[string]any{"path": path}
	}
	meta := map[string]any{typeKey: typeValue}
	if typeKey == "vct_values" {
		meta[typeKey] = []any{typeValue}
	}
	return map[string]any{"credentials": []any{map[string]any{
		"id": "card", "format": format, "meta": meta, "claims": claims,
	}}}
}

// RFC 9901 §4.1: a claim outside the disclosures is in the issuer-signed
// payload, so every presentation sends it. OpenID4VP 1.0 Appendix B.1 presents
// a jwt_vc_json credential whole. Every mdoc element is selected on its own.
func TestTheMatchListsTheClaimsThePresentationAlwaysSends(t *testing.T) {
	w := generateTestWallet(t)
	noStatus := ""
	for _, opts := range []IssueOptions{
		{Format: "sdjwt", VCT: "urn:example:card", Claims: map[string]any{"member_id": "M-1", "nickname": "Bo"}, AlwaysDisclosed: []string{"member_id"}},
		{Format: "jwt", VCT: "urn:example:jwt-card", Claims: map[string]any{"member_id": "M-1", "nickname": "Bo"}},
		{Format: "mdoc", DocType: "org.example.card", Claims: map[string]any{"member_id": "M-1", "nickname": "Bo"}, StatusListURI: &noStatus},
	} {
		if _, err := w.IssueCredential(opts); err != nil {
			t.Fatal(err)
		}
	}
	for _, tc := range []struct {
		name  string
		query map[string]any
		want  []string
	}{
		{"sd-jwt", alwaysDisclosedQuery("dc+sd-jwt", "vct_values", "urn:example:card", []any{"member_id"}, []any{"nickname"}), []string{"member_id"}},
		{"jwt_vc_json", alwaysDisclosedQuery("jwt_vc_json", "vct_values", "urn:example:jwt-card", []any{"member_id"}, []any{"nickname"}), []string{"member_id", "nickname"}},
		{"mdoc", alwaysDisclosedQuery("mso_mdoc", "doctype_value", "org.example.card", []any{"org.example.card", "member_id"}, []any{"org.example.card", "nickname"}), nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			matches, _ := w.matchDCQL(tc.query)
			if len(matches) != 1 {
				t.Fatalf("%d matches, want 1", len(matches))
			}
			got := slices.Clone(matches[0].AlwaysDisclosed)
			slices.Sort(got)
			if !slices.Equal(got, tc.want) {
				t.Errorf("always disclosed %v, want %v", got, tc.want)
			}
		})
	}
}

// The holder cannot withhold a plain claim, so the selection keeps it and the
// activity log lists it as disclosed.
func TestWithholdingAPlainClaimKeepsItInTheSelection(t *testing.T) {
	w := generateTestWallet(t)
	if _, err := w.IssueCredential(IssueOptions{Format: "sdjwt", VCT: "urn:example:card", Claims: map[string]any{"member_id": "M-1", "nickname": "Bo"}, AlwaysDisclosed: []string{"member_id"}}); err != nil {
		t.Fatal(err)
	}
	matches, _ := w.matchDCQL(alwaysDisclosedQuery("dc+sd-jwt", "vct_values", "urn:example:card", []any{"member_id"}, []any{"nickname"}))
	if len(matches) != 1 {
		t.Fatalf("%d matches, want 1", len(matches))
	}
	got := w.applySelectedClaims(matches, map[string][]string{matches[0].CredentialID: {}})
	if !slices.Equal(got[0].SelectedKeys, []string{"member_id"}) {
		t.Errorf("selected keys %v, want the plain member_id", got[0].SelectedKeys)
	}
	if got[0].Claims["member_id"] != "M-1" {
		t.Errorf("claims %v, want member_id", got[0].Claims)
	}
}
