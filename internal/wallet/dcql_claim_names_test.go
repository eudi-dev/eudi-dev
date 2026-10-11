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
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/dcql"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vp"
)

// A claim name may contain any character, so a selector must name it without
// ambiguity and read back to the same claims path.
func TestSelectorRoundTripsClaimNamesWithSeparators(t *testing.T) {
	for _, path := range [][]any{
		{"a.b"},
		{"address", "street[1]"},
		{`quote"d`, nil},
		{"", "x"},
		{"list", float64(0), "x.y"},
	} {
		selector := dcql.ClaimPathString(path)
		got, ok := dcql.ParseSDJWTSelector(selector)
		if !ok {
			t.Errorf("%#v: selector %q does not parse", path, selector)
			continue
		}
		for i := range got {
			if n, isInt := got[i].(int); isInt {
				got[i] = float64(n)
			}
		}
		if !reflect.DeepEqual(got, path) {
			t.Errorf("%#v: selector %q reads back as %#v", path, selector, got)
		}
	}
}

// OID4VP 1.0 §7.1 selects a claim by its key, whatever characters it holds.
func TestPresentationDisclosesAClaimWithADotInItsName(t *testing.T) {
	w := generateTestWallet(t)
	issued, err := w.IssueCredential(IssueOptions{
		Format: "sdjwt", VCT: "urn:test:dotted:1",
		Claims: map[string]any{"org.example.level": "gold", "given_name": "Alice"},
	})
	if err != nil {
		t.Fatalf("issuing: %v", err)
	}
	query := map[string]any{"credentials": []any{map[string]any{
		"id": "q", "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []any{"urn:test:dotted:1"}},
		"claims": []any{map[string]any{"path": []any{"org.example.level"}}},
	}}}
	matches := evaluateDCQL(t, w, query)
	if len(matches) != 1 {
		t.Fatalf("matches = %v, want the issued credential", matches)
	}
	token, err := vpToken(w, matches[0], &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "n", ClientID: "x509_hash:abc"}})
	if err != nil {
		t.Fatalf("presenting: %v", err)
	}
	disclosed := 0
	for _, d := range issued.Credential.Disclosures {
		if strings.Contains(token.Token, d.Raw) {
			if d.Name != "org.example.level" {
				t.Errorf("disclosed %s, which the query did not ask for", d.Name)
			}
			disclosed++
		}
	}
	if disclosed != 1 {
		t.Errorf("the presentation carries %d disclosures, want the one for org.example.level", disclosed)
	}
}

// OID4VP 1.0 §7.1.1: a null component over an empty array selects nothing,
// and "If the set of elements currently selected is empty, abort processing".
func TestEvaluateDCQL_NullOverAnEmptyArrayDoesNotMatch(t *testing.T) {
	w := generateTestWallet(t)
	jwt, err := signJWT(map[string]any{"alg": "ES256", "typ": "JWT"}, map[string]any{"vct": "urn:test:empty:1", "nationalities": []any{}}, w.IssuerKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.ImportCredential(jwt); err != nil {
		t.Fatal(err)
	}
	w.ValidationMode = ValidationModeStrict
	query := map[string]any{"credentials": []any{map[string]any{
		"id": "q", "format": "jwt_vc_json", "meta": map[string]any{}, "require_cryptographic_holder_binding": false,
		"claims": []any{map[string]any{"path": []any{"nationalities", nil}}},
	}}}
	if matches := evaluateDCQL(t, w, query); len(matches) != 0 {
		t.Errorf("matches = %v, want none", matches)
	}
}
