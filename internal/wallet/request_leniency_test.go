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
	"testing"
)

// OID4VP 1.0 Appendix B.1.1: "Each inner array specifies a set of fully
// expanded types that MUST be present in the fully expanded types in the type
// property of the Verifiable Credential".
func TestEvaluateDCQL_TypeValuesOfAW3CCredential(t *testing.T) {
	w := generateTestWallet(t)
	jwt, err := signJWT(map[string]any{"alg": "ES256", "typ": "JWT"}, map[string]any{
		"vc": map[string]any{"type": []any{"VerifiableCredential", "UniversityDegreeCredential"}},
	}, w.IssuerKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.ImportCredential(jwt); err != nil {
		t.Fatal(err)
	}
	w.ValidationMode = ValidationModeStrict
	for _, tc := range []struct {
		typeValues []any
		want       int
	}{
		{[]any{[]any{"https://www.w3.org/2018/credentials#VerifiableCredential", "https://example.org/examples#UniversityDegreeCredential"}}, 1},
		{[]any{[]any{"https://example.org/examples#BachelorDegree"}, []any{"UniversityDegreeCredential"}}, 1},
		{[]any{[]any{"https://example.org/examples#BachelorDegree"}}, 0},
	} {
		query := map[string]any{"credentials": []any{map[string]any{
			"id": "vc", "format": "jwt_vc_json", "require_cryptographic_holder_binding": false,
			"meta": map[string]any{"type_values": tc.typeValues},
		}}}
		if matches := evaluateDCQL(t, w, query); len(matches) != tc.want {
			t.Errorf("type_values %v: %d matches, want %d", tc.typeValues, len(matches), tc.want)
		}
	}
}
