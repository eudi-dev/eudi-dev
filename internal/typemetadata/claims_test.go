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

package typemetadata

import (
	"strings"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
	"github.com/eudi-dev/eudi-dev/v3/internal/sdjwt"
)

// issued is an SD-JWT VC whose claims are selectively disclosable, except
// family_name, address.locality and the elements of nationalities.
func issued(t *testing.T) *sdjwt.Token {
	t.Helper()
	key, err := mock.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := mock.GenerateSDJWT(mock.SDJWTConfig{
		Issuer: "https://issuer.example", VCT: "https://issuer.example/type", ExpiresIn: time.Hour, Key: key,
		Claims: map[string]any{
			"given_name":    "Erika",
			"family_name":   "Mustermann",
			"address":       map[string]any{"locality": "Berlin"},
			"nationalities": []any{"DE", "FR"},
		},
		AlwaysDisclosed: []string{"family_name", "nationalities", "address.locality"},
	})
	if err != nil {
		t.Fatal(err)
	}
	token, err := sdjwt.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func boolPtr(v bool) *bool { return &v }

// §5.6: a mandatory claim must be present, and sd decides whether a claim is
// a Disclosure of its own.
func TestValidateChecksTheClaimMetadata(t *testing.T) {
	token := issued(t)
	for _, tt := range []struct {
		name  string
		claim Claim
		want  string
	}{
		{"present mandatory claim", Claim{Path: []any{"given_name"}, Mandatory: boolPtr(true)}, ""},
		{"missing mandatory claim", Claim{Path: []any{"birthdate"}, Mandatory: boolPtr(true)}, "§5.6.3"},
		{"disclosure where always", Claim{Path: []any{"given_name"}, SD: SDAlways}, ""},
		{"plain claim where always", Claim{Path: []any{"family_name"}, SD: SDAlways}, "§5.6.4"},
		{"disclosure where never", Claim{Path: []any{"given_name"}, SD: SDNever}, "§5.6.4"},
		{"plain array elements where never", Claim{Path: []any{"nationalities", nil}, SD: SDNever}, ""},
		{"claim inside a disclosed object", Claim{Path: []any{"address", "locality"}, SD: SDNever}, ""},
		{"index counts issued elements", Claim{Path: []any{"nationalities", float64(1)}, Mandatory: boolPtr(true)}, ""},
		{"key in a value that is not an object", Claim{Path: []any{"given_name", "first"}}, "§5.6.1"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			metadata := &Metadata{Claims: []Claim{tt.claim}}
			problems := metadata.Validate(token.Payload, token.Disclosures)
			if tt.want == "" && len(problems) > 0 {
				t.Errorf("problems = %v, want none", problems)
			}
			if tt.want != "" && (len(problems) != 1 || !strings.Contains(problems[0].String(), tt.want)) {
				t.Errorf("problems = %v, want one with %s", problems, tt.want)
			}
		})
	}
}

// A verifier sees only the disclosed claims, so an undisclosed mandatory claim
// is no problem. The sd rules still apply to what it sees.
func TestValidatePresentationSkipsTheMandatoryCheck(t *testing.T) {
	token := issued(t)
	metadata := &Metadata{Claims: []Claim{
		{Path: []any{"birthdate"}, Mandatory: boolPtr(true)},
		{Path: []any{"family_name"}, SD: SDAlways},
	}}
	problems := metadata.ValidatePresentation(token.Payload, token.Disclosures)
	if len(problems) != 1 || !strings.Contains(problems[0].String(), "§5.6.4") {
		t.Errorf("problems = %v, want only the sd problem of family_name", problems)
	}
}
