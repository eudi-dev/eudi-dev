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

package sdjwt

import (
	"strings"
	"testing"
)

// Lenient parsing records each recoverable violation and strict parsing rejects it.
func TestParse_RecoverableBreaks(t *testing.T) {
	claim, claimDigest := disclosureOf(t, "salt", "given_name", "Erika")
	arrayEntry, arrayEntryDigest := disclosureOf(t, "salt", "DE")
	sdKeyDisc, sdKeyDigest := disclosureOf(t, "salt", "_sd", "x")
	vctDisc, vctDigest := disclosureOf(t, "salt", "vct", "shadow")

	cases := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "duplicate disclosure",
			raw:  assembleSDJWT(t, map[string]any{"iss": "https://issuer.example", "_sd": []any{claimDigest}}, claim, claim),
			want: "more than once",
		},
		{
			name: "unreferenced disclosure",
			raw:  assembleSDJWT(t, map[string]any{"iss": "https://issuer.example", "_sd": []any{}}, claim),
			want: "not referenced",
		},
		{
			name: "_sd is not an array",
			raw:  assembleSDJWT(t, map[string]any{"iss": "https://issuer.example", "_sd": "nope"}),
			want: "not an array",
		},
		{
			name: "_sd entry is not a string",
			raw:  assembleSDJWT(t, map[string]any{"iss": "https://issuer.example", "_sd": []any{42}}),
			want: "not a string",
		},
		{
			name: "digest twice in one _sd array",
			raw:  assembleSDJWT(t, map[string]any{"iss": "https://issuer.example", "_sd": []any{claimDigest, claimDigest}}, claim),
			want: "more than once",
		},
		{
			name: "digest reused across objects",
			raw:  assembleSDJWT(t, map[string]any{"iss": "https://issuer.example", "_sd": []any{claimDigest}, "address": map[string]any{"_sd": []any{claimDigest}}}, claim),
			want: "more than once",
		},
		{
			name: "array-entry disclosure in an _sd array",
			raw:  assembleSDJWT(t, map[string]any{"iss": "https://issuer.example", "_sd": []any{arrayEntryDigest}}, arrayEntry),
			want: "two elements",
		},
		{
			name: "object disclosure in an array element",
			raw:  assembleSDJWT(t, map[string]any{"iss": "https://issuer.example", "nationalities": []any{map[string]any{"...": claimDigest}}}, claim),
			want: "three elements",
		},
		{
			name: "disclosure named _sd",
			raw:  assembleSDJWT(t, map[string]any{"iss": "https://issuer.example", "_sd": []any{sdKeyDigest}}, sdKeyDisc),
			want: `named "_sd"`,
		},
		{
			name: "disclosure redefines a signed claim",
			raw:  assembleSDJWT(t, map[string]any{"iss": "https://issuer.example", "vct": "urn:eudi:pid:1", "_sd": []any{vctDigest}}, vctDisc),
			want: "vct",
		},
		{
			name: "array placeholder with extra keys",
			raw:  assembleSDJWT(t, map[string]any{"iss": "https://issuer.example", "nationalities": []any{map[string]any{"...": "abc", "x": 1}}}),
			want: "other keys",
		},
		{
			name: "array placeholder is not a string",
			raw:  assembleSDJWT(t, map[string]any{"iss": "https://issuer.example", "nationalities": []any{map[string]any{"...": 42}}}),
			want: "does not refer to a string",
		},
		{
			name: "unparseable disclosure",
			raw:  assembleSDJWT(t, map[string]any{"iss": "https://issuer.example"}, "@@not-base64@@"),
			want: "could not be parsed",
		},
		{
			name: "unsupported _sd_alg",
			raw:  assembleSDJWT(t, map[string]any{"iss": "https://issuer.example", "_sd_alg": "sha-999"}),
			want: "not a supported hash algorithm",
		},
		{
			name: "_sd_alg is not a string",
			raw:  assembleSDJWT(t, map[string]any{"iss": "https://issuer.example", "_sd_alg": 256}),
			want: "_sd_alg is not a string",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Parse(tc.raw); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("strict Parse: err = %v, want it to reject mentioning %q", err, tc.want)
			}
			token, err := ParseLenient(tc.raw)
			if err != nil {
				t.Fatalf("lenient ParseLenient rejected the credential: %v", err)
			}
			if !strings.Contains(strings.Join(token.Deviations, "\n"), tc.want) {
				t.Fatalf("lenient ParseLenient recorded no deviation mentioning %q, got %v", tc.want, token.Deviations)
			}
		})
	}
}
