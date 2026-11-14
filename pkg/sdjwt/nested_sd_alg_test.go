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
	"os"
	"strings"
	"testing"
)

// Some issuers repeat the SD structure in a credentialSubject object with a
// second _sd_alg. RFC 9901 §4.1.1 forbids the nested copy. It repeats the
// top-level hash, so lenient parsing resolves the claims and records a deviation.
func TestParse_NestedSDAlgIsTolerated(t *testing.T) {
	raw, err := os.ReadFile("testdata/nested_sd_alg.txt")
	if err != nil {
		t.Fatal(err)
	}

	input := strings.TrimSpace(string(raw))

	if _, err := Parse(input); err == nil {
		t.Fatal("Parse accepted a credential with a nested _sd_alg, want rejection")
	}

	token, err := ParseLenient(input)
	if err != nil {
		t.Fatalf("ParseLenient rejected a credential with a nested _sd_alg: %v", err)
	}

	// The credentialSubject copy breaks two rules. It has a nested _sd_alg and it
	// repeats the top-level digests.
	joined := strings.Join(token.Deviations, "\n")
	if !strings.Contains(joined, "_sd_alg is inside a nested object") {
		t.Fatalf("missing nested-_sd_alg deviation, got %v", token.Deviations)
	}
	if !strings.Contains(joined, "appears more than once") {
		t.Fatalf("missing duplicate-digest deviation, got %v", token.Deviations)
	}

	if got, _ := token.ResolvedClaims["family_name"].(string); got != "Mustermann" {
		t.Fatalf("family_name did not resolve, got %q", got)
	}
	cs, ok := token.ResolvedClaims["credentialSubject"].(map[string]any)
	if !ok {
		t.Fatalf("credentialSubject missing from resolved claims")
	}
	if _, present := cs["_sd_alg"]; present {
		t.Fatalf("the nested _sd_alg leaked into the resolved credentialSubject")
	}
}
