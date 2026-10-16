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

package scheme

import "testing"

// RFC 3986 §3.1: "schemes are case-insensitive".
func TestSchemesMatchWithoutCase(t *testing.T) {
	for uri, want := range map[string][2]bool{
		"openid4vp://authorize?x=1":             {true, false},
		"OPENID4VP://authorize?x=1":             {true, false},
		"  Haip-VP://?request_uri=x":            {true, false},
		"openid-credential-offer://?x=1":        {false, true},
		"EU-EAA-OFFER://?credential_offer=x":    {false, true},
		"eu-eaap://?request_uri=x":              {true, false},
		"https://verifier.example/openid4vp://": {false, false},
		"openid4vp:authorize":                   {false, false},
	} {
		if got := [2]bool{IsPresentation(uri), IsIssuance(uri)}; got != want {
			t.Errorf("%q: presentation, issuance = %v, want %v", uri, got, want)
		}
	}
}
