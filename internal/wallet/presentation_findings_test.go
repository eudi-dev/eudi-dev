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
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
)

// Debug mode presents a credential outside the query's trusted_authorities
// (OpenID4VP 1.0 §6.1). The response then reports it as a finding.
func TestAPresentationOutsideTheTrustedAuthoritiesIsAFinding(t *testing.T) {
	w := pidBaselineWallet(t)
	matches := evaluateDCQL(t, w, map[string]any{"credentials": []any{consentPIDQuery("pid", "dc+sd-jwt")}})
	if len(matches) == 0 {
		t.Fatal("no match for the PID query")
	}
	matches = matches[:1]
	matches[0].UntrustedAuthority = true
	params := &oid4vp.Request{AuthorizationRequest: oid4vc.AuthorizationRequest{Nonce: "n", ClientID: "https://verifier.example"}}
	if _, err := w.createVPTokenMap(matches, params); err != nil {
		t.Fatal(err)
	}
	if len(params.Findings) != 1 || !strings.Contains(params.Findings[0], "matches none of the trusted_authorities of query "+matches[0].QueryID) {
		t.Errorf("findings %v, want the trusted_authorities finding", params.Findings)
	}
}
