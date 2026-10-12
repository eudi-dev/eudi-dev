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

package oid4vp

import (
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/oid4vc"
)

func TestARFRequiresAnAccessCertificate(t *testing.T) {
	findings := ARFFindings(&Request{AuthorizationRequest: oid4vc.AuthorizationRequest{ClientID: "redirect_uri:https://verifier.example/response"}})
	if !containsSubstring(findings, "RPA_03") {
		t.Errorf("findings %v, want the RPA_03 finding", findings)
	}
}

// ARF RPRC_19 requires a registration certificate even though OpenID4VP makes
// verifier_info optional. RPRC_17 has the wallet warn the user without one.
func TestARFRequiresARegistrationCertificate(t *testing.T) {
	findings := ARFFindings(&Request{RequestPayload: map[string]any{"dcql_query": map[string]any{}}})
	if !containsSubstring(findings, "ARF RPRC_17 and RPRC_19 and ETSI TS 119 472-2 OIDFVP-HAIP-COMMON-REQ-RO-13 as adapted by CIR (EU) 2026/1731 Annex XII: the request carries no registration certificate") {
		t.Errorf("findings %v, want the RPRC_17 and RPRC_19 finding", findings)
	}
}
