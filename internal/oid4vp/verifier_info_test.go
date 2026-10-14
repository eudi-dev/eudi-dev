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

	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vc"
)

func TestARFRequiresAnAccessCertificate(t *testing.T) {
	findings := ARFFindings(&Request{AuthorizationRequest: oid4vc.AuthorizationRequest{ClientID: "redirect_uri:https://verifier.example/response"}})
	if !containsSubstring(findings, "RPA_03") {
		t.Errorf("findings %v, want the RPA_03 finding", findings)
	}
}

// Wallets must check a registration certificate only from 11 August 2028
// (CIR (EU) 2026/1731), so a request without one gets a warning.
func TestAMissingRegistrationCertificateIsAWarning(t *testing.T) {
	request := &Request{RequestPayload: map[string]any{"dcql_query": map[string]any{}}}
	if findings := ARFFindings(request); containsSubstring(findings, "no registration certificate") {
		t.Errorf("findings %v, want the missing registration certificate only as a warning", findings)
	}
	if advisories := ARFAdvisories(request); !containsSubstring(advisories, "carries no registration certificate (typ rc-wrp+jwt) in verifier_info. Wallets must check registration certificates from 11 August 2028") {
		t.Errorf("advisories %v, want the missing registration certificate", advisories)
	}
}
