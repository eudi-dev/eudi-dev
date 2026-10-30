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
	"encoding/json"
	"slices"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/dcql"
	"github.com/eudi-dev/eudi-dev/v3/internal/findings"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
	"github.com/eudi-dev/eudi-dev/v3/internal/validate"
)

var (
	unregisteredIssuer = findings.ARF.Registration("RPRC_22a").Cited("ARF RPRC_22a and ETSI TS 119 472-3 V1.1.1 ISS-MDATA-REG_CERT-4.2.3-04 as adapted by CIR (EU) 2026/1731 Annex XI").
				New("the issuer metadata carries no registration certificate")
	missingNonce = findings.OID4VP.Protocol("§5.2").New("nonce is required")
)

// Clients older than finding_details read the detail line and the texts in
// details.findings. Both keep their form.
func TestFindingsEntryKeepsTheTextsAndAddsTheRules(t *testing.T) {
	w := generateTestWallet(t)
	w.warnFindings("issuance", "issuer_findings", subjectIssuer, "Findings about the issuer", findings.List{unregisteredIssuer, missingNonce}, nil)

	entry := w.GetLog()[len(w.GetLog())-1]
	if entry.Detail != "Findings about the issuer (2 findings, see details)" || entry.Severity != severityWarning {
		t.Errorf("entry = %q (%s), want the summary as a warning", entry.Detail, entry.Severity)
	}
	if entry.FindingSubject != subjectIssuer || len(entry.FindingDetails) != 2 ||
		entry.FindingDetails[0].Rule != "ARF RPRC_22a" || entry.FindingDetails[0].Group != findings.GroupRegistration ||
		entry.FindingDetails[1].Group != findings.GroupProtocol {
		t.Errorf("finding subject %q, details %+v", entry.FindingSubject, entry.FindingDetails)
	}

	data, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	var legacy struct {
		Detail  string `json:"detail"`
		Details struct {
			Findings []string `json:"findings"`
		} `json:"details"`
	}
	if err := json.Unmarshal(data, &legacy); err != nil || !slices.Equal(legacy.Details.Findings, []string{unregisteredIssuer.String(), missingNonce.String()}) {
		t.Errorf("legacy view = %+v (%v)", legacy, err)
	}
}

func TestOneCitedDeviationCarriesItsRule(t *testing.T) {
	w := generateTestWallet(t)
	if err := w.reportDeviation(deviation{action: "issuance", event: "server_deviation", finding: missingNonce}); err != nil {
		t.Fatal(err)
	}
	entry := w.GetLog()[len(w.GetLog())-1]
	if entry.Detail != missingNonce.String() || len(entry.FindingDetails) != 1 || entry.FindingDetails[0] != missingNonce {
		t.Errorf("entry = %q with %+v, want the finding text and its rule", entry.Detail, entry.FindingDetails)
	}

	w.ValidationMode = ValidationModeStrict
	err := w.reportDeviation(deviation{action: "issuance", event: "server_deviation", finding: missingNonce})
	if err == nil || err.Error() != missingNonce.String() {
		t.Errorf("strict refusal = %v, want the finding text", err)
	}
}

// Findings about registration, certificates and trusted lists are in the
// registration group. Findings about the messages are in the protocol group.
func TestFindingsBelongToTheirGroup(t *testing.T) {
	for name, tc := range map[string]struct {
		list findings.List
		want findings.Group
	}{
		"unsigned issuer metadata":           {issuerARFFindings(issuerAuthentication{metadata: map[string]any{}}), findings.GroupRegistration},
		"request without access certificate": {oid4vp.ARFFindings(&oid4vp.Request{}), findings.GroupRegistration},
		"credential without x5c":             {validate.HAIPCredentialChain(nil), findings.GroupProtocol},
		"empty DCQL query":                   {dcql.QueryFindings(map[string]any{}), findings.GroupProtocol},
	} {
		if len(tc.list) == 0 {
			t.Errorf("%s: no findings", name)
		}
		for _, finding := range tc.list {
			if finding.Group != tc.want {
				t.Errorf("%s: %s is in the %s group, want %s", name, finding, finding.Group, tc.want)
			}
		}
	}
}
