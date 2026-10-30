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

package findings

import (
	"encoding/json"
	"errors"
	"fmt"
	"testing"
)

func TestFindingTextStartsWithItsFullCitation(t *testing.T) {
	rule := ARF.Registration("RPRC_22a").Cited("ARF RPRC_22a and ETSI TS 119 472-3 V1.1.1 ISS-MDATA-REG_CERT-4.2.3-04 as adapted by CIR (EU) 2026/1731 Annex XI")
	got := rule.New("the issuer metadata carries no registration certificate")
	if got.Spec != "ARF" || got.Rule != "ARF RPRC_22a" || got.Group != GroupRegistration {
		t.Errorf("finding = %+v, want rule ARF RPRC_22a in the registration group", got)
	}
	if want := "ARF RPRC_22a and ETSI TS 119 472-3 V1.1.1 ISS-MDATA-REG_CERT-4.2.3-04 as adapted by CIR (EU) 2026/1731 Annex XI: the issuer metadata carries no registration certificate"; got.String() != want {
		t.Errorf("String = %q, want %q", got.String(), want)
	}
}

func TestFindingWithoutLongerCitationCitesItsRule(t *testing.T) {
	got := OID4VP.Protocol("§5.2").Newf("%s is required", "nonce")
	if got.String() != "OID4VP 1.0 §5.2: nonce is required" || got.Citation != "" || got.Group != GroupProtocol {
		t.Errorf("finding = %+v (%q)", got, got.String())
	}
}

func TestUncitedFindingIsItsText(t *testing.T) {
	if got := Uncited("the response is not valid JSON"); got.String() != "the response is not valid JSON" {
		t.Errorf("String = %q", got.String())
	}
}

func TestListMarshalsAsTheTextArray(t *testing.T) {
	list := List{OID4VP.Protocol("§5.2").New("nonce is required"), Uncited("plain")}
	data, err := json.Marshal(list)
	if err != nil {
		t.Fatal(err)
	}
	if want := `["OID4VP 1.0 §5.2: nonce is required","plain"]`; string(data) != want {
		t.Errorf("JSON = %s, want %s", data, want)
	}
	var back List
	if err := json.Unmarshal(data, &back); err != nil {
		t.Fatal(err)
	}
	if len(back) != 2 || back[0].String() != list[0].String() || back[1].String() != "plain" {
		t.Errorf("round trip = %+v", back)
	}
}

func TestDetailsMarshalAsObjects(t *testing.T) {
	data, err := json.Marshal(List{ARF.Registration("RPRC_02a").New("the registration certificate does not chain to a trusted registrar")}.Details())
	if err != nil {
		t.Fatal(err)
	}
	if want := `[{"spec":"ARF","rule":"ARF RPRC_02a","url":"https://eudi.dev/latest/annexes/annex-2/annex-2.02-high-level-requirements-by-topic/#RPRC_02a","text":"the registration certificate does not chain to a trusted registrar","group":"registration"}]`; string(data) != want {
		t.Errorf("JSON = %s, want %s", data, want)
	}
}

type citedError struct{ finding Finding }

func (e citedError) Error() string    { return e.finding.String() }
func (e citedError) Finding() Finding { return e.finding }

func TestFromErrorKeepsTheRuleOfACitedError(t *testing.T) {
	cited := SDJWTVC.Protocol("§5.3").New("the wallet retrieves Type Metadata only from an HTTPS URL")
	if got := FromError(fmt.Errorf("resolving: %w", citedError{cited})); got != cited {
		t.Errorf("FromError = %+v, want %+v", got, cited)
	}
	if got := FromError(errors.New("plain")); got != Uncited("plain") {
		t.Errorf("FromError = %+v, want the uncited text", got)
	}
}

// A versioned specification leaves the version out of the label and the rule.
// The full citation names it.
func TestVersionedSpecCitesItsVersion(t *testing.T) {
	got := ETSI119475.Registration("GEN-5.2.4-01").New("the registration certificate has no iat")
	if got.Spec != "ETSI TS 119 475" || got.Rule != "ETSI TS 119 475 GEN-5.2.4-01" || got.Citation != "ETSI TS 119 475 V1.2.1 GEN-5.2.4-01" {
		t.Errorf("finding = %+v", got)
	}
	if want := "ETSI TS 119 475 V1.2.1 GEN-5.2.4-01: the registration certificate has no iat"; got.String() != want {
		t.Errorf("String = %q, want %q", got.String(), want)
	}
}

func TestRulesLinkToThePublishedText(t *testing.T) {
	for _, tc := range []struct {
		rule Rule
		want string
	}{
		{OID4VP.Protocol("§5.9.3"), "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#section-5.9.3"},
		{OID4VP.Protocol("Appendix A.3.2"), "https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#appendix-A.3.2"},
		{HAIP.Protocol("§5.1/§5.2"), "https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html#section-5.1"},
		{HAIP.Protocol(""), "https://openid.net/specs/openid4vc-high-assurance-interoperability-profile-1_0.html"},
		{RFC(5280).Protocol("§6.1.3 (a)(2)"), "https://www.rfc-editor.org/rfc/rfc5280.html#section-6.1.3"},
		{ARF.Registration("RPRC_22a"), "https://eudi.dev/latest/annexes/annex-2/annex-2.02-high-level-requirements-by-topic/#RPRC_22a"},
		{SDJWTVC.Protocol("§5.3.1"), "https://datatracker.ietf.org/doc/html/draft-ietf-oauth-sd-jwt-vc-19#section-5.3.1"},
		{ETSI119475.Registration("GEN-5.2.4-01"), ""},
	} {
		if got := tc.rule.New("x").URL; got != tc.want {
			t.Errorf("%s: URL = %q, want %q", tc.rule.id, got, tc.want)
		}
	}
}

func TestDraftCitesItsFullName(t *testing.T) {
	got := Draft("ABCA-10", "draft-ietf-oauth-attestation-based-client-auth-10").Protocol("§8").New("x")
	if got.Rule != "ABCA-10 §8" || got.Citation != "draft-ietf-oauth-attestation-based-client-auth-10 §8" {
		t.Errorf("finding = %+v", got)
	}
}
