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

package regcert

import (
	"strings"
	"testing"
	"time"

	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
)

// ETSI TS 119 475 V1.2.1 Annex B.2.9 requires format and meta, so an entry
// without them registers nothing (ARF RPRC_21).
func TestARegisteredEntryWithoutFormatOrTypeRegistersNothing(t *testing.T) {
	query := map[string]any{"credentials": []any{map[string]any{
		"id": "pid", "format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
		"claims": []any{map[string]any{"path": []any{"given_name"}}},
	}}}
	// A registration certificate lists the claims of an entry under "claim"
	// (ETSI TS 119 475 V1.2.1 Annex B.2.9).
	claims := []any{map[string]any{"path": []any{"given_name"}}}
	for name, tc := range map[string]struct {
		entry    map[string]any
		findings int
	}{
		"format and type": {map[string]any{"format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []any{mock.DefaultPIDVCT}}, "claim": claims}, 0},
		"no format":       {map[string]any{"meta": map[string]any{"vct_values": []any{mock.DefaultPIDVCT}}, "claim": claims}, 1},
		"no type":         {map[string]any{"format": "dc+sd-jwt", "claim": claims}, 1},
	} {
		cert := map[string]any{"credentials": []any{tc.entry}}
		if findings := OverAskingFindings(cert, query); len(findings) != tc.findings {
			t.Errorf("%s: findings %v, want %d", name, findings, tc.findings)
		}
	}
}

func TestRegistrationCertificateContentFindings(t *testing.T) {
	if findings := ContentFindings(conformantRegistrationCert()); len(findings) != 0 {
		t.Errorf("a conformant certificate should have no findings, got %v", findings)
	}

	sparse := map[string]any{"name": "X", "sub": "Y", "iat": float64(time.Now().Unix())}
	findings := ContentFindings(sparse)
	for _, want := range []string{"privacy_policy", "srv_description", "entitlements", "support_uri", "supervisory_authority", "credentials", "status", "country", "registry_uri", "policy_id", "certificate_policy"} {
		if !containsSubstring(findings, want) {
			t.Errorf("findings %v should name the missing %s", findings, want)
		}
	}
}

func TestOverAskingFindings(t *testing.T) {
	cert := conformantRegistrationCert()

	asksGivenName := map[string]any{"credentials": []any{map[string]any{
		"format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
		"claims": []any{map[string]any{"path": []any{"given_name"}}},
	}}}
	if findings := OverAskingFindings(cert, asksGivenName); len(findings) != 0 {
		t.Errorf("asking a registered claim should not be over-asking, got %v", findings)
	}

	asksFamilyName := map[string]any{"credentials": []any{map[string]any{
		"format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
		"claims": []any{map[string]any{"path": []any{"family_name"}}},
	}}}
	if !containsSubstring(OverAskingFindings(cert, asksFamilyName), "family_name") {
		t.Error("asking an unregistered claim should be over-asking")
	}

	parent := map[string]any{"credentials": []any{map[string]any{
		"format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
		"claim":  []any{map[string]any{"path": []any{"address"}}},
	}}}
	asksChild := map[string]any{"credentials": []any{map[string]any{
		"format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
		"claims": []any{map[string]any{"path": []any{"address", "street_address"}}},
	}}}
	if findings := OverAskingFindings(parent, asksChild); len(findings) != 0 {
		t.Errorf("a registered parent path should cover a child, got %v", findings)
	}

	// An unregistered credential type is one finding however many claims it
	// requests.
	asksUnregisteredType := map[string]any{"credentials": []any{map[string]any{
		"format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": []any{"urn:eudi:other:1"}},
		"claims": []any{
			map[string]any{"path": []any{"given_name"}},
			map[string]any{"path": []any{"family_name"}},
		},
	}}}
	if findings := OverAskingFindings(cert, asksUnregisteredType); len(findings) != 1 {
		t.Errorf("an unregistered type should be one finding for the query, got %v", findings)
	}

	// An entry without a claim list declares no attributes (ETSI TS 119 475
	// V1.2.1 Annex B.2.9), so every requested claim over-asks.
	typeOnly := map[string]any{"credentials": []any{map[string]any{
		"format": "dc+sd-jwt",
		"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
	}}}
	if !containsSubstring(OverAskingFindings(typeOnly, asksGivenName), "given_name") {
		t.Errorf("a type registered without claims should make given_name over-asking, got %v", OverAskingFindings(typeOnly, asksGivenName))
	}

	// A missing credentials list already has a content finding.
	noCredentials := map[string]any{"name": "X"}
	if findings := OverAskingFindings(noCredentials, asksGivenName); len(findings) != 0 {
		t.Errorf("a certificate with no credentials should produce no over-asking findings, got %v", findings)
	}
}

func TestRegistrationValidityFindings(t *testing.T) {
	now := time.Now()
	longLived := map[string]any{"iat": float64(now.Unix()), "exp": float64(now.AddDate(2, 0, 0).Unix())}
	if !containsSubstring(validityFindings(longLived, "ARF RPRC_17"), "more than 12 months") {
		t.Error("a certificate valid for two years should be flagged")
	}
	expired := map[string]any{"iat": float64(now.AddDate(0, -2, 0).Unix()), "exp": float64(now.AddDate(0, -1, 0).Unix())}
	if !containsSubstring(validityFindings(expired, "ARF RPRC_17"), "expired") {
		t.Error("an expired certificate should be flagged")
	}
	if findings := validityFindings(map[string]any{"iat": float64(now.Unix())}, "ARF RPRC_17"); len(findings) != 0 {
		t.Errorf("a certificate with iat and no exp should pass, got %v", findings)
	}
}

// A listed attestation matches an offered type with the same format and type.
// An entry without a type matches nothing (ARF RPRC_15).
func TestProvidesNeedsTheFormatAndAType(t *testing.T) {
	if Provides([]Credential{{format: "dc+sd-jwt"}}, "dc+sd-jwt", []string{"urn:example:diploma"}) {
		t.Error("a listed entry without a type authorised a type")
	}
	if Provides([]Credential{{format: "mso_mdoc", types: []string{"urn:example:diploma"}}}, "dc+sd-jwt", []string{"urn:example:diploma"}) {
		t.Error("a type in another format matched")
	}
	if !Provides([]Credential{{format: "dc+sd-jwt", types: []string{"urn:example:diploma"}}}, "dc+sd-jwt", []string{"urn:example:diploma"}) {
		t.Error("the listed type did not match")
	}
}

func containsSubstring(values []string, want string) bool {
	for _, value := range values {
		if strings.Contains(value, want) {
			return true
		}
	}
	return false
}

func conformantRegistrationCert() map[string]any {
	return map[string]any{
		"name":                  "Test Verifier",
		"sub":                   "LEIEU-TEST",
		"country":               "EU",
		"registry_uri":          "https://registrar.example",
		"policy_id":             []any{"0.4.0.19475.3.1"},
		"certificate_policy":    "https://registrar.example/policy",
		"srv_description":       []any{map[string]any{"lang": "en", "value": "Test service"}},
		"entitlements":          []any{"https://uri.etsi.org/19475/Entitlement/Service_Provider"},
		"privacy_policy":        "https://example/privacy",
		"support_uri":           "https://example/support",
		"supervisory_authority": map[string]any{"email": "dpa@example"},
		"iat":                   float64(time.Now().Unix()),
		"status":                map[string]any{"status_list": map[string]any{"idx": float64(7), "uri": "https://registrar.example/status"}},
		"credentials": []any{map[string]any{
			"format": "dc+sd-jwt",
			"meta":   map[string]any{"vct_values": []any{"urn:eudi:pid:1"}},
			"claim":  []any{map[string]any{"path": []any{"given_name"}}},
		}},
	}
}
