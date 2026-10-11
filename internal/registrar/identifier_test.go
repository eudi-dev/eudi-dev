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

package registrar

import (
	"testing"
	"time"
)

// ETSI TS 119 475 V1.2.1 Table 2 maps each identifier type to a legal person
// semantics identifier of ETSI EN 319 412-1 V1.6.1 §5.1.4.
func TestTheSemanticsIdentifierFollowsTheIdentifierType(t *testing.T) {
	for _, tc := range []struct {
		id      Identifier
		country string
		want    string
	}{
		// LEG-5.1.4-07 b and its example 2.
		{Identifier{Type: EUIDIdentifierType, Identifier: "DED2601V.HRB12345"}, "", "NTRDE-DED2601V.HRB12345"},
		{Identifier{Type: EUIDIdentifierType, Identifier: "ELGEMI.123456789"}, "", "NTREL-ELGEMI.123456789"},
		{Identifier{Type: LEIIdentifierType, Identifier: "529900T8BM49AURSDO55"}, "", "LEIXG-529900T8BM49AURSDO55"},
		// LEG-5.1.4-04 and example 1.
		{Identifier{Type: VATINIdentifierType, Identifier: "BE0876866142"}, "", "VATBE-0876866142"},
		{Identifier{Type: VATINIdentifierType, Identifier: "EL123456789"}, "", "VATEL-123456789"},
		{Identifier{Type: TINIdentifierType, Identifier: "12345678901"}, "DE", "VATDE-12345678901"},
		{Identifier{Type: EORIIdentifierType, Identifier: "DE1234567"}, "", "EORDE-1234567"},
		{Identifier{Type: ExciseIdentifierType, Identifier: "DE00012345678"}, "", "EXCDE-00012345678"},
	} {
		got, err := SemanticIdentifier(tc.id, tc.country)
		if err != nil || got != tc.want {
			t.Errorf("%s %s: %q, %v, want %q", tc.id.Type, tc.id.Identifier, got, err, tc.want)
		}
	}
}

// ETSI TS 119 475 V1.2.1 B.2.2: the country is an ISO 3166-1 alpha-2 code. A
// registration without one takes it from an identifier that carries a
// country. The EUID and VAT prefix EL is Greece, GR in ISO 3166-1. A LEI
// carries no country (XG), so its registration names the country.
func TestTheCountryOfARegistrationIsAnISOCode(t *testing.T) {
	w := generateTestWallet(t)
	for _, id := range []Identifier{{Type: EUIDIdentifierType, Identifier: "ELGEMI.123456789"}, {Type: VATINIdentifierType, Identifier: "EL123456789"}} {
		rp, err := w.RegisterRelyingParty(WalletRelyingParty{TradeName: "Greek Shop " + id.Identifier, Identifier: []Identifier{id}})
		if err != nil {
			t.Fatal(err)
		}
		if rp.Country != "GR" {
			t.Errorf("%s: country %q, want GR", id.Identifier, rp.Country)
		}
	}
	lei := []Identifier{{Type: LEIIdentifierType, Identifier: "529900T8BM49AURSDO55"}}
	if rp, err := w.RegisterRelyingParty(WalletRelyingParty{TradeName: "LEI Shop", Identifier: lei}); err == nil {
		t.Errorf("a LEI without a country registered with the country %q", rp.Country)
	}
	if rp, err := w.RegisterRelyingParty(WalletRelyingParty{TradeName: "LEI Shop", Country: "DE", Identifier: lei}); err != nil || rp.Country != "DE" {
		t.Errorf("a LEI with a country: %q, %v", rp.Country, err)
	}
}

// ETSI TS 119 475 V1.2.1 Annex B.2.1 and the example of Annex C: srv_description
// is an array of arrays. Each registered description keeps its languages in
// its own inner array.
func TestTheRegistrationCertificateKeepsEachServiceDescription(t *testing.T) {
	descriptions := ServiceDescription{
		{{Lang: "en", Content: "Shop"}, {Lang: "de", Content: "Laden"}},
		{{Lang: "en", Content: "Age check"}},
	}
	claims, err := RegistrationCertificateClaimsFor("https://wallet.example", RegistrationCertificateContent{Name: "Shop", Subject: "NTRNL-NLTEST.1", Description: descriptions}, nil, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	got, _ := claims["srv_description"].([]any)
	if len(got) != 2 || len(got[0].([]map[string]any)) != 2 || len(got[1].([]map[string]any)) != 1 {
		t.Errorf("srv_description %v, want one inner array per description", claims["srv_description"])
	}
}

// An identifier without a type may be a certificate's semantics identifier.
func TestAnUntypedIdentifierTakesTheTypeItsValueShows(t *testing.T) {
	for value, want := range map[string]Identifier{
		"NLTEST.1A2B":                {Type: EUIDIdentifierType, Identifier: "NLTEST.1A2B"},
		"NTRDE-DED2601V.HRB12345":    {Type: EUIDIdentifierType, Identifier: "DED2601V.HRB12345"},
		"LEIXG-529900T8BM49AURSDO55": {Type: LEIIdentifierType, Identifier: "529900T8BM49AURSDO55"},
		"VATBE-0876866142":           {Type: VATINIdentifierType, Identifier: "BE0876866142"},
	} {
		if got := typedIdentifier(value); got != want {
			t.Errorf("%s: %+v, want %+v", value, got, want)
		}
	}
}

// A VATIN and a TIN that map to the same semantics identifier name the same
// party, so the second registration is refused.
func TestIdentifiersCompareByTheirSemanticsIdentifier(t *testing.T) {
	w := generateTestWallet(t)
	if _, err := w.RegisterRelyingParty(WalletRelyingParty{TradeName: "VAT Shop", Country: "NL", Identifier: []Identifier{{Type: VATINIdentifierType, Identifier: "NL123456789"}}}); err != nil {
		t.Fatal(err)
	}
	_, err := w.RegisterRelyingParty(WalletRelyingParty{TradeName: "TIN Shop", Country: "NL", Identifier: []Identifier{{Type: TINIdentifierType, Identifier: "123456789"}}})
	if err == nil {
		t.Error("a TIN with the semantics identifier of a registered VATIN was registered")
	}
}

// An update through the semantics identifier keeps one identifier.
func TestAnUpdateThroughTheSemanticsIdentifierKeepsOneIdentifier(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	semantic, err := SemanticIdentifier(rp.Identifier[0], rp.Country)
	if err != nil {
		t.Fatal(err)
	}
	rp.Identifier = []Identifier{{Identifier: semantic}}
	updated, err := w.UpdateRelyingParty(rp)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Identifier) != 1 {
		t.Errorf("identifiers %+v, want one", updated.Identifier)
	}
}

// An empty service identifier names a party's only service. With several,
// the caller names one.
func TestAnEmptyServiceIdentifierNamesTheOnlyService(t *testing.T) {
	one := WalletRelyingParty{Identifier: []Identifier{{Identifier: "NLTEST.1"}}, Services: []WalletRelyingPartyService{{ServiceIdentifier: "web"}}}
	if service, err := findService(one, ""); err != nil || service.ServiceIdentifier != "web" {
		t.Errorf("one service: %+v, %v", service, err)
	}
	two := one
	two.Services = append(two.Services, WalletRelyingPartyService{ServiceIdentifier: "app"})
	if _, err := findService(two, ""); err == nil {
		t.Error("an empty identifier picked one of two services")
	}
	if service, err := findService(two, "app"); err != nil || service.ServiceIdentifier != "app" {
		t.Errorf("named service: %+v, %v", service, err)
	}
}
