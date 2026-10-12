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
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/eudi-dev/eudi-dev/v3/internal/mock"
)

func TestTheRegistrarAssignsWhatARegistrationLeavesOut(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)

	id := rp.Identifier[0]
	if semantic, err := SemanticIdentifier(id, rp.Country); err != nil || id.Type != EUIDIdentifierType || semantic != "NTRNL-"+id.Identifier {
		t.Errorf("identifier %+v (%q, %v), want an assigned EUID", id, semantic, err)
	}
	if rp.RegistryURI != "https://wallet.example/api/registrar/wrp/"+id.Identifier || rp.LegalPerson.LegalName[0] != "Example Shop" {
		t.Errorf("registry URI %q, legal name %v", rp.RegistryURI, rp.LegalPerson.LegalName)
	}
	use := rp.Services[0].IntendedUses[0]
	if use.IntendedUseIdentifier == "" || use.CreatedAt == "" || len(use.PrivacyPolicy) == 0 {
		t.Errorf("intended use %+v, want an identifier, a date and a privacy policy", use)
	}
	if _, err := w.RegisterRelyingParty(rp); err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Errorf("registering the same identifier again: %v", err)
	}
}

func TestAnUpdateKeepsRegisteredIntendedUses(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	kept := rp.Services[0].IntendedUses[0].IntendedUseIdentifier
	created := rp.Services[0].IntendedUses[0].CreatedAt
	rp.Services[0].IntendedUses[0].CreatedAt = "1999-01-01"
	added := IntendedUse{
		Purpose:     []MultiLangString{{Lang: "en", Content: "Ticket check"}},
		Credentials: []RegisteredCredential{{Format: "mso_mdoc", Meta: map[string]any{"doctype_value": mock.PIDNamespace}, Claims: []RegisteredClaim{{Path: []any{mock.PIDNamespace, "given_name"}}}}},
	}
	rp.Services[0].IntendedUses = append(rp.Services[0].IntendedUses, added)

	updated, err := w.UpdateRelyingParty(rp)
	if err != nil {
		t.Fatalf("UpdateRelyingParty: %v", err)
	}
	uses := updated.Services[0].IntendedUses
	if len(uses) != 2 || uses[0].IntendedUseIdentifier != kept || uses[0].CreatedAt != created || uses[1].IntendedUseIdentifier == "" {
		t.Fatalf("intended uses %+v, want the first kept with its date and the second assigned", uses)
	}
	if err := w.DeleteRelyingParty(rp.Identifier[0].Identifier); err != nil {
		t.Fatalf("DeleteRelyingParty: %v", err)
	}
	if _, err := w.UpdateRelyingParty(rp); err == nil || !strings.Contains(err.Error(), "not registered") {
		t.Errorf("updating a deleted registration: %v", err)
	}
}

func TestRegistrationsAreChecked(t *testing.T) {
	use := func(id string) IntendedUse {
		return IntendedUse{IntendedUseIdentifier: id, Purpose: []MultiLangString{{Lang: "en", Content: "Age check"}}, Credentials: []RegisteredCredential{{Format: "dc+sd-jwt", Meta: map[string]any{"vct_values": []any{mock.DefaultPIDVCT}}, Claims: []RegisteredClaim{{Path: []any{"given_name"}}}}}}
	}
	for _, tc := range []struct {
		name string
		rp   WalletRelyingParty
		want string
	}{
		{"country name", WalletRelyingParty{TradeName: "Shop", Country: "Germany"}, "two-letter country code"},
		{"intended use without purpose", WalletRelyingParty{TradeName: "Shop", Services: []WalletRelyingPartyService{{IntendedUses: []IntendedUse{{
			Credentials: use("").Credentials,
		}}}}}, "needs a purpose"},
		{"credential without claims", WalletRelyingParty{TradeName: "Shop", Services: []WalletRelyingPartyService{{IntendedUses: []IntendedUse{{
			Purpose:     use("").Purpose,
			Credentials: []RegisteredCredential{{Format: "dc+sd-jwt", Meta: map[string]any{"vct_values": []any{mock.DefaultPIDVCT}}}},
		}}}}}, "needs at least one claim"},
		{"EUID with a space", WalletRelyingParty{TradeName: "Shop", Identifier: []Identifier{{Identifier: "NLTEST.12 34", Type: EUIDIdentifierType}}}, "not an EUID"},
		{"semantics identifier as EUID", WalletRelyingParty{TradeName: "Shop", Identifier: []Identifier{{Identifier: "NTRNL-12345678", Type: EUIDIdentifierType}}}, "not an EUID"},
		{"short LEI", WalletRelyingParty{TradeName: "Shop", Identifier: []Identifier{{Identifier: "529900T8BM49", Type: LEIIdentifierType}}}, "not a LEI"},
		{"unknown identifier type", WalletRelyingParty{TradeName: "Shop", Identifier: []Identifier{{Identifier: "12345678", Type: "https://example.com/id"}}}, "not one of the types"},
		{"service twice", WalletRelyingParty{TradeName: "Shop", Services: []WalletRelyingPartyService{{ServiceIdentifier: "web"}, {ServiceIdentifier: "web"}}}, "registered twice"},
		{"intended use twice", WalletRelyingParty{TradeName: "Shop", Services: []WalletRelyingPartyService{{IntendedUses: []IntendedUse{use("a"), use("a")}}}}, "registered twice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := generateTestWallet(t).RegisterRelyingParty(tc.rp)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %v, want one containing %q", err, tc.want)
			}
		})
	}
}

// A registration can't claim another party's identifier, also as an
// additional identifier.
func TestARegistrationCannotTakeAnotherPartysIdentifier(t *testing.T) {
	w := generateTestWallet(t)
	taken := registerTestRelyingParty(t, w).Identifier[0].Identifier
	_, err := w.RegisterRelyingParty(WalletRelyingParty{
		TradeName:  "Other Shop",
		Identifier: []Identifier{{Identifier: "NLTEST.OTHER"}, {Identifier: taken}},
	})
	if err == nil || !strings.Contains(err.Error(), "already registered") {
		t.Errorf("error %v, want the identifier taken", err)
	}
}

// The primary identifier is in every issued certificate, so an update sent
// through another identifier keeps it.
func TestAnUpdateThroughASecondaryIdentifierKeepsThePrimary(t *testing.T) {
	w := generateTestWallet(t)
	rp := registerTestRelyingParty(t, w)
	primary := rp.Identifier[0]
	rp.Identifier = append(rp.Identifier, Identifier{Type: "http://data.europa.eu/eudi/id/EUID", Identifier: "DEHRB.12345"})
	if _, err := w.UpdateRelyingParty(rp); err != nil {
		t.Fatal(err)
	}
	rp.Identifier = []Identifier{rp.Identifier[1]}
	updated, err := w.UpdateRelyingParty(rp)
	if err != nil {
		t.Fatal(err)
	}
	if len(updated.Identifier) != 2 || updated.Identifier[0] != primary {
		t.Errorf("identifiers %+v, want %v first", updated.Identifier, primary)
	}
}

// The API keeps registrations small, so a public demo stays small between
// resets.
func TestTheAPIRefusesAnOversizedRegistration(t *testing.T) {
	reg := generateTestWallet(t)
	h := &Server{Registrar: func() *Registrar { return reg.Registrar }, Mutate: func(change func() bool) { change() }}
	body, _ := json.Marshal(WalletRelyingParty{TradeName: "Shop", Services: make([]WalletRelyingPartyService, 21)})
	rec := httptest.NewRecorder()
	h.Routes()["POST /api/registrar/wrp"](rec, httptest.NewRequest(http.MethodPost, "/api/registrar/wrp", bytes.NewReader(body)))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "at most 20 services") {
		t.Errorf("%d %s, want the size limit", rec.Code, rec.Body)
	}
}

// A service that only acts as an intermediary has no entitlement (TS05 v1.5
// §2.4.1).
func TestAPureIntermediaryHasNoEntitlement(t *testing.T) {
	w := generateTestWallet(t)
	intermediary := WalletRelyingParty{TradeName: "Example Intermediary", Services: []WalletRelyingPartyService{{IsIntermediary: true}}}
	stored, err := w.RegisterRelyingParty(intermediary)
	if err != nil {
		t.Fatal(err)
	}
	if got := stored.Services[0].Entitlements; len(got) != 0 {
		t.Errorf("entitlements %v, want none", got)
	}
	intermediary.Services[0].Entitlements = []string{ServiceProviderEntitlement}
	if _, err := w.RegisterRelyingParty(intermediary); err == nil || !strings.Contains(err.Error(), "intermediary") {
		t.Errorf("error %v, want the entitlement refused", err)
	}
}
