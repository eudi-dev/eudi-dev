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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/mock"
	"github.com/dominikschlosser/eudi-dev/v3/internal/registrar"
)

func TestRegistrationsAreStored(t *testing.T) {
	for name, open := range map[string]func(t *testing.T) *WalletStore{
		"file":   func(t *testing.T) *WalletStore { return NewWalletStore(t.TempDir()) },
		"entity": func(t *testing.T) *WalletStore { store, _ := entityStore(t); return store },
	} {
		t.Run(name, func(t *testing.T) {
			store := open(t)
			w, err := store.LoadOrCreate()
			if err != nil {
				t.Fatal(err)
			}
			rp := registerTestRelyingParty(t, w)
			if err := store.Save(w); err != nil {
				t.Fatal(err)
			}
			reloaded, err := store.LoadOrCreate()
			if err != nil {
				t.Fatal(err)
			}
			if got, ok := reloaded.Registrar().RelyingParty(rp.Identifier[0].Identifier); !ok || got.Services[0].IntendedUses[0].IntendedUseIdentifier != rp.Services[0].IntendedUses[0].IntendedUseIdentifier {
				t.Fatalf("reloaded registration %+v, found %v", got, ok)
			}
			if err := reloaded.Registrar().DeleteRelyingParty(rp.Identifier[0].Identifier); err != nil {
				t.Fatal(err)
			}
			if err := store.Save(reloaded); err != nil {
				t.Fatal(err)
			}
			if again, err := store.LoadOrCreate(); err != nil || len(again.Registrar().RegisteredRelyingParties()) != 0 {
				t.Fatalf("registrations after delete %+v (%v), want none", again.Registrar().RegisteredRelyingParties(), err)
			}
		})
	}
}

// Storage keeps the order of registrations and certificates. The registrar
// reuses the stored current certificate after a reload.
func TestRegistrarOrderAndCertificatesSurviveAReload(t *testing.T) {
	for name, open := range map[string]func(t *testing.T) *WalletStore{
		"file":   func(t *testing.T) *WalletStore { return NewWalletStore(t.TempDir()) },
		"entity": func(t *testing.T) *WalletStore { store, _ := entityStore(t); return store },
	} {
		t.Run(name, func(t *testing.T) {
			store := open(t)
			w, err := store.LoadOrCreate()
			if err != nil {
				t.Fatal(err)
			}
			var identifiers []string
			for range 12 {
				identifiers = append(identifiers, registerTestRelyingParty(t, w).Identifier[0].Identifier)
			}
			rp, _ := w.Registrar().RelyingParty(identifiers[0])
			req := registrar.RegistrationCertificateRequest{Identifier: identifiers[0], IntendedUseIdentifier: rp.Services[0].IntendedUses[0].IntendedUseIdentifier}
			var current string
			for range 12 {
				result, err := w.Registrar().IssueRegistrationCertificate(req)
				if err != nil {
					t.Fatal(err)
				}
				current = result.RegistrationCertificate
			}
			if err := store.Save(w); err != nil {
				t.Fatal(err)
			}
			reloaded, err := store.LoadOrCreate()
			if err != nil {
				t.Fatal(err)
			}
			var order []string
			for _, party := range reloaded.Registrar().RegisteredRelyingParties() {
				order = append(order, party.Identifier[0].Identifier)
			}
			if !slices.Equal(order, identifiers) {
				t.Errorf("registrations reloaded in the order %v, want %v", order, identifiers)
			}
			result, issued, err := reloaded.Registrar().CurrentRegistrationCertificate(req)
			if err != nil || issued || result.RegistrationCertificate != current {
				t.Errorf("current certificate after the reload is not the newest stored one (%v)", err)
			}
		})
	}
}

// The wallet checks a registration certificate without the registry. So a
// relying party's certificates keep working after the wallet loses the
// registry, for example on memory storage after a restart.
func TestIssuedCertificatesWorkWithoutTheRegistry(t *testing.T) {
	reg := generateTestWallet(t)
	key, chain, verifierInfo := registeredVerifier(t, reg)

	fresh := generateTestWallet(t)
	if len(fresh.Registrar().RegisteredRelyingParties()) != 0 {
		t.Fatal("the fresh wallet has registrations")
	}
	query := func(claim string) map[string]any {
		return map[string]any{"credentials": []any{map[string]any{
			"id": "pid", "format": "dc+sd-jwt",
			"meta":   map[string]any{"vct_values": []any{mock.DefaultPIDVCT}},
			"claims": []any{map[string]any{"path": []any{claim}}},
		}}}
	}
	certs, _ := verifiedRegistrationCertificates(map[string]any{"verifier_info": verifierInfo})
	if findings := overAskingFindings(certs[0], query("given_name")); len(findings) != 0 {
		t.Errorf("a registered claim: %v", findings)
	}
	if findings := overAskingFindings(certs[0], query("birthdate")); len(findings) != 1 {
		t.Errorf("an unregistered claim: %v, want one finding", findings)
	}
	if purposes, _ := consentRegistration(signedARFRequest(t, fresh, key, chain, verifierInfo)); len(purposes) != 1 || purposes[0] != "Age check" {
		t.Errorf("purposes %v, want Age check", purposes)
	}
}

func registrarJSON(t *testing.T, srv *Server, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)
	return rec
}

// The registrar API follows TS05 v1.5 for records and the German sandbox for
// certificates.
func TestTheRegistrarAPI(t *testing.T) {
	srv := newTestServer(t, true)
	if _, err := srv.wallet.EnsureDemoRegistrations(); err != nil {
		t.Fatal(err)
	}
	created := registrarJSON(t, srv, "POST", "/api/registrar/wrp", `{"tradeName":"Example Shop","services":[{"serviceIdentifier":"web","intendedUses":[{"purpose":[{"lang":"en","content":"Age check"}],"credentials":[{"format":"dc+sd-jwt","meta":{"vct_values":["`+mock.DefaultPIDVCT+`"]},"claims":[{"path":["given_name"]}]}]}]}]}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("POST /wrp: %d %s", created.Code, created.Body.String())
	}
	var rp registrar.WalletRelyingParty
	if err := json.Unmarshal(created.Body.Bytes(), &rp); err != nil {
		t.Fatal(err)
	}
	id, use := rp.Identifier[0].Identifier, rp.Services[0].IntendedUses[0].IntendedUseIdentifier

	t.Run("signed list", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/api/registrar/wrp?intendeduseidentifier="+use, nil)
		rec := httptest.NewRecorder()
		srv.mux.ServeHTTP(rec, req)
		if rec.Header().Get("Content-Type") != "application/jwt" {
			t.Fatalf("content type %q, want application/jwt", rec.Header().Get("Content-Type"))
		}
		payload, err := base64.RawURLEncoding.DecodeString(strings.Split(rec.Body.String(), ".")[1])
		if err != nil {
			t.Fatal(err)
		}
		var page struct {
			Iss  string                         `json:"iss"`
			Data []registrar.WalletRelyingParty `json:"data"`
		}
		if err := json.Unmarshal(payload, &page); err != nil || page.Iss == "" || len(page.Data) != 1 || page.Data[0].TradeName != "Example Shop" {
			t.Fatalf("page %+v (%v), want the one matching registration", page, err)
		}
	})
	t.Run("the demo issuer and verifier are ordinary records", func(t *testing.T) {
		var page struct {
			Data []registrar.WalletRelyingParty
		}
		if err := json.Unmarshal(registrarJSON(t, srv, "GET", "/api/registrar/wrp", "").Body.Bytes(), &page); err != nil || len(page.Data) != 3 {
			t.Fatalf("records %+v (%v), want the demo issuer, the demo verifier and the registration", page.Data, err)
		}
		issuer, verifier := page.Data[0], page.Data[1]
		if issuer.TradeName != DemoIssuerName || len(issuer.Services) != 1 || len(issuer.Services[0].ProvidesAttestations) == 0 || len(issuer.Services[0].IntendedUses) != 1 {
			t.Errorf("demo issuer %+v, want one provider service with the identity check", issuer)
		}
		if verifier.TradeName != DemoVerifierName || len(verifier.Services) != 1 || len(verifier.Services[0].IntendedUses) != 1 || len(verifier.Services[0].ProvidesAttestations) != 0 {
			t.Errorf("demo verifier %+v, want one service with one intended use", verifier)
		}
		if issuer.Identifier[0].Identifier == verifier.Identifier[0].Identifier {
			t.Errorf("both records have the identifier %s", issuer.Identifier[0].Identifier)
		}
	})
	t.Run("one service", func(t *testing.T) {
		if rec := registrarJSON(t, srv, "GET", "/api/registrar/wrp/"+id+"/services/web", ""); rec.Code != http.StatusOK {
			t.Fatalf("service: %d", rec.Code)
		}
		if rec := registrarJSON(t, srv, "GET", "/api/registrar/wrp/"+id+"/services/other", ""); rec.Code != http.StatusNotFound {
			t.Fatalf("unknown service: %d, want 404", rec.Code)
		}
	})
	t.Run("check intended use", func(t *testing.T) {
		for claim, want := range map[string]bool{"given_name": true, "birthdate": false} {
			rec := registrarJSON(t, srv, "GET", "/api/registrar/wrp/check-intended-use?identifier="+id+"&intendeduseidentifier="+use+"&claimpath="+claim, "")
			var page struct {
				Data struct {
					IsRegistered bool `json:"isRegistered"`
				} `json:"data"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil || page.Data.IsRegistered != want {
				t.Errorf("claim %s: %s, want isRegistered %v", claim, rec.Body.String(), want)
			}
		}
	})
	t.Run("check intended use without the intended use identifier", func(t *testing.T) {
		for query, want := range map[string]bool{
			"identifier=" + id + "&claimpath=given_name":                     true,
			"credentialmeta=" + mock.DefaultPIDVCT + "&claimpath=given_name": true,
			"identifier=" + id + "&claimpath=birthdate":                      false,
		} {
			var page struct {
				Data struct {
					IsRegistered bool `json:"isRegistered"`
				} `json:"data"`
			}
			if err := json.Unmarshal(registrarJSON(t, srv, "GET", "/api/registrar/wrp/check-intended-use?"+query, "").Body.Bytes(), &page); err != nil || page.Data.IsRegistered != want {
				t.Errorf("%s: isRegistered %v, want %v", query, page.Data.IsRegistered, want)
			}
		}
		if rec := registrarJSON(t, srv, "GET", "/api/registrar/wrp/check-intended-use?identifier=LEIXG-1", ""); rec.Code != http.StatusNotFound {
			t.Errorf("an unregistered relying party: %d, want 404", rec.Code)
		}
	})
	t.Run("filters", func(t *testing.T) {
		count := func(query string) int {
			var page struct {
				Data []registrar.WalletRelyingParty
			}
			if err := json.Unmarshal(registrarJSON(t, srv, "GET", "/api/registrar/wrp?"+query, "").Body.Bytes(), &page); err != nil {
				t.Fatal(err)
			}
			return len(page.Data)
		}
		for query, want := range map[string]int{
			"tradename=Example&policy=" + url.QueryEscape("https://issuer.example/privacy-policy"): 1,
			"tradename=Example&isintermediary=false":                                               1,
			"tradename=Example&isintermediary=true":                                                0,
			"tradename=Example&usesintermediary=web":                                               0,
			"tradename=Example&claimpath=given_name":                                               1,
		} {
			if got := count(query); got != want {
				t.Errorf("%s: %d records, want %d", query, got, want)
			}
		}
	})
	t.Run("certificates", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		csr, _ := json.Marshal(testAccessCSR(t, key))
		if rec := registrarJSON(t, srv, "POST", "/api/registrar/access-certificates", `{"identifier":"`+id+`","csr":`+string(csr)+`}`); rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), "x509_hash:") {
			t.Fatalf("access certificate: %d %s", rec.Code, rec.Body.String())
		}
		if rec := registrarJSON(t, srv, "POST", "/api/registrar/registration-certificates", `{"identifier":"`+id+`","intendedUseIdentifier":"`+use+`"}`); rec.Code != http.StatusCreated || !strings.Contains(rec.Body.String(), "verifierInfo") {
			t.Fatalf("registration certificate: %d %s", rec.Code, rec.Body.String())
		}
		if rec := registrarJSON(t, srv, "POST", "/api/registrar/registration-certificates", `{"identifier":"LEIXG-1","intendedUseIdentifier":"`+use+`"}`); rec.Code != http.StatusNotFound {
			t.Fatalf("an unregistered relying party: %d, want 404", rec.Code)
		}
	})
	t.Run("update", func(t *testing.T) {
		rp.TradeName = "Example Store"
		body, _ := json.Marshal(rp)
		rec := registrarJSON(t, srv, "PUT", "/api/registrar/wrp", string(body))
		var page struct{ Data registrar.WalletRelyingParty }
		err := json.Unmarshal(rec.Body.Bytes(), &page)
		updated := page.Data
		if err != nil || rec.Code != http.StatusOK ||
			updated.TradeName != "Example Store" || updated.Services[0].IntendedUses[0].IntendedUseIdentifier != use {
			t.Fatalf("PUT: %d %s, want the new name and the kept intended use", rec.Code, rec.Body.String())
		}
	})
	t.Run("pages", func(t *testing.T) {
		var first, second struct {
			Data       []registrar.WalletRelyingParty `json:"data"`
			Pagination struct {
				HasNextPage bool   `json:"has_next_page"`
				NextCursor  string `json:"next_cursor"`
			} `json:"pagination"`
		}
		if err := json.Unmarshal(registrarJSON(t, srv, "GET", "/api/registrar/wrp?limit=2", "").Body.Bytes(), &first); err != nil ||
			len(first.Data) != 2 || !first.Pagination.HasNextPage || first.Pagination.NextCursor != "2" {
			t.Fatalf("first page %+v (%v), want two records and a cursor", first, err)
		}
		if err := json.Unmarshal(registrarJSON(t, srv, "GET", "/api/registrar/wrp?limit=2&cursor=2", "").Body.Bytes(), &second); err != nil ||
			len(second.Data) != 1 || second.Pagination.HasNextPage || second.Data[0].Identifier[0].Identifier != id {
			t.Fatalf("second page %+v (%v), want the registration and no next page", second, err)
		}
	})
	t.Run("delete", func(t *testing.T) {
		if rec := registrarJSON(t, srv, "DELETE", "/api/registrar/wrp/"+id, ""); rec.Code != http.StatusNoContent {
			t.Fatalf("DELETE: %d", rec.Code)
		}
		if rec := registrarJSON(t, srv, "GET", "/api/registrar/wrp/"+id, ""); rec.Code != http.StatusNotFound {
			t.Fatalf("GET after DELETE: %d, want 404", rec.Code)
		}
	})
}

func TestTheRegistrarServesItsPlaceholderPages(t *testing.T) {
	srv := newTestServer(t, true)
	for _, path := range []string{"/privacy-policy", "/support", "/supervisory-authority", "/rulebook"} {
		resp := serverRequest(t, srv, http.MethodGet, path, "")
		if resp.Code != http.StatusOK || !strings.Contains(resp.Body.String(), "eudi-dev test") {
			t.Errorf("GET %s = %d %q", path, resp.Code, resp.Body.String())
		}
	}
}

// The demo registrations change only when the templates do.
func TestTheDemoRegistrationsFollowTheTemplates(t *testing.T) {
	w := generateTestWallet(t)
	if changed, err := w.EnsureDemoRegistrations(); err != nil || !changed {
		t.Fatalf("first run: changed %v, %v", changed, err)
	}
	if changed, err := w.EnsureDemoRegistrations(); err != nil || changed {
		t.Fatalf("second run: changed %v, %v", changed, err)
	}
	if _, err := credtemplate.Save(w.Templates, credtemplate.Template{Name: "badge", Format: "sdjwt", VCT: "urn:example:badge:1", Category: credtemplate.CategoryPubEAA}); err != nil {
		t.Fatal(err)
	}
	if changed, err := w.EnsureDemoRegistrations(); err != nil || !changed {
		t.Fatalf("after a new template: changed %v, %v", changed, err)
	}
	issuer, _ := w.Registrar().RelyingParty(ownProviderIdentifier(t, w))
	if !slices.Contains(issuer.Services[0].Entitlements, registrar.PubEAAProviderEntitlement) {
		t.Errorf("entitlements %v, want the PuB-EAA provider", issuer.Services[0].Entitlements)
	}
}

// The demo issuer holds a provider certificate and a verifier certificate for
// its identity check from the start, also when its registration is kept.
func TestTheDemoPartiesHoldEveryCertificateFromTheStart(t *testing.T) {
	for _, register := range []func(*Wallet) (bool, error){(*Wallet).EnsureDemoRegistrations, (*Wallet).RegisterMissingDemoParties} {
		w := generateTestWallet(t)
		if _, err := register(w); err != nil {
			t.Fatal(err)
		}
		issuer := ownProviderIdentifier(t, w)
		var uses []string
		for _, s := range w.Registrar().RegistrationCertificateStatuses(issuer) {
			uses = append(uses, s.Service+"/"+s.IntendedUse)
		}
		if !slices.Contains(uses, demoIssuer().Services[0].ServiceIdentifier+"/") || !slices.Contains(uses, "/"+demoIssuer().Services[0].IntendedUses[0].IntendedUseIdentifier) {
			t.Errorf("certificates %v, want the provider and the identity check", uses)
		}
	}
}

// The demo issuer is the provider on the trusted lists, so its registration
// names the organization that the default provider certificates carry.
func TestTheDemoIssuerRegistrationMatchesTheProviderCertificates(t *testing.T) {
	caKey, _ := mock.GenerateKey()
	ca, err := mock.GenerateCACert(caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, _ := mock.GenerateKey()
	leaf, err := mock.GenerateLeafCertWithOptions(caKey, ca, &leafKey.PublicKey, mock.LeafCertOptions{})
	if err != nil {
		t.Fatal(err)
	}
	issuer := demoIssuer()
	if got := leaf.Subject.Organization; len(got) != 1 || got[0] != issuer.LegalPerson.LegalName[0] {
		t.Errorf("certificate organization %v, want %q", got, issuer.LegalPerson.LegalName[0])
	}
	if got := leaf.Subject.Country; len(got) != 1 || got[0] != issuer.Country {
		t.Errorf("certificate country %v, want %q", got, issuer.Country)
	}
	if got, want := certificatesOrganizationIdentifier([]string{base64.StdEncoding.EncodeToString(leaf.Raw)}), "NTR"+issuer.Country+"-"+demoIdentifier(demoIssuer); got != want {
		t.Errorf("certificate organizationIdentifier %q, want %q", got, want)
	}
}
