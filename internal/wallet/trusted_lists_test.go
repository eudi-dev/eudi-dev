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
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/dominikschlosser/eudi-dev/v3/internal/credtemplate"
	"github.com/dominikschlosser/eudi-dev/v3/internal/lote"
	"github.com/dominikschlosser/eudi-dev/v3/internal/provider"
	"github.com/dominikschlosser/eudi-dev/v3/internal/trustedlists"
)

// The anchors of the --arf checks come from the wallet's lists of access
// certificate providers and registration certificate providers (ETSI TS 119
// 602 V1.1.1 Annexes F and G). The wallet CA anchors neither.
func TestTheARFAnchorsComeFromTheWalletsLists(t *testing.T) {
	w := generateTestWallet(t)
	_, accessCA, err := w.Signer().RelyingPartyAccessCA()
	if err != nil {
		t.Fatal(err)
	}
	_, registrarCA, err := w.Signer().RegistrarCA()
	if err != nil {
		t.Fatal(err)
	}
	walletCA := w.Signer().TrustAnchor()
	contains := func(certs []*x509.Certificate, cert *x509.Certificate) bool {
		return slices.ContainsFunc(certs, cert.Equal)
	}
	if got := w.TrustedLists().RelyingPartyCAs(); !contains(got, accessCA) || contains(got, walletCA) {
		t.Errorf("access anchors %d, want the relying party access CA and not the wallet CA", len(got))
	}
	if got := w.TrustedLists().RegistrarCAs(); !contains(got, registrarCA) || contains(got, walletCA) || contains(got, accessCA) {
		t.Errorf("registrar anchors %d, want the registrar CA only", len(got))
	}
	if got := w.TrustedLists().RegistrationStatusCAs(); !contains(got, registrarCA) {
		t.Errorf("status anchors %d, want the registrar CA", len(got))
	}
}

// A CA put on the PID list anchors the PIDs of that issuer (ARF ISSU_07).
func TestAnAddedIssuerCAAnchorsItsPIDs(t *testing.T) {
	foreign := generateTestWalletWithPID(t)
	pid := foreign.GetCredentials()[0]
	w := generateTestWallet(t)
	w.RequireARF = true
	if findings := w.trustAnchorFindings(receivedCredential(pid.Raw)); !containsSubstring(findings, "ISSU_07") {
		t.Fatalf("findings %v, want ISSU_07 for a foreign PID", findings)
	}
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: foreign.Signer().TrustAnchor().Raw}))
	if _, err := addTrustedEntity(w, credtemplate.CategoryPID, "Foreign PID Provider", caPEM); err != nil {
		t.Fatal(err)
	}
	if findings := w.trustAnchorFindings(receivedCredential(pid.Raw)); len(findings) != 0 {
		t.Errorf("findings %v, want none with the issuer CA on the PID list", findings)
	}
}

// An external PID list on the list of trusted lists anchors its providers,
// once its signer chains to a trusted list operator (ARF ISSU_07, TLPub_07).
func TestAnExternalPIDListAnchorsItsProviders(t *testing.T) {
	foreign := generateTestWalletWithPID(t)
	foreign.IssuerURL = "https://foreign.example"
	pid := foreign.GetCredentials()[0]
	list, err := foreign.TrustedLists().SignedGroupList(foreign.IssuerURL, foreign.TrustedLists().DefaultGroup(), "/api/trustlists/pid")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { _, _ = rw.Write([]byte(list)) }))
	t.Cleanup(srv.Close)

	w := generateTestWallet(t)
	w.RequireARF = true
	if _, err := addTrustedList(w, srv.URL); err != nil {
		t.Fatal(err)
	}
	if findings := w.trustAnchorFindings(receivedCredential(pid.Raw)); !containsSubstring(findings, "ISSU_07") {
		t.Errorf("findings %v, want ISSU_07 while the list operator is unknown", findings)
	}
	w.TrustSettings.ListCAPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: foreign.Signer().TrustAnchor().Raw})
	if findings := w.trustAnchorFindings(receivedCredential(pid.Raw)); len(findings) != 0 {
		t.Errorf("findings %v, want none with a trusted list operator", findings)
	}
}

// Only issuance services that are not withdrawn anchor a credential (ETSI TS
// 119 602 V1.1.1 Table H.3).
func TestOnlyCurrentIssuanceServicesAreAnchors(t *testing.T) {
	cert := func(name string) lote.CertInfo { return lote.CertInfo{Subject: name} }
	list := &lote.List{Entities: []lote.TrustedEntity{{Services: []lote.TrustedService{
		{ServiceType: "http://uri.etsi.org/19602/SvcType/PubEAA/Issuance", ServiceStatus: lote.PubEAANotifiedStatus, Certificates: []lote.CertInfo{cert("notified")}},
		{ServiceType: "http://uri.etsi.org/19602/SvcType/PubEAA/Issuance", ServiceStatus: "http://uri.etsi.org/19602/PubEAAProvidersList/SvcStatus/withdrawn", Certificates: []lote.CertInfo{cert("withdrawn")}},
		{ServiceType: "http://uri.etsi.org/19602/SvcType/PubEAA/Revocation", Certificates: []lote.CertInfo{cert("revocation")}},
	}}}}
	if got := lote.ServiceCertificates(list, lote.IssuanceServices); len(got) != 1 || got[0].Subject != "notified" {
		t.Errorf("anchors %+v, want the notified issuance service", got)
	}
}

// The list of trusted lists points to all of the wallet's lists, with each
// list's type and signer certificate (ETSI TS 119 602 V1.1.1 §6.3.13).
func TestTheListOfTrustedListsPointsToEveryList(t *testing.T) {
	foreign := generateTestWallet(t)
	external, err := foreign.TrustedLists().SignedGroupList("https://foreign.example", foreign.TrustedLists().DefaultGroup(), "/api/trustlists/pid")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) { _, _ = rw.Write([]byte(external)) }))
	t.Cleanup(srv.Close)
	w := generateTestWallet(t)
	w.IssuerURL = "https://wallet.example"
	w.TrustSettings.ConfiguredLists = []string{srv.URL}
	w.TrustSettings.ListCAPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: foreign.Signer().TrustAnchor().Raw})

	raw, err := w.TrustedLists().ListOfLists(w.IssuerURL)
	if err != nil {
		t.Fatal(err)
	}
	operators, err := w.TrustedLists().ListCAs()
	if err != nil {
		t.Fatal(err)
	}
	if err := trustedlists.VerifyListSigner(raw, operators); err != nil {
		t.Fatal(err)
	}
	list, err := lote.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if list.SchemeInfo.LoTEType != trustedlists.ListOfListsType {
		t.Errorf("type %q, want %q", list.SchemeInfo.LoTEType, trustedlists.ListOfListsType)
	}
	types := map[string]string{}
	for _, p := range list.SchemeInfo.Pointers {
		types[p.Location] = p.LoTEType
		if len(p.Certificates) != 1 || p.SchemeOperatorName == "" || p.SchemeTerritory == "" {
			t.Errorf("pointer %+v, want one signer certificate, the operator name and the territory", p)
		}
	}
	for location, want := range map[string]string{
		"https://wallet.example/api/trustlists/pid":       lote.PIDProvidersListType,
		"https://wallet.example/api/trustlists/access-ca": lote.AccessCertProvidersListType,
		"https://wallet.example/api/trustlists/registrar": lote.RegistrationCertProvidersListType,
		srv.URL: lote.PIDProvidersListType,
	} {
		if types[location] != want {
			t.Errorf("pointer %s has type %q, want %q", location, types[location], want)
		}
	}
}

// Users add providers and external lists through the API, and the wallet
// stores them.
func TestTheTrustAPIAddsAndRemovesEntitiesAndLists(t *testing.T) {
	srv := newTestServer(t, true)
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: generateTestWallet(t).Signer().TrustAnchor().Raw}))
	body, _ := json.Marshal(map[string]string{"list": "eaa", "name": "Example University", "certificates": caPEM})
	rec := serverRequest(t, srv, http.MethodPost, "/api/trust/entities", string(body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("adding an entity: %d %s", rec.Code, rec.Body)
	}
	var entity trustedlists.Entity
	if err := json.Unmarshal(rec.Body.Bytes(), &entity); err != nil {
		t.Fatal(err)
	}
	if rec := serverRequest(t, srv, http.MethodPost, "/api/trust/lists", `{"url":"https://lists.example/pid"}`); rec.Code != http.StatusCreated {
		t.Fatalf("adding a list: %d %s", rec.Code, rec.Body)
	}
	if rec := serverRequest(t, srv, http.MethodPost, "/api/trust/entities", `{"list":"nowhere","certificates":""}`); rec.Code != http.StatusBadRequest {
		t.Errorf("an unknown list: %d, want 400", rec.Code)
	}

	var state trustedlists.Summary
	if err := json.Unmarshal(serverRequest(t, srv, http.MethodGet, "/api/trust", "").Body.Bytes(), &state); err != nil {
		t.Fatal(err)
	}
	if len(state.Entities) != 1 || state.Entities[0].Name != "Example University" || len(state.Lists) != 1 || !strings.HasSuffix(state.ListsURL, "/api/trustlists/lists") {
		t.Fatalf("state %+v", state)
	}
	// The wallet signs the entity onto its list.
	group, _ := srv.wallet.TrustedLists().FindGroup("eaa", "", "")
	raw, err := srv.wallet.TrustedLists().SignedGroupList(srv.wallet.IssuerURL, group, "/api/trustlists/eaa")
	if err != nil {
		t.Fatal(err)
	}
	if list, err := lote.Parse(raw); err != nil || !slices.ContainsFunc(list.Entities, func(e lote.TrustedEntity) bool { return e.Name == "Example University" }) {
		t.Errorf("the eaa list does not name the entity (%v)", err)
	}

	if rec := serverRequest(t, srv, http.MethodDelete, "/api/trust/entities/"+entity.ID, ""); rec.Code != http.StatusNoContent {
		t.Errorf("removing the entity: %d", rec.Code)
	}
	if rec := serverRequest(t, srv, http.MethodDelete, "/api/trust/lists?url=https://lists.example/pid", ""); rec.Code != http.StatusNoContent {
		t.Errorf("removing the list: %d", rec.Code)
	}
	if rec := serverRequest(t, srv, http.MethodDelete, "/api/trust/entities/"+entity.ID, ""); rec.Code != http.StatusNotFound {
		t.Errorf("removing it again: %d, want 404", rec.Code)
	}
}

// Added providers and lists survive a reload on every storage mode.
func TestTrustedEntitiesAndListsSurviveAReload(t *testing.T) {
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
			caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: w.Signer().TrustAnchor().Raw}))
			entity, err := addTrustedEntity(w, "qeaa", "Example Bank", caPEM)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := addTrustedList(w, "https://lists.example/pid"); err != nil {
				t.Fatal(err)
			}
			if err := store.Save(w); err != nil {
				t.Fatal(err)
			}
			reloaded, err := store.LoadOrCreate()
			if err != nil {
				t.Fatal(err)
			}
			if got := reloaded.TrustedLists().Entities(); len(got) != 1 || got[0].ID != entity.ID {
				t.Errorf("entities %+v, want the added one", got)
			}
			if got := reloaded.AddedTrustedLists; !slices.Equal(got, []string{"https://lists.example/pid"}) {
				t.Errorf("lists %v, want the added one", got)
			}
		})
	}
}

// A list of trusted lists leads the wallet to the lists in its pointers. A
// pointed-to list must be signed with a certificate from its pointer (ETSI TS
// 119 602 V1.1.1 §6.3.13).
func TestAListOfTrustedListsLeadsToItsLists(t *testing.T) {
	foreign := generateTestWalletWithPID(t)
	pid := foreign.GetCredentials()[0]
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		var raw string
		var err error
		if r.URL.Path == "/api/trustlists/lists" {
			raw, err = foreign.TrustedLists().ListOfLists(foreign.IssuerURL)
		} else {
			raw, err = foreign.TrustedLists().SignedGroupList(foreign.IssuerURL, foreign.TrustedLists().DefaultGroup(), "/api/trustlists/pid")
		}
		if err != nil {
			http.Error(rw, err.Error(), http.StatusInternalServerError)
			return
		}
		_, _ = rw.Write([]byte(raw))
	}))
	t.Cleanup(srv.Close)
	foreign.IssuerURL = srv.URL

	w := generateTestWallet(t)
	w.RequireARF = true
	w.TrustSettings.ListCAPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: foreign.Signer().TrustAnchor().Raw})
	if _, err := addTrustedList(w, srv.URL+"/api/trustlists/lists"); err != nil {
		t.Fatal(err)
	}
	if findings := w.trustAnchorFindings(receivedCredential(pid.Raw)); len(findings) != 0 {
		t.Errorf("findings %v, want none through the pointed-to PID list", findings)
	}
	state := w.TrustedLists().Summary()
	if !slices.ContainsFunc(state.Lists, func(l trustedlists.Link) bool {
		return l.URL == srv.URL+"/api/trustlists/pid" && l.Via == srv.URL+"/api/trustlists/lists" && l.Error == ""
	}) {
		t.Errorf("lists %+v, want the PID list reached through the list of trusted lists", state.Lists)
	}
}

// Strict mode refuses an unreadable list. Debug mode adds it and says why it
// can't be used.
func TestAnUnreadableListIsRefusedInStrictModeAndReportedInDebugMode(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	w := generateTestWallet(t)
	w.ValidationMode = ValidationModeStrict
	if _, err := addTrustedList(w, srv.URL); err == nil {
		t.Error("strict mode added an unreadable list")
	}
	w.ValidationMode = ValidationModeDebug
	link, err := addTrustedList(w, srv.URL)
	if err != nil || link.Error == "" {
		t.Errorf("link %+v, err %v, want the list with the reason", link, err)
	}
	if state := w.TrustedLists().Summary(); len(state.Lists) != 1 || state.Lists[0].Error == "" {
		t.Errorf("lists %+v, want the list with the reason", state.Lists)
	}
}

// A CA added to the registrar list anchors the registration certificates and
// their status lists (ETSI TS 119 602 V1.1.1 Table G.3).
func TestAnAddedRegistrarCAAnchorsCertificatesAndStatusLists(t *testing.T) {
	w := generateTestWallet(t)
	ca := generateTestWallet(t).Signer().TrustAnchor()
	if _, err := addTrustedEntity(w, provider.RegistrarListID, "Other Registrar", string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.Raw}))); err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(w.TrustedLists().RegistrarCAs(), ca.Equal) || !slices.ContainsFunc(w.TrustedLists().RegistrationStatusCAs(), ca.Equal) {
		t.Error("the added registrar CA anchors neither the certificates nor their status lists")
	}
}

// An unreachable list is fetched once a minute, not on every check.
func TestAFailedListIsReusedForAMinute(t *testing.T) {
	var fetches atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		fetches.Add(1)
		http.NotFound(rw, nil)
	}))
	t.Cleanup(srv.Close)
	w := generateTestWallet(t)
	for range 3 {
		if _, err := w.TrustedLists().ReadList(srv.URL); err == nil {
			t.Fatal("read an unreachable list")
		}
	}
	if got := fetches.Load(); got != 1 {
		t.Errorf("fetched %d times, want once", got)
	}
}

// The capacity bounds added providers and lists on every path, the CLI
// included.
func TestCapacityBoundsAddedProvidersAndLists(t *testing.T) {
	w := generateTestWallet(t)
	w.TrustSettings.MaxEntities, w.TrustSettings.MaxLists = 1, 1
	w.AddedTrustedLists = []string{"https://lists.example/one"}
	if _, err := addTrustedList(w, "https://lists.example/two"); !errors.Is(err, trustedlists.ErrFull) {
		t.Errorf("a second list: %v, want trustedlists.ErrFull", err)
	}
	if err := w.TrustedLists().ListRoom("https://lists.example/one"); err != nil {
		t.Errorf("a list the wallet has: %v", err)
	}
	pem := string(certPEM(w.CertChain[len(w.CertChain)-1]))
	if _, err := addTrustedEntity(w, "pid", "first", pem); err != nil {
		t.Fatal(err)
	}
	if _, err := addTrustedEntity(w, "eaa", "second", pem); !errors.Is(err, trustedlists.ErrFull) {
		t.Errorf("a second provider: %v, want trustedlists.ErrFull", err)
	}
}

// A stored trusted-list CA that no longer decodes is reported, so the wallet
// doesn't trust fewer list operators without saying why.
func TestTrustListCAsReportsAnUnreadableEntity(t *testing.T) {
	w := generateTestWallet(t)
	w.TrustedEntities = []trustedlists.Entity{{ID: "x", List: trustedlists.TrustedListCAID, Name: "broken", Certificates: []string{"not base64"}}}
	if _, err := w.TrustedLists().ListCAs(); err == nil || !strings.Contains(err.Error(), "broken") {
		t.Errorf("ListCAs: %v", err)
	}
}

// addTrustedEntity puts a provider with the certificates in PEM on the list,
// as the trust API does.
func addTrustedEntity(w *Wallet, list, name, certificatesPEM string) (trustedlists.Entity, error) {
	entity, err := trustedlists.NewEntity(list, name, certificatesPEM)
	if err != nil {
		return trustedlists.Entity{}, err
	}
	return entity, w.TrustedLists().StoreEntity(entity)
}

// addTrustedList puts an external list on the list of trusted lists, as the
// trust API does.
func addTrustedList(w *Wallet, rawURL string) (trustedlists.Link, error) {
	set := w.TrustedLists()
	if err := set.ListRoom(rawURL); err != nil {
		return trustedlists.Link{}, err
	}
	link, err := set.CheckList(rawURL)
	if err != nil {
		return trustedlists.Link{}, err
	}
	return link, set.StoreList(link.URL)
}
