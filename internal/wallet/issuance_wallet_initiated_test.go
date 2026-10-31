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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eudi-dev/eudi-dev/v3/internal/consent"
	"github.com/eudi-dev/eudi-dev/v3/internal/credtype"
	"github.com/eudi-dev/eudi-dev/v3/internal/oid4vp"
	"github.com/eudi-dev/eudi-dev/v3/internal/registrar"
)

func displayed(format, typ, name string) map[string]any {
	configuration := map[string]any{"format": format, "credential_metadata": map[string]any{"display": []any{map[string]any{"name": name}}}}
	if format == credtype.FormatMDOC {
		configuration["doctype"] = typ
	} else {
		configuration["vct"] = typ
	}
	return configuration
}

// National PIDs share one doctype. An entry gets its own mdoc configuration and
// one configuration per format (ARF ISSU_12a).
func TestAnEntryMatchesOneConfigurationPerFormat(t *testing.T) {
	configurations := map[string]any{
		"dutch-sdjwt":  displayed(credtype.FormatSDJWT, "urn:dutch", "Dutch PID"),
		"dutch-mdoc":   displayed(credtype.FormatMDOC, "eu.pid", "Dutch PID"),
		"german-mdoc":  displayed(credtype.FormatMDOC, "eu.pid", "German PID"),
		"german-sdjwt": displayed(credtype.FormatSDJWT, "urn:german", "German PID"),
	}
	entry := registrar.CatalogAttestation{Name: "Dutch PID", Credentials: []registrar.CatalogCredential{
		{Format: credtype.FormatSDJWT, Type: "urn:dutch"}, {Format: credtype.FormatMDOC, Type: "eu.pid"},
	}}
	got := matchingConfigurations(configurations, entry)
	if !slices.Equal(got, []string{"dutch-mdoc", "dutch-sdjwt"}) {
		t.Errorf("configurations = %v", got)
	}
	if formats := configurationFormats(configurations, got); !slices.Equal(formats, []string{credtype.FormatMDOC, credtype.FormatSDJWT}) {
		t.Errorf("formats = %v", formats)
	}
}

// The request has no issuer_state, because no issuer started it.
func TestAWalletInitiatedOfferHasNoIssuerState(t *testing.T) {
	uri, err := walletInitiatedOffer("https://issuer.example", []string{"pid"})
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := url.Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	var offer map[string]any
	if err := json.Unmarshal([]byte(parsed.Query().Get("credential_offer")), &offer); err != nil {
		t.Fatal(err)
	}
	if offer["credential_issuer"] != "https://issuer.example" || strings.Contains(uri, "issuer_state") {
		t.Errorf("offer = %v", offer)
	}
}

// A query without a credential names the catalogue entry that answers it. A
// query with a credential or an unknown type names none.
func TestAQueryWithoutACredentialNamesItsCatalogueEntry(t *testing.T) {
	srv := newTestServer(t, true)
	entries := srv.wallet.Registrar().CatalogAttestations()
	if len(entries) == 0 || len(entries[0].Credentials) == 0 {
		t.Fatal("the test wallet has no catalogue")
	}
	entry, credential := entries[0], entries[0].Credentials[0]
	meta := map[string]any{"vct_values": []any{credential.Type}}
	if credential.Format == credtype.FormatMDOC {
		meta = map[string]any{"doctype_value": credential.Type}
	}
	query := map[string]any{"credentials": []any{
		map[string]any{"id": "known", "format": credential.Format, "meta": meta},
		map[string]any{"id": "unknown", "format": "dc+sd-jwt", "meta": map[string]any{"vct_values": []any{"urn:unknown"}}},
		map[string]any{"id": "held", "format": credential.Format, "meta": meta},
	}}
	options := &consent.CredentialOptions{Queries: []consent.QueryOptions{
		{ID: "known"}, {ID: "unknown"}, {ID: "held", Candidates: []consent.Match{{CredentialID: "a"}}},
	}}
	srv.wallet.flagObtainableCredentials(query, options)
	if got := options.Queries[0].Obtainable; !slices.Contains(got, consent.Obtainable{ID: entry.Schema.ID, Name: entry.Name}) {
		t.Errorf("known query: %+v, want %q", got, entry.Name)
	}
	if options.Queries[1].Obtainable != nil || options.Queries[2].Obtainable != nil {
		t.Errorf("queries = %+v, want no entry for the unknown type and the held credential", options.Queries)
	}
}

// OpenID4VCI 1.0 §5.1.2: scope carries several credentials. One configuration
// without a scope moves all of them to authorization_details (§5.1.1).
func TestOneAuthorizationCoversEveryConfiguration(t *testing.T) {
	w := generateTestWallet(t)
	metadata := map[string]any{"credential_configurations_supported": map[string]any{
		"sdjwt": map[string]any{"scope": "pid"},
		"mdoc":  map[string]any{"scope": "pid"},
		"other": map[string]any{"scope": "ticket"},
		"plain": map[string]any{},
	}}
	scoped, err := w.authorizationCredentialRequest(metadata, []string{"sdjwt", "mdoc", "other"})
	if err != nil || scoped.Get("scope") != "pid ticket" {
		t.Errorf("scope = %q (%v), want each scope once", scoped.Get("scope"), err)
	}
	mixed, err := w.authorizationCredentialRequest(metadata, []string{"sdjwt", "plain"})
	if err != nil {
		t.Fatal(err)
	}
	var details []map[string]any
	if err := json.Unmarshal([]byte(mixed.Get("authorization_details")), &details); err != nil {
		t.Fatal(err)
	}
	if mixed.Get("scope") != "" || len(details) != 2 || details[1]["credential_configuration_id"] != "plain" {
		t.Errorf("request = %v", mixed)
	}
}

// A credential that arrives while the dialog is open answers its query. A dialog
// with an answer for every query keeps what the user selected.
func TestAnIssuedCredentialReachesTheWaitingDialog(t *testing.T) {
	w := generateTestWalletWithPID(t)
	cred := w.GetCredentials()[0]
	meta := map[string]any{"vct_values": []any{cred.VCT}}
	format := cred.Format
	if format == credtype.FormatMDOC {
		meta = map[string]any{"doctype_value": cred.DocType}
	}
	query := map[string]any{"credentials": []any{map[string]any{"id": "wanted", "format": format, "meta": meta}}}

	waiting := consent.NewRequest(consent.TypePresentation, "")
	waiting.DCQLQuery = query
	waiting.CredentialOptions = &consent.CredentialOptions{Queries: []consent.QueryOptions{{ID: "wanted"}}}
	answered := consent.NewRequest(consent.TypePresentation, "")
	answered.DCQLQuery = query
	keep := &consent.CredentialOptions{Queries: []consent.QueryOptions{{ID: "wanted", Candidates: []consent.Match{{CredentialID: "kept"}}}}}
	answered.CredentialOptions = keep
	for _, req := range []*consent.Request{waiting, answered} {
		if err := w.Consents().Create(req); err != nil {
			t.Fatal(err)
		}
	}
	announced, unsubscribe := w.Consents().Subscribe()
	defer unsubscribe()

	w.refreshWaitingPresentations()

	if len(waiting.MatchedCreds) == 0 || len(waiting.CredentialOptions.Queries[0].Candidates) == 0 {
		t.Errorf("waiting dialog: %+v", waiting.CredentialOptions)
	}
	if answered.CredentialOptions != keep {
		t.Errorf("answered dialog changed: %+v", answered.CredentialOptions)
	}
	select {
	case req := <-announced:
		if req.ID != waiting.ID || !req.Updated {
			t.Errorf("announced %s, want the waiting dialog", req.ID)
		}
	default:
		t.Error("the update was not announced")
	}
}

func TestARequestListsEachConfigurationOnce(t *testing.T) {
	srv := newTestServer(t, true)
	w := serverRequest(t, srv, http.MethodPost, issuancePath, `{"issuer":"https://issuer.example","credential_configuration_ids":["pid","pid"]}`)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "twice") {
		t.Errorf("POST = %d: %s", w.Code, w.Body)
	}
}

// A token that leaves out a configuration has no credential for it. The
// identifier of another configuration stays with that configuration.
func TestATokenWithoutTheConfigurationIssuesNothingForIt(t *testing.T) {
	w := generateTestWallet(t)
	grant := &accessGrant{response: map[string]any{"authorization_details": []any{
		map[string]any{"credential_configuration_id": "sdjwt", "credential_identifiers": []any{"id-1"}},
	}}}
	_, err := w.issueAdditionalConfiguration(issuanceSession{renewal: CredentialRenewal{ConfigurationID: "mdoc"}}, grant)
	if err == nil || !strings.Contains(err.Error(), "does not cover") {
		t.Errorf("err = %v", err)
	}
}

func TestARotatedRefreshTokenReachesEveryFormat(t *testing.T) {
	w := generateTestWallet(t)
	w.Credentials = []StoredCredential{
		{ID: "sdjwt", Renewal: &CredentialRenewal{RefreshToken: "old"}},
		{ID: "mdoc", Renewal: &CredentialRenewal{RefreshToken: "old"}},
		{ID: "other", Renewal: &CredentialRenewal{RefreshToken: "unrelated"}},
	}
	w.DeferredIssuances = []DeferredIssuance{{CredentialRenewal: CredentialRenewal{RefreshToken: "old"}}}
	w.replaceRefreshToken("old", "new")
	if w.Credentials[0].Renewal.RefreshToken != "new" || w.Credentials[1].Renewal.RefreshToken != "new" || w.DeferredIssuances[0].RefreshToken != "new" {
		t.Errorf("credentials %+v, deferred %+v", w.Credentials, w.DeferredIssuances)
	}
	if w.Credentials[2].Renewal.RefreshToken != "unrelated" {
		t.Errorf("another authorization's token changed: %+v", w.Credentials[2].Renewal)
	}
}

// One format that fails or waits leaves the others in the wallet, and the result
// tells each outcome.
func TestEachFormatReportsItsOwnOutcome(t *testing.T) {
	w := generateTestWallet(t)
	issuer, offerURI := setupMockIssuer(t, w, mockIssuerOpts{additionalResponses: map[string]map[string]any{
		"later":   {"transaction_id": "tx-1", "interval": 3600},
		"refused": {"error": "invalid_credential_request"},
	}})
	defer issuer.Close()
	before := len(w.GetCredentials())

	result, err := w.ProcessCredentialOfferWithOptions(offerURI, OfferOptions{ConfigurationID: "test-config", AdditionalConfigurations: []string{"later", "refused"}})
	if err != nil {
		t.Fatal(err)
	}
	if result.CredentialID == "" || len(result.Additional) != 2 {
		t.Fatalf("result = %+v", result)
	}
	if later := result.Additional[0]; !later.Pending || later.TransactionID != "tx-1" {
		t.Errorf("deferred format = %+v", later)
	}
	if refused := result.Additional[1]; refused.Error == "" || refused.CredentialID != "" {
		t.Errorf("refused format = %+v", refused)
	}
	if got := len(w.GetCredentials()) - before; got != 1 {
		t.Errorf("%d credentials stored, want the one that arrived", got)
	}
}

// A request the user started does not consent to what the issuer asks for
// afterwards.
func TestAnIssuerRequestedPresentationAsksTheUser(t *testing.T) {
	srv := newTestServer(t, false)
	wallet := srv.wallet
	wallet.AutoAccept = false
	wallet.VCIVersion = VCIVersion11
	wallet.VCIClientID = "wallet-client"
	issuer := newInteractiveIssuer(t, wallet)

	finished := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		finished <- serverRequest(t, srv, http.MethodPost, issuancePath, `{"issuer":"`+issuer.url+`","credential_configuration_ids":["test-config"]}`)
	}()
	var prompt *consent.Request
	for deadline := time.Now().Add(5 * time.Second); prompt == nil && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		for _, req := range wallet.Consents().Pending() {
			prompt = req
		}
	}
	if prompt == nil {
		t.Fatal("the wallet did not ask the user")
	}
	if issuer.intermediateForm != nil {
		t.Error("the wallet presented before the user answered")
	}
	serverRequest(t, srv, http.MethodPost, "/api/requests/"+prompt.ID+"/deny", "")
	select {
	case <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("the flow kept waiting after the denial")
	}
	if strings.Contains(issuer.intermediateForm.Get("openid4vp_response"), "vp_token") {
		t.Error("the wallet presented after a denial")
	}
}

func TestACatalogueEntryNamesAnIssuer(t *testing.T) {
	w := generateTestWallet(t)
	entry := registrar.CatalogAttestation{Name: "Diploma", CredentialIssuer: "https://issuer.example/",
		Credentials: []registrar.CatalogCredential{{Format: credtype.FormatSDJWT, Type: "urn:example:diploma:1"}}}
	if _, err := w.Registrar().AddCatalogAttestation(entry); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(w.knownIssuers(), KnownIssuer{Name: "issuer.example", URL: "https://issuer.example"}) {
		t.Errorf("known issuers = %+v", w.knownIssuers())
	}
	entry.Name, entry.CredentialIssuer = "Other", "ftp://issuer.example"
	entry.Credentials[0].Type = "urn:example:other:1"
	if _, err := w.Registrar().AddCatalogAttestation(entry); err == nil {
		t.Error("the catalogue took an issuer that is not a web URL")
	}
}

// An empty wallet has no other credential to offer, so only the catalogue decides
// whether the dialog opens.
func TestAnEmptyWalletOffersWhatTheCatalogueHas(t *testing.T) {
	w := generateTestWallet(t)
	if _, err := w.Registrar().AddCatalogAttestation(registrar.CatalogAttestation{Name: "Diploma",
		Credentials: []registrar.CatalogCredential{{Format: credtype.FormatSDJWT, Type: "urn:example:diploma:1"}}}); err != nil {
		t.Fatal(err)
	}
	query := func(vct string) map[string]any {
		return map[string]any{"credentials": []any{map[string]any{"id": "q", "format": credtype.FormatSDJWT, "meta": map[string]any{"vct_values": []any{vct}}}}}
	}
	options := w.obtainableOptions(query("urn:example:diploma:1"))
	if options == nil || len(options.Queries) != 1 || options.Queries[0].Candidates == nil || len(options.Queries[0].Obtainable) != 1 {
		t.Fatalf("options = %+v", options)
	}
	if got := w.obtainableOptions(query("urn:example:unknown:1")); got != nil {
		t.Errorf("options = %+v for a type outside the catalogue", got)
	}
}

// Visitors can add catalogue entries on a public demo, so the issuers they name
// count too.
func TestAPublicDemoKnowsTheIssuersVisitorsName(t *testing.T) {
	srv := newTestServer(t, false)
	if err := srv.SetDemo(DemoOptions{}); err != nil {
		t.Fatal(err)
	}
	if _, err := srv.wallet.Registrar().AddCatalogAttestation(registrar.CatalogAttestation{Name: "Visitor's", CredentialIssuer: "https://visitor.example",
		Credentials: []registrar.CatalogCredential{{Format: credtype.FormatSDJWT, Type: "urn:example:visitor:1"}}}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(srv.wallet.knownIssuers(), KnownIssuer{Name: "visitor.example", URL: "https://visitor.example"}) {
		t.Errorf("known issuers = %+v", srv.wallet.knownIssuers())
	}
}

// A person in strict mode can still request the missing credential. A request
// nobody answers ends with no_match.
func TestStrictModeAsksAboutACredentialFromTheCatalogue(t *testing.T) {
	w := generateTestWallet(t)
	w.ValidationMode = ValidationModeStrict
	if _, err := w.Registrar().AddCatalogAttestation(registrar.CatalogAttestation{Name: "Diploma",
		Credentials: []registrar.CatalogCredential{{Format: credtype.FormatSDJWT, Type: "urn:example:diploma:1"}}}); err != nil {
		t.Fatal(err)
	}
	authReq := queryRequest(map[string]any{"credentials": []any{map[string]any{"id": "q", "format": credtype.FormatSDJWT, "meta": map[string]any{"vct_values": []any{"urn:example:diploma:1"}}}}})
	person := w.evaluatePresentationRequest(authReq, presentationEntry{action: "presentation", subject: "The request", interactive: true})
	if person.invalid != nil || person.refusal != nil || person.options == nil {
		t.Errorf("with a person: invalid %v, refusal %+v, options %+v", person.invalid, person.refusal, person.options)
	}
	headless := w.evaluatePresentationRequest(authReq, presentationEntry{action: "presentation", subject: "The request"})
	if headless.refusal == nil || headless.refusal.status != "no_match" {
		t.Errorf("without a person: refusal %+v, want no_match", headless.refusal)
	}
}

// The sign-in of a requested credential would hide the window of a Digital
// Credentials API call, so that call ends with no_match.
func TestADigitalCredentialsCallOffersNoIssuance(t *testing.T) {
	w := generateTestWallet(t)
	if _, err := w.Registrar().AddCatalogAttestation(registrar.CatalogAttestation{Name: "Diploma",
		Credentials: []registrar.CatalogCredential{{Format: credtype.FormatSDJWT, Type: "urn:example:diploma:1"}}}); err != nil {
		t.Fatal(err)
	}
	authReq := queryRequest(map[string]any{"credentials": []any{map[string]any{"id": "q", "format": credtype.FormatSDJWT, "meta": map[string]any{"vct_values": []any{"urn:example:diploma:1"}}}}})
	authReq.Source = oid4vp.SourceDCAPI
	outcome := w.evaluatePresentationRequest(authReq, presentationEntry{action: "presentation", subject: "The request", interactive: true})
	if outcome.refusal == nil || outcome.refusal.status != "no_match" {
		t.Errorf("refusal %+v, want no_match", outcome.refusal)
	}
}

// The list names the entry's issuer without asking it. The request asks it and
// reports what is wrong.
func TestARequestByAttestationAsksTheIssuer(t *testing.T) {
	srv := newTestServer(t, false)
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"credential_issuer": "http://" + r.Host, "credential_configurations_supported": map[string]any{"other": displayed(credtype.FormatSDJWT, "urn:example:other:1", "Other")}})
	}))
	defer issuer.Close()
	entry, err := srv.wallet.Registrar().AddCatalogAttestation(registrar.CatalogAttestation{Name: "Diploma", CredentialIssuer: issuer.URL,
		Credentials: []registrar.CatalogCredential{{Format: credtype.FormatSDJWT, Type: "urn:example:diploma:1"}}})
	if err != nil {
		t.Fatal(err)
	}
	credentials, _ := srv.wallet.IssuableCredentials()
	listed := slices.ContainsFunc(credentials, func(c IssuableCredential) bool {
		return c.ID == entry.Schema.ID && len(c.Issuers) == 1 && c.Issuers[0].URL == issuer.URL && len(c.Issuers[0].Configurations) == 0
	})
	if !listed {
		t.Errorf("credentials = %+v, want the named issuer", credentials)
	}
	request := func(url string) *httptest.ResponseRecorder {
		return serverRequest(t, srv, http.MethodPost, issuancePath, `{"issuer":"`+url+`","attestation":"`+entry.Schema.ID+`"}`)
	}
	if w := request(issuer.URL); w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "offer Diploma") {
		t.Errorf("issuer without the type: %d %s", w.Code, w.Body)
	}
	if w := request("https://elsewhere.example"); w.Code != http.StatusBadRequest {
		t.Errorf("another issuer: %d %s", w.Code, w.Body)
	}
	dead, err := srv.wallet.Registrar().AddCatalogAttestation(registrar.CatalogAttestation{Name: "Dead", CredentialIssuer: "http://127.0.0.1:1",
		Credentials: []registrar.CatalogCredential{{Format: credtype.FormatSDJWT, Type: "urn:example:dead:1"}}})
	if err != nil {
		t.Fatal(err)
	}
	if w := serverRequest(t, srv, http.MethodPost, issuancePath, `{"issuer":"http://127.0.0.1:1","attestation":"`+dead.Schema.ID+`"}`); w.Code != http.StatusBadGateway {
		t.Errorf("issuer without an answer: %d %s", w.Code, w.Body)
	}
}

// One failed refresh keeps the requests of the issuer working.
func TestAFailedRefreshKeepsTheOffer(t *testing.T) {
	var cache issuerOfferCache
	issuers := []KnownIssuer{{Name: "Issuer", URL: "https://issuer.example"}}
	read := func(fetch issuerOfferFetch) map[string]any {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			offered, loading := cache.read(issuers, fetch)
			if !loading {
				return offered[0]
			}
			time.Sleep(time.Millisecond)
		}
		t.Fatal("the fetch didn't end")
		return nil
	}
	read(func(string) (map[string]any, error) { return map[string]any{"ticket": map[string]any{}}, nil })
	cache.mu.Lock()
	entry := cache.entries[issuers[0].URL]
	entry.retryAt = time.Time{}
	cache.entries[issuers[0].URL] = entry
	cache.mu.Unlock()
	if got := read(func(string) (map[string]any, error) { return nil, errors.New("down") }); len(got) != 1 {
		t.Errorf("offer = %v, want the last one", got)
	}
}

// An entry can't request more than the limit, whatever the metadata lists.
func TestARequestByAttestationHasTheLimit(t *testing.T) {
	srv := newTestServer(t, false)
	configurations := map[string]any{}
	for i := range maxIssuanceConfigurations + 1 {
		configurations[fmt.Sprintf("c%d", i)] = displayed(credtype.FormatSDJWT, "urn:example:diploma:1", "Other")
	}
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"credential_issuer": "http://" + r.Host, "credential_configurations_supported": configurations})
	}))
	defer issuer.Close()
	entry, err := srv.wallet.Registrar().AddCatalogAttestation(registrar.CatalogAttestation{Name: "Diploma", CredentialIssuer: issuer.URL,
		Credentials: []registrar.CatalogCredential{{Format: credtype.FormatSDJWT, Type: "urn:example:diploma:1"}}})
	if err != nil {
		t.Fatal(err)
	}
	w := serverRequest(t, srv, http.MethodPost, issuancePath, `{"issuer":"`+issuer.URL+`","attestation":"`+entry.Schema.ID+`"}`)
	if w.Code != http.StatusBadRequest {
		t.Errorf("POST = %d: %s", w.Code, w.Body)
	}
}

// Anyone can choose a trade name on a shared registrar, so the address stays
// visible.
func TestAnIssuerNameShowsItsAddress(t *testing.T) {
	w := generateTestWallet(t)
	if _, err := w.Registrar().RegisterRelyingParty(registrar.WalletRelyingParty{
		TradeName: "Party",
		Services: []registrar.WalletRelyingPartyService{{ServiceIdentifier: "issuer", ServiceTradeName: "Federal Office", CredentialIssuer: "https://evil.example",
			IntendedUses: []registrar.IntendedUse{{
				Purpose:     []registrar.MultiLangString{{Lang: "en", Content: "Diplomas"}},
				Credentials: []registrar.RegisteredCredential{{Format: credtype.FormatSDJWT, Meta: map[string]any{"vct_values": []any{"urn:example:diploma:1"}}, Claims: []registrar.RegisteredClaim{{Path: []any{"name"}}}}},
			}}}},
	}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(w.knownIssuers(), KnownIssuer{Name: "Federal Office (evil.example)", URL: "https://evil.example"}) {
		t.Errorf("known issuers = %+v", w.knownIssuers())
	}
}

// The queries with a catalogue entry must be able to answer the request.
func TestAnUnanswerableQueryOpensNoDialog(t *testing.T) {
	w := generateTestWallet(t)
	if _, err := w.Registrar().AddCatalogAttestation(registrar.CatalogAttestation{Name: "Diploma",
		Credentials: []registrar.CatalogCredential{{Format: credtype.FormatSDJWT, Type: "urn:example:diploma:1"}}}); err != nil {
		t.Fatal(err)
	}
	queries := []any{
		map[string]any{"id": "a", "format": credtype.FormatSDJWT, "meta": map[string]any{"vct_values": []any{"urn:example:diploma:1"}}},
		map[string]any{"id": "b", "format": credtype.FormatSDJWT, "meta": map[string]any{"vct_values": []any{"urn:example:unknown:1"}}},
	}
	if got := w.obtainableOptions(map[string]any{"credentials": queries}); got != nil {
		t.Errorf("options = %+v", got)
	}
	alternatives := []any{map[string]any{"options": []any{[]any{"a"}, []any{"b"}}}}
	if w.obtainableOptions(map[string]any{"credentials": queries, "credential_sets": alternatives}) == nil {
		t.Error("alternatives: no options, want the query with an entry")
	}
	optional := []any{map[string]any{"required": false, "options": []any{[]any{"b"}}}}
	if got := w.obtainableOptions(map[string]any{"credentials": queries[1:], "credential_sets": optional}); got != nil {
		t.Errorf("optional sets without an entry: options = %+v", got)
	}
	both := []any{map[string]any{"options": []any{[]any{"a", "b"}}}}
	if got := w.obtainableOptions(map[string]any{"credentials": queries, "credential_sets": both}); got != nil {
		t.Errorf("an option with an unknown query: options = %+v", got)
	}
}

// A visitor's issuer can't attach itself to another entry, whatever its metadata
// says.
func TestAPublicDemoListsAVisitorsIssuerOnItsOwnEntry(t *testing.T) {
	w := generateTestWallet(t)
	w.sharedRegistrar = true
	entry := func(name, issuer, typ string) {
		if _, err := w.Registrar().AddCatalogAttestation(registrar.CatalogAttestation{Name: name, CredentialIssuer: issuer,
			Credentials: []registrar.CatalogCredential{{Format: credtype.FormatSDJWT, Type: typ}}}); err != nil {
			t.Fatal(err)
		}
	}
	entry("Operator's", "", "urn:example:operator:1")
	entry("Visitor's", "https://visitor.example", "urn:example:visitor:1")
	w.issuerOffers = issuerOfferCache{entries: map[string]issuerOffer{
		"https://visitor.example": {
			configurations: map[string]any{"fake": displayed(credtype.FormatSDJWT, "urn:example:operator:1", "Fake")},
			retryAt:        time.Now().Add(time.Hour),
		},
	}}
	credentials, _ := w.IssuableCredentials()
	for _, credential := range credentials {
		if credential.Name == "Operator's" && len(credential.Issuers) != 0 {
			t.Errorf("issuers = %+v", credential.Issuers)
		}
	}
}

// The list keeps a bounded part of the metadata and still matches.
func TestTheListKeepsWhatMatchingNeeds(t *testing.T) {
	configurations := map[string]any{"extra": "not a configuration"}
	for i := range maxListedConfigurations + 1 {
		configuration := displayed(credtype.FormatSDJWT, "urn:example:diploma:1", "Diploma")
		configuration["claims"] = strings.Repeat("x", 1000)
		configurations[fmt.Sprintf("c%04d", i)] = configuration
	}
	listed := listedConfigurations(configurations)
	if len(listed) != maxListedConfigurations {
		t.Fatalf("listed %d", len(listed))
	}
	first := listed["c0000"].(map[string]any)
	if first["claims"] != nil || !hasDisplayName(first, "Diploma") {
		t.Errorf("first = %v", first)
	}
}

// A hanging issuer doesn't hold up the list, and the wallet asks it once.
func TestTheIssuerListWaitsForNoIssuer(t *testing.T) {
	var cache issuerOfferCache
	release := make(chan struct{})
	var calls atomic.Int32
	fetch := func(string) (map[string]any, error) {
		calls.Add(1)
		<-release
		return map[string]any{"ticket": map[string]any{}}, nil
	}
	issuers := []KnownIssuer{{Name: "Issuer", URL: "https://issuer.example"}}
	offered, loading := cache.read(issuers, fetch)
	if !loading || offered[0] != nil {
		t.Fatalf("first read: offered %v, loading %v", offered, loading)
	}
	if _, loading := cache.read(issuers, fetch); !loading {
		t.Error("the fetch ended before its release")
	}
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for loading && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
		offered, loading = cache.read(issuers, fetch)
	}
	if loading || len(offered[0]) != 1 || calls.Load() != 1 {
		t.Errorf("offered %v, loading %v after %d fetches", offered, loading, calls.Load())
	}
}
